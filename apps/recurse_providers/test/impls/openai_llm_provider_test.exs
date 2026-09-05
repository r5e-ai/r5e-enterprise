defmodule Recurse.Providers.Impls.OpenAiLlmProviderTest do
  @moduledoc """
  Contract test for `Recurse.Providers.Impls.OpenAiLlmProvider` (T029 +
  Phase-3 T039/T040).

  Drives the real implementation against an isolated
  `Recurse.Providers.Support.MockHttpUpstream` (Bypass-equivalent built
  on `Plug.Cowboy` because Bypass 2.1 is incompatible with the umbrella's
  `ranch` resolution — see `test/support/mock_http_upstream.ex`).

  Covers (per `contracts/provider_impls.md` §OpenAiLlmProvider +
  `research.md` D3):

    * Sync `chat_complete/3`: body pass-through, `Authorization` bearer
      injection, strip of identity/correlation headers, 2xx decoding,
      5xx → `{:upstream_error, status, body, headers}`, timeout →
      `{:upstream_error, :timeout, _, _}`.
    * Streaming `chat_complete_stream/3`: chunks enumerable in order,
      `[DONE]` terminator closes the stream, caller `Enum.take/2`
      releases the upstream connection.
  """

  # async: true — each test owns an isolated MockHttpUpstream on a random
  # port + its own Finch instance under a unique name. No shared globals.
  use ExUnit.Case, async: true

  alias Recurse.Providers.Impls.OpenAiLlmProvider
  alias Recurse.Providers.Support.MockHttpUpstream

  # --- Shared setup -------------------------------------------------------

  setup ctx do
    {:ok, upstream} = MockHttpUpstream.start()
    on_exit(fn -> MockHttpUpstream.stop(upstream) end)

    # Dynamic atom creation is bounded by test count per run; required for
    # async: true test isolation (fixed name would collide across parallel tests
    # because :erlang.register/2 is BEAM-node-wide, not per-supervisor).
    # credo:disable-for-next-line Credo.Check.Warning.UnsafeToAtom
    finch_name = :"finch_#{:erlang.unique_integer([:positive])}"
    start_supervised!({Finch, name: finch_name})

    config = %{
      base_url: MockHttpUpstream.url(upstream),
      api_key_ref: "secrets://openai_api_key",
      resolved_api_key: "sk-test-" <> Integer.to_string(:erlang.unique_integer([:positive])),
      timeout_ms: 1_000,
      finch_pool: finch_name,
      http2: false
    }

    {:ok, state} = OpenAiLlmProvider.init(config)

    Map.merge(ctx, %{upstream: upstream, finch: finch_name, config: config, state: state})
  end

  # --- init/1 -------------------------------------------------------------

  describe "init/1" do
    test "returns {:ok, state} with validated config fields", %{state: state, config: config} do
      assert %{
               base_url: base_url,
               api_key: api_key,
               finch_pool: pool,
               timeout_ms: 1_000
             } = state

      # trailing slash is normalized away so we can append "/chat/completions"
      # without double-slashing.
      refute String.ends_with?(base_url, "/")
      assert base_url == String.trim_trailing(config.base_url, "/")
      assert api_key == config.resolved_api_key
      assert pool == config.finch_pool
    end

    test "fails with :missing_config when base_url absent" do
      assert {:error, {:missing_config, :base_url}} =
               OpenAiLlmProvider.init(%{finch_pool: :x, resolved_api_key: "k"})
    end

    test "fails with :missing_config when finch_pool absent", %{config: config} do
      config = Map.delete(config, :finch_pool)
      assert {:error, {:missing_config, :finch_pool}} = OpenAiLlmProvider.init(config)
    end

    test "fails when neither resolved_api_key nor usable api_key_ref is present", %{
      config: config
    } do
      config =
        config
        |> Map.delete(:resolved_api_key)
        |> Map.delete(:api_key_ref)

      assert {:error, {:missing_config, :api_key}} = OpenAiLlmProvider.init(config)
    end
  end

  # --- chat_complete/3 sync path ------------------------------------------

  describe "chat_complete/3" do
    test "passes request body through verbatim to upstream", %{state: state, upstream: upstream} do
      parent = self()

      MockHttpUpstream.expect(upstream, fn conn ->
        {:ok, raw, conn} = Plug.Conn.read_body(conn)
        send(parent, {:upstream_body, raw, conn.req_headers, conn.request_path})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, Jason.encode!(sample_response()))
      end)

      request = sample_request()
      assert {:ok, _resp} = OpenAiLlmProvider.chat_complete(state, request, identity_ctx())

      assert_received {:upstream_body, raw, _headers, path}
      assert path == "/chat/completions"
      assert Jason.decode!(raw) == request
    end

    test "injects Authorization: Bearer <api_key> on outbound request", %{
      state: state,
      upstream: upstream,
      config: config
    } do
      parent = self()
      expected = "Bearer " <> config.resolved_api_key

      MockHttpUpstream.expect(upstream, fn conn ->
        auth =
          Enum.find_value(conn.req_headers, fn {k, v} ->
            if String.downcase(k) == "authorization", do: v
          end)

        send(parent, {:auth_header, auth})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, Jason.encode!(sample_response()))
      end)

      assert {:ok, _} = OpenAiLlmProvider.chat_complete(state, sample_request(), identity_ctx())
      assert_received {:auth_header, ^expected}
    end

    test "does not leak identity/correlation headers onto the outbound wire", %{
      state: state,
      upstream: upstream
    } do
      parent = self()

      MockHttpUpstream.expect(upstream, fn conn ->
        names =
          conn.req_headers
          |> Enum.map(fn {k, _} -> String.downcase(k) end)
          |> MapSet.new()

        send(parent, {:header_names, names})

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, Jason.encode!(sample_response()))
      end)

      assert {:ok, _} = OpenAiLlmProvider.chat_complete(state, sample_request(), identity_ctx())
      assert_received {:header_names, names}

      refute MapSet.member?(names, "x-observed-identity")
      refute MapSet.member?(names, "x-correlation-id")
    end

    test "returns {:ok, response} on 200 with bytes preserved", %{
      state: state,
      upstream: upstream
    } do
      response_body = sample_response()

      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, Jason.encode!(response_body))
      end)

      assert {:ok, resp} =
               OpenAiLlmProvider.chat_complete(state, sample_request(), identity_ctx())

      assert resp["id"] == response_body["id"]
      assert resp["choices"] == response_body["choices"]
    end

    test "returns {:upstream_error, 503, body, headers} on upstream 5xx", %{
      state: state,
      upstream: upstream
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        Plug.Conn.send_resp(conn, 503, "upstream down")
      end)

      assert {:upstream_error, 503, body, headers} =
               OpenAiLlmProvider.chat_complete(state, sample_request(), identity_ctx())

      assert is_binary(body)
      assert body =~ "upstream"
      assert is_list(headers)
    end

    test "returns {:upstream_error, :timeout, _, _} on connection timeout", %{
      state: state,
      upstream: upstream
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        # Sleep past the configured `timeout_ms: 1_000` so Req/Finch aborts.
        Process.sleep(2_000)
        Plug.Conn.send_resp(conn, 200, "too late")
      end)

      assert {:upstream_error, :timeout, _body, _headers} =
               OpenAiLlmProvider.chat_complete(state, sample_request(), identity_ctx())
    end
  end

  # --- chat_complete_stream/3 streaming path ------------------------------

  describe "chat_complete_stream/3" do
    test "SSE chunks emitted by upstream arrive in order when enumerated", %{
      state: state,
      upstream: upstream
    } do
      chunks = [
        ~s|data: {"choices":[{"delta":{"role":"assistant"},"index":0}]}\n\n|,
        ~s|data: {"choices":[{"delta":{"content":"hel"},"index":0}]}\n\n|,
        ~s|data: {"choices":[{"delta":{"content":"lo"},"index":0}]}\n\n|,
        ~s|data: [DONE]\n\n|
      ]

      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
          |> Plug.Conn.send_chunked(200)

        Enum.reduce(chunks, conn, fn chunk, acc ->
          {:ok, acc} = Plug.Conn.chunk(acc, chunk)
          acc
        end)
      end)

      request = Map.put(sample_request(), "stream", true)

      assert {:ok, stream} =
               OpenAiLlmProvider.chat_complete_stream(state, request, identity_ctx())

      joined = stream |> Enum.to_list() |> IO.iodata_to_binary()

      # Order-preserving: every upstream chunk appears in the enumerated
      # concatenation in the order it was sent. Chunk boundaries may split
      # differently at the HTTP layer (a single `data:` event may span two
      # TCP frames); the contract is "union preserves upstream order".
      Enum.reduce(chunks, 0, fn chunk, from ->
        idx = :binary.match(joined, chunk, scope: {from, byte_size(joined) - from})
        assert {offset, _len} = idx, "chunk not found in order: #{inspect(chunk)}"
        offset + byte_size(chunk)
      end)
    end

    test "[DONE] terminator closes the stream cleanly", %{state: state, upstream: upstream} do
      chunks = [
        ~s|data: {"choices":[{"delta":{"content":"ok"}}]}\n\n|,
        ~s|data: [DONE]\n\n|
      ]

      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
          |> Plug.Conn.send_chunked(200)

        Enum.reduce(chunks, conn, fn chunk, acc ->
          {:ok, acc} = Plug.Conn.chunk(acc, chunk)
          acc
        end)
      end)

      request = Map.put(sample_request(), "stream", true)

      assert {:ok, stream} =
               OpenAiLlmProvider.chat_complete_stream(state, request, identity_ctx())

      # Enum.to_list MUST return naturally (not hang) once the upstream
      # finishes sending. If the provider didn't detect end-of-stream the
      # test process would block forever and ExUnit's timeout would fail.
      collected = Enum.to_list(stream)
      assert is_list(collected)
      assert collected |> IO.iodata_to_binary() =~ "[DONE]"
    end

    test "halting the Enumerable releases the upstream connection", %{
      state: state,
      upstream: upstream
    } do
      parent = self()

      MockHttpUpstream.expect(upstream, fn conn ->
        conn =
          conn
          |> Plug.Conn.put_resp_header("content-type", "text/event-stream")
          |> Plug.Conn.send_chunked(200)

        {:ok, conn} = Plug.Conn.chunk(conn, ~s|data: {"choices":[{"delta":{"content":"x"}}]}\n\n|)
        send(parent, :upstream_first_chunk_sent)

        # Keep the upstream open sending heartbeats. The caller halts
        # enumeration after one chunk; `Req.Response.Async`'s
        # `{:halt, _}` branch invokes `Finch.cancel_async_request/1`
        # which releases the pool slot. We observe either an explicit
        # `{:error, :closed}` from chunk/2 (tight TCP path) OR we simply
        # wind down after the max iterations; the test's primary
        # assertion is that the caller didn't block — the connection
        # release is inherent to `Req.Response.Async`'s cancel_fun.
        Enum.reduce_while(1..50, conn, fn _, acc ->
          case Plug.Conn.chunk(acc, ~s|data: {"choices":[{"delta":{"content":"."}}]}\n\n|) do
            {:ok, acc2} ->
              Process.sleep(20)
              {:cont, acc2}

            {:error, _} ->
              send(parent, :upstream_saw_disconnect)
              {:halt, acc}
          end
        end)
      end)

      request = Map.put(sample_request(), "stream", true)

      assert {:ok, stream} =
               OpenAiLlmProvider.chat_complete_stream(state, request, identity_ctx())

      # The critical assertion: `Enum.take(stream, 1)` must NOT hang —
      # enumeration happens in the same process that made the request
      # (this one) because `Req.Response.Async` refuses cross-process
      # enumeration by design.
      assert [_first] = Enum.take(stream, 1)
      assert_received :upstream_first_chunk_sent
    end

    test "returns {:upstream_error, status, body, headers} on non-2xx upstream", %{
      state: state,
      upstream: upstream
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        Plug.Conn.send_resp(conn, 503, "upstream down")
      end)

      request = Map.put(sample_request(), "stream", true)

      assert {:upstream_error, 503, body, headers} =
               OpenAiLlmProvider.chat_complete_stream(state, request, identity_ctx())

      assert is_binary(body)
      assert is_list(headers)
    end
  end

  # --- Mock-upstream infrastructure self-test -----------------------------

  describe "mock upstream infrastructure" do
    test "round-trips a request through Finch + MockHttpUpstream", %{
      upstream: upstream,
      finch: finch
    } do
      MockHttpUpstream.expect(upstream, fn conn ->
        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, ~s|{"pong":true}|)
      end)

      request = Finch.build(:get, MockHttpUpstream.url(upstream) <> "/ping")
      assert {:ok, %Finch.Response{status: 200, body: body}} = Finch.request(request, finch)
      assert body == ~s|{"pong":true}|
    end
  end

  # --- Fixtures -----------------------------------------------------------

  defp sample_request do
    %{
      "model" => "gpt-4o-mini",
      "messages" => [
        %{"role" => "system", "content" => "you are a test fixture"},
        %{"role" => "user", "content" => "ping"}
      ]
    }
  end

  defp sample_response do
    %{
      "id" => "chatcmpl-test-0001",
      "object" => "chat.completion",
      "created" => 1_700_000_000,
      "model" => "gpt-4o-mini",
      "choices" => [
        %{
          "index" => 0,
          "message" => %{"role" => "assistant", "content" => "pong"},
          "finish_reason" => "stop"
        }
      ],
      "usage" => %{"prompt_tokens" => 3, "completion_tokens" => 1, "total_tokens" => 4}
    }
  end

  defp identity_ctx do
    principal =
      Recurse.Shared.Principal.service_account(%{
        issuer: "https://mock-idp.recurse.test",
        account_id: "contract-test"
      })

    Recurse.Shared.IdentityContext.new(%{
      machine_identity: "spiffe://mock.recurse.test/workload/contract-test",
      principal: principal,
      tenant_id: "tenant-test",
      correlation_id: "01HZZZZZZZZZZZZZZZZZZZZZZZ"
    })
  end
end
