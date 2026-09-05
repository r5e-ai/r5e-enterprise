defmodule Recurse.Gateway.Fold.SubmitterTest do
  @moduledoc """
  Spec 012 S9b — every `spec_for_*` map the submitter builds is validated
  against the **admitted schema** of its Kind, using the kernel's own
  validator (`R5e.Kind.Validate.structure/2` + `constraints/3`, the two
  halves of `validateStructure`/`validateConstraints`) over the seed files
  the fold admits at boot (`apps/recurse_fold/priv/kinds/*.json`, verbatim
  copies of spec 010's). So: required keys present, no key outside the
  schema (`additionalProperties: false`), refs in their declared form,
  enums/minimums/`exactlyOne`/`requires` honoured, and — scanned
  separately here as well — **no float anywhere**.

  Pure functions only; no kernel is booted. The dual-write itself is
  `submitter_integration_test.exs`.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Fold.Submitter
  alias Recurse.Shared.LlmProxy.ToolUseIntent

  @hex String.duplicate("ab", 32)
  @bytes_ref "bytes:sha256:" <> @hex
  @event_ref "event:sha256:" <> @hex
  @session_ref "gateway.r5e.io/v1alpha1/AgentSession/sha256:" <> @hex
  @prompt_name "sha256:" <> @hex
  @completion_name "sha256:" <> String.duplicate("cd", 32)
  @run_id "6d3a5f70-0b6c-4d8e-9a3c-2f1e4b5c6d7e"

  # -- the Kinds, as admitted -------------------------------------------------

  defp kind!(name) do
    path = Path.join([to_string(:code.priv_dir(:recurse_fold)), "kinds", name <> ".json"])
    {:ok, kind} = path |> File.read!() |> Jason.decode!() |> R5e.Kind.from_map()
    kind
  end

  defp assert_valid!(kind_file, spec) do
    kind = kind!(kind_file)
    assert :ok = R5e.Kind.Validate.structure(kind, spec), "structure: #{inspect(spec)}"
    assert :ok = R5e.Kind.Validate.constraints(kind, spec), "constraints: #{inspect(spec)}"
    assert_no_floats(spec)

    # Belt to the validator's brace: every top-level key is declared.
    declared = kind.schema["properties"] |> Map.keys() |> MapSet.new()
    extra = spec |> Map.keys() |> MapSet.new() |> MapSet.difference(declared)
    assert MapSet.size(extra) == 0, "keys outside #{kind_file}'s schema: #{inspect(extra)}"
    spec
  end

  defp assert_no_floats(v) when is_float(v), do: flunk("float in spec: #{v}")
  defp assert_no_floats(m) when is_map(m), do: Enum.each(m, fn {_k, v} -> assert_no_floats(v) end)
  defp assert_no_floats(l) when is_list(l), do: Enum.each(l, &assert_no_floats/1)
  defp assert_no_floats(_), do: :ok

  # -- fixtures ---------------------------------------------------------------

  defp call_state(overrides \\ %{}) do
    Map.merge(
      %{
        tenant_id: "01TEN_TEST",
        principal_id: "claude-code:00000000-0000-0000-0000-000000000000",
        principal_kind: "obo_human",
        session_id: "session-1",
        started_at: ~U[2026-09-02 10:00:00.123456Z],
        completed_at: ~U[2026-09-02 10:00:01.500000Z],
        model: "claude-haiku-4-5-20251001",
        provider: "anthropic",
        upstream_host: "api.anthropic.com",
        transport: :https_sse,
        api_format: :anthropic_messages,
        request_path: "/v1/messages?beta=true",
        prompt_hash: :crypto.hash(:sha256, "req"),
        response_hash: :crypto.hash(:sha256, "resp"),
        prompt_token_count: 10,
        completion_token_count: 181,
        reasoning_token_count: 102,
        cedar_bundle_hash: :crypto.hash(:sha256, "bundle"),
        upstream_status_code: 200,
        error_kind: nil,
        intents: [],
        latency_ms: 1377,
        added_latency_ms: 0,
        client_session_id: "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca",
        upstream_response_headers: [{"content-type", "text/event-stream; charset=utf-8"}]
      },
      overrides
    )
  end

  defp intent(args, opts \\ []) do
    {:ok, intent} =
      ToolUseIntent.new(
        Map.merge(
          %{
            call_id: "toolu_01LZV8Ni38xTJKZoqdQM8Pdk",
            tool_name: "Bash",
            tool_args: args,
            extracted_at: ~U[2026-09-02 10:00:01.000000Z],
            provider_event_span: %{start_byte_offset: 0, end_byte_offset: 10, event_indices: [1]}
          },
          Map.new(opts)
        )
      )

    intent
  end

  # -- AgentSession -------------------------------------------------------------

  describe "spec_for_agent_session/1" do
    test "names the client session under sourceIds and the harness" do
      spec = assert_valid!("agent-session", Submitter.spec_for_agent_session(call_state()))

      assert spec == %{
               "harness" => "claude-code",
               "startedAt" => "2026-09-02T10:00:00.123456Z",
               "sourceIds" => %{"session" => "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca"}
             }
    end

    test "omits the harness for a principal that is not Claude Code" do
      spec =
        assert_valid!(
          "agent-session",
          Submitter.spec_for_agent_session(call_state(%{principal_id: "anonymous"}))
        )

      refute Map.has_key?(spec, "harness")
    end
  end

  # -- Prompt / Completion ---------------------------------------------------------

  describe "spec_for_prompt/3 and spec_for_completion/2" do
    test "Prompt cites the bytes, the media type and the session" do
      spec =
        assert_valid!("prompt", Submitter.spec_for_prompt(call_state(), @bytes_ref, @session_ref))

      assert spec["contentRef"] == %{"$ref" => @bytes_ref}
      assert spec["mediaType"] == "application/json"
      assert spec["session"] == %{"$ref" => @session_ref}
      refute Map.has_key?(spec, "role")
    end

    test "Prompt without a session omits the ref" do
      spec = assert_valid!("prompt", Submitter.spec_for_prompt(call_state(), @bytes_ref, nil))
      refute Map.has_key?(spec, "session")
    end

    test "Completion carries the upstream content type without its parameters" do
      spec = assert_valid!("completion", Submitter.spec_for_completion(call_state(), @bytes_ref))
      assert spec["mediaType"] == "text/event-stream"
      assert spec["observedAt"] == "2026-09-02T10:00:01.500000Z"
    end

    test "Completion with no content-type header omits mediaType" do
      spec =
        assert_valid!(
          "completion",
          Submitter.spec_for_completion(call_state(%{upstream_response_headers: []}), @bytes_ref)
        )

      refute Map.has_key?(spec, "mediaType")
    end
  end

  # -- LlmCall ---------------------------------------------------------------------

  describe "spec_for_llm_call/4" do
    test "maps the call's coordinates onto the Kind and nothing else" do
      spec =
        assert_valid!(
          "llm-call",
          Submitter.spec_for_llm_call(call_state(), @prompt_name, @session_ref, @run_id)
        )

      assert spec == %{
               "model" => "claude-haiku-4-5-20251001",
               "prompt" => %{"$ref" => "gateway.r5e.io/v1alpha1/Prompt/" <> @prompt_name},
               "provider" => "anthropic",
               "upstreamHost" => "api.anthropic.com",
               "transport" => "https-sse",
               "apiFormat" => "anthropic_messages",
               "requestPath" => "/v1/messages?beta=true",
               "session" => %{"$ref" => @session_ref},
               "sourceIds" => %{
                 "session" => "ecdcbccc-ecb4-40f4-bbb1-db3ad3b16bca",
                 "run" => @run_id
               },
               "startedAt" => "2026-09-02T10:00:00.123456Z"
             }
    end

    test "wss transport, no session, no client session id" do
      spec =
        assert_valid!(
          "llm-call",
          Submitter.spec_for_llm_call(
            call_state(%{
              transport: :wss,
              client_session_id: nil,
              api_format: "openai_responses"
            }),
            @prompt_name,
            nil,
            @run_id
          )
        )

      assert spec["transport"] == "wss"
      assert spec["apiFormat"] == "openai_responses"
      refute Map.has_key?(spec, "session")
      assert spec["sourceIds"] == %{"run" => @run_id}
    end

    test "gateway-only facts have no slot and are not smuggled in" do
      spec = Submitter.spec_for_llm_call(call_state(), @prompt_name, nil, @run_id)

      for key <- ~w(principal_source upstream_org_id parser parse kind parameters tools) do
        refute Map.has_key?(spec, key)
      end
    end
  end

  # -- ToolCall ---------------------------------------------------------------------

  describe "spec_for_tool_call/4" do
    test "inlines decoded args, cites the LlmCall with its index, keeps the provider call id" do
      i = intent(%{"command" => "ls -la", "description" => "List files"})

      spec =
        assert_valid!("tool-call", Submitter.spec_for_tool_call(i, @event_ref, 0, @session_ref))

      assert spec == %{
               "tool" => "Bash",
               "args" => %{"command" => "ls -la", "description" => "List files"},
               "llmCall" => %{"$ref" => @event_ref},
               "index" => 0,
               "callId" => "toolu_01LZV8Ni38xTJKZoqdQM8Pdk",
               "session" => %{"$ref" => @session_ref},
               "extractedAt" => "2026-09-02T10:00:01.000000Z"
             }
    end

    test "without an LlmCall the ref is absent (and index is still allowed)" do
      spec = assert_valid!("tool-call", Submitter.spec_for_tool_call(intent(%{}), nil, 3, nil))
      refute Map.has_key?(spec, "llmCall")
      assert spec["index"] == 3
      assert spec["args"] == %{}
    end

    test ":too_large args become a hash + size under names that say so" do
      raw = ~s({"command":"#{String.duplicate("x", 20_000)}"})
      i = intent(:too_large, raw_json: raw)
      spec = assert_valid!("tool-call", Submitter.spec_for_tool_call(i, @event_ref, 1))

      assert spec["args"] == %{
               "argsHash" => "sha256:" <> Base.encode16(:crypto.hash(:sha256, raw), case: :lower),
               "argsSizeBytes" => byte_size(raw),
               "argsOmitted" => true
             }
    end
  end

  # -- LlmResponse ---------------------------------------------------------------------

  describe "spec_for_llm_response/4" do
    test "ok: completion, tool calls in order, integer usage and latency" do
      spec =
        assert_valid!(
          "llm-response",
          Submitter.spec_for_llm_response(call_state(), @event_ref, @completion_name, [
            "event:sha256:" <> String.duplicate("11", 32),
            "event:sha256:" <> String.duplicate("22", 32)
          ])
        )

      assert spec == %{
               "llmCall" => %{"$ref" => @event_ref},
               "outcome" => "ok",
               "toolCalls" => [
                 %{"$ref" => "event:sha256:" <> String.duplicate("11", 32)},
                 %{"$ref" => "event:sha256:" <> String.duplicate("22", 32)}
               ],
               "completion" => %{
                 "$ref" => "gateway.r5e.io/v1alpha1/Completion/" <> @completion_name
               },
               "upstreamStatus" => 200,
               "usage" => %{"inputTokens" => 10, "outputTokens" => 181, "reasoningTokens" => 102},
               "latency" => %{"upstreamMs" => 1377, "addedMs" => 0},
               "completedAt" => "2026-09-02T10:00:01.500000Z"
             }
    end

    test "error: no completion, the enterprise error_kind as errorKind, no status when 0" do
      spec =
        assert_valid!(
          "llm-response",
          Submitter.spec_for_llm_response(
            call_state(%{
              error_kind: "upstream_connection_failed",
              upstream_status_code: 0,
              reasoning_token_count: nil,
              completion_token_count: 0
            }),
            @event_ref,
            nil,
            []
          )
        )

      assert spec["outcome"] == "error"
      assert spec["errorKind"] == "upstream_connection_failed"
      assert spec["toolCalls"] == []
      refute Map.has_key?(spec, "completion")
      refute Map.has_key?(spec, "upstreamStatus")
      assert spec["usage"] == %{"inputTokens" => 10, "outputTokens" => 0}
    end

    test "every enterprise error_kind is in the Kind's enum" do
      for kind <-
            ~w(upstream_4xx upstream_5xx parser_failure policy_evaluation_failure upstream_connection_failed) do
        assert_valid!(
          "llm-response",
          Submitter.spec_for_llm_response(
            call_state(%{error_kind: kind, upstream_status_code: 502}),
            @event_ref,
            nil,
            []
          )
        )
      end
    end
  end

  # -- decisions ----------------------------------------------------------------------

  describe "gateway_decision/1 and mismatch?/2" do
    test "the three gateway decisions collapse to allow / deny / error" do
      assert Submitter.gateway_decision({:allow}) == :allow
      assert Submitter.gateway_decision({:deny, %{rule_id: "policy1", reason: "x"}}) == :deny
      assert Submitter.gateway_decision({:error, :cedar_eval_error}) == :error
    end

    test "a mismatch is the gateway letting through what the fold denied, or the reverse" do
      refute Submitter.mismatch?(:allow, :allow)
      refute Submitter.mismatch?(:deny, :deny)
      refute Submitter.mismatch?(:error, :deny)
      assert Submitter.mismatch?(:allow, :deny)
      assert Submitter.mismatch?(:deny, :allow)
      assert Submitter.mismatch?(:error, :allow)
    end
  end
end
