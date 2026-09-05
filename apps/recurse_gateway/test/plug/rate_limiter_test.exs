defmodule Recurse.Gateway.Plug.RateLimiterTest do
  @moduledoc """
  Unit tests for `Recurse.Gateway.Plug.RateLimiter` (F002 T092 / FR-030).

  Scope:
    * init/1 validates `:plane` + `:limit`.
    * call/2 allow-under-limit, deny-at-limit, distinct-subject isolation.
    * Error shapes: OpenAI (`:protocol_native`) vs F001 envelope (`:envelope`).
    * Missing principal / tenant → fail closed with 429.
    * Retry-After + RateLimit-* headers present.

  The Hammer backend runs for real (ETS) under a unique name per test so
  tests stay async-safe.
  """

  use ExUnit.Case, async: true

  alias Recurse.Gateway.Plug.RateLimiter
  alias Recurse.Shared.IdentityContext
  alias Recurse.Shared.Principal

  defmodule TestBackend do
    # Per-test ETS-backed Hammer backend. Using `use Hammer, backend: :ets`
    # spins up a child_spec that the test starts under `start_supervised!`.
    use Hammer, backend: :ets
  end

  setup do
    # Unique table name per test run avoids bucket leakage between async
    # tests. Hammer 7 ETS backend keys tables by the module name, so the
    # shared `TestBackend` is fine as long as we use a distinct subject per
    # test (enforced via `make_ref/0` below).
    _pid = start_supervised!({TestBackend, clean_period: :timer.minutes(10)})
    :ok
  end

  describe "init/1" do
    test "accepts valid :data plane opts" do
      opts = RateLimiter.init(plane: :data, limit: 60)

      assert %{
               plane: :data,
               limit: 60,
               scale_ms: 60_000,
               error_style: :protocol_native
             } = opts
    end

    test "accepts valid :audit plane opts with envelope error style" do
      opts = RateLimiter.init(plane: :audit, limit: 120)

      assert %{
               plane: :audit,
               limit: 120,
               error_style: :envelope
             } = opts
    end

    test "raises on invalid :plane" do
      assert_raise ArgumentError, ~r/:plane must be :data or :audit/, fn ->
        RateLimiter.init(plane: :bogus, limit: 10)
      end
    end

    test "raises on missing :limit" do
      assert_raise KeyError, fn ->
        RateLimiter.init(plane: :data)
      end
    end

    test "raises on non-positive :limit" do
      assert_raise ArgumentError, ~r/positive integer/, fn ->
        RateLimiter.init(plane: :data, limit: 0)
      end
    end
  end

  describe "call/2 — data plane" do
    test "allows N requests under the limit then denies the (N+1)th" do
      subject = unique_subject()
      opts = build_opts(:data, limit: 3, backend: TestBackend)

      # 3 allowed
      for _ <- 1..3 do
        conn = build_conn_with_principal(subject)
        result = RateLimiter.call(conn, opts)
        refute result.halted, "conn should not be halted under the limit"
      end

      # 4th denied
      conn = build_conn_with_principal(subject)
      denied = RateLimiter.call(conn, opts)
      assert denied.halted
      assert denied.status == 429
      body = JSON.decode!(denied.resp_body)

      assert %{
               "error" => %{
                 "type" => "rate_limit_error",
                 "code" => "rate_limit_exceeded"
               }
             } = body

      assert header(denied, "retry-after") != nil
      assert header(denied, "ratelimit-limit") == "3"
      assert header(denied, "ratelimit-remaining") == "0"
    end

    test "different subjects do not share the bucket" do
      opts = build_opts(:data, limit: 2, backend: TestBackend)
      sub_a = unique_subject()
      sub_b = unique_subject()

      # Subject A uses up both allowed hits
      for _ <- 1..2, do: RateLimiter.call(build_conn_with_principal(sub_a), opts)

      # Subject A is now denied
      denied_a = RateLimiter.call(build_conn_with_principal(sub_a), opts)
      assert denied_a.halted
      assert denied_a.status == 429

      # Subject B still has a fresh bucket
      allowed_b = RateLimiter.call(build_conn_with_principal(sub_b), opts)
      refute allowed_b.halted
    end

    test "missing principal fails closed with 429" do
      opts = build_opts(:data, limit: 60, backend: TestBackend)
      # Plug.Conn with no :identity_ctx assigned.
      conn = Plug.Test.conn(:post, "/v1/chat/completions")
      denied = RateLimiter.call(conn, opts)
      assert denied.halted
      assert denied.status == 429
      body = JSON.decode!(denied.resp_body)
      assert body["error"]["code"] == "rate_limit_exceeded"
    end

    test "sets RateLimit-* headers on allow" do
      opts = build_opts(:data, limit: 10, backend: TestBackend)
      conn = build_conn_with_principal(unique_subject())
      result = RateLimiter.call(conn, opts)

      refute result.halted
      assert header(result, "ratelimit-limit") == "10"
      assert Integer.parse(header(result, "ratelimit-remaining")) != :error
      assert Integer.parse(header(result, "ratelimit-reset")) != :error
    end
  end

  describe "call/2 — audit plane" do
    test "envelope error shape on deny" do
      opts = build_opts(:audit, limit: 1, backend: TestBackend)
      tenant = unique_tenant()

      _ = RateLimiter.call(build_conn_with_tenant(tenant), opts)
      denied = RateLimiter.call(build_conn_with_tenant(tenant), opts)

      assert denied.halted
      assert denied.status == 429
      body = JSON.decode!(denied.resp_body)

      assert %{
               "error" => %{
                 "code" => "ERR_RATE_LIMITED"
               }
             } = body

      assert header(denied, "retry-after") != nil
    end

    test "missing tenant fails closed" do
      opts = build_opts(:audit, limit: 10, backend: TestBackend)
      conn = Plug.Test.conn(:get, "/v1/audit/receipts")

      denied = RateLimiter.call(conn, opts)
      assert denied.halted
      assert denied.status == 429
      body = JSON.decode!(denied.resp_body)
      assert body["error"]["code"] == "ERR_RATE_LIMITED"
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp build_opts(plane, opts) do
    limit = Keyword.fetch!(opts, :limit)
    backend = Keyword.fetch!(opts, :backend)

    RateLimiter.init(
      plane: plane,
      limit: limit,
      scale_ms: Keyword.get(opts, :scale_ms, 60_000),
      backend: backend
    )
  end

  defp build_conn_with_principal(subject) do
    ctx = %IdentityContext{
      machine_identity: {:observed_identity, %{"sub" => subject}},
      principal: %Principal{
        kind: :obo_human,
        issuer: "https://idp.example.invalid",
        subject: subject,
        recurse_role: "caller"
      },
      tenant_id: "01HQZN5K7J8M9N0P1Q2R3S4T5V",
      correlation_id: "test-corr-#{subject}",
      resolved_at_usec: System.os_time(:microsecond)
    }

    :post
    |> Plug.Test.conn("/v1/chat/completions")
    |> Plug.Conn.assign(:identity_ctx, ctx)
  end

  defp build_conn_with_tenant(tenant_id) do
    ctx = %IdentityContext{
      machine_identity: {:observed_identity, %{"sub" => "audit-caller"}},
      principal: %Principal{
        kind: :obo_human,
        issuer: "https://idp.example.invalid",
        subject: "audit-caller",
        recurse_role: "tenant_auditor"
      },
      tenant_id: tenant_id,
      correlation_id: "test-corr-audit",
      resolved_at_usec: System.os_time(:microsecond)
    }

    :get
    |> Plug.Test.conn("/v1/audit/receipts")
    |> Plug.Conn.assign(:identity_ctx, ctx)
  end

  defp header(conn, name) do
    conn.resp_headers
    |> Enum.find_value(fn
      {^name, v} -> v
      _ -> nil
    end)
  end

  defp unique_subject,
    do: "subj-" <> Base.url_encode64(:crypto.strong_rand_bytes(6), padding: false)

  defp unique_tenant, do: "01HQZN" <> Base.encode16(:crypto.strong_rand_bytes(10), case: :upper)
end
