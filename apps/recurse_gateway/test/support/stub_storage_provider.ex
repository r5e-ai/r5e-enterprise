defmodule Recurse.Gateway.Test.StubStorageProvider do
  @moduledoc """
  Deterministic `Recurse.Providers.StorageProvider` impl for integration
  tests (F002 T054).

  Records every `put_payload/3` call as raw bytes + SHA-256 hash in an
  ETS table keyed by `{__MODULE__, tenant_id}`, so tests that need to
  assert "the Gateway sent THESE canonicalized bytes to Storage" can
  read them back without touching a real S3. The returned URI is a stub
  `s3://test-bucket/...` string shaped like the real `S3StorageProvider`
  output — Audit-Plane consumers only care about shape, not reachability.

  ## Iron Law check (`elixir:otp-thinking`)

    1. Mutable state across calls? Technically yes — the ETS table holds
       put history. But the table is declared `:public` + `:named_table`
       at provider init; subsequent calls touch ETS directly without a
       mailbox. No GenServer wrapper.
    2. Concurrent execution? Yes — multiple Bandit request processes may
       call `put_payload/3` concurrently. ETS handles that with its
       built-in concurrency primitives.
    3. Fault isolation? No — we want crashes to surface in the test; no
       supervision needed.

  Plain module + ETS is the right shape. No process.

  ## Usage from test

      setup do
        :ok = Recurse.Gateway.Test.StubStorageProvider.reset()
        ...
      end

      test "records the canonicalized payload bytes" do
        # ... trigger a Gateway request ...
        [%{payload: bytes, uri: uri}] =
          Recurse.Gateway.Test.StubStorageProvider.puts(tenant_id)

        assert uri =~ "s3://test-bucket/"
        assert Jason.decode!(bytes)["request"]["model"] == "gpt-4o-mini"
      end

  ## Cross-references

    * `apps/recurse_providers/lib/recurse_providers/storage_provider.ex`
      — the behaviour under test (same interface as the real S3 impl).
    * `specs/002-standalone-gateway-vertical-slice/tasks.md` T054.
  """

  @behaviour Recurse.Providers.StorageProvider

  @table :recurse_gateway_stub_storage_puts

  @impl true
  def init(config) when is_map(config) do
    ensure_table!()
    {:ok, %{bucket: Map.get(config, :bucket, "test-bucket")}}
  end

  @impl true
  def put_payload(state, bytes, %Recurse.Shared.IdentityContext{tenant_id: tenant_id})
      when is_binary(bytes) do
    ensure_table!()

    hash = :crypto.hash(:sha256, bytes)

    # Deterministic URI mirrors the S3StorageProvider's `s3://<bucket>/
    # tenants/<tid>/runs/<date>/<run>.json` shape. We don't know the
    # run_id here (put_payload is agnostic of it); use a short random
    # suffix so concurrent puts don't collide. Auditors see these URIs
    # in receipt rows; test assertions parse-or-match-prefix, never the
    # opaque suffix.
    suffix = hash |> Base.encode16(case: :lower) |> binary_part(0, 16)
    date = Date.utc_today() |> Date.to_iso8601()
    uri = "s3://#{state.bucket}/tenants/#{tenant_id}/runs/#{date}/#{suffix}.json"

    entry = %{
      tenant_id: tenant_id,
      payload: bytes,
      uri: uri,
      hash: hash,
      inserted_at: DateTime.utc_now()
    }

    # ETS bag lets us accumulate multiple puts per tenant_id. Ordering by
    # `inserted_at` on read recovers insertion order.
    true = :ets.insert(@table, {tenant_id, entry})

    {:ok, %{uri: uri, hash: hash}}
  end

  @impl true
  def get_payload(_state, uri, _ctx) do
    ensure_table!()

    match =
      Enum.find_value(:ets.tab2list(@table), fn
        {_tid, %{uri: ^uri, payload: bytes}} -> bytes
        _ -> nil
      end)

    case match do
      nil -> {:error, :not_found}
      bytes -> {:ok, bytes}
    end
  end

  @impl true
  def delete_payload(_state, uri, _ctx) do
    ensure_table!()

    Enum.each(:ets.tab2list(@table), fn
      {tid, %{uri: ^uri} = entry} -> :ets.delete_object(@table, {tid, entry})
      _ -> :ok
    end)

    :ok
  end

  @impl true
  def capabilities(_state), do: [:put, :get, :delete]

  @impl true
  def healthcheck(_state), do: :ok

  @impl true
  def terminate(_state, _reason), do: :ok

  # -- Test-only introspection ------------------------------------------------

  @doc """
  Return the list of put_payload entries for the given tenant, in
  insertion order. Each entry is a map with `:payload`, `:uri`,
  `:hash`, and `:inserted_at`.
  """
  @spec puts(String.t()) :: [map()]
  def puts(tenant_id) when is_binary(tenant_id) do
    ensure_table!()

    @table
    |> :ets.lookup(tenant_id)
    |> Enum.map(fn {^tenant_id, entry} -> entry end)
    |> Enum.sort_by(& &1.inserted_at, DateTime)
  end

  @doc """
  Clear all recorded puts. Call from a test's setup block (or on_exit)
  to guarantee per-test isolation.
  """
  @spec reset() :: :ok
  def reset do
    ensure_table!()
    :ets.delete_all_objects(@table)
    :ok
  end

  # -- Private ---------------------------------------------------------------

  defp ensure_table! do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [:bag, :public, :named_table, read_concurrency: true])
        :ok

      _tid ->
        :ok
    end
  end
end
