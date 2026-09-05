defmodule Recurse.Providers.Impls.OciPolicyProvider.Cosign.TestPubkeyFetcher do
  @moduledoc """
  Test-only KMS public-key fetcher for
  `Recurse.Providers.Impls.OciPolicyProvider.Cosign`. Exposes the same
  API contract the production `Cosign.DefaultKmsPubkeyFetcher` does
  (`fetch_public_key_der/1`), but pulls fixtures from a test-owned ETS
  table instead of `kms:GetPublicKey`.

  Wired in via the `:cosign_kms_pubkey_fetcher` Application env, set in
  `setup` of `Recurse.Providers.Impls.OciPolicyProvider.CosignTest`. We
  use ETS rather than `:persistent_term` so per-test fixtures don't
  collide with the cosign module's own `:persistent_term` cache and so
  call counts can be reset cheaply without retiring the test process.

  ## API

    * `put_pem(arn, pem)` — register a PEM-encoded SPKI public key for
      future fetches against `arn`. Cosign's `decode_spki_der/1` accepts
      both raw DER and PEM, so the fetcher can return PEM here without
      needing to round-trip through DER.
    * `put_error(arn, reason)` — register a failure condition for an ARN
      (the fetch returns `{:error, reason}`).
    * `call_count(arn)` — observe how many times the fetcher has been
      invoked against the given ARN. Used by the cache-hit assertion in
      `cosign_test.exs`.
    * `reset()` — clear all registrations + call counts. Intended for
      use only when a single test wants to assert call ordering against
      its own freshly-seeded state.
  """

  @table __MODULE__.Table
  @counts __MODULE__.Counts

  @doc """
  Public-key fetcher contract — same shape as
  `Cosign.DefaultKmsPubkeyFetcher.fetch_public_key_der/1`.
  """
  @spec fetch_public_key_der(String.t()) :: {:ok, binary()} | {:error, term()}
  def fetch_public_key_der(arn) when is_binary(arn) do
    ensure_tables_started()
    :ets.update_counter(@counts, arn, 1, {arn, 0})

    case :ets.lookup(@table, arn) do
      [{^arn, {:pem, pem}}] -> {:ok, pem}
      [{^arn, {:error, reason}}] -> {:error, reason}
      [] -> {:error, {:test_fetcher_arn_not_registered, arn}}
    end
  end

  @doc "Register a PEM SPKI for `arn`."
  @spec put_pem(String.t(), String.t()) :: :ok
  def put_pem(arn, pem) when is_binary(arn) and is_binary(pem) do
    ensure_tables_started()
    :ets.insert(@table, {arn, {:pem, pem}})
    :ok
  end

  @doc "Register an error response for `arn`."
  @spec put_error(String.t(), term()) :: :ok
  def put_error(arn, reason) when is_binary(arn) do
    ensure_tables_started()
    :ets.insert(@table, {arn, {:error, reason}})
    :ok
  end

  @doc "Return the number of times `fetch_public_key_der/1` has been called for `arn`."
  @spec call_count(String.t()) :: non_neg_integer()
  def call_count(arn) when is_binary(arn) do
    ensure_tables_started()

    case :ets.lookup(@counts, arn) do
      [{^arn, n}] -> n
      [] -> 0
    end
  end

  @doc "Wipe all fixtures + counts. Avoid in async tests; use unique ARNs instead."
  @spec reset() :: :ok
  def reset do
    ensure_tables_started()
    :ets.delete_all_objects(@table)
    :ets.delete_all_objects(@counts)
    :ok
  end

  # Lazy table init — both ETS tables are public and named so cross-process
  # access (multiple async tests in different processes) Just Works without
  # needing a supervised owner. The `try` guards against the
  # already-exists race when two test setups race the first call.
  defp ensure_tables_started do
    ensure_table(@table)
    ensure_table(@counts)
  end

  defp ensure_table(name) do
    if :ets.whereis(name) == :undefined do
      try do
        :ets.new(name, [:public, :named_table, :set, read_concurrency: true])
      rescue
        ArgumentError -> :ok
      end
    end

    :ok
  end
end
