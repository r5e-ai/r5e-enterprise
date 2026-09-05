defmodule Recurse.Providers.LedgerProvider do
  @moduledoc """
  Provider Interface — LedgerProvider.

  Spec source: FR-003. Backed by Trillian (connected) or Postgres-Merkle (dev /
  Air-Gapped Appliance) per `stack_ledger_dev_prod.md` memory; both backends
  present THIS contract.

  Phase-1 implementation supports session-scoped two-level Merkle (FR-036 / FR-037):
  the unit committed via this interface is a session-chain epoch root, NOT
  individual events.

  Reference implementations (Feature 002+ per tasks T063):

  - `TrillianLedger` — Google Trillian gRPC client
  - `PostgresMerkleLedger` — Recurse-native Postgres-Merkle implementation per
    research D5

  All inclusion proofs MUST be emitted in RFC 9162 (CT v2.0) `TransItem` wire
  format per Phase-1 research recommendation 4 — auditors verify with stock
  RFC 9162 libraries regardless of backend.
  """

  @type config :: map()
  @type state :: term()

  @typedoc "Index of an entry in the global ledger."
  @type ledger_index :: non_neg_integer()

  @typedoc "RFC 9162 TransItem inclusion proof (binary-encoded TLS structure)."
  @type rfc9162_inclusion_proof :: binary()

  @typedoc "Tree size at the time the proof was generated."
  @type tree_size :: non_neg_integer()

  @typedoc "Root hash of the global ledger at the time of the proof."
  @type root_hash :: binary()

  @typedoc """
  Optional-feature capability flags an implementation declares via `capabilities/1`.
  """
  @type capability ::
          :commit_epoch
          | :inclusion_proofs
          | :consistency_proofs
          | :rfc9162_native
          | :backfill

  @doc """
  Initialize the provider with deployment-time configuration.
  """
  @callback init(config) :: {:ok, state} | {:error, term()}

  @doc """
  Commit a session-chain epoch root to the global ledger.

  Returns the assigned ledger index, the resulting tree size, and the root hash.
  This is the call the Broadway commit pipeline invokes per FR-040.

  Failure (network error, ledger overload) MUST surface as `{:error, reason}` —
  the caller (Runtime commit pipeline) handles backoff and the
  `commit_retry`/`commit_retry_exhausted` session transitions per FR-040 / FR-044.
  """
  @callback commit_epoch(
              state,
              session_id :: String.t(),
              epoch_index :: non_neg_integer(),
              epoch_root :: binary()
            ) ::
              {:ok, %{index: ledger_index, tree_size: tree_size, root: root_hash}}
              | {:error, term()}

  @doc """
  Generate an RFC 9162 inclusion proof for the entry at the given ledger index.

  Used by the Audit Plane when serving receipts (FR-021 outer container's
  `inclusion_proof_global` field). The proof MUST be an RFC 9162 TransItem
  binary, regardless of backend (transcoded if the backend is not
  RFC-9162-native).
  """
  @callback inclusion_proof(
              state,
              ledger_index,
              tree_size_at_proof :: tree_size
            ) :: {:ok, rfc9162_inclusion_proof} | {:error, term()}

  @doc """
  Produce a consistency proof between two tree sizes (for clients holding
  older roots).

  Optional in Phase 1 — implementations MAY return `{:error, :not_supported}`
  if not implemented. Support is advertised via the `:consistency_proofs`
  capability flag.
  """
  @callback consistency_proof(
              state,
              from_tree_size :: tree_size,
              to_tree_size :: tree_size
            ) :: {:ok, binary()} | {:error, term()}

  @doc """
  Current root hash and tree size.
  """
  @callback current_root(state) ::
              {:ok, %{tree_size: tree_size, root: root_hash}} | {:error, term()}

  @doc """
  Optional-feature capability flags. See `t:capability/0` for allowed values.
  """
  @callback capabilities(state) :: [capability]

  @doc """
  Healthcheck for `/healthz` aggregation (FR-014).
  """
  @callback healthcheck(state) :: :ok | {:degraded, term()} | {:down, term()}

  @doc """
  Graceful shutdown — flush buffered commits, close backend connections.
  """
  @callback terminate(state, reason :: term()) :: :ok
end
