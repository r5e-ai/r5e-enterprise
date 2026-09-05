defmodule Recurse.Providers.Impls.PostgresMerkleLedger do
  @moduledoc """
  Postgres-Merkle reference implementation of
  `Recurse.Providers.LedgerProvider` (F001 FR-003, research D5).

  Two public entry points:

    * **Behaviour callbacks** (narrow, F001 surface) — `init/1`,
      `capabilities/1`, `healthcheck/1`, `terminate/2`, `commit_epoch/4`,
      `inclusion_proof/3`, `consistency_proof/3`, `current_root/1`.
    * **Module-level methods** (rich, F002 surface, per AD-001 c' precedent) —
      `commit_attestation/2`, `query_by_run_id/1`,
      `force_commit_for_run_ids/2` (T060, FR-017),
      `query_paginated/1` (T059, FR-021),
      `generate_inclusion_proof/1` (T064, FR-022),
      `query_pending_outbox/1` / `retry_outbox_entry/2` /
      `mark_dead_letter/2` / `commit_outbox_success/3` /
      `outbox_depth/0` (T090, FR-032).

  The split is spelled out in `specs/002-standalone-gateway-vertical-slice/tasks.md` T033.
  Alternative providers (Trillian, future backends) implement only the
  behaviour callbacks; F002 callers hit `commit_attestation/2` on this impl
  directly.

  ## Commit flow (commit_attestation/2)

  Given a `%Recurse.Shared.Attestation.Envelope{}` the module executes ten
  steps inside an `Ecto.Multi` at `:serializable` isolation:

    1. Upsert `tenants` row (idempotent).
    2. Insert `sessions` row (new per 1-run-1-session).
    3. Insert `session_epochs` row at `epoch_index = 0`.
    4. JCS-canonicalize the `SignedPredicate` map; `MerkleTree.hash_leaf/1`.
    5. Insert the `attestations` row at `verification_level: :signed`.
    6. Insert the leaf into `merkle_nodes` under
       `tree_id = "session_{sid}_epoch_0"`. Under 1-run-1-session there
       is a single leaf so `epoch_root = leaf_hash` (no interior walks).
    7. Update `session_epochs.epoch_root` + `epoch_end_at`.
    8. Update the attestation's `verification_level` → `:local_inclusion_verified`
       and persist `session_chain_root`.
    9. Delegate internally to the SAME helper the behaviour `commit_epoch/4`
       uses: appends `epoch_root` as a new leaf of the global tree, inserts
       the `global_ledger_entries` row, walks interior nodes up
       `tree_id = "global"`, returns `{index, tree_size, root}`.
   10. Update the attestation's `verification_level` → `:global_inclusion_verified`
       and persist RFC 9162 TransItem-encoded `global_inclusion_proof`.

  After the transaction commits (and ONLY then), the module broadcasts
  `{:first_committed, run_id, attestation_map}` on topic
  `recurse:attestation_first_committed` via `Phoenix.PubSub`. Broadcasting
  inside the transaction would risk publishing a receipt that a rollback
  erases; broadcasting after `Repo.transaction/2` succeeds is the correct
  order per FR-024's "one SIEM event per attestation" rule.

  ## State

  `init/1` returns a plain map — `%{repo: Repo, pubsub: pubsub_name,
  config: config}`. The impl is stateless; the Repo is supervised elsewhere
  (`RecurseProviders.Application`); `MerkleTree` is a pure module. No
  GenServers live here.
  """

  @behaviour Recurse.Providers.LedgerProvider

  import Ecto.Query, only: [from: 2]

  alias Ecto.Multi
  alias Recurse.Providers.Impls.PostgresMerkleLedger.MerkleTree

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.{
    Attestation,
    GlobalLedgerEntry,
    MerkleNode,
    PayloadOutbox,
    Session,
    SessionEpoch,
    Tenant
  }

  alias Recurse.Providers.LedgerProvider
  alias Recurse.Providers.Repo
  alias Recurse.Shared.Attestation.Envelope
  alias Recurse.Shared.Attestation.SignedPredicate
  alias Recurse.Shared.Jcs

  @typedoc "Opaque impl state. Stateless — just the Repo module + pubsub name + config."
  @type state :: %{
          required(:repo) => module(),
          required(:pubsub) => atom(),
          required(:config) => map()
        }

  @global_tree_id "global"
  @first_commit_topic "recurse:attestation_first_committed"
  # Fixed RFC 9162 `log_id` for the Postgres-Merkle reference impl. RFC 9162
  # requires a 32-byte log identifier; we derive a stable one from a known
  # string so every standalone-deployment emits the same value (auditors can
  # recognize the log). Different deployments that want unique IDs can
  # override via config; Phase-1 doesn't expose that knob.
  @postgres_merkle_log_id :crypto.hash(:sha256, "recurse.postgres_merkle.log_id.v1")

  # -- Behaviour callbacks ---------------------------------------------------

  @doc """
  Initialize the provider. Config is carried through verbatim; the Repo +
  PubSub are resolved from application env at call sites so every call runs
  against the same supervised infrastructure.
  """
  @impl true
  @spec init(LedgerProvider.config()) :: {:ok, state()} | {:error, term()}
  def init(config) when is_map(config) do
    {:ok, %{repo: Repo, pubsub: Recurse.PubSub, config: config}}
  end

  @impl true
  @spec capabilities(state()) :: [LedgerProvider.capability()]
  def capabilities(_state) do
    [:commit_epoch, :inclusion_proofs, :rfc9162_native]
  end

  @impl true
  @spec healthcheck(state()) :: :ok | {:degraded, term()} | {:down, term()}
  def healthcheck(%{repo: repo}) do
    case Ecto.Adapters.SQL.query(repo, "SELECT 1", [], log: false) do
      {:ok, _} -> :ok
      {:error, reason} -> {:down, reason}
    end
  rescue
    err -> {:down, err}
  end

  @impl true
  @spec terminate(state(), term()) :: :ok
  def terminate(_state, _reason), do: :ok

  @doc """
  Narrow F001 callback: append a PRE-COMPUTED `epoch_root` as a new leaf of
  the global tree. Inserts the `global_ledger_entries` row and the
  corresponding `merkle_nodes` rows (leaf + walked interior nodes) under
  `tree_id = "global"`. Returns `{index, tree_size, root}`.

  `session_id`/`epoch_index` are used to FK the `global_ledger_entries`
  row back to the originating session epoch row. The caller (Gateway or
  a future Trillian-parity client) is responsible for having already
  persisted the `sessions`/`session_epochs` rows.
  """
  @impl true
  @spec commit_epoch(
          state(),
          session_id :: String.t(),
          epoch_index :: non_neg_integer(),
          epoch_root :: binary()
        ) ::
          {:ok,
           %{
             index: LedgerProvider.ledger_index(),
             tree_size: LedgerProvider.tree_size(),
             root: LedgerProvider.root_hash()
           }}
          | {:error, term()}
  def commit_epoch(%{repo: repo} = _state, session_id, epoch_index, epoch_root)
      when is_binary(session_id) and is_integer(epoch_index) and epoch_index >= 0 and
             byte_size(epoch_root) == 32 do
    now = DateTime.utc_now()

    multi =
      Multi.new()
      |> Multi.run(:session_epoch, fn inner_repo, _ ->
        case fetch_session_epoch(inner_repo, session_id, epoch_index) do
          nil -> {:error, :session_epoch_not_found}
          ep -> {:ok, ep}
        end
      end)
      |> append_global_commit(:session_epoch, epoch_root, now)

    case repo.transaction(multi, isolation: :serializable) do
      {:ok, %{global_commit: %{index: index, tree_size: ts, root: root}}} ->
        {:ok, %{index: index, tree_size: ts, root: root}}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  def commit_epoch(_state, _sid, _idx, _root), do: {:error, :invalid_arguments}

  @doc """
  Build an RFC 9162 `TransItem` (inclusion_v1) for the given global-ledger
  `ledger_index` against a tree of `tree_size`. The sibling hashes come from
  reconstructing the leaf list from `global_ledger_entries.session_epoch_root`
  ordered by `sequence` — the Postgres-Merkle backend stores interior
  `merkle_nodes` rows as a cache but rebuilding from the canonical leaf
  sequence is the shortest correct path and matches the
  `MerkleTree.generate_inclusion_proof/2` contract.
  """
  @impl true
  @spec inclusion_proof(
          state(),
          LedgerProvider.ledger_index(),
          LedgerProvider.tree_size()
        ) ::
          {:ok, LedgerProvider.rfc9162_inclusion_proof()}
          | {:error, term()}
  def inclusion_proof(%{repo: repo}, ledger_index, tree_size)
      when is_integer(ledger_index) and ledger_index >= 0 and
             is_integer(tree_size) and tree_size >= 1 do
    leaves = load_global_leaves(repo, tree_size)

    cond do
      length(leaves) < tree_size ->
        {:error, :tree_size_exceeds_ledger}

      ledger_index >= tree_size ->
        {:error, :index_out_of_range}

      true ->
        encode_inclusion_transitem(leaves, ledger_index, tree_size)
    end
  end

  def inclusion_proof(_state, _idx, _ts), do: {:error, :invalid_arguments}

  @doc """
  Consistency proofs are not implemented in F002 — advertised only when the
  `:consistency_proofs` capability is declared by the impl.
  """
  @impl true
  @spec consistency_proof(state(), LedgerProvider.tree_size(), LedgerProvider.tree_size()) ::
          {:ok, binary()} | {:error, term()}
  def consistency_proof(_state, _from_ts, _to_ts), do: {:error, :not_supported}

  @impl true
  @spec current_root(state()) ::
          {:ok, %{tree_size: LedgerProvider.tree_size(), root: LedgerProvider.root_hash()}}
          | {:error, term()}
  def current_root(%{repo: repo}) do
    case load_all_global_leaves(repo) do
      [] -> {:ok, %{tree_size: 0, root: <<0::256>>}}
      [_ | _] = ls -> {:ok, %{tree_size: length(ls), root: MerkleTree.build_root(ls)}}
    end
  end

  # -- Public module methods (NOT behaviour callbacks) -----------------------

  @doc """
  F002 rich commit flow. Persists the full attestation envelope, walks the
  two-level Merkle tree to `:global_inclusion_verified`, and broadcasts the
  first-committed signal on `Phoenix.PubSub` AFTER the transaction succeeds.

  `opts` accepts:

    * `:repo` — override Repo (test injection); defaults to `Recurse.Providers.Repo`.
    * `:pubsub` — override PubSub name; defaults to `Recurse.PubSub`.
    * `:tenant_attrs` — map used for the tenant upsert
      (`%{tenant_id, display_name, tier, created_at}`); defaults derived
      from the envelope's `tenant_id` with tier `:standalone_gateway`.
    * `:payload_uri` — opaque payload URI (FR-019 path scheme); defaults
      to the envelope's `SignedPredicate.payload_uri`.
    * `:policy_decision` — `:allow | :deny` (outer-container); defaults
      to `:allow`. F002 US6 distinguishes upstream errors (policy
      passed) from policy denials by storing the effective Cedar
      decision here even when the call failed upstream.
    * `:outcome` — `:success | :upstream_error | :cancelled` (outer-container);
      defaults to `:success`. Set by the caller per F002 FR-005 FR-016b
      when the Data Plane proxies through an upstream non-2xx.
    * `:upstream_status_code` — HTTP status integer carried from the
      upstream response when `outcome: :upstream_error`; `nil` otherwise.
      Populated only when the caller has a concrete upstream code
      (timeout / connection-error paths leave it `nil`).
    * `:session_mode` — defaults to `:single`. Imported source-session
      receipts pass `:source_session_epochs`, which permits many receipts
      to share a source-derived `session_id` by committing each receipt as
      its own single-leaf session epoch.

  On success returns `{:ok, %{run_id, verification_level,
  session_chain_root, global_inclusion_proof}}`. On any failure step the
  transaction rolls back, no broadcast is emitted, and `{:error, reason}`
  surfaces the offending step.
  """
  @spec commit_attestation(Envelope.t(), keyword()) ::
          {:ok,
           %{
             run_id: String.t(),
             verification_level: atom(),
             session_chain_root: binary(),
             global_inclusion_proof: binary()
           }}
          | {:error, term()}
  def commit_attestation(%Envelope{} = envelope, opts \\ []) do
    repo = Keyword.get(opts, :repo, Repo)
    pubsub = Keyword.get(opts, :pubsub, Recurse.PubSub)
    tenant_attrs = Keyword.get(opts, :tenant_attrs)
    session_mode = Keyword.get(opts, :session_mode, :single)
    policy_decision = Keyword.get(opts, :policy_decision, :allow)
    outcome = Keyword.get(opts, :outcome, :success)
    upstream_status_code = Keyword.get(opts, :upstream_status_code)
    # B7 — non-signed UI metadata; both nil for non-tool_call rows.
    tool_name = Keyword.get(opts, :tool_name)
    tool_summary = Keyword.get(opts, :tool_summary)
    # Tool-call extractor pipeline — schema-on-read tags; nil for non-tool_call
    # rows and for legacy receipts imported before the extractor landed.
    tags = Keyword.get(opts, :tags)
    # Spec 012 S6b — where the JCS predicate body behind `payload_hash` was
    # retained; nil when the emitter could not (or did not) put it.
    predicate_body_uri = Keyword.get(opts, :predicate_body_uri)
    now = DateTime.utc_now()

    %Envelope{signed_predicate: %SignedPredicate{} = sp, dsse_envelope: dsse} = envelope

    predicate_map = SignedPredicate.to_map(sp)
    predicate_bytes = Jcs.encode(predicate_map)
    leaf_hash = MerkleTree.hash_leaf(predicate_bytes)
    dsse_signature = extract_signature(dsse)

    session_epoch_index = session_epoch_index(sp, session_mode)
    session_tree_id = "session_#{sp.session_id}_epoch_#{session_epoch_index}"
    tenant_row = resolve_tenant_attrs(tenant_attrs, sp, now)

    outer_attrs = %{
      policy_decision: policy_decision,
      outcome: outcome,
      upstream_status_code: upstream_status_code,
      session_chain_epoch: session_epoch_index,
      tool_name: tool_name,
      tool_summary: tool_summary,
      tags: tags,
      predicate_body_uri: predicate_body_uri
    }

    multi =
      Multi.new()
      |> Multi.insert(:tenant, Tenant.changeset(%Tenant{}, tenant_row),
        on_conflict: :nothing,
        conflict_target: :tenant_id
      )
      |> insert_session(sp, now, session_mode)
      |> Multi.insert(
        :session_epoch,
        session_epoch_changeset(sp, leaf_hash, now, session_epoch_index)
      )
      |> Multi.insert(
        :attestation,
        attestation_changeset(sp, predicate_bytes, dsse_signature, now, outer_attrs)
      )
      |> Multi.insert(:leaf_node, leaf_node_changeset(session_tree_id, leaf_hash, now))
      |> Multi.update(
        :session_epoch_close,
        &SessionEpoch.changeset(&1.session_epoch, %{
          epoch_root: leaf_hash,
          epoch_end_at: now
        })
      )
      |> Multi.update(
        :attestation_local,
        &Attestation.changeset(&1.attestation, %{
          verification_level: :local_inclusion_verified,
          session_chain_root: leaf_hash,
          local_inclusion_proof: <<>>
        })
      )
      |> append_global_commit(:session_epoch, leaf_hash, now)
      |> Multi.run(:global_proof, fn inner_repo, %{global_commit: %{index: idx, tree_size: ts}} ->
        leaves = load_global_leaves(inner_repo, ts)

        case encode_inclusion_transitem(leaves, idx - 1, ts) do
          {:ok, proof} -> {:ok, proof}
          {:error, reason} -> {:error, {:inclusion_proof_encode, reason}}
        end
      end)
      |> Multi.update(:attestation_global, fn %{attestation_local: att, global_proof: proof} ->
        Attestation.changeset(att, %{
          verification_level: :global_inclusion_verified,
          global_inclusion_proof: proof
        })
      end)

    case run_transaction(repo, multi) do
      {:ok, changes} ->
        result = build_result(changes)
        broadcast_first_committed(pubsub, result, changes.attestation_global)
        {:ok, result}

      {:error, step, reason, _changes} ->
        {:error, {step, reason}}
    end
  end

  # Wraps `repo.transaction/2` so unique-constraint / check-constraint
  # violations surface as the `{:error, step, reason, _changes}` shape
  # rather than a raised `Ecto.ConstraintError`. This matches callers'
  # expectations (they pattern-match on `{:error, _}`) and ensures the
  # SERIALIZABLE transaction rolls back cleanly — crucially, the rollback
  # guarantees `broadcast_first_committed/2` never fires for an uncommitted
  # receipt per FR-024.
  defp run_transaction(repo, multi) do
    repo.transaction(multi, isolation: :serializable)
  rescue
    err in [Ecto.ConstraintError, Postgrex.Error, Ecto.StaleEntryError] ->
      {:error, :attestation, err, %{}}
  end

  @doc """
  Audit-Plane-basic read: return the stored attestation row keyed by `run_id`.
  Returns the schema struct as a map (signed-predicate + outer-container
  fields) or `{:error, :not_found}`.
  """
  @spec query_by_run_id(String.t()) ::
          {:ok, map()} | {:error, :not_found}
  def query_by_run_id(run_id) when is_binary(run_id) do
    case Repo.get(Attestation, run_id) do
      nil -> {:error, :not_found}
      %Attestation{} = att -> {:ok, Map.from_struct(att)}
    end
  end

  @doc """
  F002 T059 / FR-021 — paginated query over the `attestations` table.

  Accepts a map of filters + pagination params:

    * `:run_id` — filter to exactly this run_id.
    * `:session_id` — filter to exactly this session_id.
    * `:turn_id` — filter to exactly this turn_id.
    * `:verification_level` — one of
      `:signed | :local_inclusion_verified | :global_inclusion_verified`.
    * `:tier_completeness_advisory` — `:partial | :full`.
    * `:policy_decision` — `:allow | :deny`.
    * `:event_kinds` — list of atoms from the canonical `Attestation`
      enum (F004 FR-009). Pushed down as a SQL `WHERE event_kind IN (...)`
      so the LIMIT applies post-filter; without this push-down the
      most-recent N rows can be saturated by `:ui_query` self-emissions
      and starve the `:tool_call` / `:llm_call` rows the operator is
      filtering for (root cause of the F16 demo-blocker, 2026-04-30).
    * `:limit` — default 50, hard-capped at 500 per FR-021.
    * `:cursor` — opaque base64-encoded `{timestamp_ms, run_id}` from
      a previous call. `nil` on first page.

  Ordering is deterministic `timestamp DESC, run_id DESC` per FR-021.
  Returns `{:ok, %{rows: [map()], next_cursor: String.t() | nil}}`.
  Cursor is `nil` when the returned page is the last.
  """
  @spec query_paginated(map()) ::
          {:ok, %{rows: [map()], next_cursor: String.t() | nil}}
          | {:error, term()}
  def query_paginated(params) when is_map(params) do
    limit = clamp_limit(Map.get(params, :limit, 50))

    with {:ok, cursor_bound} <- decode_cursor(Map.get(params, :cursor)) do
      query =
        Attestation
        |> apply_eq_filter(:run_id, Map.get(params, :run_id))
        |> apply_eq_filter(:session_id, Map.get(params, :session_id))
        |> apply_eq_filter(:turn_id, Map.get(params, :turn_id))
        |> apply_eq_filter(:verification_level, Map.get(params, :verification_level))
        |> apply_eq_filter(
          :tier_completeness_advisory,
          Map.get(params, :tier_completeness_advisory)
        )
        |> apply_eq_filter(:policy_decision, Map.get(params, :policy_decision))
        |> apply_in_filter(:event_kind, Map.get(params, :event_kinds))
        |> apply_cursor_bound(cursor_bound)

      rows =
        query
        |> Ecto.Query.order_by([a], desc: a.timestamp, desc: a.run_id)
        |> Ecto.Query.limit(^(limit + 1))
        |> Repo.all()

      {page, next_cursor} = split_page(rows, limit)
      {:ok, %{rows: Enum.map(page, &Map.from_struct/1), next_cursor: next_cursor}}
    end
  end

  @doc """
  F004 issue #44 — facet aggregations over the FULL filtered result set.

  Accepts the same filter map as `query_paginated/1` (same eq + in
  pushdowns; cursor + limit are intentionally ignored — facet counts
  must reflect the entire matching universe, not just the most-recent
  page). Returns

      {:ok, %{
        event_kind: %{"tool_call" => 12, "ui_query" => 174, ...},
        policy_decision: %{"allow" => 180, "deny" => 6, "unknown" => 0},
        verification_level: %{"global_inclusion_verified" => 184, ...}
      }}

  Why a separate query and not in-memory aggregation over the page:
  the audit-log dashboard's high-volume `:ui_query` self-emissions
  saturate the LIMIT-50 most-recent page. Page-scoped counts make
  `:tool_call` look like 0 even when there are dozens in the table —
  the operator can't see them on the histogram, and the picker chip
  is wrongly empty. A SQL `GROUP BY` over the same WHERE-clause as
  the paginated query gives the picker the truth (FR-012). Same root
  cause as the F16 fix (MR !66) where the LIMIT-50 page was saturating
  the FILTER; this is the same shape for COUNTS.

  Implementation note: each facet runs as its own `GROUP BY` query
  rather than one CUBE query. We have at most three small enum columns
  with bounded cardinality (29 / 2 / 3 distinct values respectively);
  three round-trips on indexed columns is simpler than a single
  multi-dimensional aggregation and the cardinality is tiny enough
  that the latency cost is below noise. Re-evaluate if/when more
  facet axes land.
  """
  @spec query_facets(map()) ::
          {:ok, %{event_kind: map(), policy_decision: map(), verification_level: map()}}
  def query_facets(params) when is_map(params) do
    base =
      Attestation
      |> apply_eq_filter(:run_id, Map.get(params, :run_id))
      |> apply_eq_filter(:session_id, Map.get(params, :session_id))
      |> apply_eq_filter(:turn_id, Map.get(params, :turn_id))
      |> apply_eq_filter(:verification_level, Map.get(params, :verification_level))
      |> apply_eq_filter(
        :tier_completeness_advisory,
        Map.get(params, :tier_completeness_advisory)
      )
      |> apply_eq_filter(:policy_decision, Map.get(params, :policy_decision))
      |> apply_in_filter(:event_kind, Map.get(params, :event_kinds))

    {:ok,
     %{
       event_kind: count_by_field(base, :event_kind),
       policy_decision: count_by_field(base, :policy_decision),
       verification_level: count_by_field(base, :verification_level)
     }}
  end

  defp count_by_field(base_query, field) do
    base_query
    |> Ecto.Query.exclude(:select)
    |> Ecto.Query.exclude(:order_by)
    |> Ecto.Query.exclude(:preload)
    |> Ecto.Query.group_by([a], field(a, ^field))
    |> Ecto.Query.select([a], {field(a, ^field), count(a.run_id)})
    |> Repo.all()
    |> Enum.into(%{}, fn
      {nil, n} -> {"unknown", n}
      {atom, n} when is_atom(atom) -> {Atom.to_string(atom), n}
      {bin, n} when is_binary(bin) -> {bin, n}
    end)
  end

  @doc """
  F002 T060 / FR-017 — commit-now-on-export helper (AD-001 c').

  For each `run_id`, advance the attestation to `:global_inclusion_verified`
  if it has not already reached that level. Runs inside a SERIALIZABLE
  `Ecto.Multi` transaction so concurrent exports interleave cleanly.

  Returns `{:ok, %{run_id => :committed | {:already_global_inclusion_verified,
  epoch_root}}}`. Failing a specific run_id (not found, transaction aborted)
  surfaces `{:error, {run_id, reason}}`.

  Not a F001 `LedgerProvider` behaviour callback — public module method
  only (AD-001 c'). Callers that are not the Postgres-Merkle backend reflect
  current state with an advisory note; see `/v1/audit/export` handler.
  """
  @spec force_commit_for_run_ids(state(), [String.t()]) ::
          {:ok, %{String.t() => :committed | {:already_global_inclusion_verified, binary()}}}
          | {:error, term()}
  def force_commit_for_run_ids(%{repo: repo, pubsub: pubsub}, run_ids)
      when is_list(run_ids) do
    Enum.reduce_while(run_ids, {:ok, %{}}, fn run_id, {:ok, acc} ->
      case force_commit_single(repo, pubsub, run_id) do
        {:ok, outcome} -> {:cont, {:ok, Map.put(acc, run_id, outcome)}}
        {:error, reason} -> {:halt, {:error, {run_id, reason}}}
      end
    end)
  end

  def force_commit_for_run_ids(_state, _run_ids), do: {:error, :invalid_arguments}

  @doc """
  F002 T064 / FR-022 — build a combined RFC 9162 inclusion proof for the
  given `run_id`.

  Returns a map with:

    * `:session_chain` — binary TransItem bytes for the session-chain leaf
      (under 1-run-1-session the session tree has a single leaf so the proof
      is empty but the TransItem is still emitted for schema uniformity).
    * `:global` — binary TransItem bytes for the global-tree leaf tracking
      the session epoch root.

  Callers (EvidenceZipBuilder) write both to the `inclusion_proof.transitem`
  zip member; auditors decode them via
  `Recurse.Shared.Attestation.Rfc9162.decode/1`.
  """
  @spec generate_inclusion_proof(String.t()) ::
          {:ok, %{session_chain: binary(), global: binary()}} | {:error, term()}
  def generate_inclusion_proof(run_id) when is_binary(run_id) do
    with {:ok, att} <- fetch_attestation(run_id),
         {:ok, epoch_root} <- fetch_epoch_root(att.session_id, att.session_chain_epoch),
         {:ok, session_chain} <- build_session_chain_proof(att, epoch_root),
         {:ok, global} <- build_global_proof(epoch_root) do
      {:ok, %{session_chain: session_chain, global: global}}
    end
  end

  # -- Public module methods: S3 outbox reconciliation (FR-032, T090) --------
  #
  # These are **public module-level methods** per the AD-001 c' pattern — they
  # are NOT part of the `Recurse.Providers.LedgerProvider` behaviour. The
  # `Recurse.Gateway.Storage.OutboxReconciler` GenServer calls them directly;
  # alternative ledger backends (Trillian, etc.) are not required to
  # implement FR-032 outbox semantics.
  #
  # Cross-reference: `apps/recurse_gateway/lib/recurse_gateway/storage/outbox_reconciler.ex`.

  @doc """
  Return outbox rows eligible for retry: `status = "pending"` AND
  `next_attempt_at <= before`. Ordered by `next_attempt_at ASC` so the
  oldest backlog is processed first. Limited to `limit`.

  Result rows are plain maps with the subset of columns the reconciler
  needs: `:id, :run_id, :attestation_bytes, :payload_bytes, :target_uri,
  :attempts, :status, :next_attempt_at, :last_error`.

  `opts`:
    * `:limit` (required) — `pos_integer()`, row cap.
    * `:before` — `DateTime.t()`, the horizon. Defaults to `DateTime.utc_now/0`.
    * `:repo` — override Repo. Defaults to `Recurse.Providers.Repo`.
  """
  @spec query_pending_outbox(keyword()) :: {:ok, [map()]} | {:error, term()}
  def query_pending_outbox(opts) when is_list(opts) do
    limit = Keyword.fetch!(opts, :limit)
    before = Keyword.get(opts, :before, DateTime.utc_now())
    repo = Keyword.get(opts, :repo, Repo)

    query =
      from(o in PayloadOutbox,
        where: o.status == "pending" and o.next_attempt_at <= ^before,
        order_by: [asc: o.next_attempt_at],
        limit: ^limit,
        select: %{
          id: o.id,
          run_id: o.run_id,
          attestation_bytes: o.attestation_bytes,
          payload_bytes: o.payload_bytes,
          target_uri: o.target_uri,
          attempts: o.attempts,
          status: o.status,
          next_attempt_at: o.next_attempt_at,
          last_error: o.last_error
        }
      )

    {:ok, repo.all(query)}
  rescue
    err -> {:error, err}
  end

  @doc """
  Advance a retry row after a failed attempt. Updates `attempts`,
  `last_attempt_at`, `next_attempt_at`, and `last_error`. Keeps
  `status = "pending"` — the reconciler decides when to promote to
  `dead_letter` via `mark_dead_letter/2`.

  `attrs` map keys:
    * `:attempts` — non_neg_integer, the new attempt count.
    * `:next_attempt_at` — `DateTime.t()`, the exponential-backoff deadline.
    * `:last_error` — `String.t()`, stringified failure reason.
  """
  @spec retry_outbox_entry(Ecto.UUID.t() | String.t(), map(), keyword()) ::
          {:ok, PayloadOutbox.t()} | {:error, term()}
  def retry_outbox_entry(id, attrs, opts \\ []) when is_map(attrs) do
    repo = Keyword.get(opts, :repo, Repo)

    case repo.get(PayloadOutbox, id) do
      nil ->
        {:error, :not_found}

      %PayloadOutbox{} = row ->
        changeset =
          PayloadOutbox.retry_changeset(
            row,
            Map.merge(attrs, %{last_attempt_at: DateTime.utc_now(), status: "pending"})
          )

        repo.update(changeset)
    end
  end

  @doc """
  Transition a row to `status = "dead_letter"` after exhausting retries.

  `reason` is stringified and stored in `last_error` so operators can
  distinguish "10 attempts, last error X" from "never attempted, gave up
  because Y".
  """
  @spec mark_dead_letter(Ecto.UUID.t() | String.t(), term(), keyword()) ::
          {:ok, PayloadOutbox.t()} | {:error, term()}
  def mark_dead_letter(id, reason, opts \\ []) do
    repo = Keyword.get(opts, :repo, Repo)

    case repo.get(PayloadOutbox, id) do
      nil ->
        {:error, :not_found}

      %PayloadOutbox{} = row ->
        changeset =
          PayloadOutbox.retry_changeset(row, %{
            status: "dead_letter",
            last_attempt_at: DateTime.utc_now(),
            last_error: inspect(reason)
          })

        repo.update(changeset)
    end
  end

  @doc """
  Mark an outbox row committed after a successful storage put + ledger
  commit. `storage_result` is the map returned by
  `StorageProvider.put_payload/3` — kept on the row as observability
  metadata (the `target_uri` is already present from enqueue time).

  Note: this ONLY flips the outbox row to `committed`. Actually committing
  the attestation is the reconciler's responsibility via
  `commit_attestation/2`; those two writes are serialized by the
  reconciler's single-writer design, not by a DB transaction here.
  """
  @spec commit_outbox_success(Ecto.UUID.t() | String.t(), map(), keyword()) ::
          {:ok, PayloadOutbox.t()} | {:error, term()}
  def commit_outbox_success(id, _storage_result, opts \\ []) do
    repo = Keyword.get(opts, :repo, Repo)

    case repo.get(PayloadOutbox, id) do
      nil ->
        {:error, :not_found}

      %PayloadOutbox{} = row ->
        changeset =
          PayloadOutbox.retry_changeset(row, %{
            status: "committed",
            last_attempt_at: DateTime.utc_now(),
            last_error: nil
          })

        repo.update(changeset)
    end
  end

  @doc """
  Current count of `status = "pending"` outbox rows — fed into the
  `recurse_outbox_depth` gauge by `telemetry_poller` (FR-029 alerting
  minimum).
  """
  @spec outbox_depth(keyword()) :: non_neg_integer()
  def outbox_depth(opts \\ []) do
    repo = Keyword.get(opts, :repo, Repo)

    repo.aggregate(
      from(o in PayloadOutbox, where: o.status == "pending"),
      :count,
      :id
    )
  rescue
    _ -> 0
  end

  # -- Shared internals ------------------------------------------------------

  # Shared helper used by BOTH `commit_epoch/4` (narrow) and
  # `commit_attestation/2` (rich). Given a Multi and the step-key that will
  # resolve to a loaded `%SessionEpoch{}`, appends the global-commit steps:
  #
  #   1. Insert `global_ledger_entries` row — Postgres BIGSERIAL assigns `sequence`.
  #   2. Insert a new leaf into `merkle_nodes` under `tree_id = "global"`.
  #   3. Walk ancestors from the new leaf, inserting any new interior nodes
  #      required by the tree's new size. Use `MerkleTree.hash_interior/2`.
  #   4. Return `%{index, tree_size, root}` under the `:global_commit` key.
  #
  # Because of `SERIALIZABLE` isolation the entire sub-multi sees a consistent
  # view of prior global-ledger state; concurrent committers (none under
  # 1-run-1-session, but architecturally supported) will serialize or fail
  # cleanly with a retryable error.
  defp append_global_commit(multi, session_epoch_key, epoch_root, committed_at) do
    multi
    |> Multi.run(:global_position, fn inner_repo, _changes ->
      # 0-indexed position for the NEW leaf = count of rows currently
      # visible in this transaction. Under SERIALIZABLE + Postgres row
      # locking, concurrent committers serialize; the count is a stable
      # snapshot for the rest of the sub-multi.
      #
      # We do NOT rely on BIGSERIAL `sequence` for position because the
      # sandbox's rolled-back transactions advance the sequence without
      # leaving visible rows — tree topology must track visible row
      # density, not the non-transactional counter.
      {:ok, inner_repo.aggregate(GlobalLedgerEntry, :count, :sequence)}
    end)
    |> Multi.insert(:global_entry, fn %{^session_epoch_key => %SessionEpoch{} = ep} ->
      GlobalLedgerEntry.changeset(%GlobalLedgerEntry{}, %{
        tenant_id: tenant_id_of_session(ep.session_id),
        session_id: ep.session_id,
        session_epoch_id: ep.id,
        session_epoch_root: epoch_root,
        committed_at: committed_at
      })
    end)
    |> Multi.run(:global_leaf_insert, fn inner_repo, %{global_position: position} ->
      # Leaf at the global tree level 0 hashes the session_epoch_root via
      # MerkleTree.hash_leaf/1 — the leaf input at this level is the
      # already-32-byte epoch_root.
      leaf_hash = MerkleTree.hash_leaf(epoch_root)

      with {:ok, _} <-
             inner_repo.insert(
               MerkleNode.changeset(%MerkleNode{}, %{
                 tree_id: @global_tree_id,
                 level: 0,
                 position: position,
                 hash: leaf_hash,
                 inserted_at: committed_at
               })
             ) do
        {:ok, leaf_hash}
      end
    end)
    |> Multi.run(:global_interior_walk, fn inner_repo,
                                           %{
                                             global_position: position,
                                             global_leaf_insert: leaf_hash
                                           } ->
      walk_global_interior(inner_repo, position, leaf_hash, committed_at)
    end)
    |> Multi.run(:global_commit, fn inner_repo, %{global_position: position} ->
      tree_size = position + 1
      leaves = load_all_global_leaves(inner_repo)
      # `index` is 1-based per the F001 LedgerProvider contract comment
      # (`ledger_index` starts at the assigned sequence number 1); callers
      # use it to pair with an inclusion_proof lookup via `tree_size`.
      {:ok, %{index: tree_size, tree_size: tree_size, root: MerkleTree.build_root(leaves)}}
    end)
  end

  # Walk the global tree from the newly-inserted leaf up to the emerging root,
  # inserting any interior node whose LEFT and RIGHT children now both exist.
  # For a tree of new size `tree_size = new_position + 1` we visit levels
  # 1..ceil(log2(tree_size)); at each level a node at index `i` exists iff the
  # two children at level-1 positions `2*i` and `2*i+1` both exist.
  defp walk_global_interior(repo, new_leaf_position, _new_leaf_hash, inserted_at) do
    do_walk(repo, 1, new_leaf_position, inserted_at)
  end

  defp do_walk(_repo, _level, position, _ts) when position < 1 do
    # Once the new leaf's ancestor index at this level falls below 1, we're
    # past the root — nothing more to insert.
    {:ok, :done}
  end

  defp do_walk(repo, level, new_leaf_position, inserted_at) do
    # At level `level`, the ancestor index of the new leaf is leaf_pos >>> level.
    import Bitwise, only: [>>>: 2]
    ancestor_pos = new_leaf_position >>> level

    child_level = level - 1
    left_child_pos = ancestor_pos * 2
    right_child_pos = left_child_pos + 1

    left = fetch_node(repo, child_level, left_child_pos)
    right = fetch_node(repo, child_level, right_child_pos)

    case {left, right} do
      {%MerkleNode{hash: l}, %MerkleNode{hash: r}} ->
        interior = MerkleTree.hash_interior(l, r)

        with {:ok, _} <-
               repo.insert(
                 MerkleNode.changeset(%MerkleNode{}, %{
                   tree_id: @global_tree_id,
                   level: level,
                   position: ancestor_pos,
                   hash: interior,
                   inserted_at: inserted_at
                 }),
                 on_conflict: :nothing,
                 conflict_target: [:tree_id, :level, :position]
               ) do
          do_walk(repo, level + 1, new_leaf_position, inserted_at)
        end

      _ ->
        # Right child not yet present — this ancestor only materializes when
        # a later leaf lands; stop walking.
        {:ok, :done}
    end
  end

  defp fetch_node(repo, level, position) do
    repo.get_by(MerkleNode, tree_id: @global_tree_id, level: level, position: position)
  end

  defp fetch_session_epoch(repo, session_id, epoch_index) do
    repo.get_by(SessionEpoch, session_id: session_id, epoch_index: epoch_index)
  end

  defp tenant_id_of_session(session_id) do
    # The Multi's SERIALIZABLE snapshot ensures the session row is visible
    # by the time this callback runs. Tiny targeted query to avoid carrying
    # the session struct through the Multi for just one field.
    Repo.one!(from(s in Session, where: s.session_id == ^session_id, select: s.tenant_id))
  end

  defp load_all_global_leaves(repo) do
    repo.all(
      from(g in GlobalLedgerEntry,
        order_by: [asc: g.sequence],
        select: g.session_epoch_root
      )
    )
  end

  defp load_global_leaves(repo, tree_size) when tree_size >= 1 do
    # RFC 9162 inclusion proofs are scoped to a tree_size N meaning "the
    # first N leaves in sequence order". Slicing after the DB load
    # preserves the invariant that sequence gaps (sandbox/test rollbacks)
    # don't corrupt proofs.
    repo
    |> load_all_global_leaves()
    |> Enum.take(tree_size)
  end

  defp load_global_leaves(_repo, _tree_size), do: []

  defp encode_inclusion_transitem(leaves, index, tree_size) do
    case MerkleTree.generate_inclusion_proof(leaves, index) do
      {:ok, path} ->
        transitem =
          Recurse.Shared.Attestation.Rfc9162.inclusion_v1(
            @postgres_merkle_log_id,
            index,
            tree_size,
            path
          )

        {:ok, Recurse.Shared.Attestation.Rfc9162.encode(transitem)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # -- Changeset + result helpers --------------------------------------------

  defp session_epoch_index(
         %SignedPredicate{session_chain_position: position},
         :source_session_epochs
       )
       when is_integer(position) and position >= 0,
       do: position

  defp session_epoch_index(_sp, _session_mode), do: 0

  defp insert_session(multi, %SignedPredicate{} = sp, now, :source_session_epochs) do
    Multi.insert(multi, :session, session_changeset(sp, now),
      on_conflict: :nothing,
      conflict_target: :session_id
    )
  end

  defp insert_session(multi, %SignedPredicate{} = sp, now, _session_mode) do
    Multi.insert(multi, :session, session_changeset(sp, now))
  end

  defp session_changeset(%SignedPredicate{} = sp, now) do
    Session.changeset(%Session{session_id: sp.session_id}, %{
      tenant_id: sp.tenant_id,
      session_scope: :discovery_session,
      state: :active,
      session_start: now,
      principal_kind: principal_kind_from(sp.principal),
      principal_canonical: Jcs.encode(sp.principal)
    })
  end

  defp session_epoch_changeset(%SignedPredicate{} = sp, leaf_hash, now, epoch_index) do
    SessionEpoch.changeset(%SessionEpoch{}, %{
      session_id: sp.session_id,
      epoch_index: epoch_index,
      epoch_root: leaf_hash,
      epoch_start_at: now,
      event_count: 1
    })
  end

  defp attestation_changeset(%SignedPredicate{} = sp, predicate_bytes, dsse_signature, now, outer) do
    %{
      policy_decision: policy_decision,
      outcome: outcome,
      upstream_status_code: upstream_status_code
    } = outer

    Attestation.changeset(%Attestation{run_id: sp.run_id}, %{
      session_id: sp.session_id,
      turn_id: sp.turn_id || sp.run_id,
      event_kind: sp.event_kind,
      machine_identity: stringify_keys(sp.machine_identity),
      principal: sp.principal,
      tenant_id: sp.tenant_id,
      policy_canonical_hash: sp.policy_canonical_hash,
      payload_hash: sp.payload_hash,
      payload_uri: sp.payload_uri,
      correlation_id: sp.correlation_id,
      signer_kms_key_id: sp.signer,
      signer_key_version: "v1",
      timestamp: parse_timestamp(sp.timestamp) || now,
      signed_predicate_bytes: predicate_bytes,
      dsse_signature: dsse_signature,
      verification_level: :signed,
      tier_completeness_advisory: :partial,
      session_chain_epoch: Map.fetch!(outer, :session_chain_epoch),
      policy_decision: policy_decision,
      outcome: outcome,
      upstream_status_code: upstream_status_code,
      # B7 — non-signed UI metadata; both nil for non-tool_call rows.
      tool_name: Map.get(outer, :tool_name),
      tool_summary: Map.get(outer, :tool_summary),
      # Tool-call extractor pipeline — schema-on-read tags; nil for non-tool_call
      # rows and for legacy receipts imported before the extractor landed.
      tags: Map.get(outer, :tags),
      # Spec 012 S6b — retained predicate body reference (not signed).
      predicate_body_uri: Map.get(outer, :predicate_body_uri)
    })
  end

  defp leaf_node_changeset(tree_id, leaf_hash, now) do
    MerkleNode.changeset(%MerkleNode{}, %{
      tree_id: tree_id,
      level: 0,
      position: 0,
      hash: leaf_hash,
      inserted_at: now
    })
  end

  defp resolve_tenant_attrs(nil, %SignedPredicate{tenant_id: tid}, now) do
    %{
      tenant_id: tid,
      display_name: tid,
      tier: :standalone_gateway,
      created_at: now
    }
  end

  defp resolve_tenant_attrs(attrs, _sp, _now) when is_map(attrs), do: attrs

  defp build_result(%{
         attestation_global: %Attestation{
           run_id: run_id,
           verification_level: vl,
           session_chain_root: root,
           global_inclusion_proof: proof
         }
       }) do
    %{
      run_id: run_id,
      verification_level: vl,
      session_chain_root: root,
      global_inclusion_proof: proof
    }
  end

  defp broadcast_first_committed(pubsub, result, %Attestation{} = att) do
    payload = Map.put(result, :attestation, Map.from_struct(att))

    Phoenix.PubSub.broadcast(
      pubsub,
      @first_commit_topic,
      {:first_committed, result.run_id, payload}
    )
  end

  # Principal kind enum comes from the F001 FR-026 three-way; use
  # `to_existing_atom` so unknown strings fall into the default branch
  # instead of minting new atoms at runtime.
  defp principal_kind_from(%{"kind" => kind}) when is_binary(kind), do: safe_kind(kind)
  defp principal_kind_from(%{kind: kind}) when is_atom(kind), do: kind
  defp principal_kind_from(%{kind: kind}) when is_binary(kind), do: safe_kind(kind)
  defp principal_kind_from(_), do: :service_account

  defp safe_kind(kind) when is_binary(kind) do
    String.to_existing_atom(kind)
  rescue
    ArgumentError -> :service_account
  end

  defp stringify_keys(m) when is_map(m) do
    Map.new(m, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), v}
      {k, v} -> {k, v}
    end)
  end

  defp parse_timestamp(nil), do: nil

  defp parse_timestamp(bin) when is_binary(bin) do
    case DateTime.from_iso8601(bin) do
      {:ok, dt, _offset} -> dt
      # Documented `DateTime.from_iso8601/1` failure shape — malformed
      # binary in a row we read from disk. Treat as missing rather than
      # crashing the row decode; any other shape is an unexpected bug
      # and will raise on case mismatch.
      {:error, _reason} -> nil
    end
  end

  defp parse_timestamp(%DateTime{} = dt), do: dt

  defp extract_signature(%{"signatures" => [%{"sig" => s} | _]}) when is_binary(s) do
    case Base.decode64(s) do
      {:ok, bytes} -> bytes
      :error -> s
    end
  end

  defp extract_signature(%{signatures: [%{sig: s} | _]}) when is_binary(s), do: s
  defp extract_signature(bin) when is_binary(bin), do: bin
  defp extract_signature(_), do: <<0::size(8 * 72)>>

  # -- Internal helpers: query_paginated/1 -----------------------------------

  @max_page_limit 500
  @default_page_limit 50

  defp clamp_limit(limit) when is_integer(limit) and limit >= 1,
    do: min(limit, @max_page_limit)

  defp clamp_limit(_), do: @default_page_limit

  defp apply_eq_filter(query, _field, nil), do: query

  defp apply_eq_filter(query, field, value) do
    Ecto.Query.where(query, [a], field(a, ^field) == ^value)
  end

  # F004 FR-009 — IN-filter for set-valued enum columns. `nil` and empty
  # list both mean "no filter" (consistent with `apply_eq_filter`'s nil
  # contract). Pushing the `event_kind IN (...)` predicate to SQL means
  # the row LIMIT applies after the filter; without this, list pages
  # are dominated by the high-volume `:ui_query` self-emission rows.
  defp apply_in_filter(query, _field, nil), do: query
  defp apply_in_filter(query, _field, []), do: query

  defp apply_in_filter(query, field, values) when is_list(values) do
    Ecto.Query.where(query, [a], field(a, ^field) in ^values)
  end

  # Cursor is `{timestamp_iso8601_usec, run_id}` base64-encoded JSON. The
  # ordering invariant is `timestamp DESC, run_id DESC`, so a cursor value
  # acts as the strict upper bound on the next page. We preserve microsecond
  # precision (the `:utc_datetime_usec` column) so tight-clock bursts paginate
  # correctly.
  defp decode_cursor(nil), do: {:ok, nil}

  defp decode_cursor(cursor) when is_binary(cursor) do
    with {:ok, raw} <- Base.url_decode64(cursor, padding: false),
         {:ok, decoded} <- Jason.decode(raw),
         %{"ts" => ts_iso, "run_id" => run_id}
         when is_binary(ts_iso) and is_binary(run_id) <- decoded,
         {:ok, ts, _offset} <- DateTime.from_iso8601(ts_iso) do
      {:ok, {ts, run_id}}
    else
      _ -> {:error, :invalid_cursor}
    end
  end

  defp apply_cursor_bound(query, nil), do: query

  defp apply_cursor_bound(query, {ts, run_id}) do
    # Strict lexicographic bound on a DESC-ordered result set: the next page
    # starts at rows with an earlier timestamp, OR the same timestamp with
    # a lexicographically-smaller run_id.
    Ecto.Query.where(
      query,
      [a],
      a.timestamp < ^ts or (a.timestamp == ^ts and a.run_id < ^run_id)
    )
  end

  defp split_page(rows, limit) do
    case Enum.split(rows, limit) do
      {page, []} ->
        {page, nil}

      {page, _overflow} ->
        last = List.last(page)
        {page, encode_cursor(last)}
    end
  end

  defp encode_cursor(%Attestation{timestamp: ts, run_id: run_id}) do
    json =
      Jason.encode!(%{
        "ts" => DateTime.to_iso8601(ts),
        "run_id" => run_id
      })

    Base.url_encode64(json, padding: false)
  end

  # -- Internal helpers: force_commit_for_run_ids/2 --------------------------

  # Short-circuit if already at global_inclusion_verified. Otherwise run the
  # partial commit pipeline inside a SERIALIZABLE Ecto.Multi transaction.
  defp force_commit_single(repo, pubsub, run_id) do
    case repo.get(Attestation, run_id) do
      nil ->
        {:error, :not_found}

      %Attestation{verification_level: :global_inclusion_verified} = att ->
        {:ok, {:already_global_inclusion_verified, att.session_chain_root}}

      %Attestation{} = att ->
        advance_attestation(repo, pubsub, att)
    end
  end

  defp advance_attestation(repo, pubsub, %Attestation{} = att) do
    now = DateTime.utc_now()

    session_epoch =
      repo.get_by(SessionEpoch, session_id: att.session_id, epoch_index: att.session_chain_epoch)

    epoch_root = derive_epoch_root(session_epoch, att)

    multi =
      Multi.new()
      |> Multi.run(:session_epoch, fn _repo, _ ->
        case session_epoch do
          nil -> {:error, :session_epoch_not_found}
          %SessionEpoch{} = se -> {:ok, se}
        end
      end)
      |> ensure_local_commit(att, epoch_root, now)
      |> append_global_commit(:session_epoch, epoch_root, now)
      |> Multi.run(:global_proof, fn inner_repo, %{global_commit: %{index: idx, tree_size: ts}} ->
        leaves = load_global_leaves(inner_repo, ts)

        case encode_inclusion_transitem(leaves, idx - 1, ts) do
          {:ok, proof} -> {:ok, proof}
          {:error, reason} -> {:error, {:inclusion_proof_encode, reason}}
        end
      end)
      |> Multi.update(:attestation_global, fn %{global_proof: proof} ->
        Attestation.changeset(att, %{
          verification_level: :global_inclusion_verified,
          session_chain_root: epoch_root,
          global_inclusion_proof: proof
        })
      end)

    case run_transaction(repo, multi) do
      {:ok, changes} ->
        broadcast_first_committed(
          pubsub,
          %{
            run_id: att.run_id,
            verification_level: :global_inclusion_verified,
            session_chain_root: epoch_root,
            global_inclusion_proof: changes.global_proof
          },
          changes.attestation_global
        )

        {:ok, :committed}

      {:error, _step, reason, _changes} ->
        {:error, reason}
    end
  end

  # When the attestation is still at `:signed` (hasn't reached
  # local_inclusion_verified), update the session_epoch row so its
  # `epoch_root` matches the attestation's leaf hash (consistent with
  # commit_attestation/2's step 7).
  defp ensure_local_commit(
         multi,
         %Attestation{verification_level: :signed} = att,
         epoch_root,
         now
       ) do
    multi
    |> Multi.update(:session_epoch_close, fn %{session_epoch: se} ->
      SessionEpoch.changeset(se, %{epoch_root: epoch_root, epoch_end_at: now})
    end)
    |> Multi.update(:attestation_local, fn _ ->
      Attestation.changeset(att, %{
        verification_level: :local_inclusion_verified,
        session_chain_root: epoch_root
      })
    end)
  end

  defp ensure_local_commit(multi, %Attestation{}, _epoch_root, _now), do: multi

  # Derive the leaf hash from the attestation bytes (same formula as
  # commit_attestation/2 step 4). Under 1-run-1-session the epoch root ==
  # leaf hash.
  defp derive_epoch_root(%SessionEpoch{epoch_root: root}, _att)
       when is_binary(root) and byte_size(root) == 32,
       do: root

  defp derive_epoch_root(_session_epoch, %Attestation{signed_predicate_bytes: bytes})
       when is_binary(bytes) do
    MerkleTree.hash_leaf(bytes)
  end

  # -- Internal helpers: generate_inclusion_proof/1 --------------------------

  defp fetch_attestation(run_id) do
    case Repo.get(Attestation, run_id) do
      nil -> {:error, :not_found}
      %Attestation{} = att -> {:ok, att}
    end
  end

  defp fetch_epoch_root(session_id, epoch_index) do
    case Repo.get_by(SessionEpoch, session_id: session_id, epoch_index: epoch_index) do
      nil ->
        {:error, :session_epoch_not_found}

      %SessionEpoch{epoch_root: root} when is_binary(root) and byte_size(root) == 32 ->
        {:ok, root}

      %SessionEpoch{} ->
        {:error, :session_epoch_not_committed}
    end
  end

  # Session-chain proof: under the 1-run-1-session heuristic there is a
  # single leaf per session tree, so the audit path is empty. We still
  # emit an RFC 9162 TransItem so the zip carries a uniform shape (tree_size=1,
  # leaf_index=0, path=[]).
  defp build_session_chain_proof(%Attestation{signed_predicate_bytes: bytes}, _epoch_root)
       when is_binary(bytes) do
    leaves = [bytes]
    encode_inclusion_transitem(leaves, 0, 1)
  end

  defp build_session_chain_proof(_att, _epoch_root), do: {:error, :invalid_attestation}

  # Global proof: find the global_ledger_entry whose `session_epoch_root`
  # matches the session's committed root, then build a proof at that
  # leaf index against the current visible tree size.
  defp build_global_proof(epoch_root) do
    leaves = load_all_global_leaves(Repo)

    case Enum.find_index(leaves, &(&1 == epoch_root)) do
      nil ->
        {:error, :global_leaf_not_found}

      index ->
        tree_size = length(leaves)
        encode_inclusion_transitem(leaves, index, tree_size)
    end
  end
end
