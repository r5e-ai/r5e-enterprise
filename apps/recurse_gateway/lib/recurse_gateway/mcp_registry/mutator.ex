defmodule Recurse.Gateway.McpRegistry.Mutator do
  @moduledoc """
  Serialized writer for the Trusted MCP Registry catalog (F7 quarantine
  workflow — `PATCH /v1/mcp/registry/:id`).

  ## Why a GenServer (Iron Law check — `elixir:otp-thinking`)

    1. Mutable state? Yes — owns the write side of the catalog file +
       `:persistent_term` cache. Concurrent operator quarantine clicks
       MUST serialize: two simultaneous PATCH requests against the same
       entry would otherwise read-modify-write race and lose one
       update. Every other consumer (the read paths in `Loader`, the
       runtime gate in `McpServerHandler`) only reads from
       `:persistent_term`.
    2. Concurrent execution? Yes — the GenServer is the serialization
       point.
    3. Fault isolation? Yes — write failures (e.g., read-only
       filesystem on a misconfigured EC2 release) MUST surface to the
       caller as `{:error, reason}` so the handler returns 500
       fail-closed; the receipt is NOT emitted on persistence failure
       (no audit gap, no phantom state change).

  All three YES → GenServer is justified.

  ## Read/write asymmetry — same shape as `Recurse.Gateway.Policy.BundleLoader`

  This mirrors the established F002 BundleLoader pattern: writers
  serialize through the GenServer; readers go straight to
  `:persistent_term` for lock-free hot-path access. `Loader` is the
  read-side seam (`Loader.list/0`, `Loader.get/1`, `Loader.catalog/0`);
  `Mutator` is the write-side seam (`update_trust_tier/3`).

  ## Persistence semantics

  Phase-1: the catalog is a hand-curated JSON file shipping in
  `priv/mcp_registry/registry.json`. To survive BEAM restart, mutations
  MUST be flushed to disk before the receipt commits. We write to the
  configured `:mcp_registry_path` (see `Loader.registry_path/0`) using
  the standard "write to tmp + rename" idiom for atomicity (a half-
  written JSON would otherwise crash the next boot's
  `Loader.load!/0`).

  Production deployments that ship `priv/` as an immutable artifact
  MUST configure `:mcp_registry_path` to point at a writable persistent
  volume; otherwise the first quarantine click returns 500 and no
  ledger receipt is committed. Phase-2+ replaces this with a per-tenant
  Postgres-backed registry, removing the priv-write coupling entirely.

  ## Cedar policy_constraints update — snapshot + restore (F002+F004 fix)

  Per the design brief's §"Quarantine workflow", a quarantine action
  also flips the entry's `policy_constraints.cedar_policies` from
  `permit(...)` to `forbid(...)` (and vice-versa for restore). This
  field is the auditor-facing documentation of the runtime gate; the
  actual enforcement is in `McpServerHandler.dispatch/6` via direct
  `entry.trust_tier` read, but keeping the documented Cedar source
  in-sync prevents drift.

  Naive "rebuild from a tier-canonical template" loses any per-entry
  constraints (e.g. `principal.role in ["operator", "developer"]` on
  `filesystem-mcp`, `principal.role == "developer"` on
  `github-issues-mcp`) on a single quarantine→restore cycle, silently
  weakening the policy on each restore. To prevent this:

    * Entering `:quarantined`: snapshot the previous
      `cedar_policies` + `rate_limit_per_minute` into sibling
      `pre_quarantine_cedar_policies` +
      `pre_quarantine_rate_limit_per_minute` fields on
      `policy_constraints` BEFORE rewriting to the canonical
      `forbid(...)` clause + 0 rate limit.
    * Restoring out of `:quarantined`: if those snapshot fields are
      present, restore the original `cedar_policies` and
      `rate_limit_per_minute` verbatim, then drop the snapshot keys.
      Falls back to the tier-canonical template only when no snapshot
      exists (legacy quarantined entry from before this MR shipped).
    * community<->verified (no involvement of `:quarantined`):
      preserve `cedar_policies` if any clause carries non-template
      constraints; otherwise refresh to the tier-canonical template.
      Rate limit is always preserved (lifted to 60/min only if missing
      or pinned at 0).

  ## Sibling-MR coordination

  The original design brief is `design/briefs/07-mcp-registry.md`,
  which lives on the `chore/design-briefs-pencil-handoff` branch (MR
  !86 / commit `cfbafb5`); it has not yet merged into `main`. This MR
  ships independently — runtime + tests do not depend on the brief
  file — and should merge in tandem with !86 so reviewers can resolve
  the design citation from a single tree post-merge. If this MR lands
  first, the moduledoc citation will dangle until !86 follows; that's
  acceptable because the relevant brief sections are paraphrased
  inline above (snapshot+restore semantics; rate-limit handling).

  ## Cross-references

    * `Recurse.Gateway.McpRegistry.Loader` — read-side seam (boot-time
      load + per-call `:persistent_term` reads).
    * `Recurse.Gateway.Admin.McpRegistryHandler.update/1` — the Plug
      handler that calls `update_trust_tier/3`.
    * `Recurse.Gateway.DataPlane.McpServerHandler.dispatch/6` — the
      runtime gate that reads `entry.trust_tier` and enforces
      quarantine.
    * `design/briefs/07-mcp-registry.md` §"Quarantine workflow"
      (lives on `chore/design-briefs-pencil-handoff`, MR !86 — see
      "Sibling-MR coordination" above).
  """

  use GenServer

  alias Recurse.Gateway.McpRegistry.Loader

  require Logger

  @typedoc "Permitted target trust tiers for operator-driven mutation."
  @type target_tier :: :verified | :community | :quarantined

  @typedoc "Per-mutation context — auditor-facing reason + actor for the receipt payload."
  @type mutation_ctx :: %{
          required(:actor_principal_subject) => String.t(),
          optional(:reason) => String.t() | nil
        }

  @typedoc """
  Successful update — returns the previous tier, the previous full
  entry (for handler-level rollback if a downstream step like the
  ledger commit fails), and the new entry.
  """
  @type update_ok ::
          {:ok,
           %{
             previous_tier: target_tier(),
             previous_entry: Loader.entry(),
             entry: Loader.entry()
           }}

  @typedoc "Failure modes. `:not_found` is a 404; everything else is a 500."
  @type update_err ::
          {:error, :not_found}
          | {:error, {:write_failed, term()}}
          | {:error, {:invalid_tier, any()}}

  @doc """
  Start the Mutator GenServer.

  Optional `:name` (defaults to `__MODULE__`) for test isolation.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Update an entry's trust_tier (and the documented Cedar policy clause)
  to `target_tier`. Persists to disk and refreshes the
  `:persistent_term` cache atomically before returning.

  Returns `{:ok, %{previous_tier:, entry:}}` on success;
  `{:error, :not_found}` if the entry id is unknown;
  `{:error, {:write_failed, reason}}` if the disk-write fails.
  """
  @spec update_trust_tier(String.t(), target_tier(), mutation_ctx(), GenServer.server()) ::
          update_ok() | update_err()
  def update_trust_tier(entry_id, target_tier, ctx, server \\ __MODULE__)

  def update_trust_tier(entry_id, target_tier, ctx, server)
      when is_binary(entry_id) and target_tier in [:verified, :community, :quarantined] and
             is_map(ctx) do
    GenServer.call(server, {:update_trust_tier, entry_id, target_tier, ctx}, 5_000)
  end

  def update_trust_tier(_entry_id, target_tier, _ctx, _server),
    do: {:error, {:invalid_tier, target_tier}}

  @doc """
  Replace an entry in-place with the supplied prior shape. Used by the
  handler to ROLL BACK an `update_trust_tier/3` mutation when a
  downstream step (DSSE-sign + ledger commit) fails — the persisted
  state must match the audit log, so a failed receipt commit must
  un-do the disk + cache mutation.

  Returns `:ok` on successful rollback, `{:error, {:write_failed, _}}`
  if the rollback write itself fails (in which case the persistent
  state is in the post-mutation shape AND the receipt is missing —
  this is a hard failure that the caller must surface as a 5xx and
  log loudly).

  Idempotent against the entry's id — if the entry is no longer in
  the catalog (concurrent removal that this MR doesn't ship), returns
  `{:error, :not_found}` rather than re-inserting.
  """
  @spec restore_entry(Loader.entry(), GenServer.server()) ::
          :ok | {:error, :not_found} | {:error, {:write_failed, term()}}
  def restore_entry(prior_entry, server \\ __MODULE__)

  def restore_entry(%{id: id} = prior_entry, server) when is_binary(id) do
    GenServer.call(server, {:restore_entry, prior_entry}, 5_000)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    {:ok, %{}}
  end

  @impl true
  def handle_call({:update_trust_tier, entry_id, target_tier, ctx}, _from, state) do
    reply = do_update(entry_id, target_tier, ctx)
    {:reply, reply, state}
  end

  @impl true
  def handle_call({:restore_entry, prior_entry}, _from, state) do
    reply = do_restore(prior_entry)
    {:reply, reply, state}
  end

  # ---------------------------------------------------------------------------
  # Implementation — read catalog, mutate entry, write back, refresh cache.
  # ---------------------------------------------------------------------------

  defp do_update(entry_id, target_tier, _ctx) do
    catalog = Loader.catalog()

    case find_entry(catalog.entries, entry_id) do
      {:error, :not_found} = err ->
        err

      {:ok, old_entry} ->
        new_entry = mutate_entry(old_entry, target_tier)
        new_catalog = replace_entry(catalog, old_entry, new_entry)

        case persist(new_catalog) do
          :ok ->
            {:ok,
             %{
               previous_tier: old_entry.trust_tier,
               previous_entry: old_entry,
               entry: new_entry
             }}

          {:error, reason} ->
            Logger.error(
              "mcp_registry: persistence failed for #{entry_id} -> #{target_tier}: " <>
                inspect(reason)
            )

            {:error, {:write_failed, reason}}
        end
    end
  end

  defp do_restore(%{id: id} = prior_entry) do
    catalog = Loader.catalog()

    case find_entry(catalog.entries, id) do
      {:error, :not_found} = err ->
        err

      {:ok, current_entry} ->
        new_catalog = replace_entry(catalog, current_entry, prior_entry)

        case persist(new_catalog) do
          :ok ->
            :ok

          {:error, reason} ->
            Logger.error(
              "mcp_registry: ROLLBACK persistence failed for #{id}: " <> inspect(reason)
            )

            {:error, {:write_failed, reason}}
        end
    end
  end

  defp find_entry(entries, id) do
    case Enum.find(entries, &(&1.id == id)) do
      nil -> {:error, :not_found}
      entry -> {:ok, entry}
    end
  end

  defp replace_entry(catalog, old_entry, new_entry) do
    new_entries =
      Enum.map(catalog.entries, fn
        ^old_entry -> new_entry
        other -> other
      end)

    %{catalog | entries: new_entries}
  end

  # Mutate an entry's `trust_tier` + the documented Cedar source +
  # `rate_limit_per_minute`, preserving any per-entry constraints
  # (e.g. `principal.role in [...]`) across a quarantine→restore
  # round-trip via sibling-field snapshotting.
  #
  # Approach (a) per the F002 + F004 GAN findings: when entering
  # `:quarantined` from any non-quarantined tier, snapshot the existing
  # `cedar_policies` + `rate_limit_per_minute` into sibling
  # `pre_quarantine_cedar_policies` + `pre_quarantine_rate_limit_per_minute`
  # fields on `policy_constraints`. When restoring out of `:quarantined`,
  # if the snapshot fields are present, restore from them and drop the
  # snapshot keys; otherwise fall back to a tier-canonical template
  # (legacy entries that were quarantined before this MR shipped, or
  # transitions between non-quarantine tiers like community→verified).
  defp mutate_entry(%{} = entry, target_tier) do
    constraints = Map.get(entry, :policy_constraints, %{}) || %{}
    previous_tier = Map.get(entry, :trust_tier)

    {new_clauses, new_rate_limit, new_constraints} =
      rewrite_constraints(constraints, entry.id, previous_tier, target_tier)

    new_constraints =
      new_constraints
      |> Map.put("cedar_policies", new_clauses)
      |> Map.put("rate_limit_per_minute", new_rate_limit)

    %{entry | trust_tier: target_tier, policy_constraints: new_constraints}
  end

  # Three transition shapes:
  #
  #   1. non-quarantined -> :quarantined  : snapshot + force forbid + 0
  #   2. :quarantined    -> non-quarantined: restore snapshot if present,
  #                                          else fall back to template
  #   3. non-quarantined -> non-quarantined (community<->verified or no-op):
  #      preserve constraints (only rewrite the leading tier-gate clause
  #      template if it's the legacy single-clause shape; otherwise leave
  #      cedar_policies untouched and just refresh rate_limit_per_minute).
  defp rewrite_constraints(constraints, server_id, _previous, :quarantined) do
    snapshot_clauses = Map.get(constraints, "cedar_policies", []) || []

    snapshot_rate_limit =
      case Map.get(constraints, "rate_limit_per_minute") do
        n when is_integer(n) and n >= 0 -> n
        _ -> 60
      end

    snapshotted =
      constraints
      |> Map.put("pre_quarantine_cedar_policies", snapshot_clauses)
      |> Map.put("pre_quarantine_rate_limit_per_minute", snapshot_rate_limit)

    {[quarantined_clause(server_id)], 0, snapshotted}
  end

  defp rewrite_constraints(constraints, server_id, :quarantined, target_tier)
       when target_tier in [:verified, :community] do
    case Map.get(constraints, "pre_quarantine_cedar_policies") do
      [_ | _] = snapshot_clauses ->
        rate_limit =
          case Map.get(constraints, "pre_quarantine_rate_limit_per_minute") do
            n when is_integer(n) and n > 0 -> n
            # Snapshot value of 0 means the entry was already restricted at
            # snapshot time; lift to the safe default rather than carry the
            # gate-denied sentinel through a restore.
            _ -> 60
          end

        cleaned =
          constraints
          |> Map.delete("pre_quarantine_cedar_policies")
          |> Map.delete("pre_quarantine_rate_limit_per_minute")

        {snapshot_clauses, rate_limit, cleaned}

      _no_snapshot ->
        # Legacy quarantined entry (pre-snapshot MR) — no original to
        # restore. Fall back to the tier-canonical template + safe rate.
        {[default_clause(server_id, target_tier)], 60, constraints}
    end
  end

  defp rewrite_constraints(constraints, server_id, _previous, target_tier)
       when target_tier in [:verified, :community] do
    # Non-quarantine tier change (community<->verified) — preserve any
    # per-entry constraints by leaving `cedar_policies` untouched if a
    # non-template clause is present, otherwise refresh the canonical
    # tier-gate clause. Rate limit is preserved (or lifted to safe
    # default if missing/zero).
    existing_clauses = Map.get(constraints, "cedar_policies", []) || []

    new_clauses =
      if all_template_clauses?(existing_clauses, server_id) do
        [default_clause(server_id, target_tier)]
      else
        existing_clauses
      end

    rate_limit =
      case Map.get(constraints, "rate_limit_per_minute") do
        n when is_integer(n) and n > 0 -> n
        _ -> 60
      end

    {new_clauses, rate_limit, constraints}
  end

  defp quarantined_clause(server_id) do
    ~s|forbid(principal, action == Recurse::Action::McpToolCall, resource) when { resource.mcp_server == "#{server_id}" };|
  end

  defp default_clause(server_id, :verified) do
    ~s|permit(principal, action == Recurse::Action::McpToolCall, resource) when { resource.mcp_server == "#{server_id}" && resource.trust_tier == "verified" };|
  end

  defp default_clause(server_id, :community) do
    ~s|permit(principal, action == Recurse::Action::McpToolCall, resource) when { resource.mcp_server == "#{server_id}" };|
  end

  # Heuristic: a clause is "template-shaped" if it mentions the server
  # id and contains no per-entry constraint keywords (`principal.role`,
  # `principal in`, custom resource attribute checks beyond the tier
  # gate). When every clause is template-shaped it is safe to rewrite
  # to the tier-canonical template; if any clause carries extra
  # constraints we leave the list alone to preserve them.
  defp all_template_clauses?(clauses, _server_id) when is_list(clauses) and clauses != [] do
    Enum.all?(clauses, fn clause when is_binary(clause) ->
      not String.contains?(clause, "principal.role") and
        not String.contains?(clause, "principal in")
    end)
  end

  defp all_template_clauses?(_clauses, _server_id), do: false

  # Atomic write: serialize the catalog to JSON, write to a sibling tmp
  # path, then rename. This guarantees the registry file is either the
  # old contents or the new contents at any instant — never a half-
  # written truncated JSON that would crash the next boot.
  #
  # NB: this is `persist/1` (no bang) per Elixir convention — it
  # returns `:ok | {:error, reason}` and never raises. The body uses
  # `rescue` to convert unexpected raises (e.g. `JSON.encode!/1`
  # failure on an unencodable term) into the same `{:error, _}` shape
  # so callers get one uniform return contract.
  defp persist(new_catalog) do
    # The built-in `JSON` module emits compact JSON (no `pretty:` option).
    # That's fine — the file is machine-loaded by `Loader.load!/0`; humans
    # diff the structured `policy_constraints` field via the SPA, not by
    # `git diff` on the catalog.
    json = JSON.encode!(catalog_to_json(new_catalog))
    final_path = Loader.registry_path()
    tmp_path = final_path <> ".tmp." <> Integer.to_string(System.unique_integer([:positive]))

    with :ok <- File.write(tmp_path, json),
         :ok <- File.rename(tmp_path, final_path) do
      :ok = Loader.load!()
      :ok
    else
      {:error, reason} ->
        # Best-effort tmp cleanup so we don't leak orphan files in tests.
        _ = File.rm(tmp_path)
        {:error, reason}
    end
  rescue
    error -> {:error, error}
  end

  defp catalog_to_json(%{} = catalog) do
    %{
      "version" => catalog.version,
      "generated_at" => catalog.generated_at,
      "description" => catalog.description,
      "entries" => Enum.map(catalog.entries, &Loader.entry_to_json/1)
    }
  end
end
