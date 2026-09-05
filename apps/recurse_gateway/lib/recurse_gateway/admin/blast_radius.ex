defmodule Recurse.Gateway.Admin.BlastRadius do
  @moduledoc """
  Blast Radius engine — F004 T086 / US3.

  Streams historical receipts through a candidate Cedar policy and
  classifies each `(original_decision, proposed_decision)` pair into the
  4-cell matrix per `contracts/blast_radius_algorithm.md`:

      original=deny  + proposed=deny  → :matches_intent
      original=allow + proposed=deny  → :unintended         (the danger case)
      original=deny  + proposed=allow → :would_have_allowed (advisory; folded into no_change for the topline)
      original=allow + proposed=allow → :no_change

  ## Iron Law check (`elixir:elixir-thinking` + `elixir:ecto-thinking` + `elixir:otp-thinking`)

    1. Mutable state across calls? No — every call's accumulator lives
       on the request process's stack.
    2. Concurrent execution? No — runs synchronously on the caller
       process. The streaming Repo.transaction holds one connection per
       compute; concurrent computes are bounded by the connection pool.
    3. Fault isolation? No — Cedar parse errors return `{:error, ...}`
       fast; per-receipt evaluation panics are rescued + counted.

  All three NO → plain functions. No GenServer.

  ## Algorithm summary (per blast_radius_algorithm.md §1-§5)

    1. Parse + canonical-hash the draft Cedar source. On parse error
       return `{:error, {:cedar_parse_error, message}}` BEFORE any DB hit.
    2. Estimate window size with a `count(*)` query. If `> 10_000`,
       return `{:async_required, estimated_count}` so the caller can
       enqueue the Oban job (per §6).
    3. Stream receipts in batches of 1,000 via `Repo.stream/2 +
       Repo.transaction/2` (timeout: 60_000ms).
    4. For each receipt, synthesize the entity store from the
       signed_predicate's principal claim, derive the Cedar action UID
       from the `event_kind` via `action_uid_from_event_kind/1`,
       evaluate against the draft Cedar, and classify the
       (original, proposed) pair.
    5. Sample preference: unintended first, then would_have_allowed,
       then matches_intent — capped at `sample_size` (default 20).
    6. Persist the summary to `policy_drafts.last_blast_radius_summary`
       on success (caller passes `:persist?` true; the sync API path does).

  ## Cache shortcut (per §7)

  If the input includes a `:cached_summary` and `:cached_at` AND the
  cached_at is within 24 hours AND `:force` is false, return the cached
  summary verbatim. The `Recurse.Gateway.Admin.PolicyDrafts.update/3`
  hook clears the cache on `cedar_source` / `scope_metadata` /
  `condition_metadata` change so a stale summary cannot survive an edit.

  ## `action_uid_from_event_kind/1`

  Single-source-of-truth dispatch sourced from `data-model.md` §0
  (canonical event_kind ↔ Cedar action matrix). Every clause matches
  the matrix verbatim. Surface T property test
  (`apps/recurse_gateway/test/admin/blast_radius_property_test.exs`)
  asserts every event_kind in §0 has a matching clause; drift fails CI.

  ## Cross-references

    * `specs/004-audit-console/contracts/blast_radius_algorithm.md`
      (full algorithm spec).
    * `specs/004-audit-console/data-model.md` §0 (canonical matrix —
      sole source for the lookup table).
    * `apps/recurse_shared/lib/recurse_shared/cedar.ex` —
      `Recurse.Cedar.evaluate_with_entities/3`.
    * `apps/recurse_gateway/lib/recurse_gateway/admin/blast_radius/async_escalation.ex`
      (T087 — Oban worker for `> 10_000` windows).
  """

  import Ecto.Query

  alias Recurse.Providers.Impls.PostgresMerkleLedger.Schemas.Attestation
  alias Recurse.Providers.Repo

  require Logger

  @batch_size 1_000
  @stream_timeout_ms 60_000
  @async_threshold 10_000
  @cache_ttl_hours 24
  @max_eval_error_ratio 0.05

  @typedoc "Cedar action UID string in the canonical Recurse namespace."
  @type cedar_action :: String.t()

  @typedoc "Per-receipt classification — the 4-cell matrix."
  @type classification ::
          :matches_intent
          | :unintended
          | :would_have_allowed
          | :no_change
          | :evaluation_error
          | :skipped

  @typedoc "Input shape accepted by `compute/1`."
  @type input :: %{
          required(:draft_id) => String.t(),
          required(:draft_cedar_source) => String.t(),
          required(:tenant_id) => String.t(),
          required(:window) => %{since: DateTime.t(), until: DateTime.t()},
          optional(:sample_size) => pos_integer(),
          optional(:force) => boolean(),
          optional(:cached_summary) => map() | nil,
          optional(:cached_at) => DateTime.t() | nil,
          optional(:persist?) => boolean()
        }

  @typedoc "Summary returned to the caller (and persisted on the draft)."
  @type summary :: %{
          draft_id: String.t(),
          window: %{since: String.t(), until: String.t()},
          total_scanned: non_neg_integer(),
          total_affected: non_neg_integer(),
          matches_intent: non_neg_integer(),
          unintended: non_neg_integer(),
          would_have_allowed: non_neg_integer(),
          no_change: non_neg_integer(),
          sample_receipts: [map()],
          computed_at: String.t(),
          cedar_source_hash: String.t(),
          duration_ms: non_neg_integer(),
          mode: String.t(),
          evaluation_errors: non_neg_integer()
        }

  @doc """
  Compute (or return cached) Blast Radius summary for the given input.

  Returns:
    * `{:ok, summary}` on a sync compute, with the summary persisted on
      the draft row when `:persist?` is true.
    * `{:cached, summary}` if a fresh-enough cache hit is returned.
    * `{:async_required, estimated_count}` if the window has more than
      10K receipts; caller should enqueue an Oban job.
    * `{:error, reason}` on Cedar parse error / evaluation collapse / etc.
  """
  @spec compute(input()) ::
          {:ok, summary()}
          | {:cached, map()}
          | {:async_required, non_neg_integer()}
          | {:error, term()}
  def compute(%{draft_cedar_source: source, tenant_id: tid, window: window} = input)
      when is_binary(source) and is_binary(tid) and is_map(window) do
    with :ok <- validate_cedar_source(source),
         :cache_miss <- check_cache(input) do
      estimated = estimate_window_size(tid, window)
      force_sync? = Map.get(input, :force_sync?, false)

      if estimated > @async_threshold and not force_sync? do
        {:async_required, estimated}
      else
        do_streaming_compute(input, estimated)
      end
    else
      {:cached, summary} -> {:cached, summary}
      {:error, _} = err -> err
    end
  end

  @doc """
  Same as `compute/1` but forces sync execution regardless of window size.
  Used by the AsyncEscalation Oban worker (which already accepts the
  long-running cost) and integration tests.
  """
  @spec compute_sync(input()) :: {:ok, summary()} | {:error, term()}
  def compute_sync(%{} = input) do
    case compute(Map.put(input, :force_sync?, true)) do
      {:ok, summary} -> {:ok, summary}
      {:cached, summary} -> {:ok, summary}
      {:error, _} = err -> err
    end
  end

  @doc """
  Threshold above which `compute/1` returns `:async_required`. Exposed so
  handlers + tests can reason about the boundary without hard-coding it.
  """
  @spec async_threshold() :: pos_integer()
  def async_threshold, do: @async_threshold

  # ---------------------------------------------------------------------------
  # Public — `action_uid_from_event_kind/1` lookup table.
  # Source: data-model.md §0 (canonical event_kind ↔ Cedar action matrix).
  #
  # Surface T property test asserts every event_kind in §0 has a clause here
  # AND that the returned Cedar action UID matches the matrix verbatim.
  # ---------------------------------------------------------------------------

  @doc """
  Map a `Recurse.Shared.Attestation.SignedPredicate` `event_kind` atom to
  the Cedar action UID it would evaluate as.

  Returns `nil` for the `:ui_retention_purge` row — that event_kind is
  not Cedar-gated and is skipped during replay (matrix §0). Any unknown
  atom returns `nil` so the streaming algorithm can short-circuit
  with `:skipped` rather than crashing.
  """
  @spec action_uid_from_event_kind(atom()) :: cedar_action() | nil
  # F002-vintage event_kinds (pre-F004 widening).
  def action_uid_from_event_kind(:llm_call), do: ~s(Recurse::Action::"ChatCompletion")
  def action_uid_from_event_kind(:tool_call), do: ~s(Recurse::Action::"ToolCall")

  def action_uid_from_event_kind(:egress_denied),
    do: ~s(Recurse::Action::"ChatCompletion")

  def action_uid_from_event_kind(:policy_denied),
    do: ~s(Recurse::Action::"ChatCompletion")

  def action_uid_from_event_kind(:session_abort),
    do: ~s(Recurse::Action::"ChatCompletion")

  # F004 UI actions — 1:1 with the canonical matrix.
  def action_uid_from_event_kind(:ui_login), do: ~s(Recurse::Action::"LoginSession")
  def action_uid_from_event_kind(:ui_session), do: ~s(Recurse::Action::"LoginSession")
  def action_uid_from_event_kind(:ui_query), do: ~s(Recurse::Action::"DashboardQuery")

  def action_uid_from_event_kind(:ui_policy_simulate),
    do: ~s(Recurse::Action::"PolicySimulate")

  def action_uid_from_event_kind(:ui_policy_replay),
    do: ~s(Recurse::Action::"PolicyReplay")

  def action_uid_from_event_kind(:ui_policy_draft_created),
    do: ~s(Recurse::Action::"PolicyDraftCreate")

  def action_uid_from_event_kind(:ui_policy_draft_edited),
    do: ~s(Recurse::Action::"PolicyDraftEdit")

  def action_uid_from_event_kind(:ui_policy_draft_archived),
    do: ~s(Recurse::Action::"PolicyDraftArchive")

  def action_uid_from_event_kind(:ui_policy_draft_dry_run),
    do: ~s(Recurse::Action::"PolicyDraftDryRun")

  def action_uid_from_event_kind(:ui_policy_suggestion_generated),
    do: ~s(Recurse::Action::"PolicySuggestionGenerate")

  def action_uid_from_event_kind(:ui_policy_suggestion_viewed),
    do: ~s(Recurse::Action::"PolicySuggestionView")

  def action_uid_from_event_kind(:ui_policy_suggestion_adopted),
    do: ~s(Recurse::Action::"PolicySuggestionAdopt")

  def action_uid_from_event_kind(:ui_policy_suggestion_dismissed),
    do: ~s(Recurse::Action::"PolicySuggestionDismiss")

  def action_uid_from_event_kind(:ui_policy_suggestion_refresh_requested),
    do: ~s(Recurse::Action::"PolicySuggestionRefresh")

  def action_uid_from_event_kind(:ui_chat), do: ~s(Recurse::Action::"ChatDrawerQuery")

  def action_uid_from_event_kind(:ui_chat_skill_invoked_query_receipts),
    do: ~s(Recurse::Action::"AuditAgentToolQueryReceipts")

  def action_uid_from_event_kind(:ui_chat_skill_invoked_fetch_receipt_detail),
    do: ~s(Recurse::Action::"AuditAgentToolFetchReceiptDetail")

  def action_uid_from_event_kind(:ui_chat_skill_invoked_explain_denial),
    do: ~s(Recurse::Action::"AuditAgentToolExplainDenial")

  def action_uid_from_event_kind(:ui_chat_skill_invoked_find_similar_receipts),
    do: ~s(Recurse::Action::"AuditAgentToolFindSimilarReceipts")

  def action_uid_from_event_kind(:ui_chat_skill_invoked_simulate_policy_dryrun),
    do: ~s(Recurse::Action::"AuditAgentToolSimulatePolicyDryrun")

  def action_uid_from_event_kind(:ui_chat_skill_invoked_suggest_policy_pattern),
    do: ~s(Recurse::Action::"AuditAgentToolSuggestPolicyPattern")

  def action_uid_from_event_kind(:ui_payload_access),
    do: ~s(Recurse::Action::"ReadPayload")

  def action_uid_from_event_kind(:ui_evidence_export),
    do: ~s(Recurse::Action::"ExportEvidence")

  # `:ui_retention_purge` — internal; not Cedar-gated; skip in replay.
  def action_uid_from_event_kind(:ui_retention_purge), do: nil

  # Unknown atoms — fail-safe skip rather than crash.
  def action_uid_from_event_kind(_other), do: nil

  @doc """
  Classify an `(original, proposed)` decision pair per §4 of the algorithm
  contract. Public so the property test (Surface T) and admin tooling can
  exercise the rule directly without going through the full pipeline.
  """
  @spec classify_pair(:allow | :deny, :allow | :deny) :: classification()
  def classify_pair(:deny, :deny), do: :matches_intent
  def classify_pair(:deny, :allow), do: :would_have_allowed
  def classify_pair(:allow, :deny), do: :unintended
  def classify_pair(:allow, :allow), do: :no_change

  @doc """
  Synthesize a Cedar entity store from a receipt's signed_predicate.
  Returns the entity-list shape consumed by Cedar's NIF (JSON-encoded
  inside `do_classify_one/2`).

  Public so the Surface T property test can build an oracle that uses
  the exact same entity-store as the algorithm under test.
  """
  @spec synthesize_entity_store(map()) :: [map()]
  def synthesize_entity_store(predicate) when is_map(predicate) do
    principal_json = lookup(predicate, "principal", %{})
    tenant_id = lookup(predicate, "tenant_id", "")

    principal_entity = build_principal_entity(principal_json, tenant_id)
    resource_entity = build_resource_entity(predicate)

    [principal_entity, resource_entity]
  end

  # Build the principal entity map — extracted from synthesize_entity_store/1
  # to keep the parent function below the credo complexity threshold.
  defp build_principal_entity(principal_json, tenant_id) do
    principal_kind = lookup(principal_json, "kind", "Recurse::Principal::Human")
    principal_id = derive_principal_id(principal_json)
    principal_type = principal_kind_to_type(principal_kind)

    %{
      "uid" => %{"type" => principal_type, "id" => principal_id},
      "attrs" => %{
        "subject" =>
          to_string(lookup(principal_json, "subject", principal_id)),
        "issuer" => to_string(lookup(principal_json, "issuer", "")),
        "groups" =>
          normalize_string_list(lookup(principal_json, "groups", [])),
        "recurse_role" =>
          to_string(lookup(principal_json, "recurse_role", "")),
        "tenant_id" => to_string(tenant_id)
      },
      "parents" => []
    }
  end

  defp build_resource_entity(predicate) do
    resource_kind = lookup(predicate, "resource_kind", "Recurse::Resource::ConsoleSurface")
    resource_attrs = lookup(predicate, "resource_attributes", %{})

    %{
      "uid" => %{"type" => resource_kind, "id" => derive_resource_id(resource_kind, resource_attrs)},
      "attrs" => stringify_keys(resource_attrs),
      "parents" => []
    }
  end

  defp derive_principal_id(principal_json) do
    lookup(principal_json, "subject", nil) ||
      lookup(principal_json, "account_id", nil) ||
      "unknown"
  end

  # Atom-or-string key lookup with a default. Used everywhere we receive
  # a JSONB-decoded map (string keys) OR a freshly-constructed Elixir map
  # (atom keys); the seam is uniform so callers don't have to know which.
  defp lookup(map, key, default) when is_binary(key) and is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} ->
        value

      :error ->
        atom_key = safe_atom(key)
        if atom_key, do: Map.get(map, atom_key, default), else: default
    end
  end

  defp safe_atom(key) when is_binary(key) do
    String.to_existing_atom(key)
  rescue
    ArgumentError -> nil
  end

  # ---------------------------------------------------------------------------
  # Internals
  # ---------------------------------------------------------------------------

  defp validate_cedar_source(source) do
    case Recurse.Cedar.validate_policy_syntax(source) do
      :ok -> :ok
      {:error, message} -> {:error, {:cedar_parse_error, message}}
    end
  end

  defp check_cache(%{cached_summary: summary, cached_at: cached_at} = input)
       when is_map(summary) and not is_nil(cached_at) do
    force? = Map.get(input, :force, false)

    age_hours =
      DateTime.diff(DateTime.utc_now(), cached_at, :hour)

    if not force? and age_hours < @cache_ttl_hours do
      {:cached, summary}
    else
      :cache_miss
    end
  end

  defp check_cache(_input), do: :cache_miss

  defp estimate_window_size(tenant_id, %{since: since, until: until}) do
    query =
      from(a in Attestation,
        where: a.tenant_id == ^tenant_id,
        where: a.timestamp >= ^since,
        where: a.timestamp < ^until,
        select: count(a.run_id)
      )

    case Repo.one(query) do
      nil -> 0
      n -> n
    end
  rescue
    _error -> 0
  end

  defp do_streaming_compute(%{} = input, estimated_count) do
    started_at = System.monotonic_time(:millisecond)
    cedar_source_hash = Recurse.Cedar.canonical_hash_hex(input.draft_cedar_source)

    sample_size = Map.get(input, :sample_size, 20)
    persist? = Map.get(input, :persist?, true)

    query =
      from(a in Attestation,
        where: a.tenant_id == ^input.tenant_id,
        where: a.timestamp >= ^input.window.since,
        where: a.timestamp < ^input.window.until,
        order_by: [asc: a.timestamp],
        select: %{
          run_id: a.run_id,
          event_kind: a.event_kind,
          principal: a.principal,
          policy_decision: a.policy_decision,
          tenant_id: a.tenant_id,
          timestamp: a.timestamp
        }
      )

    result =
      Repo.transaction(
        fn ->
          query
          |> Repo.stream(max_rows: @batch_size)
          |> Enum.reduce(initial_acc(), fn row, acc ->
            classify_and_accumulate(row, input.draft_cedar_source, acc)
          end)
        end,
        timeout: @stream_timeout_ms
      )

    duration_ms = System.monotonic_time(:millisecond) - started_at

    case result do
      {:ok, acc} ->
        finalize_summary(
          input,
          acc,
          cedar_source_hash,
          duration_ms,
          sample_size,
          persist?,
          estimated_count
        )

      {:error, reason} ->
        Logger.error(fn -> "blast_radius compute failed: #{inspect(reason)}" end)
        {:error, {:streaming_failed, reason}}
    end
  end

  defp initial_acc do
    %{
      total_scanned: 0,
      matches_intent: 0,
      unintended: 0,
      would_have_allowed: 0,
      no_change: 0,
      evaluation_errors: 0,
      skipped: 0,
      samples: %{
        unintended: [],
        would_have_allowed: [],
        matches_intent: []
      }
    }
  end

  defp classify_and_accumulate(row, draft_source, acc) do
    classification = do_classify_one(row, draft_source)
    acc = Map.update!(acc, :total_scanned, &(&1 + 1))

    case classification do
      :matches_intent ->
        acc
        |> Map.update!(:matches_intent, &(&1 + 1))
        |> add_sample(:matches_intent, row)

      :unintended ->
        acc
        |> Map.update!(:unintended, &(&1 + 1))
        |> add_sample(:unintended, row)

      :would_have_allowed ->
        acc
        |> Map.update!(:would_have_allowed, &(&1 + 1))
        |> add_sample(:would_have_allowed, row)

      :no_change ->
        Map.update!(acc, :no_change, &(&1 + 1))

      :evaluation_error ->
        Map.update!(acc, :evaluation_errors, &(&1 + 1))

      :skipped ->
        Map.update!(acc, :skipped, &(&1 + 1))
    end
  end

  # Cap each sample bucket at the global sample_size — final selection
  # happens at finalize/4. Keeping the bucket bounded avoids unbounded
  # growth on a 1M-receipt window where most fall into a single class.
  defp add_sample(acc, class, row) do
    bucket = acc.samples[class]
    # Reverse-order keep: most recent first via committed_at desc; the
    # query is `order_by asc` so we prepend the most recent at the head
    # naturally by accumulating in reverse, then truncate.
    new_bucket = [row | bucket] |> Enum.take(50)
    put_in(acc, [:samples, class], new_bucket)
  end

  # Single receipt → classification per §2.
  #
  # `try/rescue` per §"Failure modes": catch evaluation panics on a single
  # receipt and return :evaluation_error. The accumulator counts these and
  # the finalizer aborts if the ratio exceeds 5% of scanned.
  defp do_classify_one(row, draft_source) do
    case action_uid_from_event_kind(row.event_kind) do
      nil ->
        # Either unknown atom or :ui_retention_purge — skip per §2a.
        :skipped

      action_uid ->
        original = row.policy_decision

        case evaluate_against_draft(draft_source, row, action_uid) do
          {:ok, proposed} -> classify_pair(original, proposed)
          {:error, _} -> :evaluation_error
        end
    end
  rescue
    error ->
      Logger.warning(fn ->
        "blast_radius eval rescued exception: #{inspect(error)} run_id=#{inspect(Map.get(row, :run_id))}"
      end)

      :evaluation_error
  end

  defp evaluate_against_draft(draft_source, row, action_uid) do
    entities = synthesize_entity_store(row_to_predicate(row))
    entities_json = JSON.encode!(entities)

    [principal_entity, resource_entity | _] = entities

    request_json =
      JSON.encode!(%{
        "principal" =>
          ~s[#{principal_entity["uid"]["type"]}::"#{principal_entity["uid"]["id"]}"],
        "action" => action_uid,
        "resource" =>
          ~s[#{resource_entity["uid"]["type"]}::"#{resource_entity["uid"]["id"]}"],
        "context" => %{
          "tenant_id" => to_string(row.tenant_id || ""),
          "correlation_id" => "blast-radius",
          "timestamp" => System.system_time(:second)
        }
      })

    case Recurse.Cedar.evaluate_with_entities(draft_source, request_json, entities_json) do
      {:ok, %{decision: decision}} -> {:ok, decision}
      {:error, _} = err -> err
    end
  end

  # The receipt's `principal` is JSONB on the attestation row (already a
  # map). We hoist it into a "predicate-shaped" map so synthesize_entity_store/1
  # works against either real receipts or synthetic property-test fixtures.
  defp row_to_predicate(row) do
    %{
      "principal" => row.principal || %{},
      "tenant_id" => row.tenant_id,
      "resource_kind" => "Recurse::Resource::ConsoleSurface",
      "resource_attributes" => %{}
    }
  end

  defp finalize_summary(input, acc, cedar_source_hash, duration_ms, sample_size, persist?, _estimated) do
    error_ratio =
      if acc.total_scanned > 0,
        do: acc.evaluation_errors / acc.total_scanned,
        else: 0.0

    if error_ratio > @max_eval_error_ratio do
      {:error, :too_many_eval_errors}
    else
      build_and_persist_summary(input, acc, cedar_source_hash, duration_ms, sample_size, persist?)
    end
  end

  defp build_and_persist_summary(input, acc, cedar_source_hash, duration_ms, sample_size, persist?) do
    samples = build_samples(acc.samples, sample_size)
    total_affected = acc.matches_intent + acc.unintended

    summary = %{
      "draft_id" => input.draft_id,
      "window" => %{
        "since" => DateTime.to_iso8601(input.window.since),
        "until" => DateTime.to_iso8601(input.window.until)
      },
      "total_scanned" => acc.total_scanned,
      "total_affected" => total_affected,
      "matches_intent" => acc.matches_intent,
      "unintended" => acc.unintended,
      "would_have_allowed" => acc.would_have_allowed,
      "no_change" => acc.no_change,
      "sample_receipts" => samples,
      "computed_at" => DateTime.to_iso8601(DateTime.utc_now()),
      "cedar_source_hash" => cedar_source_hash,
      "duration_ms" => duration_ms,
      "mode" => "sync",
      "evaluation_errors" => acc.evaluation_errors
    }

    maybe_persist(input.draft_id, summary, persist?)

    {:ok, summary}
  end

  defp build_samples(buckets, sample_size) do
    # Sample preference per §5: unintended → would_have_allowed → matches_intent.
    [:unintended, :would_have_allowed, :matches_intent]
    |> Enum.flat_map(fn class ->
      buckets[class]
      |> Enum.map(fn row ->
        %{
          "run_id" => row.run_id,
          "classification" => Atom.to_string(class),
          "summary" => "event_kind=#{row.event_kind} decision=#{row.policy_decision}"
        }
      end)
    end)
    |> Enum.take(sample_size)
  end

  defp maybe_persist(_draft_id, _summary, false), do: :ok

  defp maybe_persist(draft_id, summary, true) do
    case Recurse.Gateway.Admin.PolicyDrafts.persist_blast_radius_summary(draft_id, summary) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.warning(fn ->
          "blast_radius summary persist failed: #{inspect(reason)} draft_id=#{draft_id}"
        end)

        :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Entity-store helpers
  # ---------------------------------------------------------------------------

  defp principal_kind_to_type("obo_human"), do: "Recurse::Principal::Human"
  defp principal_kind_to_type("service_account"), do: "Recurse::Principal::ServiceAccount"
  defp principal_kind_to_type("autonomous"), do: "Recurse::Principal::Autonomous"
  # Already-canonical Cedar type strings pass through.
  defp principal_kind_to_type("Recurse::Principal::" <> _ = t), do: t
  defp principal_kind_to_type(_), do: "Recurse::Principal::Human"

  defp normalize_string_list(list) when is_list(list), do: Enum.map(list, &to_string/1)
  defp normalize_string_list(_), do: []

  defp derive_resource_id(_kind, %{"id" => id}) when is_binary(id), do: id
  defp derive_resource_id(_kind, %{id: id}) when is_binary(id), do: id
  defp derive_resource_id(_kind, _attrs), do: "default"

  defp stringify_keys(map) when is_map(map) do
    Map.new(map, fn
      {k, v} when is_atom(k) -> {Atom.to_string(k), stringify_value(v)}
      {k, v} -> {k, stringify_value(v)}
    end)
  end

  defp stringify_keys(_), do: %{}

  defp stringify_value(v) when is_map(v) and not is_struct(v), do: stringify_keys(v)
  defp stringify_value(v) when is_list(v), do: Enum.map(v, &stringify_value/1)
  defp stringify_value(v) when is_atom(v) and not is_boolean(v) and not is_nil(v),
    do: Atom.to_string(v)

  defp stringify_value(v), do: v
end
