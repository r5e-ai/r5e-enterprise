# Contract: Blast Radius Algorithm

**Feature**: F004 | **Spec**: FR-026, FR-027, SC-008 | **Research**: D5 | **Glossary**: Blast Radius, Discovery-to-Policy

This contract defines the streaming algorithm that computes the **Blast Radius** of a draft Cedar policy: how many historical receipts the proposed rule would have affected, classified as "matches intent" or "unintended (would block legitimate work)." The algorithm is the core differentiator of the F004 policy authoring surface — without it, an operator authoring a rule has no defense against silently breaking historical workflows.

---

## Inputs

```elixir
@type input :: %{
  draft_id: Ecto.UUID.t(),
  draft_cedar_source: binary(),    # the Cedar source text
  tenant_id: binary(),
  window: %{since: DateTime.t(), until: DateTime.t()},  # default trailing 30 days
  sample_size: pos_integer()        # default 20
}
```

The window MUST be tenant-scoped. Cross-tenant leakage is prevented by the `WHERE tenant_id = $1` clause on every receipt-streaming query.

## Outputs

```elixir
@type summary :: %{
  draft_id: Ecto.UUID.t(),
  window: %{since: DateTime.t(), until: DateTime.t()},
  total_scanned: non_neg_integer(),
  total_affected: non_neg_integer(),     # matches_intent + unintended
  matches_intent: non_neg_integer(),
  unintended: non_neg_integer(),
  no_change: non_neg_integer(),          # surfaced for completeness; not displayed
  would_have_allowed: non_neg_integer(), # subset of "no_change" where original=deny, proposed=allow
  sample_receipts: [%{run_id: Ecto.UUID.t(), classification: atom(), summary: binary()}],
  computed_at: DateTime.t(),
  cedar_source_hash: binary(),
  duration_ms: non_neg_integer()
}
```

---

## Algorithm

### 1. Streaming receipt scan (batch size 1,000)

Pseudocode (Elixir-flavored):

```elixir
def compute_blast_radius(input) do
  query =
    from(a in Attestation,
      where: a.tenant_id == ^input.tenant_id,
      where: a.committed_at >= ^input.window.since,
      where: a.committed_at < ^input.window.until,
      order_by: [asc: a.committed_at],
      select: %{
        run_id: a.run_id,
        signed_predicate: a.signed_predicate,
        original_decision: a.policy_decision,
        committed_at: a.committed_at
      }
    )

  Repo.transaction(fn ->
    Repo.stream(query, max_rows: 1_000)
    |> Stream.map(&classify_one(&1, input.draft_cedar_source))
    |> Enum.reduce(%Acc{}, &accumulate/2)
  end, timeout: 60_000)
end
```

Batch size 1,000 keeps the connection-pool slot held briefly per batch; total scan time for a 10K-receipt window is ~1.5 seconds on F002 reference infrastructure.

### 2. Per-receipt classification (`classify_one/2`)

For each receipt:

```elixir
defp classify_one(%{signed_predicate: pred, original_decision: original} = r, draft_source) do
  entity_store = synthesize_entity_store(pred)

  principal_uid = principal_uid_from(pred.principal)
  action_uid = action_uid_from_event_kind(pred.event_kind)   # canonical-matrix lookup; see §2a
  resource_uid = resource_uid_from(pred.resource_kind, pred.resource_attributes)
  context = pred.context

  proposed =
    Recurse.Cedar.evaluate_with_entities(
      draft_source,
      principal_uid,
      action_uid,
      resource_uid,
      entity_store,
      context
    )

  classification = classify_pair(original, proposed)

  Map.put(r, :classification, classification)
end
```

### 2a. Cedar-action derivation from `event_kind` (canonical-matrix mapping)

**Critical**: F002's signed predicate (`Recurse.Shared.Attestation.SignedPredicate` in
`apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex`) does NOT carry
the original Cedar action UID as a first-class field. It carries `event_kind` (one of
`:llm_call | :tool_call | :egress_denied | :policy_denied | :session_abort` for F002, plus
the `:ui_*` family widened in F004) and `policy_canonical_hash`, but the Cedar action that
was actually evaluated is **implicit** from the request route.

Replay therefore reconstructs the Cedar action via a **deterministic mapping** from
`pred.event_kind` to a Cedar action UID. The mapping is **the canonical event_kind ↔
Cedar action matrix in `data-model.md` §0** — that table is the authoritative source; this
function is its inverse:

```elixir
# action_uid_from_event_kind/1 — sourced from data-model.md §0 (canonical matrix)
defp action_uid_from_event_kind(:llm_call),                    do: ~s(Recurse::Action::"ChatCompletion")
defp action_uid_from_event_kind(:tool_call),                   do: ~s(Recurse::Action::"ToolCall")
defp action_uid_from_event_kind(:egress_denied),               do: ~s(Recurse::Action::"ChatCompletion")  # gated at egress
defp action_uid_from_event_kind(:policy_denied),               do: ~s(Recurse::Action::"ChatCompletion")  # gated upstream of any UI action; F002-vintage
defp action_uid_from_event_kind(:session_abort),               do: ~s(Recurse::Action::"ChatCompletion")
# F004 UI actions — 1:1 mapping; the matrix is the authority.
defp action_uid_from_event_kind(:ui_login),                    do: ~s(Recurse::Action::"LoginSession")
defp action_uid_from_event_kind(:ui_session),                  do: ~s(Recurse::Action::"LoginSession")
defp action_uid_from_event_kind(:ui_query),                    do: ~s(Recurse::Action::"DashboardQuery")
defp action_uid_from_event_kind(:ui_policy_simulate),          do: ~s(Recurse::Action::"PolicySimulate")
defp action_uid_from_event_kind(:ui_policy_replay),            do: ~s(Recurse::Action::"PolicyReplay")
defp action_uid_from_event_kind(:ui_policy_draft_created),     do: ~s(Recurse::Action::"PolicyDraftCreate")
defp action_uid_from_event_kind(:ui_policy_draft_edited),      do: ~s(Recurse::Action::"PolicyDraftEdit")
defp action_uid_from_event_kind(:ui_policy_draft_archived),    do: ~s(Recurse::Action::"PolicyDraftArchive")
defp action_uid_from_event_kind(:ui_policy_draft_dry_run),     do: ~s(Recurse::Action::"PolicyDraftDryRun")
defp action_uid_from_event_kind(:ui_policy_suggestion_generated), do: ~s(Recurse::Action::"PolicySuggestionGenerate")
defp action_uid_from_event_kind(:ui_policy_suggestion_viewed),    do: ~s(Recurse::Action::"PolicySuggestionView")
defp action_uid_from_event_kind(:ui_policy_suggestion_adopted),   do: ~s(Recurse::Action::"PolicySuggestionAdopt")
defp action_uid_from_event_kind(:ui_policy_suggestion_dismissed), do: ~s(Recurse::Action::"PolicySuggestionDismiss")
defp action_uid_from_event_kind(:ui_policy_suggestion_refresh_requested),
                                                               do: ~s(Recurse::Action::"PolicySuggestionRefresh")
defp action_uid_from_event_kind(:ui_chat),                     do: ~s(Recurse::Action::"ChatDrawerQuery")
defp action_uid_from_event_kind(:ui_chat_skill_invoked_query_receipts),
                                                               do: ~s(Recurse::Action::"AuditAgentToolQueryReceipts")
defp action_uid_from_event_kind(:ui_chat_skill_invoked_fetch_receipt_detail),
                                                               do: ~s(Recurse::Action::"AuditAgentToolFetchReceiptDetail")
defp action_uid_from_event_kind(:ui_chat_skill_invoked_explain_denial),
                                                               do: ~s(Recurse::Action::"AuditAgentToolExplainDenial")
defp action_uid_from_event_kind(:ui_chat_skill_invoked_find_similar_receipts),
                                                               do: ~s(Recurse::Action::"AuditAgentToolFindSimilarReceipts")
defp action_uid_from_event_kind(:ui_chat_skill_invoked_simulate_policy_dryrun),
                                                               do: ~s(Recurse::Action::"AuditAgentToolSimulatePolicyDryrun")
defp action_uid_from_event_kind(:ui_chat_skill_invoked_suggest_policy_pattern),
                                                               do: ~s(Recurse::Action::"AuditAgentToolSuggestPolicyPattern")
defp action_uid_from_event_kind(:ui_payload_access),           do: ~s(Recurse::Action::"ReadPayload")
defp action_uid_from_event_kind(:ui_evidence_export),          do: ~s(Recurse::Action::"ExportEvidence")
defp action_uid_from_event_kind(:ui_retention_purge),          do: nil   # internal; not Cedar-gated; skip in replay
```

This dispatch is enforced as a single-source-of-truth: the Surface T property test
(see `property_test_surface_catalog_f004.md`) asserts that for every event_kind enumerated
in `data-model.md` §0, `action_uid_from_event_kind/1` returns the matrix's Cedar action
verbatim. Drift fails CI.

### 2b. Receipt-shape compatibility

The mapping above is unambiguous for every Day-1 F004 event_kind because the canonical
matrix is 1:1 from `event_kind` to Cedar action. F002-vintage receipts (those committed
before the F004 widening migration ran) carry only the F002 event_kinds (`:llm_call`,
`:tool_call`, `:egress_denied`, `:policy_denied`, `:session_abort`); their Cedar action is
implicit because F002 has effectively one user-Cedar-gated action per request route
(`ChatCompletion` for the Data Plane). The mapping for these is correct so long as
customer policies do not partition the F002 event-kind classes by additional Cedar actions
not present at receipt-emit time.

| Receipt vintage | event_kinds present | Cedar-action mapping correctness |
|---|---|---|
| F001 / F002 (pre-F004 migration) | `:llm_call`, `:tool_call`, `:egress_denied`, `:policy_denied`, `:session_abort` | Unambiguous — F002 has a single Cedar action per user route. Replay is faithful. |
| F004 (post-widening) | the 22 `:ui_*` atoms above | Unambiguous — canonical matrix is 1:1. Replay is faithful. |
| Future (Day-2+) | new `:ui_*` or Data-Plane atoms | MUST be added to the canonical matrix in `data-model.md` §0 before they can be emitted; the SHA-pinned matrix prevents silent drift. |

**Known limitation**: if a future customer policy gates *multiple* Cedar actions on a
single `event_kind` (e.g., `:llm_call` evaluated with `ChatCompletion` AND a derived
`PostInferenceCheck` action), the matrix would no longer be 1:1 and the signed predicate
would need to carry the explicit Cedar action UID. F002's `SignedPredicate` would then
require an `envelope_version` bump (currently `"1.0"`). This is **deferred Day-2+**;
no F004-scope customer policy needs the extension.

### 2c. Cross-references

- Canonical event_kind ↔ Cedar action mapping: `data-model.md` §0 (the matrix is the
  authority; this contract's lookup table mirrors it).
- F002 SignedPredicate definition: `apps/recurse_shared/lib/recurse_shared/attestation/signed_predicate.ex`
  (confirms `event_kind` and `policy_canonical_hash` are present; explicit Cedar action
  UID is NOT).
- Replay receipt emission (the `:ui_policy_draft_dry_run` event_kind this algorithm
  itself emits): see §"Observability" below.

### 3. Entity-store synthesis (`synthesize_entity_store/1`)

The Cedar entity store is built **entirely from the receipt's `signed_predicate.principal` JSON** — no external lookups, no cross-receipt joins. The principal entity is part of the receipt's signed predicate, so the synthesis is exact.

```elixir
defp synthesize_entity_store(%{principal: principal_json, resource_kind: r_kind, resource_attributes: r_attrs}) do
  principal_entity = %{
    "uid" => %{"type" => principal_json["kind"], "id" => principal_json["subject"]},
    "attrs" => %{
      "subject" => principal_json["subject"],
      "issuer" => principal_json["issuer"],
      "groups" => principal_json["groups"] || [],
      "recurse_role" => principal_json["recurse_role"]
      # display_name, account_id, etc., conditional on principal_json["kind"]
    },
    "parents" => []
  }

  resource_entity = %{
    "uid" => %{"type" => r_kind, "id" => derive_resource_id(r_kind, r_attrs)},
    "attrs" => r_attrs,
    "parents" => []
  }

  [principal_entity, resource_entity]
end
```

The **principal entity reflects the principal as it was at receipt-emit time**, not as it is now. This is the correct semantic for "would this proposed rule have affected this past activity?" — answering against current group membership would conflate a past event with present reality.

### 4. Classification rule (`classify_pair/2`)

```elixir
defp classify_pair(:deny, :deny), do: :matches_intent
defp classify_pair(:deny, :allow), do: :would_have_allowed   # not surfaced as "unintended"; folded into no_change
defp classify_pair(:allow, :deny), do: :unintended           # legitimate-then-blocked — the danger case
defp classify_pair(:allow, :allow), do: :no_change
```

**Rationale for the table**:

| Original | Proposed | Classification | UX surface |
|---|---|---|---|
| deny | deny | `matches_intent` | Highlighted ("rule correctly fires"). |
| deny | allow | `would_have_allowed` | Surfaced as a SEPARATE count for the operator to consider, rolled into `no_change` for the topline "affected receipts" total. UI separately shows "N denies would now be allowed — review". |
| allow | deny | `unintended` | Critical — surfaces the "would have blocked legitimate work" case. Triggers FR-027 advisory. |
| allow | allow | `no_change` | Hidden from the topline panel; counted only for sample-size context. |

**Note**: the spec phrasing in FR-026 lists "matches intent" and "unintended" as the two surfaced classes. The algorithm tracks `would_have_allowed` as a separate count (per D5) because it's actionable for the operator (potentially loosening the policy) but is NOT a "blast" event. The UI exposes it as a secondary advisory.

### 5. Sampling

Sample up to `sample_size` (default 20) receipts for UI display. Sampling preference:

1. First, all `unintended` receipts up to `min(sample_size, count)` — operator-actionable.
2. Then, fill remaining slots with `would_have_allowed` receipts (the "loosening" case is also operator-actionable).
3. Finally, fill any remaining slots with `matches_intent` receipts (illustrative).

Selection within each class is by `committed_at` descending (most recent first) to keep the sample fresh.

### 5a. API response surface (cross-reference)

The four-cell classification model is load-bearing: the UI must surface all four counts —
`matches_intent`, `unintended`, `would_have_allowed`, and (implicitly) `no_change` =
`total_scanned − total_affected − would_have_allowed` — so the operator can act on each
class. The sync API response shape lives in `audit_api_extensions.md` (the `POST
/v1/policy/drafts/{id}/dry-run` synchronous response and the cached
`policy_drafts.last_blast_radius_summary` shape). That contract MUST surface
`would_have_allowed` as a top-level integer count in lockstep with this algorithm's
`Outputs` definition above. The post-design Constitution recheck explicitly adopted the
4-cell model (per `plan.md` reconciliation #1); any UI-visible response that omits
`would_have_allowed` would silently revert to the 2-cell model and break FR-027.

### 6. Async escalation (per D5 + FR-026)

If `total_scanned > 10_000`, the synchronous response timeout would risk exceeding the SC-008-adjacent 2-second budget. The algorithm switches to async:

- Sync API endpoint `POST /v1/policy/drafts/{id}/dry-run` — if estimated window size ≤ 10K (estimated via a `count(*)` query before streaming), runs synchronously and returns the summary in the response.
- If estimated > 10K, the endpoint enqueues an Oban job (`Recurse.Gateway.SuggestionEngine.BlastRadiusJob`) and returns `202 Accepted` with `job_id` + `poll_url`. The job runs the streaming algorithm with `timeout: 600_000` (10 min hard cap) and writes the result to `policy_drafts.last_blast_radius_summary` upon completion. The SPA polls the poll URL or subscribes to a Phoenix.PubSub topic (`recurse:blast_radius_jobs`) for completion.

### 7. Cache invalidation

The result is cached on the draft row at `policy_drafts.last_blast_radius_summary` keyed by `(draft_id, draft_cedar_source_hash, window)`. The cache is invalidated when:

- Draft Cedar source is edited (`PATCH /v1/policy/drafts/{id}` clears `last_blast_radius_summary`).
- `window` changes (different `since`/`until`).
- 24 hours have passed (force re-compute to capture freshly-committed receipts).

---

## Performance budget (SC-008-adjacent)

| Window size | Mode | Target wall-clock |
|---|---|---|
| ≤ 1K receipts | Sync | ≤ 200 ms |
| ≤ 10K receipts | Sync | ≤ 2 s |
| ≤ 100K receipts | Async (Oban) | ≤ 30 s |
| ≤ 1M receipts | Async | ≤ 5 min |

Cedar evaluation per receipt is ~1ms native; the dominant cost is Postgres I/O for streaming. Connection-pool size in tier-config (`gateway.repo.pool_size`, default 20) is sized assuming up to 5 concurrent Blast Radius computations.

---

## Property-test surface T (see `property_test_surface_catalog_f004.md`)

**Invariant**: `classify_pair/2` correctness against an operator-labeled benchmark set is ≥95% precision (matches SC-008).

**Generator**:
- Bind over: random Cedar source (within a constrained grammar of permit/forbid + when clauses), random receipt-window fixtures (StreamData-generated synthetic receipts whose `signed_predicate` mirrors real attestations).
- For each `(cedar_source, fixture_window)` tuple, the generator includes a **rule-based oracle** that computes the expected classification for every fixture receipt by directly inspecting `(original_decision, proposed_decision)` without going through the algorithm under test.
- Property: for every generated tuple, `compute_blast_radius/1` produces classifications that match the oracle on ≥95% of receipts. Deviations are recorded for human review.

**Iterations**: 100 (windowed; each iteration is heavier than a typical property test).

**Operator-labeled benchmark**: a hand-curated fixture set lives at `apps/recurse_gateway/test/fixtures/blast_radius_benchmark.json` containing ~200 receipt-and-rule pairs labeled by the F004 design team. The Surface T test additionally runs against this benchmark and asserts ≥95% precision; the benchmark is updated when ambiguous cases are resolved.

---

## Failure modes

| Failure | Behavior |
|---|---|
| Cedar parse error in `draft_cedar_source` | Fail fast with `{:error, {:cedar_parse_error, line, col, message}}` before any DB query. |
| Cedar evaluation panic on a single receipt | Catch via `try/rescue`, log + emit a per-receipt `classification: :evaluation_error`, increment a counter. Continue streaming. If `:evaluation_error` count > 5% of scanned, abort with `{:error, :too_many_eval_errors}`. |
| Postgres connection pool exhaustion | The streaming transaction holds one connection; concurrent computations beyond `pool_size / 2` are queued. Returns `{:error, :pool_exhausted}` after a 5-second wait. |
| Oban job timeout (>10 min) | Job marked failed; draft's `last_blast_radius_summary` is set to `{error: "timeout"}` so the UI can display "Blast radius computation timed out — try a smaller window." |

---

## Observability

Every blast-radius computation emits an attested `:ui_policy_draft_dry_run` receipt with `signed_predicate` carrying:
- `draft_id`
- `cedar_source_hash`
- `window_since`, `window_until`
- `total_scanned`, `total_affected`, `matches_intent`, `unintended`
- `mode: "sync"|"async"`
- `duration_ms`

The receipt is the audit-trail of "operator X computed a blast radius against window Y." Auditors can replay the computation by re-running the algorithm against the same `(draft_cedar_source, window)`; with `would_have_allowed` results stable across runs, the audit trail is reproducible.

---

## Out of scope (Day-2+)

- Sampling-based blast radius for windows >1M receipts. Day-2+ when receipt volume justifies.
- Cross-tenant blast radius (auditing a rule's effect across multiple tenants). Single-tenant only in F004.
- Time-windowed re-classification (e.g., "show me only receipts from working hours"). Window is currently a contiguous date range only.
- Probabilistic classification for ambiguous cases. The current rule is deterministic; future ML-based classification deferred.
