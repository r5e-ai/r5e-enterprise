// PolicySimulator — Cedar policy authoring surface (T093 — Phase 5 US3).
//
// Per `design/r5e-enterprise-audit-ui.pen` Policy Simulator screen + spec
// FR-022 / FR-023 / FR-024 / FR-025 / FR-026 / FR-027:
//   - Four modes (URL-param `?mode=`):
//       * simulate     — run a Cedar source against a synthetic input
//       * replay       — replay a past receipt against a draft
//       * draft        — Draft from Receipt; ?run_id= seeds the editor from
//                        the source receipt's predicate (FR-023). The source
//                        receipt is cited in a banner at the top of the page.
//       * suggestions  — link out to /admin/policy-simulator/suggestions
//                        (the dedicated suggestions page owns the surface;
//                        the tab here is a routing affordance).
//   - Monaco editor is lazy-loaded — `React.lazy()` keeps the ~2MB bundle off
//     the main chunk (research D1).
//   - Scope picker (FR-024) + condition builder (FR-025) live in the right
//     rail; their state composes with the editor source via `scope_metadata`
//     and `condition_metadata` on the draft envelope.
//   - The Blast Radius panel sits below the editor; it consumes
//     `useBlastRadius(draftId)` and surfaces the 4-cell classification (FR-026)
//     plus the FR-027 unintended-block advisory.
//
// Out of scope for THIS file (handled elsewhere):
//   - The Suggestions surface (own page: PolicySimulatorSuggestions.tsx).
//   - Adopting a draft (deferred to F005+ per audit_api_extensions.md
//     "Out of scope").

import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, Outlet, useOutlet, useSearchParams } from "react-router-dom";

import { BlastRadiusPanel } from "~/components/policy/BlastRadiusPanel";
import { ConditionBuilder } from "~/components/policy/ConditionBuilder";
import { DecisionToggle, type PolicyDecisionVerdict } from "~/components/policy/DecisionToggle";
import { DraftFromReceiptBanner } from "~/components/policy/DraftFromReceiptBanner";
import { ScopePicker, type ActionScopeKind } from "~/components/policy/ScopePicker";
import { ErrorState as SharedErrorState } from "~/components/shared/states";
import { TopBar } from "~/components/shared/TopBar";
import { useBlastRadius } from "~/hooks/useBlastRadius";
import {
  useCreatePolicyDraft,
  useDraftFromReceipt,
  usePolicyDraft,
  useUpdatePolicyDraft,
  type PolicyDraftConditionMetadata,
  type PolicyDraftScopeMetadata,
} from "~/hooks/usePolicyDrafts";
import { usePolicySuggestion } from "~/hooks/usePolicySuggestions";
import { useReceiptDetail, type ReceiptDetail } from "~/hooks/useReceiptDetail";
import { api, ApiError } from "~/lib/api";
import { apiPaths } from "~/lib/apiPaths";
import { spliceConditionsIntoCedar } from "~/lib/cedarSourceSplice";
import { displayPrincipal } from "~/lib/principal";
import { routes, stripBasename } from "~/lib/routes";

// Lazy-load Monaco — keeps the ~2MB editor chunk out of the main bundle
// per research D1. Anything inside <Suspense> below will only download once
// the user lands on this route.
const CedarEditor = lazy(() => import("~/components/policy/CedarEditor"));
// Diff editor for the Replay-mode "Compare with deployed" toggle. Lazy in its
// OWN chunk so opening the Simulate tab doesn't pay for the diff bundle until
// the user flips the toggle (research D1).
const CedarDiffEditor = lazy(() => import("~/components/policy/CedarDiffEditor"));
// Defense-in-depth fallback for issue #61 — if Monaco fails to initialize
// (CSP regression, missing static asset, network blip), surface a textarea
// fallback instead of an infinite "Loading..." state.
import CedarEditorBoundary from "~/components/policy/CedarEditorBoundary";

type Mode = "simulate" | "replay" | "draft" | "suggestions";

const MODES: ReadonlyArray<{ key: Mode; label: string; hint: string }> = [
  {
    key: "simulate",
    label: "Simulate",
    hint: "Test a Cedar source against a synthetic principal/action/resource.",
  },
  {
    key: "replay",
    label: "Replay",
    hint: "Replay a historical receipt against this draft policy.",
  },
  {
    key: "draft",
    label: "Draft from Receipt",
    hint: "Generate a skeleton from a source receipt and refine it.",
  },
  {
    key: "suggestions",
    label: "Suggestions",
    hint: "Open the Suggestions queue.",
  },
];

const DEFAULT_TEMPLATE = `// Draft Cedar policy. Edit, adjust scope on the right, then run a dry-run.
permit(
  principal,
  action,
  resource
);
`;

export default function PolicySimulator(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();

  // -------------------------------------------------------------------------
  // URL-param state
  // -------------------------------------------------------------------------
  const mode: Mode = useMemo(() => {
    const m = searchParams.get("mode");
    if (m === "simulate" || m === "replay" || m === "draft" || m === "suggestions") {
      return m;
    }
    return "simulate";
  }, [searchParams]);

  const sourceRunId = searchParams.get("run_id") ?? null;

  // Suggestions handoff (brief 05) — when the operator clicks ADOPT or
  // SIMULATE FIRST on a suggestion card, the suggestions page navigates
  // here with `?mode=draft&suggestion=<id>&draft_id=<id>` (adopt path) or
  // `?mode=draft&suggestion=<id>&sandbox=1` (simulate-first / no saved
  // draft). We use `suggestionId` only for the attribution banner; the
  // `draft_id` URL param does the actual seeding via `usePolicyDraft`.
  const suggestionId = searchParams.get("suggestion");
  const incomingDraftId = searchParams.get("draft_id");
  const sandbox = searchParams.get("sandbox") === "1";

  function selectMode(next: Mode): void {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        if (next === "simulate") {
          params.delete("mode");
        } else {
          params.set("mode", next);
        }
        return params;
      },
      { replace: true },
    );
  }

  // -------------------------------------------------------------------------
  // Editor / draft state — purely local until the user explicitly saves.
  // -------------------------------------------------------------------------
  const [cedarSource, setCedarSource] = useState<string>(DEFAULT_TEMPLATE);
  const [scope, setScope] = useState<PolicyDraftScopeMetadata | null>(null);
  const [conditions, setConditions] = useState<PolicyDraftConditionMetadata[]>([]);
  const [draftId, setDraftId] = useState<string | null>(null);
  // UI-only state for the canonical's WHAT and DECISION sections.
  // The draft envelope doesn't carry these yet; once the backend
  // schema extends to include them, hoist these into the existing
  // `usePolicyDraft`/`useCreatePolicyDraft` cycle.
  const [actionScope, setActionScope] = useState<ActionScopeKind>("exact");
  const [decisionVerdict, setDecisionVerdict] = useState<PolicyDecisionVerdict>(
    () => (cedarSourceVerb(DEFAULT_TEMPLATE) === "forbid" ? "deny" : "allow"),
  );

  // -------------------------------------------------------------------------
  // Live two-way binding from condition rows back into the Cedar source's
  // `when {…}` block (per F4 brief — "When a condition is added, the Cedar
  // editor's `when {…}` block updates accordingly (live two-way binding)").
  //
  // We splice the rendered clauses into the editor source on every
  // condition change. The splice is best-effort: if the source has no
  // recognizable rule structure (the user wrote raw text we can't parse),
  // the source is left intact. Once the operator authors a `permit(...)`
  // / `forbid(...)` head we resume splicing.
  // -------------------------------------------------------------------------
  const handleConditionsChange = useCallback(
    (next: PolicyDraftConditionMetadata[]): void => {
      setConditions(next);
      setCedarSource((current) => spliceConditionsIntoCedar(current, next));
    },
    [],
  );

  // -------------------------------------------------------------------------
  // Mutations
  // -------------------------------------------------------------------------
  const createDraft = useCreatePolicyDraft();
  const fromReceipt = useDraftFromReceipt();
  const updateDraft = useUpdatePolicyDraft(draftId ?? undefined);

  // -------------------------------------------------------------------------
  // Draft-from-Receipt mode: when ?mode=draft&run_id=xxx is in the URL, kick
  // off the skeleton generation once and seed the editor with the result.
  // -------------------------------------------------------------------------
  const sourceReceipt = useReceiptDetail(
    mode === "draft" && sourceRunId ? sourceRunId : undefined,
  );

  useEffect(() => {
    if (mode !== "draft" || !sourceRunId) return;
    if (draftId) return; // Already created.
    if (fromReceipt.isPending || fromReceipt.isError) return;
    fromReceipt.mutate(
      { source_receipt_run_id: sourceRunId },
      {
        onSuccess: (draft) => {
          setDraftId(draft.id);
          // Seed source first so the splice below has a target. If the
          // skeleton already contains a `when {…}` block we splice the
          // (possibly empty) condition list in to canonicalize whitespace;
          // if it doesn't, the splice is a no-op.
          const seededSource = draft.cedar_source ?? "";
          const seededConditions = draft.condition_metadata ?? [];
          if (seededSource.length > 0) {
            setCedarSource(spliceConditionsIntoCedar(seededSource, seededConditions));
          }
          if (draft.scope_metadata) setScope(draft.scope_metadata);
          setConditions(seededConditions);
        },
      },
    );
  }, [mode, sourceRunId, draftId, fromReceipt]);

  // -------------------------------------------------------------------------
  // Suggestions-prefill mode (brief 05): two paths share this surface.
  //
  //   * ADOPT path:       `?suggestion=<id>&draft_id=<id>` — fetch the saved
  //                       draft and seed the editor with its source / scope /
  //                       conditions. `usePolicyDraft(incomingDraftId)`.
  //   * SIMULATE FIRST:   `?suggestion=<id>&sandbox=1` (no `&draft_id`) —
  //                       fetch the SUGGESTION (not a draft) and seed
  //                       `cedarSource` from `suggestion.proposed_cedar`.
  //                       No saved draft is created; any dry-run will fall
  //                       through `ensureDraftThen` and create a transient
  //                       one on demand.
  //
  // The two paths are mutually exclusive (sandbox => no draft_id), so we
  // drive them with two separate `enabled`-gated queries. Either effect is
  // a no-op once the editor has been seeded the first time (`seeded` flag).
  const prefillDraft = usePolicyDraft(
    !draftId && incomingDraftId ? incomingDraftId : undefined,
  );
  const prefillSuggestion = usePolicySuggestion(
    sandbox && suggestionId && !incomingDraftId ? suggestionId : undefined,
  );

  // Single-shot guard: only seed the editor once per mount so an operator
  // edit doesn't get clobbered when react-query refetches.
  const [seededFromSuggestion, setSeededFromSuggestion] = useState(false);

  useEffect(() => {
    if (draftId) return;
    if (!incomingDraftId) return;
    if (!prefillDraft.data) return;
    const draft = prefillDraft.data;
    setDraftId(draft.id);
    if (draft.cedar_source) setCedarSource(draft.cedar_source);
    if (draft.scope_metadata) setScope(draft.scope_metadata);
    if (draft.condition_metadata) setConditions(draft.condition_metadata);
  }, [draftId, incomingDraftId, prefillDraft.data]);

  // F001 (fix-pass-2) — sandbox path now actually seeds the Cedar editor.
  // Pre-fix the SIMULATE FIRST CTA navigated here with `?sandbox=1` and the
  // simulator silently kept the DEFAULT_TEMPLATE because the seeding effect
  // above short-circuits on `!incomingDraftId`. Operators saw the
  // attribution banner but a stock `permit(principal, action, resource)`
  // editor — defeating the CTA's stated purpose. We fetch the suggestion
  // via `usePolicySuggestion` and seed `cedarSource` from
  // `suggestion.proposed_cedar`. We don't create a saved draft (that's the
  // ADOPT path's job); `ensureDraftThen` will mint a transient draft on
  // first dry-run if the operator runs one.
  useEffect(() => {
    if (seededFromSuggestion) return;
    if (!sandbox || !suggestionId || incomingDraftId) return;
    const suggestion = prefillSuggestion.data;
    if (!suggestion) return;
    if (suggestion.proposed_cedar) {
      setCedarSource(suggestion.proposed_cedar);
    }
    setSeededFromSuggestion(true);
  }, [
    seededFromSuggestion,
    sandbox,
    suggestionId,
    incomingDraftId,
    prefillSuggestion.data,
  ]);

  // -------------------------------------------------------------------------
  // Blast Radius state — only after a draft id exists.
  // -------------------------------------------------------------------------
  const blast = useBlastRadius(draftId ?? undefined);

  // Per F002 — `ensureDraftThen` hands the resolved draft id straight to the
  // continuation. On first use, `createDraft.onSuccess` is called BEFORE the
  // re-render that re-binds `useBlastRadius(draftId)`, so a closure-captured
  // `blast.run()` would see `draftId === undefined` and no-op. Plumbing the
  // id through explicitly avoids that race. The save-failure path no longer
  // falls through to `action()` either — running blast-radius on the
  // previously-saved draft state while the editor shows newer source is a
  // silent-divergence bug; surface the error instead.
  function ensureDraftThen(action: (resolvedDraftId: string) => void): void {
    if (draftId) {
      // Push current edits before kicking off — the dry-run reads the saved source.
      updateDraft.mutate(
        { cedar_source: cedarSource, scope_metadata: scope ?? undefined, condition_metadata: conditions },
        {
          onSuccess: () => action(draftId),
          // No onError → the SaveStatus banner surfaces `updateDraft.error`;
          // we don't kick off blast-radius against stale saved state.
        },
      );
      return;
    }
    createDraft.mutate(
      {
        cedar_source: cedarSource,
        scope_metadata: scope ?? undefined,
        condition_metadata: conditions,
        source_receipt_run_id: sourceRunId,
      },
      {
        onSuccess: (draft) => {
          setDraftId(draft.id);
          action(draft.id);
        },
      },
    );
  }

  function handleRunDryRun(): void {
    // Pass the resolved id explicitly so the very first dry-run after
    // creating a draft fires against the right id (closure on `blast` was
    // captured before `setDraftId(...)` flushed).
    ensureDraftThen((id) => blast.run({ draftId: id }));
  }

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  const activeMode = MODES.find((m) => m.key === mode) ?? MODES[0]!;

  // Receipt-drawer overlay outlet — mirrors Dashboard's nested-route shape
  // (App.tsx mounts a `receipts/:run_id` child route under the simulator
  // path). When the auditor clicks `view full receipt →` from a Blast
  // Radius sample row or the DraftFromReceiptBanner, the drawer overlays
  // the simulator INSTEAD OF navigating away — preserves Cedar source,
  // condition rows, and Blast Radius output across the visit. Per F4 brief
  // §"Sample receipts list" + GAN F005.
  const drawerOutlet = useOutlet();

  return (
    <div
      className="flex min-h-0 flex-1 flex-col bg-r5e-bg font-sans text-r5e-text"
      data-testid="policy-simulator"
    >
      <TopBar
        pageContent={
          <h1 className="text-sm font-semibold text-r5e-text">
            Policy simulator
          </h1>
        }
        actions={
          <div className="flex items-center gap-3">
            <Link
              to={stripBasename(routes.policySimulatorSuggestions)}
              className="rounded-r5e-md border border-r5e-border-subtle px-2.5 py-1 text-[11px] text-r5e-accent-purple hover:border-r5e-accent-purple hover:underline"
            >
              Suggestions →
            </Link>
            <button
              type="button"
              data-testid="policy-simulator-save"
              onClick={handleRunDryRun}
              className="rounded-r5e-lg border border-r5e-border-strong px-4 py-1.5 font-mono text-[11px] uppercase text-r5e-foreground-secondary hover:text-r5e-foreground-primary"
            >
              Save Simulation
            </button>
            <button
              type="button"
              data-testid="policy-simulator-simulate"
              onClick={handleRunDryRun}
              className="rounded-r5e-lg bg-gradient-to-b from-r5e-accent-purple to-r5e-accent-pink px-4 py-1.5 font-mono text-[11px] font-semibold uppercase text-white shadow-[0_0_16px_-4px_#A855F761] hover:opacity-90"
            >
              Simulate
            </button>
          </div>
        }
      />

      <ModeTabs mode={mode} onSelect={selectMode} />
      <p className="px-6 pt-2 text-[11px] text-r5e-muted">{activeMode.hint}</p>

      {mode === "draft" && sourceRunId && (
        <DraftFromReceiptBanner
          runId={sourceRunId}
          loading={sourceReceipt.isLoading || fromReceipt.isPending}
          error={sourceReceipt.error}
          summary={sourceReceipt.data?.signed_predicate.event_kind ?? null}
        />
      )}

      {mode === "draft" && suggestionId && (
        <SuggestionAttributionBanner
          suggestionId={suggestionId}
          sandbox={sandbox}
          loading={
            sandbox && !incomingDraftId
              ? prefillSuggestion.isLoading
              : prefillDraft.isLoading
          }
          error={
            sandbox && !incomingDraftId
              ? prefillSuggestion.error
              : prefillDraft.error
          }
        />
      )}

      {/* Body + receipt drawer overlay. Same layout shape as Dashboard's
          drawer slot — host content takes the flex-1 column, the drawer
          is a 720px right-side aside that mounts only when a nested
          `receipts/:run_id` route is active. */}
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <div className="flex min-w-0 flex-1 flex-col overflow-hidden">

      {mode === "suggestions" && <SuggestionsRedirect />}

      {mode === "replay" && <ReplayMode />}

      {mode !== "suggestions" && mode !== "replay" && (
        // F4 brief — three-column layout (≥1280px; stacks below). Reads
        // 01 POLICY AS CODE → 02 SCOPE & CONDITIONS → 03 BLAST RADIUS
        // left-to-right (CODE → INTENT → IMPACT). Mobile/tablet is NOT a
        // priority for the May 10 demo per the brief; desktop SOC analyst
        // @ 1440px+ is the audience.
        <main className="grid flex-1 grid-cols-1 gap-4 overflow-hidden p-6 lg:grid-cols-[minmax(0,1fr)_320px_360px]">
          {/* Column 01 — Cedar editor */}
          <div className="flex min-h-0 flex-col gap-2">
            <SectionHeader
              title="Policy as code"
              eyebrow="01"
            >
              <SaveStatus
                pending={createDraft.isPending || updateDraft.isPending}
                draftId={draftId}
                error={
                  createDraft.error ?? updateDraft.error ?? fromReceipt.error
                }
              />
            </SectionHeader>
            <ScopeValidationBanner scope={scope} />
            <CedarEditorBoundary value={cedarSource} onChange={setCedarSource}>
              <Suspense fallback={<EditorSkeleton />}>
                <CedarEditor value={cedarSource} onChange={setCedarSource} />
              </Suspense>
            </CedarEditorBoundary>
          </div>

          {/* Column 02 — Scope + ConditionBuilder + Decision (canonical
              `MdEKl > drawer > midP` — WHO / WHAT / WHEN / DECISION
              sections in a single scrolling column). */}
          <aside
            className="flex min-h-0 flex-col gap-4 overflow-y-auto"
            data-testid="policy-simulator-scope-column"
          >
            <SectionHeader title="Scope & conditions" eyebrow="02" />
            <ScopePicker
              value={scope}
              onChange={setScope}
              actionScope={actionScope}
              onActionScopeChange={setActionScope}
            />
            <ConditionBuilder value={conditions} onChange={handleConditionsChange} />
            <DecisionToggle value={decisionVerdict} onChange={setDecisionVerdict} />
          </aside>

          {/* Column 03 — Blast radius */}
          <aside
            className="flex min-h-0 flex-col gap-2 overflow-y-auto"
            data-testid="policy-simulator-blast-column"
          >
            <SectionHeader title="Blast radius" eyebrow="03" />
            <BlastRadiusPanel
              result={blast.result}
              isPending={blast.isPending}
              error={blast.error}
              onRun={handleRunDryRun}
            />
          </aside>
        </main>
      )}
        </div>

        {/* Right drawer slot — mounts ReceiptDetail when the nested
            `receipts/:run_id` route is active. Closing the drawer
            navigates back to `..` so the auditor lands back on the
            simulator with all in-flight state preserved. */}
        {drawerOutlet && (
          <aside
            data-testid="policy-simulator-receipt-drawer"
            className="w-[720px] shrink-0 border-l border-r5e-border bg-r5e-surface"
          >
            <Outlet />
          </aside>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Replay mode (T141 — Phase 8 US6)
// ---------------------------------------------------------------------------
//
// Per `contracts/audit_api_extensions.md` POST /v1/policy/replay/{run_id}:
//   1. Operator pastes a run_id → "Load receipt" → useReceiptDetail fetches.
//   2. Three side-by-side cards display the receipt's principal / action /
//      resource (read-only summary).
//   3. "Run replay" → POST /v1/policy/replay/<run_id> with no body → display
//      decision + matched_policies + reasoning. A "matches historical ✓/✗"
//      badge compares replayed_decision against the original receipt's
//      policy_decision.
//   4. "Compare with deployed" toggle swaps the Cedar editor for the lazy
//      MonacoDiffEditor (left = deployed source from the response, right =
//      mutable). Edits debounce 600ms and re-fire the replay with
//      override_cedar_source so the operator sees the decision flip live.

interface ReplayResponse {
  run_id: string;
  original_decision: "allow" | "deny" | null;
  replayed_decision: "allow" | "deny" | null;
  decision_changed: boolean;
  matched_policies?: Array<{
    id: string;
    effect: string;
    line_start?: number;
    line_end?: number;
  }>;
  reasoning?: string | null;
  cedar_source_hash?: string | null;
  /** Excerpt of the deployed bundle — populated for the Compare toggle. */
  deployed_cedar_source?: string | null;
  attested_run_id?: string | null;
}

const REPLAY_DEBOUNCE_MS = 600;

function ReplayMode(): JSX.Element {
  const [runIdInput, setRunIdInput] = useState<string>("");
  const [loadedRunId, setLoadedRunId] = useState<string | null>(null);
  const [compareWithDeployed, setCompareWithDeployed] = useState<boolean>(false);
  const [overrideSource, setOverrideSource] = useState<string>("");
  const [replay, setReplay] = useState<ReplayResponse | null>(null);
  const [replayPending, setReplayPending] = useState<boolean>(false);
  const [replayError, setReplayError] = useState<Error | null>(null);

  const debounceRef = useRef<number | null>(null);

  const receipt = useReceiptDetail(loadedRunId ?? undefined);

  function handleLoad(): void {
    const trimmed = runIdInput.trim();
    if (!trimmed) return;
    // Reset prior state when loading a new receipt.
    setReplay(null);
    setReplayError(null);
    setOverrideSource("");
    setCompareWithDeployed(false);
    setLoadedRunId(trimmed);
  }

  async function fireReplay(override?: string | null): Promise<void> {
    if (!loadedRunId) return;
    setReplayPending(true);
    setReplayError(null);
    try {
      const body =
        override !== undefined && override !== null && override !== ""
          ? { override_cedar_source: override }
          : {};
      const resp = await api.post<ReplayResponse>(
        apiPaths.policy.replay(loadedRunId),
        body,
      );
      setReplay(resp);
      // Seed the override editor on first load with the deployed excerpt so
      // the diff is meaningful.
      if (
        overrideSource === "" &&
        resp.deployed_cedar_source &&
        override === undefined
      ) {
        setOverrideSource(resp.deployed_cedar_source);
      }
    } catch (err) {
      setReplayError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setReplayPending(false);
    }
  }

  // Debounced re-fire when the operator edits the override in compare mode.
  function scheduleOverrideReplay(next: string): void {
    setOverrideSource(next);
    if (debounceRef.current !== null) {
      window.clearTimeout(debounceRef.current);
    }
    debounceRef.current = window.setTimeout(() => {
      void fireReplay(next);
    }, REPLAY_DEBOUNCE_MS);
  }

  const decisionMatchesHistorical =
    replay && replay.original_decision !== null
      ? !replay.decision_changed
      : null;

  return (
    <main
      className="flex flex-1 flex-col gap-4 overflow-y-auto p-6"
      data-testid="replay-mode"
    >
      {/* 1. Run ID input */}
      <section
        className="flex flex-col gap-2 rounded border border-r5e-border bg-r5e-surface p-4"
        data-testid="replay-runid-input"
      >
        <label className="text-[10px] uppercase tracking-wider text-r5e-muted">
          Run ID
        </label>
        <div className="flex gap-2">
          <input
            type="text"
            value={runIdInput}
            onChange={(e) => setRunIdInput(e.target.value)}
            placeholder="paste a run_id (UUID)"
            className="flex-1 rounded border border-r5e-border bg-r5e-bg px-3 py-1.5 font-mono text-xs text-r5e-text placeholder:text-r5e-muted/60 focus:border-r5e-accent focus:outline-none"
            data-testid="replay-runid-field"
            onKeyDown={(e) => {
              if (e.key === "Enter") handleLoad();
            }}
          />
          <button
            type="button"
            onClick={handleLoad}
            disabled={!runIdInput.trim()}
            data-testid="replay-load-receipt"
            className="rounded border border-r5e-accent px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/10 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Load receipt
          </button>
        </div>
        {receipt.isLoading && (
          <span className="text-[10px] text-r5e-muted">Loading receipt…</span>
        )}
        {receipt.isError && (
          <span className="text-[10px] text-r5e-danger">
            {receipt.error instanceof ApiError
              ? receipt.error.error_description
              : (receipt.error?.message ?? "Failed to load receipt")}
          </span>
        )}
      </section>

      {/* 2. Receipt summary panels — three side-by-side cards */}
      {receipt.data && (
        <ReceiptSummaryPanels detail={receipt.data} />
      )}

      {/* 3. Run replay CTA + decision display */}
      {receipt.data && (
        <section
          className="flex flex-col gap-3 rounded border border-r5e-border bg-r5e-surface p-4"
          data-testid="replay-output"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-r5e-text">
              Replay decision
            </h2>
            <button
              type="button"
              onClick={() => void fireReplay()}
              disabled={replayPending}
              data-testid="replay-run"
              className="rounded border border-r5e-accent bg-r5e-accent/10 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {replayPending ? "Running…" : replay ? "Re-run replay" : "Run replay"}
            </button>
          </div>

          {replayError && (
            <div
              role="alert"
              className="rounded border border-r5e-danger/60 bg-r5e-danger/10 px-3 py-2 text-xs text-r5e-danger"
              data-testid="replay-error"
            >
              {replayError instanceof ApiError
                ? replayError.error_description
                : replayError.message}
            </div>
          )}

          {replay && (
            <ReplayResult
              replay={replay}
              decisionMatchesHistorical={decisionMatchesHistorical}
            />
          )}
        </section>
      )}

      {/* 4. Compare with deployed toggle + Monaco DiffEditor */}
      {replay && (
        <section
          className="flex min-h-[320px] flex-col gap-3 rounded border border-r5e-border bg-r5e-surface p-4"
          data-testid="replay-compare-section"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-r5e-text">
              Cedar source
            </h2>
            <label className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-r5e-muted">
              <input
                type="checkbox"
                checked={compareWithDeployed}
                onChange={(e) => setCompareWithDeployed(e.target.checked)}
                className="h-3 w-3 accent-r5e-accent"
                data-testid="replay-compare-toggle"
              />
              Compare with deployed
            </label>
          </div>

          <div className="flex min-h-[280px] flex-1 flex-col">
            {!compareWithDeployed && (
              <pre
                data-testid="replay-deployed-source"
                className="flex-1 overflow-x-auto rounded border border-r5e-border bg-r5e-bg p-3 font-mono text-[11px] leading-relaxed text-r5e-text"
              >
                {replay.deployed_cedar_source ?? "(deployed source not returned)"}
              </pre>
            )}
            {compareWithDeployed && (
              <CedarEditorBoundary
                value={overrideSource}
                onChange={scheduleOverrideReplay}
              >
                <Suspense fallback={<EditorSkeleton />}>
                  <CedarDiffEditor
                    original={replay.deployed_cedar_source ?? ""}
                    modified={overrideSource}
                    onModifiedChange={scheduleOverrideReplay}
                  />
                </Suspense>
              </CedarEditorBoundary>
            )}
          </div>
        </section>
      )}
    </main>
  );
}

function ReceiptSummaryPanels({
  detail,
}: {
  detail: ReceiptDetail;
}): JSX.Element {
  return (
    <section
      data-testid="replay-receipt-summary"
      className="grid grid-cols-1 gap-3 sm:grid-cols-3"
    >
      <SummaryCard
        title="Principal"
        testId="replay-summary-principal"
        rows={[
          ["subject", displayPrincipal(detail.signed_predicate.principal)],
          [
            "kind",
            detail.signed_predicate.principal_detail?.kind ?? "—",
          ],
          [
            "tenant",
            detail.signed_predicate.tenant_id ?? "—",
          ],
        ]}
      />
      <SummaryCard
        title="Action"
        testId="replay-summary-action"
        rows={[
          ["event_kind", detail.signed_predicate.event_kind ?? "—"],
          [
            "machine_identity",
            detail.signed_predicate.machine_identity ?? "—",
          ],
          [
            "session",
            detail.signed_predicate.session_id ?? "—",
          ],
        ]}
      />
      <SummaryCard
        title="Resource"
        testId="replay-summary-resource"
        rows={[
          [
            "payload_uri",
            detail.signed_predicate.payload_uri ?? "—",
          ],
          [
            "policy_hash",
            shortHash(detail.signed_predicate.policy_canonical_hash),
          ],
          [
            "outcome",
            detail.outer_container.outcome ?? "—",
          ],
        ]}
      />
    </section>
  );
}

function SummaryCard({
  title,
  rows,
  testId,
}: {
  title: string;
  rows: ReadonlyArray<readonly [string, string]>;
  testId: string;
}): JSX.Element {
  return (
    <article
      data-testid={testId}
      className="flex flex-col gap-2 rounded border border-r5e-border bg-r5e-bg p-3"
    >
      <h3 className="text-[10px] uppercase tracking-wider text-r5e-muted">
        {title}
      </h3>
      <dl className="flex flex-col gap-1 text-[11px]">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-2">
            <dt className="shrink-0 text-r5e-muted">{k}</dt>
            <dd className="truncate text-right font-mono text-r5e-text" title={v}>
              {v}
            </dd>
          </div>
        ))}
      </dl>
    </article>
  );
}

function ReplayResult({
  replay,
  decisionMatchesHistorical,
}: {
  replay: ReplayResponse;
  decisionMatchesHistorical: boolean | null;
}): JSX.Element {
  const decisionTone =
    replay.replayed_decision === "allow"
      ? "border-r5e-success/60 bg-r5e-success/10 text-r5e-success"
      : replay.replayed_decision === "deny"
        ? "border-r5e-danger/60 bg-r5e-danger/10 text-r5e-danger"
        : "border-r5e-border bg-r5e-bg text-r5e-muted";

  return (
    <div className="flex flex-col gap-3" data-testid="replay-result">
      <div className="flex flex-wrap items-center gap-2">
        <span
          data-testid="replay-decision"
          className={`inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${decisionTone}`}
        >
          {replay.replayed_decision ?? "indeterminate"}
        </span>
        {decisionMatchesHistorical !== null && (
          <span
            data-testid="replay-matches-historical"
            data-matches={decisionMatchesHistorical ? "true" : "false"}
            className={`inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
              decisionMatchesHistorical
                ? "border-r5e-success/60 bg-r5e-success/10 text-r5e-success"
                : "border-r5e-warning/60 bg-r5e-warning/10 text-r5e-warning"
            }`}
          >
            {decisionMatchesHistorical
              ? "✓ matches historical"
              : "✗ diverges from historical"}
          </span>
        )}
        <span className="text-[10px] text-r5e-muted">
          historical:{" "}
          <span className="font-mono text-r5e-text">
            {replay.original_decision ?? "—"}
          </span>
        </span>
      </div>

      {replay.reasoning && (
        <p
          data-testid="replay-reasoning"
          className="rounded border border-r5e-border bg-r5e-bg p-3 text-xs text-r5e-text"
        >
          {replay.reasoning}
        </p>
      )}

      {replay.matched_policies && replay.matched_policies.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <h3 className="text-[10px] uppercase tracking-wider text-r5e-muted">
            Matched policies ({replay.matched_policies.length})
          </h3>
          <ul
            data-testid="replay-matched-policies"
            className="flex flex-col divide-y divide-r5e-border rounded border border-r5e-border bg-r5e-bg"
          >
            {replay.matched_policies.map((p) => (
              <li
                key={p.id}
                className="flex items-center justify-between gap-2 px-3 py-1.5 text-[11px]"
              >
                <span className="font-mono text-r5e-text">{p.id}</span>
                <span className="text-r5e-muted">
                  {p.effect}
                  {typeof p.line_start === "number" && (
                    <>
                      {" · L"}
                      {p.line_start}
                      {typeof p.line_end === "number" && p.line_end !== p.line_start
                        ? `–${p.line_end}`
                        : ""}
                    </>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function shortHash(h: string | null | undefined): string {
  if (!h) return "—";
  return h.length > 18 ? `${h.slice(0, 14)}…` : h;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ModeTabs({
  mode,
  onSelect,
}: {
  mode: Mode;
  onSelect: (next: Mode) => void;
}): JSX.Element {
  return (
    <nav
      role="tablist"
      aria-label="Policy simulator mode"
      className="flex shrink-0 items-center gap-1 border-b border-r5e-border bg-r5e-surface px-6"
    >
      {MODES.map((m) => {
        const active = m.key === mode;
        return (
          <button
            key={m.key}
            type="button"
            role="tab"
            aria-selected={active}
            data-testid={`mode-tab-${m.key}`}
            onClick={() => onSelect(m.key)}
            className={`relative px-4 py-2 text-[11px] uppercase tracking-wider transition-colors ${
              active
                ? "text-r5e-accent"
                : "text-r5e-muted hover:text-r5e-text"
            }`}
          >
            {m.label}
            {active && (
              <span className="absolute inset-x-2 -bottom-px h-px bg-r5e-accent" />
            )}
          </button>
        );
      })}
    </nav>
  );
}

// Brief 05 — when the operator lands here from the suggestions page (ADOPT
// or SIMULATE FIRST CTA on a SuggestionCard), surface a small attribution
// banner so they retain context on which suggestion they're drafting from.
// `?draft_id=` is the saved-draft path (from ADOPT). `?sandbox=1` is the
// no-saved-draft path (from SIMULATE FIRST) — the editor still seeds, but
// any dry-run is scoped to a transient draft.
function SuggestionAttributionBanner({
  suggestionId,
  sandbox,
  loading,
  error,
}: {
  suggestionId: string;
  sandbox: boolean;
  loading: boolean;
  error: Error | null;
}): JSX.Element {
  return (
    <div
      data-testid="suggestion-attribution-banner"
      className="mx-6 mt-3 flex items-center justify-between gap-3 rounded border border-r5e-accent/40 bg-r5e-accent/5 px-3 py-2 text-xs"
    >
      <div className="flex flex-col gap-0.5">
        <span className="text-[10px] uppercase tracking-wider text-r5e-muted">
          {sandbox
            ? "Sandbox simulate from suggestion"
            : "Drafting from suggestion"}
        </span>
        <span className="font-mono text-r5e-text">{suggestionId}</span>
        {loading && (
          <span className="text-[10px] text-r5e-muted">
            Loading suggestion draft…
          </span>
        )}
        {error && (
          <span className="text-[10px] text-r5e-danger">
            {error instanceof ApiError ? error.error_description : error.message}
          </span>
        )}
      </div>
      <Link
        to={stripBasename(routes.policySimulatorSuggestions)}
        className="text-[11px] text-r5e-accent hover:underline"
      >
        ← back to suggestions
      </Link>
    </div>
  );
}


function SuggestionsRedirect(): JSX.Element {
  return (
    <main className="flex flex-1 items-center justify-center p-6">
      <div className="flex max-w-md flex-col items-center gap-3 rounded border border-r5e-border bg-r5e-surface p-6 text-center">
        <h2 className="text-sm font-semibold text-r5e-text">
          Suggestions live on a dedicated page
        </h2>
        <p className="text-xs text-r5e-muted">
          The Suggestions queue is a stand-alone surface. Open it to review
          heuristic + LLM-generated policy candidates and adopt one as a draft.
        </p>
        <Link
          to={stripBasename(routes.policySimulatorSuggestions)}
          className="rounded border border-r5e-accent px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/10"
        >
          Open suggestions
        </Link>
      </div>
    </main>
  );
}

function SectionHeader({
  title,
  eyebrow,
  children,
}: {
  title: string;
  /** 2-char numeric eyebrow ("01" / "02" / "03"). Per F4 brief, the eyebrow
   *  reads `01 · POLICY AS CODE` as a single mono-caps line — Pencil pen
   *  frame xMKo8 anchors left-to-right reading order CODE → INTENT → IMPACT. */
  eyebrow?: string;
  children?: ReactNode;
}): JSX.Element {
  return (
    <div className="flex items-center justify-between gap-3">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-[0.1em] text-r5e-muted">
        {eyebrow && (
          <span
            data-testid={`section-header-eyebrow-${eyebrow}`}
            className="text-r5e-accent"
            aria-hidden="true"
          >
            {eyebrow} ·{" "}
          </span>
        )}
        {title}
      </h2>
      {children && (
        <div className="flex items-center gap-2">{children}</div>
      )}
    </div>
  );
}

function ScopeValidationBanner({
  scope,
}: {
  scope: PolicyDraftScopeMetadata | null;
}): JSX.Element | null {
  // Per F4 brief — surface a red banner above the editor when scope is set
  // but `scope_value` is empty/whitespace. ADVISORY ONLY: predicts a
  // likely-broken policy, not a guaranteed backend rejection. Per F010 —
  // the backend's `validate_scope_metadata_shape/1` only emits "must
  // include :scope_kind and :scope_value keys" for nil kind/value;
  // `is_binary("")` passes the changeset, so an empty-string `scope_value`
  // is actually accepted on the wire. We surface the banner anyway because
  // an unresolved scope is almost certainly an authoring oversight, not
  // intentional.
  //
  // Branches:
  //   - scope === null         → no advisory. Per the backend changeset's
  //     nil branch, entirely-absent `scope_metadata` is tolerated; the
  //     dry-run runs with the rule's default scope.
  //   - scope set, scope_value empty/whitespace → advisory.
  //
  // Constitution Principle VII — uses the shared <ErrorState compact />
  // primitive instead of an inline `bg-r5e-danger/10` div, so this advisory
  // visually matches every other error banner in the audit console.
  if (!scope) return null;
  const value = (scope.scope_value ?? "").trim();
  if (value.length > 0) return null;
  return (
    <SharedErrorState
      compact
      testId="scope-validation-banner"
      title="Scope validation"
      detail="validation failed: scope_metadata must include scope_kind and scope_value"
    />
  );
}

function SaveStatus({
  pending,
  draftId,
  error,
}: {
  pending: boolean;
  draftId: string | null;
  error: Error | null;
}): JSX.Element | null {
  if (pending) {
    return (
      <span className="text-[10px] text-r5e-muted" data-testid="save-status-pending">
        Saving…
      </span>
    );
  }
  if (error) {
    return (
      <span
        role="alert"
        className="text-[10px] text-r5e-danger"
        data-testid="save-status-error"
      >
        {error instanceof ApiError ? error.error_description : error.message}
      </span>
    );
  }
  if (draftId) {
    return (
      <span className="text-[10px] text-r5e-muted" data-testid="save-status-saved">
        Draft saved · {draftId.slice(0, 8)}…
      </span>
    );
  }
  return (
    <span className="text-[10px] text-r5e-muted" data-testid="save-status-unsaved">
      Unsaved (a draft will be created on first dry-run)
    </span>
  );
}

/**
 * Sniff the leading verb of a Cedar source ("permit" or "forbid"). Used
 * to seed the canonical DECISION toggle so the visual reflects the
 * draft's actual policy intent at load time. Returns "permit" for
 * empty/unrecognized sources.
 */
function cedarSourceVerb(source: string): "permit" | "forbid" {
  const m = source.match(/^\s*(permit|forbid)\b/i);
  return m && m[1]?.toLowerCase() === "forbid" ? "forbid" : "permit";
}

function EditorSkeleton(): JSX.Element {
  return (
    <div
      data-testid="editor-skeleton"
      className="flex h-full min-h-[280px] flex-col items-center justify-center gap-2 rounded border border-r5e-border bg-r5e-bg text-xs text-r5e-muted"
    >
      <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-r5e-accent border-t-transparent" />
      Loading editor…
    </div>
  );
}
