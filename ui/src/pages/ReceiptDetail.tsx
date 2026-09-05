// ReceiptDetail — 720px right-side drawer overlay rendered via Dashboard's
// nested `<Outlet />` slot (T078, Phase 4 US2).
//
// Per `design/r5e-enterprise-audit-ui.pen` Receipt Detail screen + spec
// FR-017 / FR-018 / FR-019:
//   - Six tabs: Identity, Predicate, Proof, Policy, Payload, Verify.
//   - URL deep-linking: tab is `?tab=verify`, run_id is `:run_id`.
//   - Tier-completeness advisory rendered prominently in the header (FR-017).
//   - Verify tab kicks off a 5-step cryptographic verification with green/red
//     row indicators (FR-018, SC-002).
//   - Payload tab shows the "Fetching as <principal> — this access is itself
//     attested" notice BEFORE any fetch (FR-019).
//   - Backdrop click → closes the drawer (route back to `/admin/dashboard`).
//
// Visual: the Dashboard parent already provides the 720px aside slot at
// `<Outlet />`, so this component renders only the drawer's *contents*. The
// backdrop / close behavior is wired here because the drawer's lifecycle
// belongs to this route.

import { useEffect, useMemo } from "react";
import { useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Activity, Wand2 } from "lucide-react";

import { ExportEvidenceButton } from "~/components/audit/ExportEvidenceButton";
import { IdentityTab } from "~/components/audit/IdentityTab";
import { PayloadTab } from "~/components/audit/PayloadTab";
import { PolicyTab } from "~/components/audit/PolicyTab";
import { PredicateTab } from "~/components/audit/PredicateTab";
import { ProofTab } from "~/components/audit/ProofTab";
import { TagsSection } from "~/components/audit/TagsSection";
import { VerifyTab } from "~/components/audit/VerifyTab";
import { ErrorState as SharedErrorState } from "~/components/shared/states";
import { useReceiptDetail } from "~/hooks/useReceiptDetail";
import { ApiError } from "~/lib/api";
import { routes, stripBasename, timelinePath } from "~/lib/routes";

type TabKey = "identity" | "predicate" | "proof" | "policy" | "payload" | "verify";

const TABS: ReadonlyArray<{ key: TabKey; label: string }> = [
  { key: "identity", label: "Identity" },
  { key: "predicate", label: "Predicate" },
  { key: "proof", label: "Proof" },
  { key: "policy", label: "Policy" },
  { key: "payload", label: "Payload" },
  { key: "verify", label: "Verify" },
] as const;

export default function ReceiptDetail(): JSX.Element {
  const { run_id: runId } = useParams<{ run_id: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  // True when this drawer was opened via the React-Router background-location
  // modal pattern (e.g. clicked from a tool-call `attested_run_id` link in
  // <ChatPage />). In that mode `close()` should pop history rather than
  // route to `/admin/dashboard`, so the underlying surface (chat, policy
  // simulator, etc.) is restored intact. See App.tsx <AppRoutes />. (!93)
  const isModalOverlay = Boolean(
    (location.state as { backgroundLocation?: unknown } | null)?.backgroundLocation,
  );
  // F10/F008: when the drawer is opened OVER the Investigation Timeline
  // (via EventInspector "View full Tags" link) we route back to the
  // timeline rather than the dashboard so the auditor doesn't lose
  // their investigation context. The opener passes the return path via
  // react-router location.state.returnTo. (!94)
  const returnTo = (location.state as { returnTo?: string } | null)?.returnTo ?? null;

  const tab: TabKey = useMemo(() => {
    const t = searchParams.get("tab");
    if (
      t === "identity" ||
      t === "predicate" ||
      t === "proof" ||
      t === "policy" ||
      t === "payload" ||
      t === "verify"
    ) {
      return t;
    }
    return "identity";
  }, [searchParams]);

  function selectTab(next: TabKey): void {
    setSearchParams(
      (prev) => {
        const params = new URLSearchParams(prev);
        if (next === "identity") {
          params.delete("tab");
        } else {
          params.set("tab", next);
        }
        return params;
      },
      { replace: true },
    );
  }

  function close(): void {
    if (isModalOverlay) {
      // !93 modal-overlay path: pop history — restores the surface that
      // opened us (e.g. the chat page's tool-call link) without
      // unmounting it. The underlying location was captured in
      // `location.state.backgroundLocation` by the link that triggered
      // the navigate, and React Router restores it automatically on
      // back-navigation.
      navigate(-1);
      return;
    }
    if (returnTo) {
      // !94 (F10/F008): when opened from Investigation Timeline,
      // returnTo carries the timeline URL (basename already stripped) so
      // close lands the auditor back on their investigation surface
      // rather than the dashboard.
      navigate(returnTo);
      return;
    }
    if (location.pathname.startsWith(stripBasename(routes.timeline))) {
      // !94 fallback: deep-linked drawer URL with no location.state →
      // route back to the bare timeline.
      navigate(stripBasename(routes.timeline));
      return;
    }
    // Nested-route close (!89 GAN F005) — navigate to parent route.
    // Works for both Dashboard (`/admin/dashboard`) and Policy Simulator
    // (`/admin/policy-simulator`) parents. The drawer overlays the
    // surface and `..` keeps the auditor on whichever parent they came
    // from instead of hard-redirecting to Dashboard.
    navigate("..");
  }

  // Esc key closes the drawer (a11y).
  useEffect(() => {
    function onKey(e: KeyboardEvent): void {
      if (e.key === "Escape") close();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const { data, isLoading, isError, error } = useReceiptDetail(runId);

  return (
    <div
      className="flex h-full flex-col bg-r5e-surface text-r5e-text"
      data-testid="receipt-detail-drawer"
    >
      {/* Backdrop — covers the dashboard table behind the drawer. Click to close. */}
      <div
        aria-hidden="true"
        onClick={close}
        className="fixed inset-y-0 right-[720px] left-0 z-0 hidden bg-black/30 lg:block"
      />

      {/* Header */}
      <header className="relative z-10 flex shrink-0 items-start justify-between gap-3 border-b border-r5e-border bg-r5e-surface px-4 py-3">
        <div className="flex flex-col gap-1">
          <span className="text-[10px] uppercase tracking-wider text-r5e-muted">
            Receipt
          </span>
          <span className="font-mono text-xs text-r5e-text">
            {runId ?? "(no run_id)"}
          </span>
          {data && <TierAdvisory advisory={data.outer_container.tier_completeness_advisory} />}
        </div>
        <div className="flex items-center gap-2">
          {runId && <DraftPolicyFromReceiptButton runId={runId} />}
          {runId && <ViewInTimelineButton runId={runId} />}
          {runId && <ExportEvidenceButton runId={runId} />}
          <button
            type="button"
            onClick={close}
            aria-label="Close drawer"
            className="rounded border border-r5e-border px-2 py-1 text-xs text-r5e-muted hover:text-r5e-text"
          >
            Close
          </button>
        </div>
      </header>

      {/* Wave C — TagsSection (R2 design): the auditor's "what was
          attempted" surface lives ABOVE the tabs, not inside one. The
          tabs remain for crypto-chain depth (Identity/Predicate/Proof
          /Policy/Payload/Verify) but the action context is always
          visible at the top of the drawer regardless of which tab is
          active. Renders nothing for non-extracted rows (legacy
          imports, llm_call without extractor metadata) — drawer falls
          through to tabs gracefully. */}
      {data && <TagsSection data={data} />}

      {/* Tabs */}
      <nav
        role="tablist"
        className="relative z-10 flex shrink-0 items-center gap-1 border-b border-r5e-border bg-r5e-surface px-2"
      >
        {TABS.map((t) => {
          const active = t.key === tab;
          return (
            <button
              key={t.key}
              type="button"
              role="tab"
              aria-selected={active}
              data-testid={`tab-${t.key}`}
              onClick={() => selectTab(t.key)}
              className={`relative px-3 py-2 text-[11px] uppercase tracking-wider transition-colors ${
                active
                  ? "text-r5e-accent"
                  : "text-r5e-muted hover:text-r5e-text"
              }`}
            >
              {t.label}
              {active && (
                <span className="absolute inset-x-2 -bottom-px h-px bg-r5e-accent" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Body */}
      <section
        role="tabpanel"
        className="relative z-10 flex-1 overflow-y-auto px-4 py-4"
      >
        {isLoading && <LoadingState />}
        {isError && <ReceiptErrorState error={error} />}
        {data && (
          <>
            {tab === "identity" && <IdentityTab data={data} />}
            {tab === "predicate" && <PredicateTab data={data} />}
            {tab === "proof" && <ProofTab data={data} />}
            {tab === "policy" && <PolicyTab data={data} />}
            {tab === "payload" && runId && (
              <PayloadTab
                runId={runId}
                payloadUri={data.signed_predicate?.payload_uri ?? null}
              />
            )}
            {tab === "verify" && runId && <VerifyTab runId={runId} />}
          </>
        )}
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header bits
// ---------------------------------------------------------------------------

function TierAdvisory({ advisory }: { advisory: string | null }): JSX.Element | null {
  if (!advisory) return null;
  const isPartial = advisory === "partial";
  const tone = isPartial
    ? "border-r5e-warning/60 bg-r5e-warning/10 text-r5e-warning"
    : "border-r5e-success/60 bg-r5e-success/10 text-r5e-success";
  const label = isPartial ? "Tier completeness: partial" : `Tier completeness: ${advisory}`;
  return (
    <span
      data-testid="tier-completeness-advisory"
      className={`mt-1 inline-block rounded border px-2 py-0.5 text-[10px] uppercase tracking-wider ${tone}`}
    >
      {label}
    </span>
  );
}

function LoadingState(): JSX.Element {
  return (
    <div className="flex items-center gap-2 text-xs text-r5e-muted" data-testid="receipt-loading">
      <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-r5e-accent border-t-transparent" />
      Loading receipt…
    </div>
  );
}

function ReceiptErrorState({ error }: { error: Error | null }): JSX.Element {
  // Migrated to shared ErrorState primitive (R5 / Constitution Principle VII).
  const message =
    error instanceof ApiError ? error.error_description : (error?.message ?? "Unknown error");
  return (
    <SharedErrorState
      testId="receipt-error"
      title="Failed to load receipt"
      detail={message}
      compact
    />
  );
}

// ---------------------------------------------------------------------------
// Identity tab — moved to `~/components/audit/IdentityTab` for the canonical
// 5-section vertical-stack rebuild (PRINCIPAL / REQUEST SUMMARY /
// POLICY DECISION / Draft Policy CTA / CRYPTOGRAPHIC PROOF) per the
// `MdEKl > drawer > scrollContent` Pencil frame. Pre-rewrite this file
// hosted its OWN inline IdentityTab — a flat <dl> KV dump that matched
// the brief but not the .pen. The shared module + the inline coexisted
// (the GAN review missed it because the test file imported the shared
// one); the production drawer rendered the inline one. Constitution
// Principle VII consolidation: one IdentityTab, one source of truth.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// "Draft policy from this receipt" button — F004 US3 entrypoint.
//
// Spec US3 frames the Discovery-to-Policy flow as
// "receipt → skeleton → adjust scope → Blast Radius → save". This button is
// the first hop. It deep-links to the PolicySimulator in `mode=draft`, which
// kicks off the draft-from-receipt flow via `useDraftFromReceipt` (keyed off
// `mode=draft` + `run_id`).
//
// Basename note: pass the path through `stripBasename` because the SPA's
// BrowserRouter is mounted at `basename="/admin"` — feeding `navigate()` an
// absolute `/admin/...` path would auto-prefix the basename a second time
// and land on `/admin/admin/policy-simulator` (no route → blank page).
// ---------------------------------------------------------------------------
function DraftPolicyFromReceiptButton({ runId }: { runId: string }): JSX.Element {
  const navigate = useNavigate();
  const target = `${stripBasename(routes.policySimulator)}?mode=draft&run_id=${encodeURIComponent(runId)}`;
  return (
    <button
      type="button"
      data-testid="draft-policy-from-receipt"
      onClick={() => navigate(target)}
      className="flex h-7 items-center gap-1.5 rounded-md border border-r5e-accent px-2.5 text-[11px] font-semibold text-r5e-accent hover:bg-r5e-accent/10"
    >
      <Wand2 className="h-3.5 w-3.5" aria-hidden="true" />
      Draft policy from receipt
    </button>
  );
}

// ---------------------------------------------------------------------------
// "View in timeline" CTA — F10 drill-path from R2 drawer header.
//
// Per `design/briefs/10-session-trace.md`:
//   "From R2 drawer → 'View in timeline' CTA (new addition to drawer header)
//    → /admin/timeline?run_id=<id> (opens with that event selected)"
//
// One-button drill: the Timeline reads `?run_id=` and pre-selects the
// event. The Timeline page also derives the principal/correlation/session
// scope from that receipt's data so the surrounding lanes populate.
// ---------------------------------------------------------------------------
function ViewInTimelineButton({ runId }: { runId: string }): JSX.Element {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      data-testid="view-in-timeline"
      onClick={() => navigate(timelinePath({ run_id: runId }))}
      className="flex h-7 items-center gap-1.5 rounded-md border border-r5e-border px-2.5 text-[11px] font-semibold text-r5e-muted hover:border-r5e-accent hover:text-r5e-accent"
    >
      <Activity className="h-3.5 w-3.5" aria-hidden="true" />
      View in timeline
    </button>
  );
}
