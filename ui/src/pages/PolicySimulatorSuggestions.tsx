// PolicySimulatorSuggestions — operator-only suggestions queue surface
// (T135 — Phase 7 US5; redesigned per `design/briefs/05-suggestions.md`).
//
// Top-level layout:
//   ┌──────────────────────────────────────────────────────────────────┐
//   │ [← SIMULATOR]  Policy suggestions          [REFRESH SUGGESTIONS] │
//   │                                              Last run: 2 min ago │
//   ├──────────────────────────────────────────────────────────────────┤
//   │ ACTIVE · ADOPTED · DISMISSED                                     │
//   ├──────────────────────────────────────────────────────────────────┤
//   │ <SuggestionCard /> × N                                            │
//   └──────────────────────────────────────────────────────────────────┘
//
// Tabs (status filter): ACTIVE / ADOPTED / DISMISSED. Underline-on-active.
//
// Refresh button: rate-limited per F004 hardening (FR-030a). On 429 we
// surface a toast with the remaining minutes; on success we toast
// "Refresh queued — new suggestions in ~30 seconds" and dim the existing
// list to 60% opacity until the refetch lands. The "Last run" timestamp
// is derived from the latest `generated_at` in the list — if the engine
// has never run we render "—".
//
// Auth gate: auditors see a friendly notice; operators see the queue.
//
// Wire-up:
//   - usePolicySuggestionsList(filter) — list query (status filter)
//   - useAdoptPolicySuggestion()       — POST .../adopt
//   - useDismissPolicySuggestion()     — POST .../dismiss { reason }
//   - useRefreshPolicySuggestions()    — POST .../refresh

import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { SuggestionCard } from "~/components/policy/SuggestionCard";
import { TopBar } from "~/components/shared/TopBar";
import {
  ToastStack,
  type ToastTone,
} from "~/components/shared/ToastStack";
import {
  EmptyState as SharedEmptyState,
  ErrorState as SharedErrorState,
  Skeleton,
} from "~/components/shared/states";
import { useAuth } from "~/hooks/useAuth";
import {
  RefreshRateLimited,
  useAdoptPolicySuggestion,
  useDismissPolicySuggestion,
  usePolicySuggestionsList,
  useRefreshPolicySuggestions,
  type PolicySuggestion,
  type PolicySuggestionsListFilter,
} from "~/hooks/usePolicySuggestions";
import { ApiError } from "~/lib/api";
import {
  latestGeneratedAt,
  relativeFromNow,
  sortSuggestions,
} from "~/lib/policy_suggestions";
import { routes, stripBasename } from "~/lib/routes";

interface InlineToast {
  id: number;
  kind: "rate_limited" | "error" | "success";
  message: string;
}

const TAB_OPTIONS: ReadonlyArray<{
  key: NonNullable<PolicySuggestionsListFilter["status"]>;
  label: string;
}> = [
  { key: "active", label: "Active" },
  { key: "adopted_as_draft", label: "Adopted" },
  { key: "dismissed", label: "Dismissed" },
];

export default function PolicySimulatorSuggestions(): JSX.Element {
  const auth = useAuth();
  const navigate = useNavigate();

  const [statusFilter, setStatusFilter] =
    useState<PolicySuggestionsListFilter["status"]>("active");

  const filter: PolicySuggestionsListFilter = useMemo(
    () => ({ status: statusFilter }),
    [statusFilter],
  );

  const list = usePolicySuggestionsList(filter);
  const adopt = useAdoptPolicySuggestion();
  const dismiss = useDismissPolicySuggestion();
  const refresh = useRefreshPolicySuggestions();

  // Inline toasts — same lightweight pattern as Dashboard.tsx.
  const [toasts, setToasts] = useState<InlineToast[]>([]);
  const pushToast = (t: Omit<InlineToast, "id">): void => {
    const id = Date.now() + Math.random();
    setToasts((curr) => [...curr, { ...t, id }]);
    window.setTimeout(
      () => setToasts((curr) => curr.filter((x) => x.id !== id)),
      6_000,
    );
  };

  function handleRefresh(): void {
    refresh.mutate(undefined, {
      onSuccess: () => {
        pushToast({
          kind: "success",
          message: "Refresh queued — new suggestions in ~30 seconds.",
        });
      },
      onError: (err) => {
        if (err instanceof RefreshRateLimited) {
          const minutes = Math.max(1, Math.ceil(err.retry_after_seconds / 60));
          pushToast({
            kind: "rate_limited",
            message: `Rate limited. Try again in ${minutes} minute${
              minutes === 1 ? "" : "s"
            }.`,
          });
          return;
        }
        const msg =
          err instanceof ApiError ? err.error_description : err.message;
        pushToast({ kind: "error", message: `Refresh failed: ${msg}` });
      },
    });
  }

  // ADOPT navigates the operator to `/admin/policy-simulator?mode=draft&
  // suggestion=<id>&draft_id=<id>` per brief 05. The `&suggestion` param is
  // the brief-defined contract (so the simulator can show "drafting from
  // suggestion sug-..." attribution); `&draft_id` is the existing
  // simulator path that picks up the saved draft.
  function handleAdopt(suggestion: PolicySuggestion): void {
    adopt.mutate(
      { id: suggestion.id },
      {
        onSuccess: ({ draft_id }) => {
          navigate(
            `${stripBasename(routes.policySimulator)}?mode=draft&suggestion=${encodeURIComponent(
              suggestion.id,
            )}&draft_id=${encodeURIComponent(draft_id)}`,
          );
        },
        onError: (err) => {
          const msg =
            err instanceof ApiError ? err.error_description : err.message;
          pushToast({ kind: "error", message: `Adopt failed: ${msg}` });
        },
      },
    );
  }

  // SIMULATE FIRST — same simulator destination but doesn't create a saved
  // draft (the simulator's `?sandbox=1` query param keeps the run scoped to
  // a transient draft per brief 05).
  function handleSimulate(suggestion: PolicySuggestion): void {
    navigate(
      `${stripBasename(routes.policySimulator)}?mode=draft&suggestion=${encodeURIComponent(
        suggestion.id,
      )}&sandbox=1`,
    );
  }

  function handleDismiss(suggestion: PolicySuggestion, reason?: string): void {
    dismiss.mutate(
      { id: suggestion.id, reason },
      {
        onError: (err) => {
          const msg =
            err instanceof ApiError ? err.error_description : err.message;
          pushToast({ kind: "error", message: `Dismiss failed: ${msg}` });
        },
      },
    );
  }

  // Auth gate — auditors see a friendly notice instead of a 403 toast.
  if (auth.status === "authenticated" && auth.role !== "platform_operator") {
    return (
      <div
        className="flex min-h-0 flex-1 flex-col bg-r5e-bg font-sans text-r5e-text"
        data-testid="policy-suggestions-page"
      >
        <TopBar
          pageContent={
            <h1 className="text-sm font-semibold text-r5e-text">
              Policy suggestions
            </h1>
          }
        />
        <main className="flex flex-1 items-center justify-center p-6">
          <div
            data-testid="suggestions-forbidden"
            className="flex max-w-md flex-col items-center gap-3 rounded border border-r5e-border bg-r5e-surface p-6 text-center"
          >
            <h2 className="text-sm font-semibold text-r5e-text">
              Operator-only surface
            </h2>
            <p className="text-xs text-r5e-muted">
              Policy suggestions are visible to platform operators. Auditors
              can review the receipts that suggestions are generated from
              directly in the audit log.
            </p>
            <Link
              to={stripBasename(routes.dashboard)}
              className="text-[11px] text-r5e-accent hover:underline"
            >
              ← Back to dashboard
            </Link>
          </div>
        </main>
      </div>
    );
  }

  // Render — the suggestions queue.
  const rows = list.data?.suggestions ?? [];
  const sorted = sortSuggestions(rows);
  // "Last run" reflects the timestamp of the most-recent engine row,
  // independent of confidence. Pre-fix this read `sorted[0].generated_at`
  // — but `sortSuggestions` orders by confidence DESC then time DESC, so
  // a stale high-confidence row would mask a fresh low-confidence one and
  // mislead operators about engine recency. We pick the max ISO directly.
  const lastRunAt = latestGeneratedAt(rows);

  const inFlightId =
    adopt.isPending ? adopt.variables?.id ?? null
    : dismiss.isPending ? dismiss.variables?.id ?? null
    : null;

  return (
    <div
      className="flex min-h-0 flex-1 flex-col bg-r5e-bg font-sans text-r5e-text"
      data-testid="policy-suggestions-page"
    >
      <TopBar
        pageContent={
          <div className="flex items-center gap-3">
            <Link
              to={stripBasename(routes.policySimulator)}
              className="rounded border border-r5e-border px-2 py-1 text-[10px] uppercase tracking-wider text-r5e-muted hover:border-r5e-accent hover:text-r5e-accent"
            >
              ← Simulator
            </Link>
            <h1 className="text-sm font-semibold text-r5e-text">
              Policy suggestions
            </h1>
          </div>
        }
        actions={
          <div className="flex flex-col items-end gap-1">
            <button
              type="button"
              onClick={handleRefresh}
              disabled={refresh.isPending}
              data-testid="suggestions-refresh"
              className="inline-flex items-center gap-2 rounded border border-r5e-accent px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-r5e-accent hover:bg-r5e-accent/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {refresh.isPending && (
                <span
                  aria-hidden="true"
                  className="inline-block h-3 w-3 animate-spin rounded-full border border-r5e-accent border-t-transparent"
                />
              )}
              {refresh.isPending ? "Refreshing…" : "Refresh suggestions"}
            </button>
            <LastRunLine generatedAt={lastRunAt} />
          </div>
        }
      />

      <SuggestionTabs value={statusFilter} onChange={setStatusFilter} />

      <main
        data-testid="suggestions-main"
        data-refresh-pending={refresh.isPending ? "true" : "false"}
        className="flex-1 overflow-y-auto p-6"
      >
        {list.isLoading && <ListSkeleton />}
        {list.isError && (
          <ErrorBanner
            title="Failed to load suggestions"
            error={list.error}
            onRetry={() => list.refetch()}
          />
        )}
        {!list.isLoading && !list.isError && sorted.length === 0 && (
          <SuggestionsEmptyState statusFilter={statusFilter} />
        )}

        {sorted.length > 0 && (
          <ul
            data-testid="suggestions-list"
            className={`flex flex-col gap-3 transition-opacity ${
              refresh.isPending ? "opacity-60" : ""
            }`}
          >
            {sorted.map((s) => (
              <li key={s.id}>
                <SuggestionCard
                  suggestion={s}
                  onAdopt={() => handleAdopt(s)}
                  onSimulate={() => handleSimulate(s)}
                  onDismiss={(reason) => handleDismiss(s, reason)}
                  isPending={inFlightId === s.id}
                />
              </li>
            ))}
          </ul>
        )}
      </main>

      <ToastStack
        toasts={toasts.map((t) => ({
          id: t.id,
          tone: suggestionsToneFor(t.kind),
          message: t.message,
          testId: `suggestions-toast-${t.kind}`,
        }))}
        testId="suggestions-toasts"
      />
    </div>
  );
}

/** Map a suggestions-page event kind onto the shared ToastTone palette. */
function suggestionsToneFor(kind: InlineToast["kind"]): ToastTone {
  switch (kind) {
    case "rate_limited":
      return "warning";
    case "error":
      return "danger";
    case "success":
      return "success";
    default:
      return "neutral";
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Tab strip — ACTIVE · ADOPTED · DISMISSED with underline-on-active. */
function SuggestionTabs({
  value,
  onChange,
}: {
  value: PolicySuggestionsListFilter["status"];
  onChange: (next: PolicySuggestionsListFilter["status"]) => void;
}): JSX.Element {
  return (
    <nav
      role="tablist"
      aria-label="Suggestion status filter"
      className="flex shrink-0 items-center gap-1 border-b border-r5e-border bg-r5e-surface px-6"
    >
      {TAB_OPTIONS.map((opt) => {
        const active = (value ?? "active") === opt.key;
        return (
          <button
            key={opt.key}
            type="button"
            role="tab"
            aria-selected={active}
            data-testid={`suggestions-status-${opt.key}`}
            onClick={() => onChange(opt.key)}
            className={`relative px-4 py-2 text-[11px] uppercase tracking-wider transition-colors ${
              active
                ? "text-r5e-accent"
                : "text-r5e-muted hover:text-r5e-text"
            }`}
          >
            {opt.label}
            {active && (
              <span
                aria-hidden="true"
                className="absolute inset-x-2 -bottom-px h-px bg-r5e-accent"
              />
            )}
          </button>
        );
      })}
    </nav>
  );
}

/** Format the latest engine-run timestamp as a relative string. */
function LastRunLine({ generatedAt }: { generatedAt: string | null }): JSX.Element {
  const label = generatedAt ? relativeFromNow(generatedAt) : "—";
  return (
    <p
      data-testid="suggestions-last-run"
      className="text-[10px] uppercase tracking-wider text-r5e-muted"
    >
      Last run: {label}
    </p>
  );
}

function ListSkeleton(): JSX.Element {
  // R5 — three card-shaped placeholders.
  return (
    <div data-testid="suggestions-loading" className="flex flex-col gap-3">
      {[0, 1, 2].map((i) => (
        <Skeleton.Block key={i} className="h-32 w-full" />
      ))}
    </div>
  );
}

function SuggestionsEmptyState({
  statusFilter,
}: {
  statusFilter: PolicySuggestionsListFilter["status"];
}): JSX.Element {
  const config =
    statusFilter === "dismissed"
      ? {
          title: "No dismissed suggestions",
          body: "Dismissed suggestions appear here once you dismiss one with a reason.",
        }
      : statusFilter === "adopted_as_draft"
        ? {
            title: "No adopted suggestions",
            body: "Adopted suggestions appear here once you adopt one as a draft.",
          }
        : {
            title: "No active suggestions",
            body: "The engines re-run on a regular cadence; use Refresh to kick a manual run.",
          };

  return (
    <SharedEmptyState
      testId="suggestions-empty"
      title={config.title}
      body={config.body}
    />
  );
}

function ErrorBanner({
  title,
  error,
  onRetry,
}: {
  title: string;
  error: Error | null;
  onRetry: () => void;
}): JSX.Element {
  const detail =
    error instanceof ApiError
      ? error.error_description
      : (error?.message ?? "Unknown error");
  return (
    <SharedErrorState
      testId="suggestions-error"
      title={title}
      detail={detail}
      retry={{ onClick: onRetry }}
      compact
    />
  );
}
