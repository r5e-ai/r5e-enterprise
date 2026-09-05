// MCP Registry Detail — single-entry view with full SBOM + CVE breakdown.
//
// Per design/briefs/07-mcp-registry.md (F7) — the demo's "click here, see
// SBOM, see CVE, here's the actual receipt of a tool call you can curl
// right now" surface. Sections:
//
//   1. Header  — back-link to list + entry name as H1.
//   2. Overview  — 2-column key/value (TRUST TIER, PUBLISHER, VERSION,
//      TRANSPORT, SOURCE) + DESCRIPTION below as full-width paragraph.
//   3. Capabilities  — list of capability cards, each with the tool name
//      + description.
//   4. Policy Constraints  — Cedar source rendered read-only via the
//      lazy-loaded Monaco-backed CedarEditor (readOnly={true}). Below:
//      rate-limit display.
//   5. SBOM  — format + digest header; component table; per-component
//      CVE rows with severity pills (HIGH=red, MEDIUM=warning,
//      LOW=muted).
//
// Quarantine workflow (operator-only):
//   - <QuarantineButton /> visible to platform_operator role only.
//   - Opens a confirmation dialog; on confirm PATCHes the registry
//     entry (`PATCH /v1/mcp/registry/<id>`) with the new trust_tier;
//     backend emits the attested receipt and updates the policy
//     bundle. We invalidate the registry cache + show a success
//     status banner.
//
// CSP rule: NO third-party CDN-loaded chart libs; Monaco is loaded
// same-origin under /admin/vs/* per existing CedarEditor wiring.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Suspense, lazy, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";

import { TrustTierPill } from "~/components/mcp/TrustTierPill";
import CedarEditorBoundary from "~/components/policy/CedarEditorBoundary";
import { Pill } from "~/components/shared/Pill";
import { TopBar } from "~/components/shared/TopBar";
import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
import { useAuth } from "~/hooks/useAuth";
import { api, ApiError } from "~/lib/api";
import { stripBasename, routes } from "~/lib/routes";
import type { McpRegistryEntry, McpVulnerability } from "~/lib/types";

// Cedar editor is lazy-loaded — it pulls in ~2MB of Monaco. We mirror
// PolicySimulator.tsx's pattern: lazy import + Suspense + Boundary.
const CedarEditor = lazy(() => import("~/components/policy/CedarEditor"));

function SeverityPill({
  severity,
}: {
  severity: McpVulnerability["severity"];
}): JSX.Element {
  // HIGH/CRITICAL = danger-red; MEDIUM = warning-orange; LOW/UNKNOWN = muted.
  switch (severity) {
    case "critical":
    case "high":
      return (
        <Pill tone="danger" size="xs">
          {severity}
        </Pill>
      );
    case "medium":
      return (
        <Pill tone="warning" size="xs">
          medium
        </Pill>
      );
    case "low":
      return (
        <Pill tone="muted" size="xs">
          low
        </Pill>
      );
    case "unknown":
    default:
      return (
        <Pill tone="muted" size="xs">
          unknown
        </Pill>
      );
  }
}

export default function McpRegistryDetail(): JSX.Element {
  const params = useParams<{ id: string }>();
  const id = params.id ?? "";

  const { data, isLoading, error, refetch } = useQuery<McpRegistryEntry>({
    queryKey: ["mcp-registry", id],
    enabled: id.length > 0,
    queryFn: () =>
      api.get<McpRegistryEntry>(
        `/v1/mcp/registry/${encodeURIComponent(id)}`,
      ),
  });

  return (
    <>
      <TopBar
        pageContent={
          <div className="flex flex-col">
            <Link
              to={stripBasename(routes.mcpRegistry)}
              className="text-[12px] text-r5e-muted hover:text-r5e-text"
              data-testid="mcp-registry-detail-back"
            >
              ← MCP Registry
            </Link>
            <span className="text-[14px] font-semibold text-r5e-text">
              {data ? data.name : id}
            </span>
          </div>
        }
      />

      <main
        data-testid="mcp-registry-detail-page"
        className="flex flex-1 flex-col gap-6 overflow-auto bg-r5e-bg p-6 font-sans text-r5e-text"
      >
        {isLoading ? (
          <DetailSkeleton />
        ) : error ? (
          <ErrorState
            testId="mcp-registry-detail-error"
            title="Couldn't load MCP entry"
            body="The registry endpoint returned an error. Try again or check your connection."
            detail={error instanceof ApiError ? error.error_description : String(error)}
            retry={{ onClick: () => void refetch() }}
          />
        ) : data ? (
          <DetailBody entry={data} />
        ) : null}
      </main>
    </>
  );
}

function DetailSkeleton(): JSX.Element {
  return (
    <div data-testid="mcp-registry-detail-loading" className="flex flex-col gap-6">
      <Skeleton.Block className="h-32 w-full" />
      <Skeleton.Block className="h-24 w-full" />
      <Skeleton.Block className="h-40 w-full" />
      <Skeleton.Block className="h-48 w-full" />
    </div>
  );
}

function DetailBody({ entry }: { entry: McpRegistryEntry }): JSX.Element {
  const auth = useAuth();
  const isOperator = auth.status === "authenticated" && auth.role === "platform_operator";

  return (
    <>
      <PageHeader entry={entry} isOperator={isOperator} />
      {entry.trust_tier === "quarantined" && (
        <QuarantinedWarningBanner entry={entry} />
      )}
      <OverviewSection entry={entry} />
      <CapabilitiesSection entry={entry} />
      <PolicyConstraintsSection entry={entry} />
      <SbomSection entry={entry} />
    </>
  );
}

function QuarantinedWarningBanner({
  entry,
}: {
  entry: McpRegistryEntry;
}): JSX.Element {
  return (
    <div
      data-testid="mcp-detail-quarantined-banner"
      role="status"
      className="rounded border border-r5e-warning/60 bg-r5e-warning/15 px-4 py-3 text-r5e-warning"
    >
      <div className="font-mono text-[11px] font-semibold uppercase tracking-wider">
        Quarantined — tool calls are policy-denied at the Gateway
      </div>
      <p className="mt-1 text-[12px] leading-relaxed text-r5e-text">
        {entry.name} remains visible for audit and SBOM inspection, but runtime
        calls are blocked until an operator restores the trust tier.
      </p>
    </div>
  );
}

function PageHeader({
  entry,
  isOperator,
}: {
  entry: McpRegistryEntry;
  isOperator: boolean;
}): JSX.Element {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-r5e-border pb-4">
      <div className="flex flex-col gap-2">
        <h1 className="text-[24px] font-semibold text-r5e-text">{entry.name}</h1>
        <div className="flex items-center gap-2">
          <TrustTierPill
            tier={entry.trust_tier}
            size="sm"
            testId="mcp-detail-header-tier"
          />
          <span className="text-[12px] text-r5e-muted">{entry.publisher}</span>
        </div>
      </div>
      {isOperator ? <QuarantineButton entry={entry} /> : null}
    </div>
  );
}

function OverviewSection({ entry }: { entry: McpRegistryEntry }): JSX.Element {
  return (
    <Section title="Overview">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-[13px]">
        <Field label="Trust tier">
          <TrustTierPill
            tier={entry.trust_tier}
            size="sm"
            testId="mcp-detail-trust-tier"
          />
        </Field>
        <Field label="Publisher">{entry.publisher}</Field>
        <Field label="Version">
          <span className="font-mono text-r5e-text">{entry.version}</span>
        </Field>
        <Field label="Transport">
          <span className="font-mono text-r5e-muted">{entry.transport}</span>
        </Field>
        <Field label="Source" wide>
          <code
            className="rounded bg-r5e-bg px-2 py-0.5 font-mono text-[12px] text-r5e-text"
            data-testid="mcp-detail-source"
          >
            {entry.source}
          </code>
        </Field>
        <Field label="Description" wide>
          <p className="text-[13px] leading-relaxed text-r5e-text">
            {entry.description}
          </p>
        </Field>
      </dl>
    </Section>
  );
}

function CapabilitiesSection({ entry }: { entry: McpRegistryEntry }): JSX.Element {
  const tools = entry.capabilities.tools ?? [];
  return (
    <Section title="Capabilities">
      {tools.length === 0 ? (
        <EmptyState
          compact
          title="No declared tools"
          body="This MCP server has not declared any callable tools."
        />
      ) : (
        <ul
          className="grid grid-cols-1 gap-3 md:grid-cols-2"
          data-testid="mcp-detail-capabilities"
        >
          {tools.map((tool) => (
            <li
              key={tool.name}
              data-testid={`mcp-detail-capability-${tool.name}`}
              className="flex flex-col gap-1 rounded border border-r5e-border bg-r5e-surface px-3 py-2"
            >
              <div className="font-mono text-[13px] font-semibold text-r5e-text">
                {tool.name}
              </div>
              <div className="text-[12px] text-r5e-muted">
                {tool.description}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function PolicyConstraintsSection({
  entry,
}: {
  entry: McpRegistryEntry;
}): JSX.Element {
  const policies = entry.policy_constraints?.cedar_policies ?? [];
  // Concatenate the per-policy strings into one Monaco buffer; Cedar
  // grammar handles back-to-back forbid/permit blocks.
  const cedarSource = policies.length > 0 ? policies.join("\n\n") : "";
  const rateLimit = entry.policy_constraints?.rate_limit_per_minute;

  return (
    <Section title="Policy constraints">
      <div className="flex flex-col gap-3">
        {policies.length === 0 ? (
          <EmptyState
            compact
            title="No policy constraints declared"
            body="The registry-loader has not pinned any Cedar policies for this entry. Tool calls are gated by the global Cedar bundle only."
          />
        ) : (
          <div
            data-testid="mcp-detail-policy-cedar"
            // Fixed height so the layout stays predictable while Monaco
            // boots; the boundary's textarea fallback also fills this box.
            className="overflow-hidden rounded border border-r5e-border bg-r5e-bg"
            style={{ height: 160 }}
          >
            <CedarEditorBoundary
              value={cedarSource}
              // No-op: the editor is read-only; onChange is required by
              // the Boundary contract for the textarea fallback path.
              onChange={() => undefined}
            >
              <Suspense fallback={<Skeleton.Block className="h-40 w-full" />}>
                <CedarEditor
                  value={cedarSource}
                  onChange={() => undefined}
                  readOnly
                  height="100%"
                />
              </Suspense>
            </CedarEditorBoundary>
          </div>
        )}
        {rateLimit !== undefined ? (
          <div
            className="text-[12px] text-r5e-muted"
            data-testid="mcp-detail-rate-limit"
          >
            Rate limit:{" "}
            <span className="font-mono text-r5e-text">
              {rateLimit} calls / minute
            </span>
            {rateLimit === 0 ? (
              <span className="ml-2 text-r5e-warning">
                (0 ⇒ all calls policy-denied)
              </span>
            ) : null}
          </div>
        ) : null}
      </div>
    </Section>
  );
}

function SbomSection({ entry }: { entry: McpRegistryEntry }): JSX.Element {
  const components = entry.sbom.components ?? [];
  return (
    <Section title="SBOM">
      <div
        className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-r5e-muted"
        data-testid="mcp-detail-sbom-meta"
      >
        <span>
          Format: <span className="text-r5e-text">{entry.sbom.format}</span>
        </span>
        <span>
          Digest:{" "}
          <code className="rounded bg-r5e-bg px-1 py-0.5 font-mono text-[11px] text-r5e-text">
            {entry.sbom.digest}
          </code>
        </span>
      </div>
      {components.length === 0 ? (
        <EmptyState
          compact
          title="No SBOM components"
          body="The SBOM payload for this entry was empty."
        />
      ) : (
        <div className="overflow-hidden rounded border border-r5e-border bg-r5e-surface">
          <table className="w-full text-left text-[13px]">
            <thead className="bg-r5e-bg text-[11px] uppercase tracking-wider text-r5e-muted">
              <tr>
                <th className="px-4 py-2 font-mono font-semibold">Component</th>
                <th className="w-[120px] px-4 py-2 font-mono font-semibold">
                  Version
                </th>
                <th className="w-[120px] px-4 py-2 font-mono font-semibold">
                  License
                </th>
                <th className="px-4 py-2 font-mono font-semibold">
                  Vulnerabilities
                </th>
              </tr>
            </thead>
            <tbody>
              {components.map((c) => (
                <tr
                  key={`${c.name}@${c.version}`}
                  className="border-t border-r5e-border align-top"
                  data-testid={`mcp-detail-sbom-row-${c.name}`}
                >
                  <td className="px-4 py-2 font-mono text-r5e-text">{c.name}</td>
                  <td className="px-4 py-2 font-mono text-r5e-muted">
                    {c.version}
                  </td>
                  <td className="px-4 py-2 text-r5e-muted">
                    {c.license ?? "—"}
                  </td>
                  <td className="px-4 py-2">
                    {(c.vulnerabilities ?? []).length === 0 ? (
                      <span className="text-r5e-muted">none</span>
                    ) : (
                      <ul className="flex flex-col gap-1.5">
                        {(c.vulnerabilities ?? []).map((v) => (
                          <CveRow key={v.id} vulnerability={v} />
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

function CveRow({
  vulnerability,
}: {
  vulnerability: McpVulnerability;
}): JSX.Element {
  const { id, severity, summary, url } = vulnerability;
  const idElement = url ? (
    <a
      href={url}
      target="_blank"
      rel="noreferrer noopener"
      className="font-mono text-[12px] text-r5e-accent hover:underline"
      data-testid={`mcp-detail-cve-link-${id}`}
    >
      {id}
    </a>
  ) : (
    <code className="font-mono text-[12px] text-r5e-text">{id}</code>
  );

  return (
    <li
      className="flex flex-col gap-0.5"
      data-testid={`mcp-detail-cve-${id}`}
    >
      <span className="flex items-center gap-2">
        <SeverityPill severity={severity} />
        {idElement}
      </span>
      <span className="text-[12px] text-r5e-muted">{summary}</span>
    </li>
  );
}

// ---------------------------------------------------------------------------
// QuarantineButton + dialog
// ---------------------------------------------------------------------------

// Restore-tier memory: when quarantining, we stash the prior tier in
// sessionStorage so the eventual restore round-trip lands on the original
// audited tier (verified→quarantined→verified, not verified→quarantined→
// community per F006). Falls back to `community` if no memory exists —
// e.g. the entry was already quarantined when the operator loaded the
// page, or sessionStorage is unavailable. Scoped to sessionStorage rather
// than localStorage because the memory is only useful inside the operator
// session that performed the quarantine; cross-session restore picks the
// safer default.
const RESTORE_TIER_KEY_PREFIX = "r5e:mcp:restore-tier:";

function readRestoreTier(
  entryId: string,
): McpRegistryEntry["trust_tier"] | null {
  if (typeof window === "undefined" || !window.sessionStorage) return null;
  try {
    const raw = window.sessionStorage.getItem(
      `${RESTORE_TIER_KEY_PREFIX}${entryId}`,
    );
    if (raw === "verified" || raw === "community") return raw;
    return null;
  } catch {
    return null;
  }
}

function writeRestoreTier(
  entryId: string,
  tier: McpRegistryEntry["trust_tier"],
): void {
  if (typeof window === "undefined" || !window.sessionStorage) return;
  try {
    window.sessionStorage.setItem(
      `${RESTORE_TIER_KEY_PREFIX}${entryId}`,
      tier,
    );
  } catch {
    // sessionStorage may be unavailable (private mode, quota); fall through.
  }
}

function clearRestoreTier(entryId: string): void {
  if (typeof window === "undefined" || !window.sessionStorage) return;
  try {
    window.sessionStorage.removeItem(`${RESTORE_TIER_KEY_PREFIX}${entryId}`);
  } catch {
    // ignore
  }
}

function QuarantineButton({ entry }: { entry: McpRegistryEntry }): JSX.Element {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState<boolean>(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [statusBanner, setStatusBanner] = useState<
    | { kind: "success"; message: string }
    | null
  >(null);

  const isQuarantined = entry.trust_tier === "quarantined";

  // Restore target: the remembered prior tier (set when this session
  // performed the quarantine) → verified or community. Fallback for
  // entries that were already quarantined when we loaded is `community`,
  // matching the Phase-1 default in the brief.
  const restoreTier = readRestoreTier(entry.id) ?? "community";
  const targetTier: McpRegistryEntry["trust_tier"] = isQuarantined
    ? restoreTier
    : "quarantined";

  const mutation = useMutation({
    mutationFn: async () => {
      return api.patch<McpRegistryEntry>(
        `/v1/mcp/registry/${encodeURIComponent(entry.id)}`,
        { trust_tier: targetTier },
      );
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["mcp-registry"] });
      void queryClient.invalidateQueries({ queryKey: ["mcp-registry", entry.id] });
      if (isQuarantined) {
        // Successful restore — memory is consumed.
        clearRestoreTier(entry.id);
      } else {
        // Quarantining: remember what tier we came from so the eventual
        // restore lands here.
        writeRestoreTier(entry.id, entry.trust_tier);
      }
      setStatusBanner({
        kind: "success",
        message: isQuarantined
          ? `${entry.name} restored to ${targetTier}. Receipt emitted.`
          : `${entry.name} quarantined. Cedar deny policy added; receipt emitted.`,
      });
      setDialogError(null);
      setOpen(false);
    },
    onError: (err) => {
      // Render the error inside the dialog body so it isn't hidden by the
      // backdrop. The dialog stays up so the operator can retry without
      // re-opening (per F004).
      setDialogError(
        err instanceof ApiError
          ? `${err.error}: ${err.error_description}`
          : String(err),
      );
    },
  });

  function openDialog(): void {
    setDialogError(null);
    setOpen(true);
  }

  function cancelDialog(): void {
    setDialogError(null);
    setOpen(false);
  }

  return (
    <div className="flex flex-col items-end gap-2">
      <button
        type="button"
        data-testid="mcp-detail-quarantine-button"
        onClick={openDialog}
        className={
          isQuarantined
            ? "rounded border border-r5e-success px-3 py-1.5 text-[12px] font-medium text-r5e-success transition-colors hover:bg-r5e-success/15"
            : "rounded border border-r5e-warning px-3 py-1.5 text-[12px] font-medium text-r5e-warning transition-colors hover:bg-r5e-warning/15"
        }
      >
        {isQuarantined ? "Restore from quarantine" : "Quarantine this server"}
      </button>
      {statusBanner ? (
        <div
          data-testid="mcp-detail-quarantine-status"
          role="status"
          className="rounded border border-r5e-success/40 bg-r5e-success/10 px-2 py-1 text-[11px] text-r5e-success"
        >
          {statusBanner.message}
        </div>
      ) : null}
      {open ? (
        <QuarantineDialog
          entry={entry}
          mode={isQuarantined ? "restore" : "quarantine"}
          targetTier={targetTier}
          error={dialogError}
          onCancel={cancelDialog}
          onConfirm={() => mutation.mutate()}
          pending={mutation.isPending}
        />
      ) : null}
    </div>
  );
}

function QuarantineDialog({
  entry,
  mode,
  targetTier,
  error,
  onCancel,
  onConfirm,
  pending,
}: {
  entry: McpRegistryEntry;
  mode: "quarantine" | "restore";
  targetTier: McpRegistryEntry["trust_tier"];
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
  pending: boolean;
}): JSX.Element {
  const isQuarantine = mode === "quarantine";
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="mcp-detail-quarantine-title"
      data-testid="mcp-detail-quarantine-dialog"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
    >
      <div className="flex max-w-md flex-col gap-4 rounded border border-r5e-border bg-r5e-surface p-5">
        <h2
          id="mcp-detail-quarantine-title"
          className="text-[14px] font-semibold text-r5e-text"
        >
          {isQuarantine
            ? `Quarantine ${entry.name}?`
            : `Restore ${entry.name} from quarantine?`}
        </h2>
        <p className="text-[12px] leading-relaxed text-r5e-muted">
          {isQuarantine ? (
            <>
              This will set <code className="font-mono">trust_tier=quarantined</code>{" "}
              and add a forbid policy for all tool calls against this server.
              Existing in-flight tool calls will be denied. The change is
              itself attested as a{" "}
              <code className="font-mono">:ui_mcp_quarantine</code> receipt.
            </>
          ) : (
            <>
              This will set{" "}
              <code className="font-mono">trust_tier={targetTier}</code> and
              remove the forbid policy. Tool calls become subject to the
              global Cedar bundle only. The change is attested as a{" "}
              <code className="font-mono">:ui_mcp_quarantine</code> receipt.
            </>
          )}
        </p>
        {error ? (
          <div
            role="alert"
            data-testid="mcp-detail-quarantine-dialog-error"
            className="rounded border border-r5e-danger/40 bg-r5e-danger/10 px-2 py-1.5 text-[11px] text-r5e-danger"
          >
            {error}
          </div>
        ) : null}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={pending}
            data-testid="mcp-detail-quarantine-cancel"
            className="rounded border border-r5e-border px-3 py-1.5 text-[12px] text-r5e-muted hover:text-r5e-text"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            data-testid="mcp-detail-quarantine-confirm"
            className={
              isQuarantine
                ? "rounded border border-r5e-warning bg-r5e-warning/15 px-3 py-1.5 text-[12px] font-medium text-r5e-warning hover:bg-r5e-warning/25 disabled:opacity-50"
                : "rounded border border-r5e-success bg-r5e-success/15 px-3 py-1.5 text-[12px] font-medium text-r5e-success hover:bg-r5e-success/25 disabled:opacity-50"
            }
          >
            {pending
              ? "…"
              : isQuarantine
                ? "Quarantine"
                : `Restore to ${targetTier}`}
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section / Field layout primitives — local to this page; the brief calls
// for a flat 2-column grid which the Audit Console uses elsewhere only as
// inline JSX.
// ---------------------------------------------------------------------------

function Section({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}): JSX.Element {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="font-mono text-[11px] font-semibold uppercase tracking-wider text-r5e-muted">
        {title}
      </h2>
      <div className="rounded border border-r5e-border bg-r5e-surface p-4">
        {children}
      </div>
    </section>
  );
}

function Field({
  label,
  children,
  wide,
}: {
  label: string;
  children: ReactNode;
  wide?: boolean;
}): JSX.Element {
  return (
    <div className={wide ? "col-span-2" : "col-span-1"}>
      <dt className="font-mono text-[10px] uppercase tracking-wider text-r5e-muted">
        {label}
      </dt>
      <dd className="mt-1 text-[13px] text-r5e-text">{children}</dd>
    </div>
  );
}
