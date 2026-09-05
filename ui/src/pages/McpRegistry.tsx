// MCP Registry — Audit Console catalog page for trusted MCP servers.
//
// Per design/briefs/07-mcp-registry.md (F7). The list view is the entry
// point into the MCP/SBOM/Trusted-Registry vertical-slice demo (Path B):
// every MCP tool call gets a receipt with cryptographic provenance, every
// server has an SBOM, vulnerable servers are quarantined.
//
// Layout per F7 brief:
//   - <RegistryHeader /> with title + subtitle (R4 typography).
//   - Table with columns: NAME | PUBLISHER | TRUST TIER | VERSION |
//     TRANSPORT | CVES.
//   - NAME column: bold link → /admin/mcp-registry/<id>; below: 2-line
//     truncated description in r5e-muted.
//   - TRUST TIER column: <Pill> per tier (verified=success-green;
//     community=muted-slate; quarantined=warning-orange).
//   - VERSION + TRANSPORT: mono small.
//   - CVES: count badge — 0 = muted text; ≥1 = warning-orange Pill;
//     ≥1 HIGH/CRITICAL = danger-red Pill.
//   - Whole row clickable (row-level <Link> wrapper via onClick navigate).
//
// R5 states:
//   - Loading: <Skeleton.Rows rows={5} />.
//   - Error: <ErrorState retry={refetch} />.
//   - Empty: <EmptyState ... /> per brief copy.
//
// CSP rule: NO third-party CDN-loaded chart libs (CSP forbids
// `<script src="https://cdn.jsdelivr.net/...">` etc.). Hand-rolled SVG /
// table view only. See the agent-brief CSP-vs-third-party-CDN gotcha.

import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";

import { TrustTierPill } from "~/components/mcp/TrustTierPill";
import { TopBar } from "~/components/shared/TopBar";
import { Pill } from "~/components/shared/Pill";
import { EmptyState, ErrorState, Skeleton } from "~/components/shared/states";
import { api, ApiError } from "~/lib/api";
import { ADMIN_BASE, mcpRegistryDetailPath } from "~/lib/routes";
import type {
  McpRegistryEntry,
  McpRegistryListResponse,
  McpVulnerability,
} from "~/lib/types";

const REGISTRY_PATH = "/v1/mcp/registry";

// Aggregated CVE summary: total count + worst severity present.
interface CveSummary {
  count: number;
  worst: McpVulnerability["severity"] | null;
}

function summarizeVulnerabilities(entry: McpRegistryEntry): CveSummary {
  let count = 0;
  let worst: McpVulnerability["severity"] | null = null;
  const order: Record<McpVulnerability["severity"], number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    unknown: 0,
  };
  for (const c of entry.sbom.components ?? []) {
    for (const v of c.vulnerabilities ?? []) {
      count += 1;
      if (worst === null || order[v.severity] > order[worst]) {
        worst = v.severity;
      }
    }
  }
  return { count, worst };
}

function CveCountBadge({
  summary,
  testId,
}: {
  summary: CveSummary;
  testId?: string;
}): JSX.Element {
  if (summary.count === 0) {
    return (
      <span className="font-mono text-[12px] text-r5e-muted" data-testid={testId}>
        0
      </span>
    );
  }
  // High / critical → danger red. Medium / low / unknown → warning orange.
  const tone = summary.worst === "high" || summary.worst === "critical"
    ? "danger"
    : "warning";
  return (
    <Pill tone={tone} size="xs" testId={testId} uppercase={false}>
      {summary.count}
    </Pill>
  );
}

export default function McpRegistry(): JSX.Element {
  const { data, isLoading, error, refetch } = useQuery<McpRegistryListResponse>({
    queryKey: ["mcp-registry"],
    queryFn: () => api.get<McpRegistryListResponse>(REGISTRY_PATH),
  });

  return (
    <>
      <TopBar
        pageContent={
          <div className="flex flex-col">
            <span className="text-[14px] font-semibold text-r5e-text">
              MCP Registry
            </span>
            <span className="text-[12px] text-r5e-muted">
              Trusted MCP servers — every tool call attested with cryptographic
              provenance.
            </span>
          </div>
        }
      />

      <main
        data-testid="mcp-registry-page"
        className="flex flex-1 flex-col overflow-auto bg-r5e-bg p-6 font-sans text-r5e-text"
      >
        {isLoading ? (
          <div data-testid="mcp-registry-loading">
            <Skeleton.Rows rows={5} testId="mcp-registry-loading-rows" />
          </div>
        ) : error ? (
          <ErrorState
            testId="mcp-registry-error"
            title="Couldn't load MCP registry"
            body="The registry endpoint returned an error. Try again or check your connection."
            detail={error instanceof ApiError ? error.error_description : String(error)}
            retry={{ onClick: () => void refetch() }}
          />
        ) : data ? (
          <RegistryTable entries={data.entries} />
        ) : null}
      </main>
    </>
  );
}

function RegistryTable({
  entries,
}: {
  entries: McpRegistryEntry[];
}): JSX.Element {
  const navigate = useNavigate();

  if (entries.length === 0) {
    return (
      <EmptyState
        testId="mcp-registry-empty"
        title="No MCP servers registered"
        body="Curated MCP entries appear here. Add an entry via the registry-loader config or via the admin API."
      />
    );
  }

  return (
    <div
      data-testid="mcp-registry-table"
      className="overflow-hidden rounded border border-r5e-border bg-r5e-surface"
    >
      <table className="w-full text-left text-[13px]">
        <thead className="bg-r5e-bg text-[11px] uppercase tracking-wider text-r5e-muted">
          <tr>
            <th className="px-4 py-3 font-mono font-semibold">Name</th>
            <th className="w-[200px] px-4 py-3 font-mono font-semibold">
              Publisher
            </th>
            <th className="w-[130px] px-4 py-3 font-mono font-semibold">
              Trust tier
            </th>
            <th className="w-[100px] px-4 py-3 font-mono font-semibold">
              Version
            </th>
            <th className="w-[100px] px-4 py-3 font-mono font-semibold">
              Transport
            </th>
            <th className="w-[80px] px-4 py-3 text-right font-mono font-semibold">
              CVEs
            </th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => {
            const summary = summarizeVulnerabilities(entry);
            // The router-internal path (no /admin basename) is used by
            // navigate(); the absolute href on the visible <a> includes
            // /admin so middle-click + keyboard-open hit the correct URL
            // (and so the unit test for /admin/mcp-registry/<id> passes
            // — Pencil dev-handoff convention).
            const routerPath = mcpRegistryDetailPath(entry.id);
            const absoluteHref = `${ADMIN_BASE}${routerPath}`;
            return (
              <tr
                key={entry.id}
                data-testid={`mcp-registry-row-${entry.id}`}
                onClick={() => navigate(routerPath)}
                className="cursor-pointer border-t border-r5e-border transition-colors hover:bg-r5e-surface/60 focus-within:bg-r5e-surface/60"
              >
                <td className="px-4 py-3 align-top">
                  {/* Real anchor for keyboard nav + middle-click open;
                      preventDefault on plain left-click so the row's
                      onClick handles it (one navigate). Modifier-clicks
                      (cmd/ctrl/shift/middle) fall through to the browser
                      default so "open in new tab" still works. */}
                  <a
                    href={absoluteHref}
                    onClick={(e) => {
                      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) {
                        return;
                      }
                      e.preventDefault();
                    }}
                    className="font-semibold text-r5e-text hover:text-r5e-accent"
                    data-testid={`mcp-registry-link-${entry.id}`}
                  >
                    {entry.name}
                  </a>
                  <div className="mt-1 line-clamp-2 text-[12px] text-r5e-muted">
                    {entry.description}
                  </div>
                </td>
                <td className="px-4 py-3 align-top text-r5e-muted">
                  {entry.publisher}
                </td>
                <td className="px-4 py-3 align-top">
                  <TrustTierPill
                    tier={entry.trust_tier}
                    testId={`mcp-registry-tier-${entry.id}`}
                  />
                </td>
                <td className="px-4 py-3 align-top font-mono text-r5e-text">
                  {entry.version}
                </td>
                <td className="px-4 py-3 align-top font-mono text-r5e-muted">
                  {entry.transport}
                </td>
                <td className="px-4 py-3 text-right align-top">
                  <CveCountBadge
                    summary={summary}
                    testId={`mcp-registry-cve-count-${entry.id}`}
                  />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
