// Vitest unit tests for the MCP Registry pages — list + detail.
//
// Verifies:
//   - Loading / error / empty states render.
//   - Each registry entry produces a row with name, trust-tier chip, CVE count.
//   - Trust-tier pill data-tone matches R4 palette mapping (verified=success,
//     community=muted, quarantined=warning).
//   - CVE count badge: 0 → muted text; ≥1 → warning pill; HIGH/CRITICAL →
//     danger pill (per F7 brief).
//   - Detail page renders SBOM components + per-component vulnerabilities.
//   - Detail page renders Capabilities, Policy Constraints (Cedar), SBOM.
//   - Quarantine button is visible to platform_operator + hidden from
//     tenant_auditor (operator-only workflow per F7 brief).
//   - Outbound link to detail uses the absolute /admin path so middle-click
//     + keyboard-open hit the right URL (no /admin/admin double-prefix).

import { render, screen, fireEvent } from "@testing-library/react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";

import McpRegistry from "~/pages/McpRegistry";
import McpRegistryDetail from "~/pages/McpRegistryDetail";
import type {
  McpRegistryEntry,
  McpRegistryListResponse,
} from "~/lib/types";

// ----- Mocks ---------------------------------------------------------------

// CedarEditor pulls Monaco; stub it out so the policy-constraints panel
// renders deterministically in jsdom (no canvas / loader / WebWorker).
vi.mock("~/components/policy/CedarEditor", () => ({
  default: ({ value }: { value: string }) => (
    <div data-testid="cedar-editor-stub">{value}</div>
  ),
}));

// CedarEditorBoundary's timeout-guard hooks `window.setTimeout`; the stub
// just renders children inline.
vi.mock("~/components/policy/CedarEditorBoundary", () => ({
  default: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

// Per-test override of useAuth's role. Defaults to platform_operator (so
// the Quarantine button renders); the auditor-only test changes the
// implementation before render.
let currentRole: "platform_operator" | "tenant_auditor" = "platform_operator";
vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => ({
    status: "authenticated" as const,
    role: currentRole,
    principal: "operator-1",
    tenantId: "tenant-a",
  }),
}));

const mockEntries: McpRegistryEntry[] = [
  {
    id: "r5e-audit-mcp",
    name: "Recurse Audit MCP",
    description: "Verified MCP for the audit plane",
    source: "github.com/r5e/audit-mcp",
    version: "0.1.0",
    transport: "http",
    trust_tier: "verified",
    publisher: "r5e-group",
    capabilities: { tools: [{ name: "list_receipts", description: "list" }] },
    policy_constraints: { cedar_policies: [], rate_limit_per_minute: 60 },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:abc",
      components: [
        {
          name: "elixir",
          version: "1.18.1",
          license: "Apache-2.0",
          vulnerabilities: [],
        },
      ],
    },
  },
  {
    id: "filesystem-mcp",
    name: "Filesystem MCP",
    description: "Community-tier filesystem access",
    source: "github.com/modelcontextprotocol/filesystem-mcp",
    version: "0.6.2",
    transport: "stdio",
    trust_tier: "community",
    publisher: "modelcontextprotocol",
    capabilities: { tools: [{ name: "read_file", description: "read" }] },
    policy_constraints: { cedar_policies: [], rate_limit_per_minute: 30 },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:fs",
      components: [
        {
          name: "fs-glob",
          version: "1.0.0",
          license: "MIT",
          vulnerabilities: [],
        },
      ],
    },
  },
  {
    id: "legacy-pdf-mcp",
    name: "Legacy PDF MCP",
    description: "Quarantined entry",
    source: "github.com/legacy/pdf-mcp",
    version: "0.3.0",
    transport: "stdio",
    trust_tier: "quarantined",
    publisher: "example-org",
    capabilities: { tools: [{ name: "render_pdf", description: "render" }] },
    policy_constraints: {
      cedar_policies: ["forbid(...);"],
      rate_limit_per_minute: 0,
    },
    sbom: {
      format: "cyclonedx-1.5-subset",
      digest: "sha256:bad",
      components: [
        {
          name: "pdfjs-dist",
          version: "2.5.207",
          license: "Apache-2.0",
          vulnerabilities: [
            {
              id: "CVE-2024-4367",
              severity: "high",
              summary: "PDF.js arbitrary JS exec",
              fixed_versions: [">=4.2.67"],
              source: "nvd",
            },
            {
              id: "CVE-2024-9999",
              severity: "medium",
              summary: "Older MCP SDK leaks request bodies into stderr",
              source: "nvd",
            },
          ],
        },
      ],
    },
  },
];

const mockListResponse: McpRegistryListResponse = {
  version: "1.0.0",
  generated_at: "2026-04-30T00:00:00Z",
  description: "Test catalog",
  entries: mockEntries,
};

beforeEach(() => {
  currentRole = "platform_operator";
  vi.spyOn(global, "fetch").mockImplementation(async (input) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url === "/v1/mcp/registry") {
      return new Response(JSON.stringify(mockListResponse), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (url.startsWith("/v1/mcp/registry/")) {
      const id = decodeURIComponent(url.split("/").pop() ?? "");
      const entry = mockEntries.find((e) => e.id === id);
      if (!entry) {
        return new Response(
          JSON.stringify({
            error: "not_found",
            error_description: "missing",
            correlation_id: "c-1",
            attested_run_id: null,
          }),
          { status: 404, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(JSON.stringify(entry), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response("not mocked", { status: 500 });
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

function renderList() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter basename="/admin" initialEntries={["/admin/mcp-registry"]}>
        <Routes>
          <Route path="/mcp-registry" element={<McpRegistry />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function renderDetail(id: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter
        basename="/admin"
        initialEntries={[`/admin/mcp-registry/${id}`]}
      >
        <Routes>
          <Route
            path="/mcp-registry/:id"
            element={<McpRegistryDetail />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("McpRegistry list page", () => {
  it("renders the catalog table once data loads", async () => {
    renderList();
    expect(await screen.findByTestId("mcp-registry-table")).toBeInTheDocument();
    expect(screen.getByTestId("mcp-registry-row-r5e-audit-mcp")).toBeInTheDocument();
    expect(screen.getByTestId("mcp-registry-row-legacy-pdf-mcp")).toBeInTheDocument();
  });

  it("renders trust-tier chips with the entry's tier as text", async () => {
    renderList();
    const chip = await screen.findByTestId(
      "mcp-registry-tier-r5e-audit-mcp",
    );
    expect(chip.textContent).toMatch(/verified/i);
    const quarantineChip = screen.getByTestId(
      "mcp-registry-tier-legacy-pdf-mcp",
    );
    expect(quarantineChip.textContent).toMatch(/quarantined/i);
  });

  it("renders a CVE-count chip for entries with vulnerabilities", async () => {
    renderList();
    const cve = await screen.findByTestId(
      "mcp-registry-cve-count-legacy-pdf-mcp",
    );
    // Two vulnerabilities total in the quarantined fixture.
    expect(cve.textContent?.trim()).toBe("2");
  });

  it("uses danger tone for HIGH/CRITICAL CVEs and warning for medium-only", async () => {
    renderList();
    // legacy-pdf-mcp has a HIGH CVE → worst severity drives the badge tone.
    const highCve = await screen.findByTestId(
      "mcp-registry-cve-count-legacy-pdf-mcp",
    );
    expect(highCve.getAttribute("data-tone")).toBe("danger");
  });

  it("renders 0 CVEs as muted text (not a pill)", async () => {
    renderList();
    const zero = await screen.findByTestId(
      "mcp-registry-cve-count-r5e-audit-mcp",
    );
    expect(zero.textContent?.trim()).toBe("0");
    // Plain span (not a Pill) — has no data-tone attribute.
    expect(zero.getAttribute("data-tone")).toBeNull();
  });

  it("maps trust tiers to the right Pill tone (verified=success, community=muted, quarantined=warning)", async () => {
    renderList();
    const verified = await screen.findByTestId(
      "mcp-registry-tier-r5e-audit-mcp",
    );
    expect(verified.getAttribute("data-tone")).toBe("success");

    const community = screen.getByTestId("mcp-registry-tier-filesystem-mcp");
    expect(community.getAttribute("data-tone")).toBe("muted");

    const quarantined = screen.getByTestId(
      "mcp-registry-tier-legacy-pdf-mcp",
    );
    expect(quarantined.getAttribute("data-tone")).toBe("warning");
  });

  it("does not produce /admin/admin double-prefix on the detail link", async () => {
    renderList();
    const link = await screen.findByTestId("mcp-registry-link-r5e-audit-mcp");
    const href = link.getAttribute("href") ?? "";
    expect(href.startsWith("/admin/admin")).toBe(false);
    expect(href).toBe("/admin/mcp-registry/r5e-audit-mcp");
  });
});

describe("McpRegistryDetail page", () => {
  it("renders SBOM table with vulnerabilities", async () => {
    renderDetail("legacy-pdf-mcp");
    expect(await screen.findByTestId("mcp-detail-trust-tier")).toHaveTextContent(
      /quarantined/i,
    );
    expect(screen.getByTestId("mcp-detail-sbom-row-pdfjs-dist")).toBeInTheDocument();
    expect(screen.getByTestId("mcp-detail-cve-CVE-2024-4367")).toBeInTheDocument();
  });

  it("renders a 404 error envelope when the id misses", async () => {
    renderDetail("ghost");
    expect(await screen.findByTestId("mcp-registry-detail-error")).toBeInTheDocument();
  });

  it("renders capability cards for each declared tool", async () => {
    renderDetail("legacy-pdf-mcp");
    await screen.findByTestId("mcp-detail-trust-tier");
    expect(screen.getByTestId("mcp-detail-capability-render_pdf")).toBeInTheDocument();
  });

  it("renders the canonical quarantined warning banner above Overview", async () => {
    renderDetail("legacy-pdf-mcp");
    const banner = await screen.findByTestId("mcp-detail-quarantined-banner");
    expect(banner).toHaveTextContent(/QUARANTINED/i);
    expect(banner).toHaveTextContent(/policy-denied/i);
  });

  it("renders the Cedar policy block read-only when constraints are declared", async () => {
    renderDetail("legacy-pdf-mcp");
    expect(await screen.findByTestId("mcp-detail-policy-cedar")).toBeInTheDocument();
    // The stubbed CedarEditor receives the joined cedar_policies string.
    expect(screen.getByTestId("cedar-editor-stub")).toHaveTextContent(/forbid/);
  });

  it("renders the rate-limit row with deny annotation when 0", async () => {
    renderDetail("legacy-pdf-mcp");
    const rateLimit = await screen.findByTestId("mcp-detail-rate-limit");
    expect(rateLimit.textContent ?? "").toMatch(/0 calls \/ minute/);
    expect(rateLimit.textContent ?? "").toMatch(/policy-denied/);
  });

  it("renders severity pills with correct tones for HIGH and MEDIUM CVEs", async () => {
    renderDetail("legacy-pdf-mcp");
    const highCve = await screen.findByTestId("mcp-detail-cve-CVE-2024-4367");
    const highPill = highCve.querySelector('[data-testid="pill"]');
    expect(highPill?.getAttribute("data-tone")).toBe("danger");

    const medCve = screen.getByTestId("mcp-detail-cve-CVE-2024-9999");
    const medPill = medCve.querySelector('[data-testid="pill"]');
    expect(medPill?.getAttribute("data-tone")).toBe("warning");
  });

  it("shows the Quarantine button to platform_operator", async () => {
    currentRole = "platform_operator";
    renderDetail("filesystem-mcp");
    const button = await screen.findByTestId("mcp-detail-quarantine-button");
    expect(button.textContent ?? "").toMatch(/quarantine/i);
  });

  it("hides the Quarantine button from tenant_auditor", async () => {
    currentRole = "tenant_auditor";
    renderDetail("filesystem-mcp");
    await screen.findByTestId("mcp-detail-trust-tier");
    expect(screen.queryByTestId("mcp-detail-quarantine-button")).toBeNull();
  });

  it("flips the Quarantine button copy to Restore when entry is already quarantined", async () => {
    currentRole = "platform_operator";
    renderDetail("legacy-pdf-mcp");
    const button = await screen.findByTestId("mcp-detail-quarantine-button");
    expect(button.textContent ?? "").toMatch(/restore/i);
  });

  it("opens a confirmation dialog before submitting a quarantine action", async () => {
    currentRole = "platform_operator";
    renderDetail("filesystem-mcp");
    const button = await screen.findByTestId("mcp-detail-quarantine-button");
    fireEvent.click(button);
    expect(screen.getByTestId("mcp-detail-quarantine-dialog")).toBeInTheDocument();
    expect(screen.getByTestId("mcp-detail-quarantine-confirm")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-cancel"));
    expect(screen.queryByTestId("mcp-detail-quarantine-dialog")).toBeNull();
  });
});
