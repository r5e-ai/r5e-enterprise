// McpRegistryDetail — PATCH mutation tests.
//
// Closes F7 GAN F005 (`PATCH mutation path is not exercised by any test`).
// The McpRegistry.test.tsx file already covers list-table tone mapping,
// detail-page skeleton/error/empty states, role gating, dialog open +
// cancel, and the Restore-copy flip. This file is the dedicated home for
// the mutation lifecycle:
//
//   - Success path: confirm click PATCHes the entry, query cache is
//     invalidated, success banner renders, dialog closes.
//   - Error path: confirm click yields an API error, dialog stays open
//     with an inline error message inside the dialog body (NOT hidden
//     behind the modal backdrop — see F004).
//   - Dialog state machine: cancel after error clears the error;
//     re-opening starts clean; restore lands on the prior tier per F006
//     (verified→quarantined→verified, NOT verified→quarantined→
//     community).

import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import {
  describe,
  expect,
  it,
  vi,
  beforeEach,
  afterEach,
} from "vitest";

import McpRegistryDetail from "~/pages/McpRegistryDetail";
import type { McpRegistryEntry } from "~/lib/types";

// ----- Mocks ---------------------------------------------------------------

vi.mock("~/components/policy/CedarEditor", () => ({
  default: ({ value }: { value: string }) => (
    <div data-testid="cedar-editor-stub">{value}</div>
  ),
}));

vi.mock("~/components/policy/CedarEditorBoundary", () => ({
  default: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

// Default to platform_operator so the QuarantineButton + dialog render.
let currentRole: "platform_operator" | "tenant_auditor" = "platform_operator";
vi.mock("~/hooks/useAuth", () => ({
  useAuth: () => ({
    status: "authenticated" as const,
    role: currentRole,
    principal: "operator-1",
    tenantId: "tenant-a",
  }),
}));

// In-memory mutable registry — PATCH actually flips the trust_tier so
// subsequent GETs see the new state (mirrors the dev-mocks plugin).
const baseEntries: McpRegistryEntry[] = [
  {
    id: "filesystem-mcp",
    name: "Filesystem MCP",
    description: "community-tier filesystem access",
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
    id: "r5e-audit-mcp",
    name: "Recurse Audit MCP",
    description: "verified MCP for the audit plane",
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
      components: [],
    },
  },
];

let registry: McpRegistryEntry[];

// Test-controlled error injection: when set, the next PATCH call resolves
// to a 500 envelope. Cleared automatically after one trip.
let nextPatchError: { status: number; envelope: object } | null = null;

type FetchArgs = Parameters<typeof fetch>;
type FetchInit = NonNullable<FetchArgs[1]>;

function fetchMock(input: FetchArgs[0], init?: FetchArgs[1]): Promise<Response> {
  const url = typeof input === "string" ? input : input.toString();
  const method = (init?.method ?? "GET").toUpperCase();
  const detailMatch = url.match(/^\/v1\/mcp\/registry\/([^/?#]+)/);
  if (detailMatch && detailMatch[1] !== undefined) {
    const id = decodeURIComponent(detailMatch[1]);
    const idx = registry.findIndex((e) => e.id === id);
    if (idx === -1) {
      return Promise.resolve(
        new Response(
          JSON.stringify({
            error: "not_found",
            error_description: "missing",
            correlation_id: "c-1",
            attested_run_id: null,
          }),
          { status: 404, headers: { "content-type": "application/json" } },
        ),
      );
    }
    const current = registry[idx];
    if (!current) {
      return Promise.resolve(new Response("not mocked", { status: 500 }));
    }
    if (method === "GET") {
      return Promise.resolve(
        new Response(JSON.stringify(current), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }
    if (method === "PATCH") {
      if (nextPatchError) {
        const err = nextPatchError;
        nextPatchError = null;
        return Promise.resolve(
          new Response(JSON.stringify(err.envelope), {
            status: err.status,
            headers: { "content-type": "application/json" },
          }),
        );
      }
      const body = JSON.parse((init?.body as string) ?? "{}") as {
        trust_tier?: McpRegistryEntry["trust_tier"];
      };
      const updated: McpRegistryEntry = body.trust_tier
        ? { ...current, trust_tier: body.trust_tier }
        : current;
      registry[idx] = updated;
      return Promise.resolve(
        new Response(JSON.stringify(updated), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    }
  }
  return Promise.resolve(new Response("not mocked", { status: 500 }));
}

beforeEach(() => {
  currentRole = "platform_operator";
  registry = baseEntries.map((e) => ({ ...e }));
  nextPatchError = null;
  if (typeof window !== "undefined" && window.sessionStorage) {
    window.sessionStorage.clear();
  }
  vi.spyOn(global, "fetch").mockImplementation(
    fetchMock as unknown as typeof fetch,
  );
});

afterEach(() => {
  vi.restoreAllMocks();
});

function renderDetail(id: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const utils = render(
    <QueryClientProvider client={qc}>
      <MemoryRouter
        basename="/admin"
        initialEntries={[`/admin/mcp-registry/${id}`]}
      >
        <Routes>
          <Route path="/mcp-registry/:id" element={<McpRegistryDetail />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { qc, ...utils };
}

describe("McpRegistryDetail PATCH mutation", () => {
  it("PATCHes the entry to quarantined and shows the success banner on confirm", async () => {
    renderDetail("filesystem-mcp");
    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-confirm"));

    // Banner shows quarantine confirmation copy.
    const banner = await screen.findByTestId("mcp-detail-quarantine-status");
    expect(banner.textContent ?? "").toMatch(/quarantined/i);
    expect(banner.textContent ?? "").toMatch(/receipt emitted/i);

    // Dialog closed on success.
    expect(screen.queryByTestId("mcp-detail-quarantine-dialog")).toBeNull();

    // The fetch mock recorded a PATCH call with the right body.
    const patchCall = vi
      .mocked(global.fetch)
      .mock.calls.find(([, init]) => (init as FetchInit | undefined)?.method === "PATCH");
    expect(patchCall).toBeTruthy();
    const [, init] = patchCall ?? [];
    const body = JSON.parse(((init as FetchInit).body as string) ?? "{}");
    expect(body).toEqual({ trust_tier: "quarantined" });
  });

  it("invalidates the registry queries so the cache reflects the new tier", async () => {
    const { qc } = renderDetail("filesystem-mcp");
    const invalidateSpy = vi.spyOn(qc, "invalidateQueries");

    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-confirm"));
    await screen.findByTestId("mcp-detail-quarantine-status");

    // Both the list cache and the per-entry cache are invalidated.
    const calls = invalidateSpy.mock.calls.map((c) => c[0]);
    expect(calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ queryKey: ["mcp-registry"] }),
        expect.objectContaining({ queryKey: ["mcp-registry", "filesystem-mcp"] }),
      ]),
    );
  });

  it("renders an inline error inside the dialog body on PATCH failure (not behind the backdrop)", async () => {
    nextPatchError = {
      status: 500,
      envelope: {
        error: "internal_error",
        error_description: "ledger commit failed",
        correlation_id: "c-err",
        attested_run_id: null,
      },
    };
    renderDetail("filesystem-mcp");
    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-confirm"));

    // Inline dialog error appears.
    const inline = await screen.findByTestId(
      "mcp-detail-quarantine-dialog-error",
    );
    expect(inline.textContent ?? "").toMatch(/internal_error/);
    expect(inline.textContent ?? "").toMatch(/ledger commit failed/);

    // Dialog is still open so the error is visible alongside it.
    expect(
      screen.getByTestId("mcp-detail-quarantine-dialog"),
    ).toBeInTheDocument();

    // The success banner did NOT render — there was no state change.
    expect(
      screen.queryByTestId("mcp-detail-quarantine-status"),
    ).toBeNull();
  });

  it("clears the dialog error when the operator cancels and re-opens", async () => {
    nextPatchError = {
      status: 500,
      envelope: {
        error: "internal_error",
        error_description: "ledger commit failed",
        correlation_id: "c-err",
        attested_run_id: null,
      },
    };
    renderDetail("filesystem-mcp");
    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-confirm"));
    await screen.findByTestId("mcp-detail-quarantine-dialog-error");

    // Cancel — dialog closes.
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-cancel"));
    await waitFor(() =>
      expect(screen.queryByTestId("mcp-detail-quarantine-dialog")).toBeNull(),
    );

    // Re-open — error is gone (clean slate).
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-button"));
    expect(screen.getByTestId("mcp-detail-quarantine-dialog")).toBeInTheDocument();
    expect(
      screen.queryByTestId("mcp-detail-quarantine-dialog-error"),
    ).toBeNull();
  });

  it("remembers the prior tier so verified→quarantined→verified, not verified→quarantined→community", async () => {
    // Round-trip a verified entry: quarantine, then unmount + remount the
    // detail at the same id (simulating a navigate-back-and-forth) and
    // confirm the restore call uses verified, not community.
    const verifiedId = "r5e-audit-mcp";
    const first = renderDetail(verifiedId);
    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    fireEvent.click(screen.getByTestId("mcp-detail-quarantine-confirm"));
    await screen.findByTestId("mcp-detail-quarantine-status");

    first.unmount();
    vi.mocked(global.fetch).mockClear();

    // Re-render — the entry is now quarantined; the Restore button should
    // target verified per the sessionStorage memory.
    renderDetail(verifiedId);
    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    const confirmBtn = screen.getByTestId("mcp-detail-quarantine-confirm");
    expect(confirmBtn.textContent ?? "").toMatch(/verified/i);
    fireEvent.click(confirmBtn);

    await screen.findByTestId("mcp-detail-quarantine-status");

    const patchCall = vi
      .mocked(global.fetch)
      .mock.calls.find(([, init]) => (init as FetchInit | undefined)?.method === "PATCH");
    expect(patchCall).toBeTruthy();
    const [, init] = patchCall ?? [];
    const body = JSON.parse(((init as FetchInit).body as string) ?? "{}");
    expect(body).toEqual({ trust_tier: "verified" });
  });

  it("falls back to community on restore when no prior-tier memory exists", async () => {
    // Seed: an entry that is already quarantined when the operator loads
    // the page (prior session). No sessionStorage memory exists.
    const seed = registry[0];
    if (!seed) throw new Error("test fixture missing");
    registry[0] = { ...seed, trust_tier: "quarantined" };

    renderDetail("filesystem-mcp");
    fireEvent.click(await screen.findByTestId("mcp-detail-quarantine-button"));
    const confirmBtn = screen.getByTestId("mcp-detail-quarantine-confirm");
    expect(confirmBtn.textContent ?? "").toMatch(/community/i);
    fireEvent.click(confirmBtn);

    await screen.findByTestId("mcp-detail-quarantine-status");

    const patchCall = vi
      .mocked(global.fetch)
      .mock.calls.find(([, init]) => (init as FetchInit | undefined)?.method === "PATCH");
    expect(patchCall).toBeTruthy();
    const [, init] = patchCall ?? [];
    const body = JSON.parse(((init as FetchInit).body as string) ?? "{}");
    expect(body).toEqual({ trust_tier: "community" });
  });
});
