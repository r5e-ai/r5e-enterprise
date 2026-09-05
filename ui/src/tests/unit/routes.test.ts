// Vitest unit tests for the canonical route helpers in `lib/routes.ts`.
//
// Why this file exists: the SPA's basename collision (Sidebar/Draft Policy
// in MR !52, then 7 additional sites swept in this MR) shipped because no
// unit test asserted "the path you hand to react-router primitives is
// already basename-stripped". This file is that test, at the helper layer
// — every consumer that uses `stripBasename` / `receiptDetailPath` is
// implicitly covered by these invariants. Per-component <Link> rendering
// tests live alongside their components.
//
// The two invariants:
//   1. `stripBasename(p)` removes EXACTLY one leading `/admin` from
//      absolute paths starting with that prefix; non-admin paths are
//      passed through unchanged. The output, when handed back to a
//      `<BrowserRouter basename="/admin">`-mounted Link/navigate, must
//      not double-prefix to `/admin/admin/...`.
//   2. `receiptDetailPath(runId)` returns a router-safe path (already
//      basename-stripped, runId percent-encoded). Callers do NOT need
//      to wrap it in `stripBasename` again.

import { describe, expect, it } from "vitest";

import {
  ADMIN_BASE,
  receiptDetailPath,
  routes,
  stripBasename,
} from "~/lib/routes";

describe("stripBasename", () => {
  it("strips a single /admin prefix", () => {
    expect(stripBasename("/admin/dashboard")).toBe("/dashboard");
    expect(stripBasename("/admin/policy-simulator")).toBe("/policy-simulator");
    expect(stripBasename("/admin/policy-simulator/suggestions")).toBe(
      "/policy-simulator/suggestions",
    );
    expect(stripBasename("/admin/chat")).toBe("/chat");
  });

  it("returns '/' for the bare basename", () => {
    expect(stripBasename(ADMIN_BASE)).toBe("/");
    expect(stripBasename("/admin")).toBe("/");
  });

  it("preserves query strings and fragments verbatim", () => {
    expect(
      stripBasename("/admin/policy-simulator?mode=draft&run_id=abc"),
    ).toBe("/policy-simulator?mode=draft&run_id=abc");
    expect(stripBasename("/admin/chat?chat=open&seed=hello")).toBe(
      "/chat?chat=open&seed=hello",
    );
  });

  it("passes non-admin paths through unchanged", () => {
    expect(stripBasename("/dashboard")).toBe("/dashboard");
    expect(stripBasename("/external/whatever")).toBe("/external/whatever");
    expect(stripBasename("relative/path")).toBe("relative/path");
  });

  it("never produces a /admin/admin double-prefix when its result is re-prefixed", () => {
    // Simulates what BrowserRouter does: resolveTo() prepends basename to
    // the Link/navigate target. If our helper is correct, a round-trip
    // (strip → router-prepend) yields the original.
    const cases = [
      routes.dashboard,
      routes.policySimulator,
      routes.policySimulatorSuggestions,
      routes.chat,
      routes.login,
      routes.mcpRegistry,
    ];
    for (const path of cases) {
      const stripped = stripBasename(path);
      const reprepended = `${ADMIN_BASE}${stripped === "/" ? "" : stripped}`;
      expect(reprepended).toBe(path);
      expect(reprepended.startsWith("/admin/admin")).toBe(false);
    }
  });

  it("is idempotent under double-stripping", () => {
    // Defense in depth: a caller that accidentally calls stripBasename
    // twice should not mangle the path. (Today the helper is one-shot,
    // but consumers occasionally compose helpers and we want the
    // composition to stay safe.)
    expect(stripBasename(stripBasename("/admin/dashboard"))).toBe(
      "/dashboard",
    );
  });
});

describe("mcpRegistryDetailPath", () => {
  it("returns a router-safe path under /mcp-registry/", async () => {
    const { mcpRegistryDetailPath } = await import("~/lib/routes");
    expect(mcpRegistryDetailPath("r5e-audit-mcp")).toBe(
      "/mcp-registry/r5e-audit-mcp",
    );
  });

  it("percent-encodes the id so weird characters don't break the URL", async () => {
    const { mcpRegistryDetailPath } = await import("~/lib/routes");
    expect(mcpRegistryDetailPath("a/b c?d")).toBe(
      "/mcp-registry/a%2Fb%20c%3Fd",
    );
  });
});

describe("receiptDetailPath", () => {
  it("returns a router-safe path under /dashboard/receipts/", () => {
    // No leading /admin — it's already stripped.
    expect(receiptDetailPath("abc-123")).toBe(
      "/dashboard/receipts/abc-123",
    );
  });

  it("percent-encodes the runId so weird characters don't break the URL", () => {
    expect(receiptDetailPath("a/b c?d")).toBe(
      "/dashboard/receipts/a%2Fb%20c%3Fd",
    );
  });

  it("never produces an /admin/admin double-prefix when re-prefixed by the router", () => {
    const stripped = receiptDetailPath("xyz");
    const reprepended = `${ADMIN_BASE}${stripped}`;
    expect(reprepended).toBe("/admin/dashboard/receipts/xyz");
    expect(reprepended.startsWith("/admin/admin")).toBe(false);
  });
});
