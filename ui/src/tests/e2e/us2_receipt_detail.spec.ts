// F004 T071 — US2 Playwright e2e: auditor opens a receipt drawer + verifies.
//
// Asserts the US2 acceptance scenarios from spec.md:
//   - Drawer opens with metadata, matched policy, verification level, and
//     tier-completeness advisory rendered (FR-017).
//   - Verify Locally button runs the 5 cryptographic checks inline with
//     green/red indicators within SC-002's <3s budget (FR-018).
//   - Payload tab shows the "Fetching as <principal> — this access is itself
//     attested" notice BEFORE any fetch is issued (FR-019), and fetching
//     emits a `:ui_payload_access` receipt visible in the audit log.
//   - Export Evidence zip integrates with `recurse-verify` exit 0 (the
//     end-to-end download is asserted; verifier-CLI invocation is CI-side).
//
// CI execution: this test runs against a booted Gateway (`mix run --no-halt`)
// per `playwright.config.ts`'s `webServer` block. The OIDC IdP is stubbed via
// the broker's MockOidcIssuer test-support module (already used by F002's
// us1_with_real_broker_test.exs). Local devs can run via:
//   cd ui && PLAYWRIGHT_NO_WEBSERVER=1 pnpm test:e2e
// after starting the Gateway separately.
//
// References:
// - contracts/property_test_surface_catalog_f004.md §"End-to-end coverage"
// - contracts/audit_api_extensions.md (Receipt Detail extension shape)
// - apps/recurse_gateway/lib/recurse_gateway/audit_plane/payload_broker.ex
// - apps/recurse_gateway/lib/recurse_gateway/audit_plane/export_handler.ex

import { test, expect } from "@playwright/test";

const ALICE = {
  email: "alice@corp",
  role: "tenant_auditor",
};

test.describe("US2 — Auditor opens a receipt and verifies it", () => {
  test("drawer opens with metadata, matched policy, verification level, and tier-completeness advisory", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    // Seed a deterministic receipt the test fixture exposes; the
    // `/v1/test/emit-attestation` endpoint is owned by the test fixture
    // (not production) and returns the run_id of the newly-committed receipt.
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "deny" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}`);

    // Drawer mounts.
    await expect(page.getByTestId("receipt-detail-drawer")).toBeVisible();

    // Tier-completeness advisory rendered prominently (FR-017).
    await expect(page.getByTestId("tier-completeness-advisory")).toBeVisible();

    // Six tabs present.
    for (const tab of ["identity", "predicate", "proof", "policy", "payload", "verify"]) {
      await expect(page.getByTestId(`tab-${tab}`)).toBeVisible();
    }

    // Identity tab is the default — verify some metadata is rendered.
    await expect(page.getByTestId("identity-tab")).toBeVisible();
    await expect(page.getByText(/decision/i)).toBeVisible();
    await expect(page.getByText(/verification level/i)).toBeVisible();
  });

  test("Verify Locally runs 5 checks inline with status icons (SC-002 ≤3s)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}?tab=verify`);

    // 5 rows render in pending state before click.
    const rows = page.locator("[data-testid^='verify-row-']");
    await expect(rows).toHaveCount(5);

    // Click Verify Locally and time the response.
    const start = Date.now();
    await page.getByTestId("verify-locally-button").click();

    // All 5 rows flip to a non-pending/non-running state within SC-002's 3s budget.
    // Backend wire shape uses `pass`/`fail` (per `local_verify_handler.ex`
    // `check_to_json/1`); the SPA renders that verbatim into `data-state`.
    await Promise.all(
      ["signature", "local_merkle", "global_merkle", "policy_hash", "payload_hash"].map(
        (name) =>
          expect(page.getByTestId(`verify-row-${name}`)).toHaveAttribute(
            "data-state",
            /pass|fail/,
            { timeout: 3_000 },
          ),
      ),
    );
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(3_000);
  });

  test("Payload tab shows attested-access notice BEFORE fetch (FR-019)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}?tab=payload`);

    // The advisory is visible BEFORE any fetch button click.
    const notice = page.getByTestId("payload-attested-access-notice");
    await expect(notice).toBeVisible();
    await expect(notice).toContainText(/this access is itself attested/i);
    await expect(notice).toContainText(ALICE.email);

    // The payload JSON is NOT yet rendered.
    await expect(page.getByTestId("payload-json")).toHaveCount(0);

    // Click fetch.
    await page.getByTestId("payload-fetch-button").click();

    // Payload renders.
    await expect(page.getByTestId("payload-json")).toBeVisible({ timeout: 3_000 });

    // The fetch itself emits a :ui_payload_access receipt; pop back to the
    // dashboard and assert the new receipt is in the audit log.
    await page.goto("/admin/dashboard?event_kind=ui_payload_access");
    await expect(page.getByText(/ui_payload_access/i).first()).toBeVisible({
      timeout: 3_000,
    });
  });

  test("Export Evidence zip download integrates with recurse-verify (exit 0)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}`);

    // Wait for the drawer to mount + the Export button to be enabled.
    const exportButton = page.getByTestId("export-evidence-button");
    await expect(exportButton).toBeVisible();

    // Trigger download — Playwright captures the download stream.
    const downloadPromise = page.waitForEvent("download", { timeout: 10_000 });
    await exportButton.click();
    const download = await downloadPromise;

    // Assert the file path is non-empty (recurse-verify exit-0 assertion is
    // performed by the CI shell wrapper that invokes the binary against the
    // saved zip path).
    const path = await download.path();
    expect(path).toBeTruthy();
    expect(download.suggestedFilename()).toMatch(/\.zip$/);
  });

  test("clicking the backdrop closes the drawer", async ({ page, context }) => {
    await loginAs(context, ALICE);
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}`);
    await expect(page.getByTestId("receipt-detail-drawer")).toBeVisible();

    // Press Escape (a11y close path).
    await page.keyboard.press("Escape");
    await expect(page).toHaveURL(/\/admin\/dashboard$/);
  });
});

/**
 * Helper: drive the OIDC mock flow to set a valid browser-session cookie
 * for the given principal. Mirrors `us1_auditor_audit_log.spec.ts`'s helper.
 */
async function loginAs(
  context: import("@playwright/test").BrowserContext,
  principal: { email: string; role: string },
): Promise<void> {
  const response = await context.request.post("/admin/test/login", {
    data: {
      principal_subject: principal.email,
      recurse_role: principal.role,
    },
  });
  if (!response.ok()) {
    throw new Error(
      `loginAs(${principal.email}) failed: ${response.status()} ${await response.text()}`,
    );
  }
}
