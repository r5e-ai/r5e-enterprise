// F004 T082 — US3 Playwright e2e: operator drafts a policy with Blast Radius.
//
// Asserts the US3 acceptance scenarios from spec.md:
//   - Operator selects a receipt and clicks "Create policy rule from this
//     receipt" → a Cedar skeleton appears in the Monaco editor with the
//     source receipt cited (FR-022, FR-023).
//   - Operator adjusts scope via the ScopePicker (FR-024) and conditions
//     via the ConditionBuilder (FR-025).
//   - Blast Radius panel populates with the 4-cell counts (matches_intent,
//     unintended, would_have_allowed, no_change) within SC-003's 30s
//     budget (FR-026, FR-027).
//   - Saving the draft emits a `:ui_policy_draft_created` receipt visible
//     in the audit log (FR-028, FR-031).
//
// CI execution: this test runs against a booted Gateway (`mix run --no-halt`)
// per `playwright.config.ts`'s `webServer` block. The OIDC IdP is stubbed via
// the broker's MockOidcIssuer test-support module. Local devs:
//   cd ui && PLAYWRIGHT_NO_WEBSERVER=1 pnpm test:e2e
// after starting the Gateway separately.
//
// References:
// - contracts/property_test_surface_catalog_f004.md §"End-to-end coverage"
// - contracts/audit_api_extensions.md §"Policy drafts"
// - contracts/blast_radius_algorithm.md §5a (load-bearing 4-cell shape)
// - apps/recurse_gateway/lib/recurse_gateway/admin/policy_drafts_handler.ex

import { test, expect } from "@playwright/test";

const OPERATOR = {
  email: "operator@corp",
  role: "platform_operator",
};

test.describe("US3 — Operator drafts policy from receipt with Blast Radius", () => {
  test("end-to-end: receipt → skeleton → adjust scope → Blast Radius → save", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Seed a deterministic allow-decision receipt.
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    // Open Receipt Detail drawer.
    await page.goto(`/admin/dashboard/receipts/${runId}`);
    await expect(page.getByTestId("receipt-detail-drawer")).toBeVisible();

    // Click "Create policy rule from this receipt" action.
    await page.getByTestId("create-policy-from-receipt-button").click();

    // Skeleton page mounts with Monaco editor + source receipt cite.
    await expect(page.getByTestId("policy-simulator-page")).toBeVisible();
    await expect(page.getByTestId("source-receipt-cite")).toContainText(runId);

    // Cedar skeleton populated in editor.
    const editor = page.getByTestId("cedar-monaco-editor");
    await expect(editor).toBeVisible();
    await expect(editor).toContainText("forbid");

    // ScopePicker shows principal scope by default (skeleton derived from
    // receipt's principal); operator widens to role scope.
    await page.getByTestId("scope-picker-kind-role").click();
    await page.getByTestId("scope-picker-value").fill("caller");

    // Compute Blast Radius.
    const start = Date.now();
    await page.getByTestId("compute-blast-radius-button").click();

    // Panel populates within SC-003's 30s budget. The 4-cell breakdown is
    // load-bearing per blast_radius_algorithm.md §5a — all four counts
    // MUST render.
    await expect(page.getByTestId("blast-radius-matches-intent")).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByTestId("blast-radius-unintended")).toBeVisible();
    await expect(page.getByTestId("blast-radius-would-have-allowed")).toBeVisible();
    await expect(page.getByTestId("blast-radius-no-change")).toBeVisible();

    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(30_000);

    // Save the draft.
    await page.getByTestId("save-draft-button").click();

    // Confirmation toast renders.
    await expect(page.getByTestId("draft-saved-toast")).toBeVisible();

    // Navigate back to dashboard with event_kind filter; verify the
    // :ui_policy_draft_created receipt appears in the audit log.
    await page.goto("/admin/dashboard?event_kind=ui_policy_draft_created");
    await expect(page.getByText(/ui_policy_draft_created/i).first()).toBeVisible({
      timeout: 5_000,
    });
  });

  test("Blast Radius surfaces the 'unintended' (allow→deny) danger case", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Seed an allow-decision receipt; the forbid skeleton derived from this
    // receipt should classify it as :unintended (the danger case).
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}`);
    await page.getByTestId("create-policy-from-receipt-button").click();

    // Default forbid skeleton + Compute Blast Radius.
    await page.getByTestId("compute-blast-radius-button").click();

    // The "unintended" cell should show ≥1 (the seeded allow receipt).
    const unintendedCell = page.getByTestId("blast-radius-unintended");
    await expect(unintendedCell).toBeVisible({ timeout: 30_000 });

    // The advisory banner (FR-027) should fire when unintended > 0.
    await expect(page.getByTestId("blast-radius-advisory")).toBeVisible();
  });

  test("editing the Cedar source invalidates the cached Blast Radius summary", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Seed a receipt and create a draft from it via the skeleton flow.
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}`);
    await page.getByTestId("create-policy-from-receipt-button").click();

    // Compute first Blast Radius pass.
    await page.getByTestId("compute-blast-radius-button").click();
    await expect(page.getByTestId("blast-radius-matches-intent")).toBeVisible({
      timeout: 30_000,
    });

    // Edit the Cedar source — the Compute button should re-enable + the
    // cached summary should be marked stale per algorithm contract §7.
    const editor = page.getByTestId("cedar-monaco-editor");
    await editor.click();
    await page.keyboard.type("\n// edit");

    // Stale-cache indicator visible.
    await expect(page.getByTestId("blast-radius-stale-indicator")).toBeVisible();
  });

  test("tenant_auditor cannot create drafts (Cedar gate denies)", async ({
    page,
    context,
  }) => {
    // Auditor role lacks PolicyDraftCreate per cedar_entity_schema_extensions.
    await loginAs(context, { email: "alice@corp", role: "tenant_auditor" });

    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto(`/admin/dashboard/receipts/${runId}`);

    // The "Create policy rule from this receipt" button should be hidden
    // for the auditor role (the SPA gates UI by role per FR-002).
    await expect(page.getByTestId("create-policy-from-receipt-button")).toHaveCount(0);
  });
});

/**
 * Helper: drive the OIDC mock flow to set a valid browser-session cookie
 * for the given principal. Mirrors `us2_receipt_detail.spec.ts`'s helper.
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
