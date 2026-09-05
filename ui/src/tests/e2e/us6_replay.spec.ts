// F004 T138 — US6 Playwright e2e: operator replays a historical receipt.
//
// Asserts the US6 acceptance scenarios from spec.md (Replay mode tab on the
// Policy Simulator page):
//   - Operator pastes a run_id → "Load receipt" populates the three
//     side-by-side principal / action / resource summary cards from the
//     receipt's signed_predicate.
//   - "Run replay" issues POST /v1/policy/replay/<run_id> against the
//     deployed policy bundle.
//   - The default replayed_decision matches the original receipt's
//     historical policy_decision; the "✓ matches historical" badge surfaces.
//   - "Compare with deployed" toggle swaps the read-only deployed source view
//     for the lazy-loaded MonacoDiffEditor (left = deployed, right = mutable).
//   - Editing the right-side (override) source debounces and re-fires the
//     replay with `override_cedar_source` body field; the decision can flip
//     and the "diverges from historical" badge surfaces.
//
// CI execution: this test runs against a booted Gateway (`mix run --no-halt`)
// per `playwright.config.ts`'s `webServer` block. The OIDC IdP is stubbed via
// the broker's MockOidcIssuer test-support module. Local devs:
//   cd ui && PLAYWRIGHT_NO_WEBSERVER=1 pnpm test:e2e
// after starting the Gateway separately.
//
// References:
// - contracts/property_test_surface_catalog_f004.md §"End-to-end coverage"
// - contracts/audit_api_extensions.md POST /v1/policy/replay/{run_id}
// - research.md D1 (Monaco DiffEditor for replay compare)
// - apps/recurse_gateway/lib/recurse_gateway/admin/policy_replay_handler.ex

import { test, expect } from "@playwright/test";

const OPERATOR = {
  email: "operator@corp",
  role: "platform_operator",
};

test.describe("US6 — Operator replays a past receipt against deployed policy", () => {
  test("paste run_id → receipt summary populates → run replay matches historical", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Seed an allow receipt — the replay against the same deployed policy
    // should yield the same decision (matches historical).
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto("/admin/policy-simulator?mode=replay");
    await expect(page.getByTestId("replay-mode")).toBeVisible();

    // Paste run_id and load.
    await page.getByTestId("replay-runid-field").fill(runId);
    await page.getByTestId("replay-load-receipt").click();

    // The three summary cards populate from the receipt's signed_predicate.
    await expect(page.getByTestId("replay-summary-principal")).toBeVisible({
      timeout: 5_000,
    });
    await expect(page.getByTestId("replay-summary-action")).toBeVisible();
    await expect(page.getByTestId("replay-summary-resource")).toBeVisible();
    await expect(page.getByTestId("replay-summary-action")).toContainText(
      "chat_completion",
    );

    // Run replay.
    await page.getByTestId("replay-run").click();

    // Decision badge appears and matches the historical "allow".
    await expect(page.getByTestId("replay-decision")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByTestId("replay-decision")).toContainText(/allow/i);

    // Matches-historical badge.
    const badge = page.getByTestId("replay-matches-historical");
    await expect(badge).toBeVisible();
    await expect(badge).toHaveAttribute("data-matches", "true");
  });

  test("'Compare with deployed' toggle swaps in the Monaco DiffEditor (lazy)", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto("/admin/policy-simulator?mode=replay");
    await page.getByTestId("replay-runid-field").fill(runId);
    await page.getByTestId("replay-load-receipt").click();
    await page.getByTestId("replay-run").click();

    // Wait for the replay output.
    await expect(page.getByTestId("replay-decision")).toBeVisible({
      timeout: 10_000,
    });

    // Default read-only deployed source pane is visible.
    await expect(page.getByTestId("replay-deployed-source")).toBeVisible();
    // Diff editor is NOT loaded yet (lazy).
    await expect(page.getByTestId("cedar-diff-editor")).toHaveCount(0);

    // Toggle compare on.
    await page.getByTestId("replay-compare-toggle").check();

    // Diff editor mounts (lazy chunk fetched on demand).
    await expect(page.getByTestId("cedar-diff-editor")).toBeVisible({
      timeout: 10_000,
    });
    // Read-only pane is hidden.
    await expect(page.getByTestId("replay-deployed-source")).toHaveCount(0);
  });

  test("editing the override source re-fires replay with override_cedar_source", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Seed an allow receipt; we'll then override the policy with a forbid()
    // that flips the decision to deny on re-fire.
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto("/admin/policy-simulator?mode=replay");
    await page.getByTestId("replay-runid-field").fill(runId);
    await page.getByTestId("replay-load-receipt").click();
    await page.getByTestId("replay-run").click();
    await expect(page.getByTestId("replay-decision")).toBeVisible({
      timeout: 10_000,
    });

    // Flip into compare mode.
    await page.getByTestId("replay-compare-toggle").check();
    const diff = page.getByTestId("cedar-diff-editor");
    await expect(diff).toBeVisible({ timeout: 10_000 });

    // Type into the modified (right-hand) editor — Monaco accepts keystrokes
    // when focused. We click into the right-pane area and type.
    await diff.click();
    await page.keyboard.press("Control+End");
    await page.keyboard.type("\nforbid(principal, action, resource);");

    // Debounced re-fire — wait for the divergence badge.
    await expect(page.getByTestId("replay-matches-historical")).toHaveAttribute(
      "data-matches",
      "false",
      { timeout: 10_000 },
    );
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
