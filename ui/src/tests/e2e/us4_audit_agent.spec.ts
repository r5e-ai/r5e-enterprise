// F004 T097 — US4 Playwright e2e: auditor uses the Audit Agent chat drawer.
//
// Asserts the US4 acceptance scenarios from spec.md:
//   - Chat drawer opens via the `?chat=open` toggle on any authenticated
//     page (FR-036) and via the direct route `/admin/chat`.
//   - Submitting a question kicks off an SSE stream from
//     `POST /v1/chat/messages`; the agent's tokens stream into the message
//     bubble, tool calls render inline with a running indicator (FR-041),
//     and the bubble settles into a completed state.
//   - Tool-call blocks expose the tool name + args + status + a clickable
//     attestation receipt link that opens Receipt Detail (FR-038).
//   - A failed tool call surfaces the error reason + agent narration with
//     a suggested next step.
//   - Each completed assistant message renders the referenced-data footer
//     listing the API calls made on the user's behalf (FR-039).
//   - The chat surface is reachable from every authenticated route (FR-036),
//     not just `/admin/chat`.
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
// - contracts/audit_api_extensions.md §"Chat (Audit Agent)"
// - contracts/audit_agent_tools.md (six-tool vocabulary; status icons)
// - apps/recurse_gateway/lib/recurse_gateway/admin/audit_agent/runtime.ex

import { test, expect } from "@playwright/test";

const ALICE = {
  email: "alice@corp",
  role: "tenant_auditor",
};

test.describe("US4 — Auditor uses the Audit Agent chat drawer", () => {
  test("chat drawer opens via ?chat=open from any authenticated page (FR-036)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    // Drawer is reachable from the dashboard.
    await page.goto("/admin/dashboard?chat=open");
    await expect(page.getByTestId("chat-drawer")).toBeVisible();
    await expect(page.getByTestId("chat-drawer")).toContainText(/Audit Agent/i);

    // …and from the policy simulator.
    await page.goto("/admin/policy-simulator?chat=open");
    await expect(page.getByTestId("chat-drawer")).toBeVisible();

    // …and from the suggestions surface.
    await page.goto("/admin/policy-simulator/suggestions?chat=open");
    await expect(page.getByTestId("chat-drawer")).toBeVisible();

    // Direct-link route opens the standalone full-page chat surface
    // (F5 redesign — `<ChatPage />` is the dedicated page; the drawer
    // overlay only mounts on other routes via `?chat=open`).
    await page.goto("/admin/chat");
    await expect(page.getByTestId("chat-page")).toBeVisible();
    await expect(page.getByTestId("chat-page-thread")).toBeVisible();
  });

  test("agent acknowledges + executes tool calls visibly with a running indicator", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    // Seed a deterministic deny receipt to give the agent something to talk
    // about. The test fixture echoes back the run_id; the agent surface uses
    // it implicitly through suggestion chips and direct prompts.
    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "tool_call", policy_decision: "deny" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto("/admin/dashboard?chat=open");
    await expect(page.getByTestId("chat-drawer")).toBeVisible();

    // Type a question and send.
    const composer = page.getByTestId("chat-input");
    await composer.fill(`Why was run_id ${runId} denied?`);
    await page.getByTestId("chat-send").click();

    // The user message bubble appears immediately.
    await expect(page.getByTestId("message-bubble-user").first()).toBeVisible();

    // Activity strip surfaces the live status (FR-041).
    await expect(page.getByTestId("chat-activity-strip")).toBeVisible({
      timeout: 5_000,
    });

    // A tool-call block appears with a running indicator that resolves to
    // either success or error within the test budget. We assert the inline
    // tool-call element renders.
    await expect(
      page.locator('[data-testid^="tool-call-block-"]').first(),
    ).toBeVisible({ timeout: 15_000 });

    // The assistant bubble eventually settles into a completed state.
    await expect(
      page.getByTestId("message-bubble-assistant").first(),
    ).toBeVisible({ timeout: 30_000 });
  });

  test("response contains clickable receipt previews opening Receipt Detail (FR-038)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "deny" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto("/admin/dashboard?chat=open");
    await page.getByTestId("chat-input").fill(`Explain ${runId}.`);
    await page.getByTestId("chat-send").click();

    // Wait for at least one tool-call receipt link to render.
    const receiptLink = page
      .locator('[data-testid^="tool-call-receipt-"]')
      .first();
    await expect(receiptLink).toBeVisible({ timeout: 30_000 });

    // Clicking the receipt link opens the Receipt Detail drawer overlay.
    await receiptLink.click();
    await expect(page.getByTestId("receipt-detail-drawer")).toBeVisible({
      timeout: 5_000,
    });
  });

  test("failed tool call surfaces error reason + agent narration with a suggested next step", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    // The test Gateway exposes a helper to simulate a tool failure on the
    // next chat turn (`fault.next_tool_outcome=upstream_error`). When the
    // agent invokes any LLM-backed tool, the runtime returns the error
    // outcome and the SPA must surface it inline.
    await context.request.post("/v1/test/chat-fault", {
      data: { next_tool_outcome: "upstream_error", reason: "synthetic-503" },
    });

    await page.goto("/admin/dashboard?chat=open");
    await page.getByTestId("chat-input").fill("Suggest a policy pattern.");
    await page.getByTestId("chat-send").click();

    // The error-state tool block appears (status: error, error message
    // visible inline).
    const errorBlock = page.locator('[data-testid^="tool-call-block-"]').first();
    await expect(errorBlock).toBeVisible({ timeout: 30_000 });
    await expect(errorBlock).toContainText(/error/i);

    // The agent narrates a recovery suggestion in a subsequent assistant
    // message (the runtime is expected to emit additional `agent_token`
    // deltas after the failed tool result per the SSE contract).
    await expect(page.getByTestId("message-content").last()).toContainText(
      /try|retry|alternatively|instead|consider/i,
      { timeout: 30_000 },
    );
  });

  test("referenced-data footer lists API calls made on the user's behalf (FR-039)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    const seedResponse = await context.request.post("/v1/test/emit-attestation", {
      data: { event_kind: "chat_completion", policy_decision: "allow" },
    });
    const { run_id: runId } = (await seedResponse.json()) as { run_id: string };

    await page.goto("/admin/dashboard?chat=open");
    await page.getByTestId("chat-input").fill(`Find similar receipts to ${runId}.`);
    await page.getByTestId("chat-send").click();

    // Wait for the assistant message to settle into completed state.
    await expect(page.getByTestId("message-bubble-assistant").last()).toBeVisible({
      timeout: 30_000,
    });

    // Footer is rendered at the bottom of the completed assistant message.
    const footer = page.getByTestId("referenced-data-footer").last();
    await expect(footer).toBeVisible();

    // The principal (auditor's email) is rendered explicitly in the footer.
    await expect(footer).toContainText(ALICE.email);

    // At least one tool-call entry is enumerated.
    await expect(
      page.getByTestId("referenced-data-calls").last(),
    ).toBeVisible();
  });

  test("suggested prompt cards submit as a user message on click (F5 redesign)", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    await page.goto("/admin/dashboard?chat=open");

    // Suggested prompt cards are visible on an empty conversation.
    const prompts = page.getByTestId("chat-suggested-prompts");
    await expect(prompts).toBeVisible();

    // Click the first card; per the F5 brief, clicking submits the prompt
    // as a user message (not pre-fills the input).
    const firstCard = prompts.locator("button").first();
    const cardText = (await firstCard.textContent())?.trim() ?? "";
    await firstCard.click();

    // The user message bubble appears with the prompt text — confirms the
    // card submitted rather than just pre-filling.
    const userBubble = page.getByTestId("message-bubble-user").first();
    await expect(userBubble).toBeVisible();
    await expect(userBubble).toContainText(cardText.slice(0, 20));
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

