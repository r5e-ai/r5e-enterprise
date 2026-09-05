// F004 T122 — US5 Playwright e2e: operator reviews + acts on policy
// suggestions.
//
// Asserts the US5 acceptance scenarios from spec.md (FR-031 / FR-032 /
// FR-033 / FR-034):
//   - Suggestions list renders sorted (confidence DESC, then inserted_at
//     DESC), each card carrying:
//       * source-label pill (heuristic / llm)
//       * confidence pill (color-graded: high / medium / low)
//       * pattern_summary (one-line)
//       * collapsed proposed Cedar rule (click to expand)
//       * inline 4-cell blast-radius bar with counts (matches_intent /
//         unintended / would_have_allowed / no_change)
//   - "Adopt as draft" creates a new draft and routes the operator into
//     the simulator's Draft mode against that draft.
//   - "Dismiss" removes the suggestion from the active list (the backend
//     emits an attested `:ui_policy_suggestion_dismissed` event_kind).
//   - Low-confidence (<70) LLM suggestions are visually de-emphasized via
//     the `data-low-confidence="true"` attribute.
//   - "Refresh suggestions" surfaces a rate-limit toast when the backend
//     returns 429 with `retry_after_seconds` (FR-030a).
//   - tenant_auditor sees an operator-only notice (and the backend Cedar
//     gate denies any direct API call from that role).
//
// CI execution: this test runs against a booted Gateway (`mix run --no-halt`)
// per `playwright.config.ts`'s `webServer` block. The OIDC IdP is stubbed via
// the broker's MockOidcIssuer test-support module. Local devs:
//   cd ui && PLAYWRIGHT_NO_WEBSERVER=1 pnpm test:e2e
// after starting the Gateway separately.
//
// References:
// - contracts/property_test_surface_catalog_f004.md §"End-to-end coverage"
// - contracts/audit_api_extensions.md §"Policy suggestions"
// - apps/recurse_gateway/lib/recurse_gateway/admin/policy_suggestions_handler.ex

import { test, expect } from "@playwright/test";

const OPERATOR = {
  email: "operator@corp",
  role: "platform_operator",
};

const AUDITOR = {
  email: "alice@corp",
  role: "tenant_auditor",
};

test.describe("US5 — Operator reviews and acts on policy suggestions", () => {
  test("list renders sorted by confidence DESC with source/confidence pills + 4-cell blast radius", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Seed three suggestions with distinct confidence values + sources so
    // the sort + grouping behavior is observable.
    await context.request.post("/v1/test/seed-suggestions", {
      data: {
        suggestions: [
          {
            source: "heuristic",
            confidence: 95,
            pattern_summary: "alice@corp invoked search_kb 423 times in 30 days with 0 denies",
            proposed_cedar: "permit(principal, action, resource);",
            blast_radius_snapshot: {
              matches_intent: 423,
              unintended: 0,
              would_have_allowed: 0,
              no_change: 8432,
            },
          },
          {
            source: "llm",
            confidence: 78,
            pattern_summary: "agents repeatedly attempted bash_exec on /etc/passwd",
            proposed_cedar: "forbid(principal, action == Action::\"bash_exec\", resource);",
            blast_radius_snapshot: {
              matches_intent: 12,
              unintended: 1,
              would_have_allowed: 0,
              no_change: 100,
            },
          },
          {
            source: "llm",
            confidence: 55,
            pattern_summary: "low-confidence pattern: occasional mistral access on weekends",
            proposed_cedar: "forbid(principal, action, resource);",
            blast_radius_snapshot: {
              matches_intent: 3,
              unintended: 5,
              would_have_allowed: 0,
              no_change: 10,
            },
          },
        ],
      },
    });

    await page.goto("/admin/policy-simulator/suggestions");
    await expect(page.getByTestId("policy-suggestions-page")).toBeVisible();

    // The list (or grouped surface) renders all three suggestions.
    const cards = page.locator("[data-testid^='suggestion-card-']");
    await expect(cards).toHaveCount(3, { timeout: 5_000 });

    // Sort order: confidence DESC means the 95-card is first when ungrouped.
    // (With 3 rows we're below the GROUP_THRESHOLD; flat list applies.)
    const firstCard = cards.first();
    await expect(firstCard.getByTestId("suggestion-confidence-pill")).toContainText("95%");

    // Source pills present.
    await expect(firstCard.getByTestId("suggestion-source-pill")).toContainText(
      "heuristic",
    );

    // Pattern summary line.
    await expect(firstCard.getByTestId("suggestion-pattern-summary")).toContainText(
      "search_kb",
    );

    // Proposed rule is collapsed by default.
    await expect(firstCard.getByTestId("suggestion-proposed-rule")).toHaveCount(0);

    // Click to expand.
    await firstCard.getByTestId("suggestion-toggle-rule").click();
    await expect(firstCard.getByTestId("suggestion-proposed-rule")).toBeVisible();
    await expect(firstCard.getByTestId("suggestion-proposed-rule")).toContainText(
      "permit(",
    );

    // Inline 4-cell blast-radius is rendered with all four counts.
    for (const cell of [
      "matches_intent",
      "unintended",
      "would_have_allowed",
      "no_change",
    ]) {
      await expect(firstCard.getByTestId(`suggestion-blast-count-${cell}`)).toBeVisible();
    }
  });

  test("low-confidence LLM suggestions are visually de-emphasized", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    await context.request.post("/v1/test/seed-suggestions", {
      data: {
        suggestions: [
          {
            source: "llm",
            confidence: 40,
            pattern_summary: "marginal pattern; low signal",
            proposed_cedar: "forbid(principal, action, resource);",
            blast_radius_snapshot: { matches_intent: 1, unintended: 0, would_have_allowed: 0, no_change: 1 },
          },
        ],
      },
    });

    await page.goto("/admin/policy-simulator/suggestions");

    const card = page.locator("[data-testid^='suggestion-card-']").first();
    await expect(card).toBeVisible();
    await expect(card).toHaveAttribute("data-low-confidence", "true");
    await expect(card.getByTestId("suggestion-confidence-pill")).toContainText(
      /low confidence/i,
    );
  });

  test("'Adopt as draft' creates a draft and routes operator into Draft mode", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    await context.request.post("/v1/test/seed-suggestions", {
      data: {
        suggestions: [
          {
            source: "heuristic",
            confidence: 92,
            pattern_summary: "operator-action: adopt me",
            proposed_cedar: "permit(principal, action, resource);",
            blast_radius_snapshot: { matches_intent: 5, unintended: 0, would_have_allowed: 0, no_change: 0 },
          },
        ],
      },
    });

    await page.goto("/admin/policy-simulator/suggestions");

    const card = page.locator("[data-testid^='suggestion-card-']").first();
    await card.getByTestId("suggestion-adopt").click();

    // Operator is routed into the simulator's Draft mode against the new
    // draft id.
    await expect(page).toHaveURL(/\/admin\/policy-simulator\?mode=draft&draft_id=/, {
      timeout: 10_000,
    });
  });

  test("'Dismiss' records an attested event and removes the row from active", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    await context.request.post("/v1/test/seed-suggestions", {
      data: {
        suggestions: [
          {
            source: "heuristic",
            confidence: 80,
            pattern_summary: "operator-action: dismiss me",
            proposed_cedar: "permit(principal, action, resource);",
            blast_radius_snapshot: { matches_intent: 1, unintended: 0, would_have_allowed: 0, no_change: 0 },
          },
        ],
      },
    });

    await page.goto("/admin/policy-simulator/suggestions");
    const card = page.locator("[data-testid^='suggestion-card-']").first();
    await expect(card).toBeVisible();
    await card.getByTestId("suggestion-dismiss").click();

    // The card disappears from the active list (the mutation invalidates
    // the list cache and re-fetches; the empty state appears).
    await expect(page.getByTestId("suggestions-empty")).toBeVisible({
      timeout: 5_000,
    });

    // The :ui_policy_suggestion_dismissed event_kind shows up in the audit log.
    await page.goto("/admin/dashboard?event_kind=ui_policy_suggestion_dismissed");
    await expect(
      page.getByText(/ui_policy_suggestion_dismissed/i).first(),
    ).toBeVisible({ timeout: 5_000 });
  });

  test("'Refresh suggestions' surfaces a rate-limit toast on 429", async ({
    page,
    context,
  }) => {
    await loginAs(context, OPERATOR);

    // Force the next refresh request to 429 with a 120s retry-after.
    await context.request.post("/v1/test/refresh-rate-limit", {
      data: { retry_after_seconds: 120 },
    });

    await page.goto("/admin/policy-simulator/suggestions");
    await page.getByTestId("suggestions-refresh").click();

    const toast = page.getByTestId("suggestions-toast-rate_limited");
    await expect(toast).toBeVisible({ timeout: 5_000 });
    await expect(toast).toContainText(/rate limited/i);
    await expect(toast).toContainText(/2 minute/i);
  });

  test("tenant_auditor sees an operator-only notice (FR-002)", async ({
    page,
    context,
  }) => {
    await loginAs(context, AUDITOR);

    await page.goto("/admin/policy-simulator/suggestions");

    await expect(page.getByTestId("suggestions-forbidden")).toBeVisible();
    await expect(page.getByTestId("suggestions-refresh")).toHaveCount(0);
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
