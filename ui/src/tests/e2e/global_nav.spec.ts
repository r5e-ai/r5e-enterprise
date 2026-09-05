// Playwright e2e smoke for the global Sidebar navigation.
//
// Closes punch-list B1 (no global nav). The audit-console SPA used to render
// only the Dashboard — Policy Simulator and Chat were unreachable except by
// hand-typing the URL. This test asserts that:
//   1. After login, the sidebar is visible on the Dashboard.
//   2. Clicking each sidebar link navigates to the right URL and lands on
//      the right page.
//   3. The active nav item is highlighted via aria-current="page".
//
// Runs against a Gateway booted in MIX_ENV=test (see playwright.config.ts).

import { test, expect } from "@playwright/test";

const ALICE = {
  email: "alice@corp",
  role: "tenant_auditor",
};

test.describe("Global navigation — sidebar smoke", () => {
  test("sidebar links navigate to each top-level surface", async ({
    page,
    context,
  }) => {
    await loginAs(context, ALICE);

    // Land on the dashboard.
    await page.goto("/admin/dashboard");
    const sidebar = page.getByTestId("global-sidebar");
    await expect(sidebar).toBeVisible();

    // Receipts is active on the Dashboard.
    const receiptsLink = page.getByTestId("sidebar-link-receipts");
    await expect(receiptsLink).toHaveAttribute("aria-current", "page");

    // Click Policy Simulator → URL changes, simulator page mounts.
    await page.getByTestId("sidebar-link-policy-simulator").click();
    await expect(page).toHaveURL(/\/admin\/policy-simulator(?:\?|$)/);
    await expect(page.getByTestId("policy-simulator")).toBeVisible();
    await expect(
      page.getByTestId("sidebar-link-policy-simulator"),
    ).toHaveAttribute("aria-current", "page");

    // Click Chat → URL changes to /admin/chat. (No host page asserts here —
    // the chat surface is a drawer overlay.)
    await page.getByTestId("sidebar-link-chat").click();
    await expect(page).toHaveURL(/\/admin\/chat$/);
    await expect(page.getByTestId("sidebar-link-chat")).toHaveAttribute(
      "aria-current",
      "page",
    );

    // Click Receipts → back to Dashboard.
    await page.getByTestId("sidebar-link-receipts").click();
    await expect(page).toHaveURL(/\/admin\/dashboard$/);
    await expect(page.getByTestId("sidebar-link-receipts")).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  test("topbar role pill renders the auth role", async ({ page, context }) => {
    await loginAs(context, ALICE);
    await page.goto("/admin/dashboard");
    const pill = page.getByTestId("topbar-role-pill");
    await expect(pill).toBeVisible();
    await expect(pill).toHaveText(/tenant.auditor/i);
  });
});

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
