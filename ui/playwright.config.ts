// F004 T005 — Playwright e2e config per contracts/frontend_architecture.md §"Tests".
//
// Runs against a Gateway booted via `mix run --no-halt` on localhost:4000.
// Tests live under src/tests/e2e/ and cover US1–US6 acceptance scenarios.

import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: "./src/tests/e2e",
  fullyParallel: true,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  workers: isCI ? 2 : undefined,
  reporter: isCI ? [["github"], ["html", { open: "never" }]] : "list",
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: "http://localhost:4000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
  // Probe the Gateway is up before starting tests. Tests assume the Gateway
  // serves /admin/login at boot (T056 / T058 / T060 land that route).
  webServer: process.env.PLAYWRIGHT_NO_WEBSERVER
    ? undefined
    : {
        command:
          "cd .. && mix run --no-halt --no-compile -e 'Application.ensure_all_started(:recurse_gateway)'",
        url: "http://localhost:4000/admin/login",
        reuseExistingServer: !isCI,
        timeout: 60_000,
      },
});
