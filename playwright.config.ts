import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
export default defineConfig({
  testDir: "tests/e2e",
  workers: 1,
  fullyParallel: false,
  timeout: 30000,
  outputDir: "work/phase6/test-results",
  expect: { timeout: 7000 },
  reporter: [
    ["list"],
    ["html", { outputFolder: "work/phase6/playwright-report", open: "never" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:5180",
    viewport: { width: 1672, height: 941 },
    trace: "retain-on-failure",
    launchOptions: {
      downloadsPath: resolve("work/phase6/browser-downloads"),
      executablePath:
        process.env.PLAYWRIGHT_EXECUTABLE_PATH ||
        (process.platform === "win32"
          ? existsSync("C:/Program Files/Google/Chrome/Application/chrome.exe")
            ? "C:/Program Files/Google/Chrome/Application/chrome.exe"
            : "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
          : undefined),
    },
  },
  webServer: [
    {
      command:
        (process.platform === "win32"
          ? ".venv\\Scripts\\python.exe"
          : ".venv/bin/python") +
        " -m uvicorn backend.main:app --host 127.0.0.1 --port 8010 --no-access-log",
      url: "http://127.0.0.1:8010/api/health",
      reuseExistingServer: !process.env.CI,
      env: {
        PHISHLENS_DB: "work/phase6/e2e.sqlite3",
        PHISHLENS_TEST_MODE: "1",
      },
      timeout: 30000,
    },
    {
      command: "npm run dev",
      url: "http://127.0.0.1:5180",
      env: {
        PHISHLENS_FRONTEND_PORT: "5180",
        PHISHLENS_API_TARGET: "http://127.0.0.1:8010",
      },
      reuseExistingServer: !process.env.CI,
      timeout: 30000,
    },
  ],
});
