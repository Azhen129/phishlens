import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";

export default defineConfig({
  testDir: "tests/e2e",
  testMatch: "public-demo.spec.ts",
  workers: 1,
  fullyParallel: false,
  timeout: 45000,
  expect: { timeout: 10000 },
  outputDir: "work/demo/test-results",
  reporter: [["list"]],
  webServer:
    process.env.PHISHLENS_DEMO_MANAGED_SERVERS === "1"
      ? [
          {
            command:
              (process.platform === "win32"
                ? ".venv\\Scripts\\python.exe"
                : ".venv/bin/python") +
              " -m uvicorn backend.demo:app --host 127.0.0.1 --port 8012 --no-access-log --loop asyncio",
            url: "http://127.0.0.1:8012/api/health",
            reuseExistingServer: !process.env.CI,
            timeout: 30000,
          },
          {
            command: "npm run dev -- --mode demo",
            url: "http://127.0.0.1:5182",
            reuseExistingServer: !process.env.CI,
            timeout: 30000,
            env: {
              PHISHLENS_FRONTEND_PORT: "5182",
              PHISHLENS_API_TARGET: "http://127.0.0.1:8012",
            },
          },
        ]
      : undefined,
  use: {
    baseURL: process.env.PHISHLENS_DEMO_BASE_URL || "http://127.0.0.1:5182",
    viewport: { width: 1672, height: 941 },
    // Protected-preview credentials must never enter recorded network traces.
    trace: process.env.PHISHLENS_PREVIEW_ACCESS_FILE
      ? "off"
      : "retain-on-failure",
    launchOptions: {
      executablePath:
        process.env.PLAYWRIGHT_EXECUTABLE_PATH ||
        (process.platform === "win32"
          ? existsSync("C:/Program Files/Google/Chrome/Application/chrome.exe")
            ? "C:/Program Files/Google/Chrome/Application/chrome.exe"
            : "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
          : undefined),
    },
  },
});
