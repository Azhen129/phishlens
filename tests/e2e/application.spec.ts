import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
const raw = readFileSync("fixtures/suspicious-invoice.eml", "utf8");
test.beforeEach(async ({ request }) => {
  const health = await (await request.get("/api/health")).json();
  expect(
    health.test_mode,
    "Refusing to reset a database without isolated test mode",
  ).toBe(true);
  await request.delete("/api/data", {
    data: { confirm: "DELETE ALL LOCAL DATA" },
  });
});
test("empty database preserves all three dense layouts without invented results", async ({
  page,
}) => {
  for (const [route, name] of [
    ["/", "dashboard"],
    ["/analyze/email", "email"],
    ["/investigations", "investigations"],
  ]) {
    await page.goto(route);
    await expect(page.locator(".api-error")).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await page.screenshot({
      path: `docs/ml/phase6/screenshots/${name}-empty.png`,
      fullPage: false,
    });
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBeTruthy();
  }
});
test("pasted email evidence, case edits, filtering and report download persist", async ({
  page,
  request,
}) => {
  await page.goto("/");
  await page.getByLabel("Email content").fill(raw);
  const analysisResponse = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/analyze/email") && r.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Analyze Safely", exact: true })
    .click();
  const scan = await (await analysisResponse).json();
  await expect(page.locator(".threat-summary")).toContainText(
    `${scan.assessment?.risk || scan.risk} Risk`,
  );
  await expect(page.locator(".finding-grid")).toContainText(
    /Authentication|authentication/,
  );
  await page
    .getByRole("button", { name: "Create Investigation", exact: true })
    .click();
  await expect(page).toHaveURL(/investigations/);
  await expect(page.locator(".case-table")).toContainText("[DEV FIXTURE]");
  await page.getByRole("tab", { name: "Report Settings", exact: true }).click();
  await page.getByRole("button", { name: "Edit notes", exact: true }).click();
  await page
    .locator(".case-analyst-notes textarea")
    .fill("Confirmed with the training team; fixture evidence reviewed.");
  await page.getByRole("button", { name: "Save Notes", exact: true }).click();
  await expect(page.locator(".case-analyst-notes")).toContainText(
    "fixture evidence reviewed",
  );
  const download = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Generate Report (PDF)", exact: true })
    .click();
  expect((await download).suggestedFilename()).toMatch(/\.pdf$/);
  await page.reload();
  await page.getByRole("tab", { name: "Report Settings", exact: true }).click();
  await expect(page.locator(".case-analyst-notes")).toContainText(
    "fixture evidence reviewed",
  );
  const records = await (await request.get("/api/investigations")).json();
  expect(records[0].notes).toContain("fixture evidence reviewed");
  await page.getByPlaceholder(/Search cases/).fill("no-match-zz");
  await expect(page.locator(".case-table tbody tr")).toHaveCount(0);
});
test("eml upload, inert content and passive URL analysis", async ({ page }) => {
  const outbound: string[] = [];
  page.on("request", (r) => {
    if (!r.url().startsWith("http://127.0.0.1:5180")) outbound.push(r.url());
  });
  await page.goto("/analyze/email");
  await page
    .locator("input[type=file]")
    .setInputFiles("fixtures/suspicious-invoice.eml");
  const analysisResponse = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/analyze/email/file") &&
      r.request().method() === "POST",
  );
  await page.getByRole("button", { name: /Run Analysis/ }).click();
  const scan = await (await analysisResponse).json();
  await expect(page.locator(".email-risk-label")).toContainText(
    scan.assessment?.risk || scan.risk,
  );
  await page.getByRole("tab", { name: "Parsed View", exact: true }).click();
  await expect(page.locator(".email-raw")).toContainText(
    /development fixture/i,
  );
  await page.getByRole("link", { name: "Analyze URL", exact: true }).click();
  await page
    .getByLabel("URL to investigate")
    .fill("http://user:password@192.0.2.22/account/verify");
  const urlResponse = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/analyze/url") && r.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Analyze Safely", exact: true })
    .click();
  await expect(page.locator(".url-summary")).toContainText("Risk");
  await expect(page.locator(".finding-grid")).toContainText(
    /IP|Credential|credential/,
  );
  const urlScan = await (await urlResponse).json();
  await page
    .getByRole("button", { name: "Save Investigation", exact: true })
    .click();
  await page.getByRole("link", { name: "Investigations", exact: true }).click();
  await expect(page.locator(".case-table tbody tr")).toHaveCount(1);
  await expect(page.locator(".case-table tbody tr")).toContainText(
    "192.0.2.22",
  );
  await page.getByRole("link", { name: "History", exact: true }).click();
  await expect(
    page.getByRole("button", { name: `Open analysis ${urlScan.id}` }),
  ).toBeVisible();
  expect(outbound).toEqual([]);
});
test("fixture screenshots and responsive layouts use actual computed scans", async ({
  page,
  request,
}) => {
  const ordinary = readFileSync("fixtures/ordinary-update.eml", "utf8");
  const fixtureInputs = [
    ordinary.replace("Weekly project update", "Meeting agenda"),
    ordinary,
    raw.replace(
      "Action required: verify your account and invoice",
      "Account suspension notice",
    ),
    "From: documents@example.test\nSubject: [DEV FIXTURE] Q4 statement\nContent-Type: text/plain\n\nUrgent: verify your account. https://one.two.three.example.test/review",
    raw.replace(
      "Action required: verify your account and invoice",
      "Your invoice is ready",
    ),
    raw
      .replace("Accounts Payable", "Microsoft Support")
      .replace(
        "Action required: verify your account and invoice",
        "Verify your Microsoft account",
      ),
  ];
  for (let i = 0; i < fixtureInputs.length; i++) {
    const result = await (
      await request.post("/api/analyze/email", {
        data: {
          raw: fixtureInputs[i],
        },
      })
    ).json();
    const c = await (
      await request.post("/api/investigations", {
        data: {
          analysis_id: result.id,
          notes: "Explicit development fixture; not a user detection.",
        },
      })
    ).json();
    if (i === 5) {
      await request.patch("/api/investigations/" + c.id, {
        data: { status: "In Progress" },
      });
      await request.patch("/api/investigations/" + c.id, {
        data: {
          notes:
            "Explicit development fixture. Indicators reviewed; independent verification required.",
        },
      });
    }
  }
  for (const [route, name] of [
    ["/", "dashboard"],
    ["/analyze/email", "email"],
    ["/investigations", "investigations"],
  ]) {
    await page.goto(route);
    await expect(page.locator(".api-error")).toHaveCount(0);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
    await expect(page.locator(".app-content")).toContainText("[DEV FIXTURE]");
    if (name === "email")
      await expect(page.locator(".email-raw")).toContainText("[DEV FIXTURE]");
    await page.screenshot({
      path: `docs/ml/phase6/screenshots/${name}-fixture.png`,
      fullPage: false,
    });
  }
  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 1280, height: 800 },
    { width: 390, height: 844 },
  ]) {
    await page.setViewportSize(viewport);
    for (const [route, name] of [
      ["/", "dashboard"],
      ["/analyze/email", "email"],
      ["/investigations", "investigations"],
    ]) {
      await page.goto(route);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await expect(page.locator(".app-content")).toContainText("[DEV FIXTURE]");
      if (name === "email")
        await expect(page.locator(".email-raw")).toContainText("[DEV FIXTURE]");
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBeTruthy();
      await page.screenshot({
        path: `docs/ml/phase6/screenshots/${name}-${viewport.width}.png`,
        fullPage: false,
      });
      if (viewport.width === 390)
        await page.screenshot({
          path: `docs/ml/phase6/screenshots/${name}-390-full.png`,
          fullPage: true,
        });
    }
  }
});
test("mobile navigation and full evidence details are keyboard accessible", async ({
  page,
  request,
}) => {
  const scan = await (
    await request.post("/api/analyze/email", { data: { raw } })
  ).json();
  await page.goto("/");
  await page
    .getByRole("button", {
      name: "Display text vs. destination mismatch",
      exact: true,
    })
    .click();
  await expect(page.getByRole("dialog")).toContainText("accounts.example.test");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Settings & Privacy",
  );
});
test("all routes and privacy deletion are functional", async ({
  page,
  request,
}) => {
  await request.post("/api/analyze/url", {
    data: { url: "https://example.test" },
  });
  for (const route of ["/reports", "/history", "/settings"]) {
    await page.goto(route);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  }
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Delete All Local Data" }).click();
  await expect
    .poll(async () =>
      (await request.get("/api/analyses")).json().then((x) => x.length),
    )
    .toBe(0);
});
