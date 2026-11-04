import { test, expect } from "@playwright/test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const evidenceDir = "docs/ml/phase6";
const workDir = "work/phase6";

test("English, obfuscated, mixed, unsupported and short text use the declared inference paths", async ({
  page,
  request,
}) => {
  const health = await (await request.get("/api/health")).json();
  expect(health.test_mode).toBe(true);
  expect(health.models.email_en.available).toBe(true);
  const english =
    "Please review the attached agenda for our project meeting tomorrow. We will discuss progress and plan the next stage together.";
  const spanish =
    "Su cuenta requiere una verificación urgente. Confirme su contraseña para evitar la suspensión y revise los detalles de seguridad inmediatamente.";
  for (const spec of [
    { body: english, status: "supported", available: true },
    {
      body: english.replace(/([a-z])(?=[a-z])/gi, "$1\u00ad"),
      status: "supported",
      available: true,
    },
    {
      body: "Veuillez trouver le compte rendu de notre réunion. Nous allons discuter des prochains travaux et organiser les projets de notre équipe.",
      status: "unsupported",
      available: false,
    },
    { body: english + "\n\n" + spanish, status: "mixed", available: false },
    { body: "OK", status: "too_short", available: false },
  ]) {
    await page.goto("/");
    await page
      .getByLabel("Email content")
      .fill("Subject: [DEV FIXTURE] Routing test\n\n" + spec.body);
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/analyze/email") &&
        r.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Analyze Safely", exact: true })
      .click();
    const scan = await (await response).json();
    expect(scan.ml.available).toBe(spec.available);
    expect(scan.ml.language_routing_status).toBe(spec.status);
    expect(scan.ml.language_routing_version).toBe("language-format-v3");
    if (spec.available) {
      expect(scan.ml.model_key).toBe("email_en");
      await expect(page.locator(".summary-info")).toContainText(
        "ML decision score",
      );
    } else {
      expect(scan.ml.phishing_probability).toBeUndefined();
      expect(scan.assessment.method).toBe("heuristic_fallback");
      await expect(page.locator(".summary-info")).toContainText(
        "Explainable rules",
      );
    }
  }
});

for (const spec of [
  { name: "Spanish", language: "es", fixture: "spanish-account-review.eml" },
  { name: "English", language: "en", fixture: "suspicious-invoice.eml" },
]) {
  test(`actual trained ${spec.name} classifier survives investigation review and PDF export`, async ({
    page,
    request,
  }) => {
    const health = await (await request.get("/api/health")).json();
    expect(health.test_mode, "Refusing to alter a non-test database").toBe(
      true,
    );
    expect(health.models.email.available).toBe(true);
    expect(health.models.email_en.available).toBe(true);
    expect(health.models.url.available).toBe(true);
    await request.delete("/api/data", {
      data: { confirm: "DELETE ALL LOCAL DATA" },
    });
    await page.goto("/analyze/email");
    await page
      .locator("input[type=file]")
      .setInputFiles(`fixtures/${spec.fixture}`);
    const response = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/analyze/email/file") &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: /Run Analysis/ }).click();
    const scan = await (await response).json();
    expect(scan.ml.available).toBe(true);
    expect(scan.ml.supported_languages).toEqual([spec.language]);
    expect(scan.ml.detected_language).toBe(spec.language);
    expect(scan.ml.language_routing_version).toBe("language-format-v3");
    expect(scan.ml.phishing_probability).toBeGreaterThanOrEqual(0);
    expect(scan.ml.phishing_probability).toBeLessThanOrEqual(1);
    await expect(page.locator(".email-decision-text")).toContainText(
      spec.language === "en"
        ? "English research ML score:"
        : "Spanish ML score:",
    );
    if (spec.language === "en") {
      expect(scan.ml.prediction_warning).toBeTruthy();
      await expect(page.locator(".email-decision-text")).toContainText(
        "not confidence",
      );
    }
    if (await page.locator(".toast button").count())
      await page.locator(".toast button").click();
    await page.screenshot({
      path: `${evidenceDir}/screenshots/email-${spec.language}.png`,
      fullPage: false,
    });
    await page
      .getByRole("button", { name: "Save Investigation", exact: true })
      .click();
    await page
      .getByRole("link", { name: "Investigations", exact: true })
      .click();
    await expect(page.locator(".case-table tbody tr")).toHaveCount(1);
    await page
      .getByRole("tab", { name: "Report Settings", exact: true })
      .click();
    await page.getByRole("button", { name: "Edit notes", exact: true }).click();
    const analystNote = `Phase 6 ${spec.name} fixture review. Trained model metadata preserved.`;
    await page.locator(".case-analyst-notes textarea").fill(analystNote);
    await page.getByRole("button", { name: "Save Notes", exact: true }).click();
    await expect(page.locator(".case-analyst-notes")).toContainText(
      analystNote,
    );
    await page.getByLabel(/Case status/i).selectOption("In Review");
    await expect
      .poll(async () =>
        (await request.get("/api/investigations"))
          .json()
          .then((rows) => rows[0].status),
      )
      .toBe("In Review");
    await page.reload();
    const records = await (await request.get("/api/investigations")).json();
    expect(records[0].notes).toBe(analystNote);
    expect(records[0].analysis.ml).toEqual(scan.ml);
    expect(records[0].final_assessment).toEqual(scan.assessment);
    expect(records[0].risk).toBe(scan.assessment.risk);
    expect(records[0].heuristic_score).toBe(scan.score);
    const download = page.waitForEvent("download");
    await page
      .getByRole("button", { name: "Generate Report (PDF)", exact: true })
      .click();
    const browserDownload = await download;
    expect(browserDownload.suggestedFilename()).toMatch(
      /^phishlens-report-.*\.pdf$/,
    );
    const pdfResponse = await request.get(browserDownload.url());
    expect(pdfResponse.status()).toBe(200);
    expect(pdfResponse.headers()["content-type"]).toContain("application/pdf");
    const pdfBytes = await pdfResponse.body();
    expect(pdfBytes.subarray(0, 5).toString()).toBe("%PDF-");
    await mkdir(workDir, { recursive: true });
    await writeFile(`${workDir}/report-${spec.language}.pdf`, pdfBytes);
    // Some sandboxed Windows Chrome processes cannot finalize a download file.
    // Verify the UI initiation and actual PDF payload separately, recording the
    // native transfer result rather than pretending that file delivery passed.
    const nativeFailure = await browserDownload.failure();
    let nativePayloadMatches: boolean | null = null;
    if (nativeFailure === null) {
      const nativePath = `${workDir}/native-report-${spec.language}.pdf`;
      await browserDownload.saveAs(nativePath);
      nativePayloadMatches = (await readFile(nativePath)).equals(pdfBytes);
      expect(nativePayloadMatches).toBe(true);
    }
    await writeFile(
      `${evidenceDir}/download-verification-${spec.language}.json`,
      JSON.stringify(
        {
          browser_download_started: true,
          filename: browserDownload.suggestedFilename(),
          native_browser_failure: nativeFailure,
          native_transfer_payload_matches: nativePayloadMatches,
          download_directory: `${workDir}/browser-downloads`,
          pdf_http_status: pdfResponse.status(),
          pdf_bytes: pdfBytes.length,
          pdf_sha256: createHash("sha256").update(pdfBytes).digest("hex"),
          pdf_payload_retrieved_and_verified: true,
        },
        null,
        2,
      ),
    );
    if (await page.locator(".toast button").count())
      await page.locator(".toast button").click();
    await page.getByRole("tab", { name: "Case Summary", exact: true }).click();
    await page.screenshot({
      path: `${evidenceDir}/screenshots/investigation-${spec.language}.png`,
      fullPage: false,
    });
    await page.getByRole("link", { name: "Dashboard", exact: true }).click();
    await expect(page.locator(".summary-info")).toContainText("ML score:");
    await expect(page.locator(".helper")).toContainText(
      "3/3 local classifiers loaded",
    );
    await page.screenshot({
      path: `${evidenceDir}/screenshots/dashboard-${spec.language}.png`,
      fullPage: false,
    });
    await page.getByRole("link", { name: "Analyze URL", exact: true }).click();
    await page
      .getByLabel("URL to investigate")
      .fill("https://example.test/documentation/project");
    await page
      .getByRole("button", { name: "Analyze Safely", exact: true })
      .click();
    await expect(page.locator(".url-summary")).toContainText(
      "ML decision score",
    );
    if (await page.locator(".toast button").count())
      await page.locator(".toast button").click();
    await page.screenshot({
      path: `${evidenceDir}/screenshots/url-${spec.language}.png`,
      fullPage: false,
    });
    if (spec.language === "en") {
      await page.getByRole("link", { name: "Reports", exact: true }).click();
      await expect(
        page.getByRole("button", {
          name: `Download ${browserDownload.suggestedFilename()}`,
        }),
      ).toBeVisible();
      await page.screenshot({
        path: `${evidenceDir}/screenshots/reports-en.png`,
      });
      await page.getByRole("link", { name: "History", exact: true }).click();
      await expect(
        page.getByRole("button", { name: `Open analysis ${scan.id}` }),
      ).toBeVisible();
      await page.screenshot({
        path: `${evidenceDir}/screenshots/history-en.png`,
      });
      await page.getByRole("link", { name: "Settings", exact: true }).click();
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(
        "Settings & Privacy",
      );
      await expect(page.locator(".settings-list")).toContainText(
        scan.ml.model_version,
      );
      await page.screenshot({
        path: `${evidenceDir}/screenshots/settings-en.png`,
      });
    }
  });
}
