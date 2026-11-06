import {
  test,
  expect,
  type APIRequestContext,
  type BrowserContext,
} from "@playwright/test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const evidenceDirectory =
  process.env.PHISHLENS_DEMO_EVIDENCE || "work/hosted-demo-evidence";
const demoBaseURL =
  process.env.PHISHLENS_DEMO_BASE_URL || "http://127.0.0.1:5182";
const demoOrigin = new URL(demoBaseURL).origin;
let previewAccess: Promise<string | undefined> | undefined;
const previewSessions = new WeakMap<APIRequestContext, Promise<void>>();

function previewSecret() {
  previewAccess ??= (async () => {
    const path = process.env.PHISHLENS_PREVIEW_ACCESS_FILE;
    if (!path) return undefined;
    let value: unknown;
    try {
      value = JSON.parse(await readFile(path, "utf8"));
    } catch {
      throw new Error("The preview access file could not be loaded.");
    }
    const secret =
      typeof value === "object" && value !== null && "secret" in value
        ? value.secret
        : undefined;
    if (
      typeof secret !== "string" ||
      secret.length === 0 ||
      secret.length > 4096 ||
      /[\r\n]/.test(secret)
    ) {
      throw new Error("The preview access file has an invalid credential.");
    }
    return secret;
  })();
  return previewAccess;
}

async function authorizePreviewContext(context: BrowserContext) {
  await ensurePreviewSession(context.request);
}

async function ensurePreviewSession(request: APIRequestContext) {
  const secret = await previewSecret();
  if (!secret) return;
  let session = previewSessions.get(request);
  if (!session) {
    session = (async () => {
      try {
        // A temporary Vercel share link is a cookie bootstrap, not an
        // automation-header credential. Never navigate a visible page to it.
        const bootstrap = new URL("/", demoOrigin);
        bootstrap.searchParams.set("_vercel_share", secret);
        const response = await request.get(bootstrap.href, { maxRedirects: 0 });
        const status = response.status();
        await response.dispose();
        const state = await request.storageState();
        if (
          status < 200 ||
          status >= 400 ||
          !state.cookies.some(
            (cookie) =>
              cookie.name === "_vercel_jwt" &&
              cookie.domain.replace(/^\./, "") === new URL(demoOrigin).hostname,
          )
        ) {
          throw new Error("Preview access was not established.");
        }
      } catch {
        // Request diagnostics can contain the credential-bearing query URL.
        throw new Error("Preview access failed; request details are omitted.");
      }
    })();
    previewSessions.set(request, session);
  }
  await session;
}

async function ownApiOptions(path: string) {
  if (
    !path.startsWith("/api/") ||
    new URL(path, demoBaseURL).origin !== demoOrigin
  ) {
    throw new Error(
      "Preview API access is limited to this demo's relative API.",
    );
  }
  return { maxRedirects: 0 };
}

async function ownApiGet(request: APIRequestContext, path: string) {
  try {
    await ensurePreviewSession(request);
    return await request.get(path, await ownApiOptions(path));
  } catch {
    throw new Error(
      "The demo API request failed; request details are omitted.",
    );
  }
}

async function ownApiPost(
  request: APIRequestContext,
  path: string,
  data: unknown,
) {
  try {
    await ensurePreviewSession(request);
    return await request.post(path, { data, ...(await ownApiOptions(path)) });
  } catch {
    throw new Error(
      "The demo API request failed; request details are omitted.",
    );
  }
}

test.skip(
  process.env.PHISHLENS_PUBLIC_DEMO_TESTS !== "1",
  "Public demo checks require the stateless demo entrypoint and guest frontend.",
);

test.beforeEach(async ({ context }) => {
  await mkdir(evidenceDirectory, { recursive: true });
  await authorizePreviewContext(context);
});

test("guest cases use computed synthetic evidence and stay isolated to each tab", async ({
  page,
  context,
  request,
}) => {
  const health = await (await ownApiGet(request, "/api/health")).json();
  expect(health.mode).toBe("public-demo");
  expect(health.ml.available).toBe(false);
  const contentRequests: string[] = [];
  page.on("request", (r) => {
    if (r.method() !== "GET") contentRequests.push(new URL(r.url()).pathname);
  });
  await page.goto("/");
  await expect(
    page.getByRole("note", { name: "Public demo privacy" }),
  ).toContainText("Rules only");
  await page.getByRole("button", { name: "Load synthetic examples" }).click();
  await expect(page.locator(".recent-table tbody tr")).toHaveCount(2);
  await expect(page.locator(".recent-table")).toContainText("[SYNTHETIC DEMO]");
  await page.screenshot({
    path: resolve(evidenceDirectory, "dashboard-synthetic.png"),
    fullPage: false,
  });
  expect(contentRequests).toEqual(["/api/analyze/email", "/api/analyze/email"]);
  await page.getByRole("link", { name: "Investigations", exact: true }).click();
  await expect(page.locator(".case-table tbody tr")).toHaveCount(2);
  await page.getByRole("tab", { name: "Report Settings", exact: true }).click();
  await expect(page.locator(".case-analyst-notes")).toContainText(
    "Synthetic demonstration example",
  );
  await page.getByRole("tab", { name: "Case Summary", exact: true }).click();
  await page.screenshot({
    path: resolve(evidenceDirectory, "investigations-synthetic.png"),
    fullPage: false,
  });

  const secondTab = await context.newPage();
  await secondTab.goto("/investigations");
  await expect(secondTab.locator(".case-table tbody tr")).toHaveCount(0);
  await secondTab.close();
  const isolated = await page.context().browser()!.newContext();
  await authorizePreviewContext(isolated);
  const otherVisitor = await isolated.newPage();
  await otherVisitor.goto(new URL("/investigations", page.url()).href);
  await expect(otherVisitor.locator(".case-table tbody tr")).toHaveCount(0);
  await isolated.close();
  expect(
    await page.evaluate(() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage),
    })),
  ).toEqual({ local: [], session: [] });
  expect((await ownApiGet(request, "/api/investigations")).status()).toBe(404);
  expect((await ownApiGet(request, "/api/reports")).status()).toBe(404);
  await page.reload();
  await expect(page.locator(".case-table tbody tr")).toHaveCount(0);
});

test("email analysis, case review and real PDF generation work without shared storage", async ({
  page,
  request,
}) => {
  const unsafeRequests: string[] = [];
  page.on("request", (r) => {
    if (/192\.0\.2\.25|accounts\.example\.test/.test(r.url()))
      unsafeRequests.push(r.url());
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
  expect(scan.ml.available).toBe(false);
  expect(scan.assessment.method).toBe("heuristic_fallback");
  expect(scan.evidence.length).toBeGreaterThan(0);
  await expect(page.locator(".email-risk-label")).toContainText(scan.risk);
  await expect(page.locator(".email-decision-text")).toContainText(
    "Rules-only demo",
  );
  await page.screenshot({
    path: resolve(evidenceDirectory, "email-analyzed.png"),
    fullPage: false,
  });
  await page
    .getByRole("button", { name: "Save Investigation", exact: true })
    .click();
  await page.getByRole("link", { name: "Investigations", exact: true }).click();
  await expect(page.locator(".case-table tbody tr")).toHaveCount(1);
  await page.getByRole("tab", { name: "Report Settings", exact: true }).click();
  await page.getByRole("button", { name: "Edit notes", exact: true }).click();
  await page
    .locator(".case-analyst-notes textarea")
    .fill("Synthetic hosted demo review. PDF and temporary state verified.");
  await page.getByRole("button", { name: "Save Notes", exact: true }).click();
  await page.getByLabel(/Case status/i).selectOption("In Review");
  await expect(page.locator(".case-table")).toContainText("In Review");
  const waiting = page.waitForEvent("download");
  const reportResponse = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/demo/reports") && r.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Generate Report (PDF)", exact: true })
    .click();
  const pdfHttp = await reportResponse;
  expect(pdfHttp.status()).toBe(200);
  expect(pdfHttp.headers()["content-type"]).toContain("application/pdf");
  const independentPdf = await ownApiPost(
    request,
    "/api/demo/reports",
    pdfHttp.request().postDataJSON(),
  );
  expect(independentPdf.status()).toBe(200);
  const bytes = await independentPdf.body();
  expect(bytes.subarray(0, 5).toString()).toBe("%PDF-");
  const download = await waiting;
  expect(download.suggestedFilename()).toMatch(/^phishlens-report-.*\.pdf$/);
  const failure = await download.failure();
  const evidence = resolve(evidenceDirectory);
  await mkdir(evidence, { recursive: true });
  await writeFile(resolve(evidence, "hosted-demo-report.pdf"), bytes);
  let nativeMatches = null;
  if (failure === null) {
    const nativePath = resolve(evidence, "native-hosted-demo-report.pdf");
    await download.saveAs(nativePath);
    nativeMatches = (await readFile(nativePath)).equals(bytes);
    expect(nativeMatches).toBe(true);
  }
  await writeFile(
    resolve(evidence, "native-pdf-result.json"),
    JSON.stringify(
      {
        native_failure: failure,
        native_matches_http: nativeMatches,
        http_status: pdfHttp.status(),
        bytes: bytes.length,
        filename: download.suggestedFilename(),
      },
      null,
      2,
    ),
  );
  expect(unsafeRequests).toEqual([]);
  expect((await ownApiGet(request, "/api/analyses/" + scan.id)).status()).toBe(
    404,
  );
  await page.getByRole("link", { name: "Reports", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: /Reports/ }).first(),
  ).toBeVisible();
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(
    page.getByText("Demo Data & Privacy", { exact: true }),
  ).toBeVisible();
});

test("URL input stays passive and the guest layouts fit desktop and mobile", async ({
  page,
}) => {
  await page.goto("/analyze/url");
  await page
    .getByLabel("URL to investigate")
    .fill("http://user:password@192.0.2.22/account/verify");
  const response = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/analyze/url") && r.request().method() === "POST",
  );
  await page
    .getByRole("button", { name: "Analyze Safely", exact: true })
    .click();
  const scan = await (await response).json();
  expect(scan.kind).toBe("url");
  expect(scan.ml.available).toBe(false);
  expect(scan.evidence.length).toBeGreaterThan(0);
  await expect(page.locator(".url-summary")).toContainText("Risk");
  for (const width of [1672, 390]) {
    await page.setViewportSize({ width, height: 941 });
    for (const route of ["/", "/analyze/email", "/investigations"]) {
      await page.goto(route);
      await expect(
        page.getByRole("note", { name: "Public demo privacy" }),
      ).toBeVisible();
      expect(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
      ).toBe(true);
      await page.screenshot({
        path: resolve(
          evidenceDirectory,
          `${route === "/" ? "dashboard" : route.includes("email") ? "email" : "investigations"}-${width}.png`,
        ),
        fullPage: false,
      });
    }
  }
});
