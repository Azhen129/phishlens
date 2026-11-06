import { beforeEach, describe, expect, it, vi } from "vitest";
import { demoApi } from "./demoApi";
import type { Analysis } from "./types";

const source =
  "Subject: [SYNTHETIC DEMO] Account review\n\nSynthetic content only.";
const scan: Analysis = {
  id: "scan-demo-1",
  kind: "email",
  created_at: "2026-11-05T10:00:00+00:00",
  subject: "[SYNTHETIC DEMO] Account review",
  score: 10,
  risk: "Low",
  summary: "One observed rule indicator.",
  evidence: [
    {
      id: "language-urgency",
      title: "Urgent language",
      source: "Message language",
      detail: "Observed fixture text.",
      severity: "Low",
      weight: 10,
    },
  ],
  links: [],
  attachments: [],
  ml: { available: false, reason: "Rules-only public demo." },
  assessment: {
    method: "heuristic_fallback",
    score: 10,
    risk: "Low",
    label: "Low heuristic risk",
    limitations: [],
  },
  duration_ms: 1,
};

function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(async () => {
  await demoApi.clearData();
  vi.restoreAllMocks();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => response(scan)),
  );
});

describe("public guest workspace", () => {
  it("keeps guest cases and notes in memory and computes charts from them", async () => {
    const analysis = await demoApi.analyzeEmail(source);
    const item = await demoApi.saveCase(analysis.id);
    await demoApi.updateCase(item.id, {
      status: "In Review",
      notes: "Synthetic analyst note.",
    });
    expect((await demoApi.cases())[0]).toMatchObject({
      notes: "Synthetic analyst note.",
      status: "In Review",
    });
    expect(await demoApi.metrics()).toMatchObject({
      total: 1,
      reports: 0,
      high: 0,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith("/api/analyze/email", expect.anything());
    const copied = await demoApi.cases();
    copied[0].notes = "changed copy";
    expect((await demoApi.cases())[0].notes).toBe("Synthetic analyst note.");
  });

  it("requests a real PDF from its original source and preserves report snapshots", async () => {
    const analysis = await demoApi.analyzeEmail(source);
    const item = await demoApi.saveCase(analysis.id);
    await demoApi.updateCase(item.id, {
      status: "In Review",
      notes: "Saved review.",
    });
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response("%PDF-demo", {
        headers: { "Content-Type": "application/pdf" },
      }),
    );
    const report = await demoApi.report({ case_id: item.id });
    const body = JSON.parse(vi.mocked(fetch).mock.calls[1][1]!.body as string);
    expect(body).toMatchObject({
      input: source,
      kind: "email",
      analysis_id: analysis.id,
      case: { id: item.id, status: "In Review", notes: "Saved review." },
    });
    expect(report.filename).toMatch(/^phishlens-report-.*\.pdf$/);
    expect((await demoApi.reports())[0].id).toBe(report.id);
    expect((await demoApi.metrics()).reports).toBe(1);
    await demoApi.deleteAnalysis(analysis.id);
    expect(await demoApi.cases()).toEqual([]);
    expect(await demoApi.reports()).toEqual([]);
  });

  it("preserves uploaded email bytes for the report reanalysis", async () => {
    const bytes = new Uint8Array([65, 233, 66]);
    const file = {
      name: "fixture.eml",
      size: bytes.length,
      arrayBuffer: async () => bytes.buffer,
      text: async () => "A�B",
    } as File;
    const analysis = await demoApi.uploadEmail(file);
    vi.mocked(fetch).mockResolvedValueOnce(
      new Response("%PDF-demo", {
        headers: { "Content-Type": "application/pdf" },
      }),
    );
    await demoApi.report({ analysis_id: analysis.id });
    const body = JSON.parse(vi.mocked(fetch).mock.calls[1][1]!.body as string);
    expect(body.input_base64).toBe("QelC");
    expect(body.input).toBeUndefined();
  });

  it("keeps an empty separate tab and clears current-tab records", async () => {
    await demoApi.analyzeEmail(source);
    vi.resetModules();
    const otherTab = (await import("./demoApi")).demoApi;
    expect(await otherTab.analyses()).toEqual([]);
    expect(await demoApi.analyses()).toHaveLength(1);
    await demoApi.clearData();
    expect(await demoApi.analyses()).toEqual([]);
  });

  it("does not restore an in-flight analysis after the user clears the tab", async () => {
    let finish!: (value: Response) => void;
    vi.mocked(fetch).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const pending = demoApi.analyzeEmail(source);
    await demoApi.clearData();
    finish(response(scan));
    await expect(pending).rejects.toThrow("cleared");
    expect(await demoApi.analyses()).toEqual([]);
  });

  it("does not restore a PDF after the user clears its investigation", async () => {
    const analysis = await demoApi.analyzeEmail(source);
    const item = await demoApi.saveCase(analysis.id);
    let finish!: (value: Response) => void;
    vi.mocked(fetch).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const pending = demoApi.report({ case_id: item.id });
    await demoApi.clearData();
    finish(
      new Response("%PDF-demo", {
        headers: { "Content-Type": "application/pdf" },
      }),
    );
    await expect(pending).rejects.toThrow("cleared");
    expect(await demoApi.reports()).toEqual([]);
  });

  it("does not invent analysis results after a service failure", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      response({ detail: "Email exceeds the demo limit." }, 413),
    );
    await expect(demoApi.analyzeEmail(source)).rejects.toThrow("demo limit");
    expect(await demoApi.analyses()).toEqual([]);
  });

  it("rejects large input before sending it to the public service", async () => {
    await expect(
      demoApi.analyzeEmail("x".repeat(256 * 1024 + 1)),
    ).rejects.toThrow("256 KiB");
    expect(fetch).not.toHaveBeenCalled();
  });
});
