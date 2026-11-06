import suspiciousExample from "../../fixtures/suspicious-invoice.eml?raw";
import ordinaryExample from "../../fixtures/ordinary-update.eml?raw";
import { request, requestResponse } from "./request";
import type {
  Analysis,
  CaseStatus,
  Investigation,
  Metrics,
  ModelHealth,
  Report,
} from "./types";

const SESSION_LIMIT = 20;
const EMAIL_BYTES = 256 * 1024;
const analyses = new Map<
  string,
  { analysis: Analysis; input: string; inputBase64?: string }
>();
const cases = new Map<string, Investigation>();
const reports = new Map<string, { report: Report; pdf: Blob }>();
const downloadUrls = new Set<string>();
let sessionRevision = 0;

function requireAnalysis(id: string) {
  const value = analyses.get(id);
  if (!value) throw new Error("This analysis is unavailable in this demo tab.");
  return value;
}

function requireCase(id: string) {
  const value = cases.get(id);
  if (!value)
    throw new Error("This investigation is unavailable in this demo tab.");
  return value;
}

function checkSpace(size: number) {
  if (size >= SESSION_LIMIT)
    throw new Error(
      "This demo holds up to 20 items. Clear this tab's demo data to continue.",
    );
}

function remember(
  analysis: Analysis,
  input: string,
  revision: number,
  inputBase64?: string,
) {
  if (revision !== sessionRevision)
    throw new Error(
      "The demo tab was cleared while this analysis was running.",
    );
  checkSpace(analyses.size);
  analyses.set(analysis.id, {
    analysis: structuredClone(analysis),
    input,
    inputBase64,
  });
  return structuredClone(analysis);
}

function listCases() {
  return structuredClone([...cases.values()].reverse());
}

function sessionMetrics(): Metrics {
  const visible = [...cases.values()].filter(
    (item) => item.status !== "Archived",
  );
  const trend = new Map<string, number[]>();
  const categoryCounts = new Map<string, number>();
  for (const item of visible) {
    const date = item.created_at.slice(0, 10);
    trend.set(date, [...(trend.get(date) || []), item.score]);
    const ids = item.analysis.evidence.map((finding) => finding.id).join(" ");
    const category = ids.includes("language-credentials")
      ? "Credential language"
      : /brand|lookalike/.test(ids)
        ? "Brand / identity indicators"
        : ids.includes("attachment")
          ? "Attachment indicators"
          : item.analysis.evidence.some((finding) =>
                /^(URL|Extracted URL|HTML anchor)/.test(finding.source),
              )
            ? "URL syntax indicators"
            : "Other / no indicators";
    categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);
  }
  return {
    total: visible.length,
    high: visible.filter((item) => item.risk === "High").length,
    false_positives: visible.filter((item) => item.status === "False Positive")
      .length,
    reports: reports.size,
    trend: [...trend]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, values]) => ({
        date,
        score:
          Math.round(
            (10 * values.reduce((sum, value) => sum + value, 0)) /
              values.length,
          ) / 10,
      })),
    severity: (["High", "Medium", "Low"] as const).map((name) => ({
      name,
      value: visible.filter((item) => item.risk === name).length,
    })),
    categories: [...categoryCounts].map(([name, value]) => ({ name, value })),
  };
}

export const demoApi = {
  analyzeEmail: async (raw: string) => {
    const revision = sessionRevision;
    checkSpace(analyses.size);
    if (new TextEncoder().encode(raw).length > EMAIL_BYTES)
      throw new Error("Public demo emails are limited to 256 KiB.");
    const analysis = await request<Analysis>("/analyze/email", {
      method: "POST",
      body: JSON.stringify({ raw }),
    });
    return remember(analysis, raw, revision);
  },
  uploadEmail: async (file: File) => {
    const revision = sessionRevision;
    checkSpace(analyses.size);
    if (!file.name.toLowerCase().endsWith(".eml"))
      throw new Error("Choose an .eml file for analysis.");
    if (file.size > EMAIL_BYTES)
      throw new Error("Public demo emails are limited to 256 KiB.");
    const data = new FormData();
    data.append("file", file);
    const analysis = await request<Analysis>("/analyze/email/file", {
      method: "POST",
      body: data,
    });
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return remember(analysis, await file.text(), revision, btoa(binary));
  },
  analyzeUrl: async (url: string) => {
    const revision = sessionRevision;
    checkSpace(analyses.size);
    const analysis = await request<Analysis>("/analyze/url", {
      method: "POST",
      body: JSON.stringify({ url }),
    });
    return remember(analysis, url, revision);
  },
  analyses: async () =>
    structuredClone(
      [...analyses.values()].reverse().map((item) => item.analysis),
    ),
  analysis: async (id: string) => structuredClone(requireAnalysis(id).analysis),
  deleteAnalysis: async (id: string) => {
    requireAnalysis(id);
    analyses.delete(id);
    for (const [caseId, item] of cases)
      if (item.analysis_id === id) cases.delete(caseId);
    for (const [reportId, item] of reports)
      if (item.report.analysis_id === id) reports.delete(reportId);
  },
  cases: async () => listCases(),
  saveCase: async (analysis_id: string) => {
    checkSpace(cases.size);
    const analysis = structuredClone(requireAnalysis(analysis_id).analysis);
    const at = new Date().toISOString();
    const item: Investigation = {
      id: "PL-" + crypto.randomUUID().slice(0, 8).toUpperCase(),
      analysis_id,
      subject: analysis.subject,
      score: analysis.score,
      risk: analysis.risk,
      heuristic_score: analysis.score,
      heuristic_risk: analysis.risk,
      assessment_method: "heuristic_fallback",
      final_assessment: analysis.assessment,
      source: analysis.kind === "email" ? "Email" : "URL",
      status: "Open",
      notes: "",
      created_at: at,
      updated_at: at,
      analysis,
      timeline: [
        {
          at,
          title: "Investigation created",
          detail:
            "Temporary guest investigation created from a passive analysis.",
        },
        {
          at,
          title: "Evidence attached",
          detail: `${analysis.evidence.length} observations. Heuristic score ${analysis.score}/100.`,
        },
      ],
    };
    cases.set(item.id, item);
    return structuredClone(item);
  },
  updateCase: async (
    id: string,
    data: { status?: CaseStatus; notes?: string },
  ) => {
    const item = requireCase(id);
    if (data.notes && data.notes.length > 4000)
      throw new Error("Demo analyst notes are limited to 4,000 characters.");
    const at = new Date().toISOString();
    if (data.status && data.status !== item.status) {
      item.timeline.push({
        at,
        title: "Status changed",
        detail: `${item.status} → ${data.status}`,
      });
      item.status = data.status;
    }
    if (data.notes !== undefined && data.notes !== item.notes) {
      item.timeline.push({
        at,
        title: "Analyst review",
        detail: "Analyst notes updated.",
      });
      item.notes = data.notes;
    }
    item.timeline = item.timeline.slice(-20);
    item.updated_at = at;
    return structuredClone(item);
  },
  deleteCase: async (id: string) => {
    requireCase(id);
    cases.delete(id);
    for (const [reportId, item] of reports)
      if (item.report.case_id === id) reports.delete(reportId);
  },
  metrics: async () => sessionMetrics(),
  report: async (data: {
    analysis_id?: string;
    case_id?: string;
    include_raw?: boolean;
  }) => {
    const revision = sessionRevision;
    checkSpace(reports.size);
    if (Boolean(data.analysis_id) === Boolean(data.case_id))
      throw new Error("Select one analysis or investigation for the report.");
    const investigation = data.case_id
      ? structuredClone(requireCase(data.case_id))
      : undefined;
    const stored = requireAnalysis(
      investigation?.analysis_id || data.analysis_id!,
    );
    const id = "report-" + crypto.randomUUID().replaceAll("-", "").slice(0, 16);
    const created_at = new Date().toISOString();
    const response = await requestResponse("/demo/reports", {
      method: "POST",
      body: JSON.stringify({
        kind: stored.analysis.kind,
        ...(stored.inputBase64
          ? { input_base64: stored.inputBase64 }
          : { input: stored.input }),
        analysis_id: stored.analysis.id,
        analyzed_at: stored.analysis.created_at,
        report_id: id,
        created_at,
        include_raw: data.include_raw || false,
        case: investigation && {
          id: investigation.id,
          status: investigation.status,
          notes: investigation.notes,
          created_at: investigation.created_at,
          timeline: investigation.timeline,
        },
      }),
    });
    if (!response.headers.get("content-type")?.startsWith("application/pdf"))
      throw new Error("The demo service did not return a PDF report.");
    const pdf = await response.blob();
    if ((await pdf.slice(0, 5).text()) !== "%PDF-")
      throw new Error("The demo service returned an incomplete PDF report.");
    if (
      revision !== sessionRevision ||
      !analyses.has(stored.analysis.id) ||
      (investigation && !cases.has(investigation.id))
    )
      throw new Error(
        "The demo data was cleared while this report was being prepared.",
      );
    checkSpace(reports.size);
    const report: Report = {
      id,
      created_at,
      filename: `phishlens-${id}.pdf`,
      url: "memory:" + id,
      analysis_id: stored.analysis.id,
      case_id: investigation?.id,
    };
    reports.set(id, { report, pdf });
    if (investigation) {
      const item = requireCase(investigation.id);
      item.timeline.push({
        at: created_at,
        title: "Report generated",
        detail: report.filename,
      });
      item.timeline = item.timeline.slice(-20);
      item.updated_at = created_at;
    }
    return structuredClone(report);
  },
  reports: async () =>
    structuredClone([...reports.values()].reverse().map((item) => item.report)),
  downloadReport: (report: Report) => {
    const stored = reports.get(report.id);
    if (!stored)
      throw new Error("This report is unavailable in this demo tab.");
    const url = URL.createObjectURL(stored.pdf);
    downloadUrls.add(url);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = stored.report.filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      downloadUrls.delete(url);
    }, 60000);
  },
  health: () => request<ModelHealth>("/health"),
  clearData: async () => {
    sessionRevision += 1;
    analyses.clear();
    cases.clear();
    reports.clear();
    for (const url of downloadUrls) URL.revokeObjectURL(url);
    downloadUrls.clear();
  },
};

export async function loadDemoExamples() {
  const examples = [ordinaryExample, suspiciousExample].map((raw) =>
    raw.replace("Subject: [DEV FIXTURE]", "Subject: [SYNTHETIC DEMO]"),
  );
  for (const raw of examples) {
    const previous = [...analyses.values()].find((item) => item.input === raw);
    const analysis = previous?.analysis || (await demoApi.analyzeEmail(raw));
    if (![...cases.values()].some((item) => item.analysis_id === analysis.id)) {
      const item = await demoApi.saveCase(analysis.id);
      await demoApi.updateCase(item.id, {
        notes:
          "Synthetic demonstration example. All indicators were computed by the passive heuristic analyzer.",
      });
    }
  }
}
