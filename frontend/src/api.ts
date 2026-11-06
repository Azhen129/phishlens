import type {
  Analysis,
  Investigation,
  Metrics,
  Report,
  CaseStatus,
  ModelHealth,
} from "./types";
import { request } from "./request";
import { isPublicDemo } from "./environment";
import { demoApi } from "./demoApi";

const localApi = {
  analyzeEmail: (raw: string) =>
    request<Analysis>("/analyze/email", {
      method: "POST",
      body: JSON.stringify({ raw }),
    }),
  uploadEmail: (file: File) => {
    const data = new FormData();
    data.append("file", file);
    return request<Analysis>("/analyze/email/file", {
      method: "POST",
      body: data,
    });
  },
  analyzeUrl: (url: string) =>
    request<Analysis>("/analyze/url", {
      method: "POST",
      body: JSON.stringify({ url }),
    }),
  analyses: () => request<Analysis[]>("/analyses"),
  analysis: (id: string) =>
    request<Analysis>("/analyses/" + encodeURIComponent(id)),
  deleteAnalysis: (id: string) =>
    request<void>("/analyses/" + encodeURIComponent(id), { method: "DELETE" }),
  cases: () => request<Investigation[]>("/investigations"),
  saveCase: (analysis_id: string) =>
    request<Investigation>("/investigations", {
      method: "POST",
      body: JSON.stringify({ analysis_id }),
    }),
  updateCase: (id: string, data: { status?: CaseStatus; notes?: string }) =>
    request<Investigation>("/investigations/" + encodeURIComponent(id), {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
  deleteCase: (id: string) =>
    request<void>("/investigations/" + encodeURIComponent(id), {
      method: "DELETE",
    }),
  metrics: () => request<Metrics>("/metrics"),
  report: (data: {
    analysis_id?: string;
    case_id?: string;
    include_raw?: boolean;
  }) =>
    request<Report>("/reports", { method: "POST", body: JSON.stringify(data) }),
  reports: () => request<Report[]>("/reports"),
  downloadReport: (report: Report) => {
    const anchor = document.createElement("a");
    anchor.href = "/api/reports/" + encodeURIComponent(report.id) + "/download";
    anchor.download = report.filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
  },
  health: () => request<ModelHealth>("/health"),
  clearData: () =>
    request<void>("/data", {
      method: "DELETE",
      body: JSON.stringify({ confirm: "DELETE ALL LOCAL DATA" }),
    }),
};

export const api = isPublicDemo ? demoApi : localApi;
