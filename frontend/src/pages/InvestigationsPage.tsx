import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Activity,
  Archive,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Crosshair,
  Download,
  ExternalLink,
  FileText,
  Folder,
  Layers,
  Link,
  Mail,
  MoreHorizontal,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  TriangleAlert,
} from "lucide-react";
import { api } from "../api";
import { finalSummary, ModelDetails } from "../ModelResult";
import type { Analysis, CaseStatus, Investigation, Metrics } from "../types";
import "./investigations.css";

type Props = {
  cases: Investigation[];
  metrics: Metrics | null;
  onRefresh: () => void;
  notify: (s: string) => void;
  onOpenAnalysis: (a: Analysis) => void;
  reportsMode?: boolean;
};
type Report = { id: string; filename: string; created_at: string; url: string };
const statuses: CaseStatus[] = [
  "Open",
  "In Progress",
  "In Review",
  "Resolved",
  "False Positive",
  "Closed",
  "Archived",
];
const colors = ["#00d8d1", "#26c8bc", "#ffc63b", "#ff6068", "#82949e"];
const dateTime = (s: string) =>
  new Date(s).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
function Risk({ value }: { value: string }) {
  return (
    <span className={`case-pill case-risk-${value.toLowerCase()}`}>
      {value}
    </span>
  );
}
function CaseIcon({ source }: { source: string }) {
  return source.toLowerCase() === "url" ? (
    <Link size={17} />
  ) : (
    <Mail size={17} />
  );
}

export default function InvestigationsPage({
  cases,
  metrics,
  onRefresh,
  notify,
  onOpenAnalysis,
  reportsMode = false,
}: Props) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [days, setDays] = useState("30");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState("Case Summary");
  const [sortDescending, setSortDescending] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [notes, setNotes] = useState("");
  const [editing, setEditing] = useState(false);
  const [includeRaw, setIncludeRaw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reports, setReports] = useState<Report[]>([]);
  const [confirmation, setConfirmation] = useState<"archive" | "delete" | null>(
    null,
  );
  const [error, setError] = useState("");
  const selected = cases.find((c) => c.id === selectedId) || cases[0] || null;
  const filtered = useMemo(
    () =>
      cases
        .filter((c) => {
          const matches =
            `${c.id} ${c.subject} ${c.notes} ${c.analysis.email?.from || ""} ${c.analysis.links?.map((l) => l.host).join(" ")}`
              .toLowerCase()
              .includes(query.toLowerCase());
          return (
            matches &&
            (!status ? c.status !== "Archived" : c.status === status) &&
            (!severity || c.risk === severity) &&
            (!source || c.source === source) &&
            (days === "all" ||
              Date.now() - new Date(c.updated_at).getTime() <= +days * 86400000)
          );
        })
        .sort(
          (a, b) =>
            (new Date(b.updated_at).getTime() -
              new Date(a.updated_at).getTime()) *
            (sortDescending ? 1 : -1),
        ),
    [cases, query, status, severity, source, days, sortDescending],
  );
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const rows = filtered.slice(
    (Math.min(page, pages) - 1) * pageSize,
    Math.min(page, pages) * pageSize,
  );
  const categories = metrics?.categories || [];
  const categoryTotal = categories.reduce((sum, c) => sum + c.value, 0);
  const chartStops = useMemo(() => {
    let sum = 0;
    return categories
      .map((c, i) => {
        const start = sum;
        sum += categoryTotal ? (c.value / categoryTotal) * 100 : 0;
        return `${colors[i % colors.length]} ${start}% ${sum}%`;
      })
      .join(", ");
  }, [categories, categoryTotal]);

  useEffect(() => {
    setPage(1);
  }, [query, days, status, severity, source, pageSize]);
  useEffect(() => {
    setQuery(searchParams.get("q") || "");
  }, [searchParams]);
  useEffect(() => {
    setNotes(selected?.notes || "");
    setEditing(false);
  }, [selected?.id, selected?.notes]);
  useEffect(() => {
    if (reportsMode)
      api
        .reports()
        .then((r) => setReports(r as Report[]))
        .catch((e) => setError(e.message));
  }, [reportsMode, metrics?.reports]);
  useEffect(() => {
    if (!confirmation) return;
    const previousFocus = document.activeElement as HTMLElement | null;
    const dialog = document.querySelector<HTMLElement>(".case-confirm-dialog");
    const buttons = dialog?.querySelectorAll<HTMLButtonElement>("button");
    buttons?.[0]?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setConfirmation(null);
      if (event.key === "Tab" && buttons?.length) {
        const first = buttons[0],
          last = buttons[buttons.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previousFocus?.focus();
    };
  }, [confirmation]);

  async function perform(action: () => Promise<unknown>, success: string) {
    setBusy(true);
    setError("");
    try {
      await action();
      onRefresh();
      notify(success);
      return true;
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "The operation could not be completed.",
      );
      return false;
    } finally {
      setBusy(false);
    }
  }
  async function exportReport() {
    if (!selected) return;
    await perform(async () => {
      const report = await api.report({
        case_id: selected.id,
        include_raw: includeRaw,
      });
      api.downloadReport(report);
      if (reportsMode) setReports((await api.reports()) as Report[]);
    }, "PDF report generated from the saved evidence.");
  }
  function openCase() {
    if (selected) {
      onOpenAnalysis(selected.analysis);
      navigate(
        selected.analysis.kind === "url" ? "/analyze/url" : "/analyze/email",
      );
    }
  }
  function resetFilters() {
    setQuery("");
    setDays("30");
    setStatus("");
    setSeverity("");
    setSource("");
    setPage(1);
  }
  const timeline = selected?.timeline || [];
  const notesEditor = selected && (
    <div className="case-analyst-notes">
      <label htmlFor="analyst-notes">Analyst notes</label>
      {editing ? (
        <>
          <textarea
            id="analyst-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            maxLength={10000}
            placeholder="Record your review and recommended next steps…"
          />
          <div>
            <button
              className="button primary"
              disabled={busy}
              onClick={() =>
                perform(
                  () => api.updateCase(selected.id, { notes }),
                  "Analyst notes saved.",
                ).then((ok) => {
                  if (ok) setEditing(false);
                })
              }
            >
              Save Notes
            </button>
            <button
              className="button"
              onClick={() => {
                setNotes(selected.notes);
                setEditing(false);
              }}
            >
              Cancel
            </button>
          </div>
        </>
      ) : (
        <>
          <p>{selected.notes || "No analyst notes yet."}</p>
          <button className="case-text-button" onClick={() => setEditing(true)}>
            Edit notes
          </button>
        </>
      )}
      <button className="case-delete" onClick={() => setConfirmation("delete")}>
        <Trash2 size={14} />
        Delete case
      </button>
    </div>
  );

  return (
    <div className="investigations-page">
      <div className="case-page-title">
        <h1>
          {reportsMode
            ? "Reports & Evidence Exports"
            : "Investigations & Reports"}
        </h1>
        <p>
          {reportsMode
            ? "Download generated reports and create evidence-backed exports from saved investigations."
            : "Manage investigation cases, review findings, generate reports, and track historical activity."}
        </p>
      </div>
      {error && (
        <div className="case-error" role="alert">
          {error}
          <button onClick={() => setError("")} aria-label="Dismiss error">
            ×
          </button>
        </div>
      )}
      <div className="case-main-grid">
        <div className="case-left-column">
          <div className="case-kpis">
            <div className="case-kpi">
              <span className="case-kpi-icon">
                <Folder />
              </span>
              <div>
                <strong>Total Investigations</strong>
                <b>{(metrics?.total ?? cases.length).toLocaleString()}</b>
                <small>Saved local cases</small>
              </div>
            </div>
            <div className="case-kpi case-kpi-danger">
              <span className="case-kpi-icon">
                <TriangleAlert />
              </span>
              <div>
                <strong>High Risk Cases</strong>
                <b>
                  {metrics?.high ??
                    cases.filter((c) => c.risk === "High").length}
                </b>
                <small>Estimated risk · not a verdict</small>
              </div>
            </div>
            <div className="case-kpi">
              <span className="case-kpi-icon">
                <ShieldCheck />
              </span>
              <div>
                <strong>False Positives Reviewed</strong>
                <b>{metrics?.false_positives ?? 0}</b>
                <small>Marked by an analyst</small>
              </div>
            </div>
            <div className="case-kpi">
              <span className="case-kpi-icon">
                <FileText />
              </span>
              <div>
                <strong>Reports Exported</strong>
                <b>{metrics?.reports ?? 0}</b>
                <small>Evidence-backed PDF reports</small>
              </div>
            </div>
          </div>
          <section
            className="panel case-table-panel"
            aria-label={reportsMode ? "Generated reports" : "Investigations"}
          >
            <div className="case-table-toolbar">
              <span className="case-toolbar-tab">
                <Crosshair size={21} />
                {reportsMode ? "Generated Reports" : "Investigations"}
              </span>
              <div className="case-toolbar-actions">
                <button
                  className="button"
                  disabled={!selected || busy}
                  onClick={exportReport}
                >
                  <FileText size={16} />
                  Generate Report
                </button>
                <button
                  className="button primary"
                  onClick={() => navigate("/analyze/email")}
                >
                  <Plus size={18} />
                  New Investigation
                </button>
              </div>
            </div>
            {reportsMode ? (
              <div className="reports-library">
                {reports.length ? (
                  reports.map((report) => (
                    <article key={report.id}>
                      <span className="case-kpi-icon">
                        <FileText />
                      </span>
                      <div>
                        <strong>{report.filename}</strong>
                        <small>{dateTime(report.created_at)}</small>
                      </div>
                      <button
                        className="button"
                        onClick={() => api.downloadReport(report)}
                        aria-label={`Download ${report.filename}`}
                      >
                        <Download size={16} />
                        Download
                      </button>
                    </article>
                  ))
                ) : (
                  <div className="case-empty">
                    <FileText size={34} />
                    <h3>No reports generated yet</h3>
                    <p>
                      Select an investigation and generate a PDF containing its
                      actual findings and limitations.
                    </p>
                  </div>
                )}
              </div>
            ) : (
              <>
                <div className="case-filters">
                  <label className="case-search">
                    <Search size={17} />
                    <input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search cases by subject, sender, domain, or case ID..."
                      aria-label="Search investigations"
                    />
                  </label>
                  <select
                    aria-label="Date range"
                    value={days}
                    onChange={(e) => setDays(e.target.value)}
                  >
                    <option value="30">Last 30 Days</option>
                    <option value="7">Last 7 Days</option>
                    <option value="all">All Time</option>
                  </select>
                  <select
                    aria-label="Filter status"
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                  >
                    <option value="">All Statuses</option>
                    {statuses.map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                  <select
                    aria-label="Filter severity"
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                  >
                    <option value="">All Severities</option>
                    {["High", "Medium", "Low"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                  <select
                    aria-label="Filter source"
                    value={source}
                    onChange={(e) => setSource(e.target.value)}
                  >
                    <option value="">All Sources</option>
                    <option>Email</option>
                    <option>URL</option>
                  </select>
                  <button className="case-text-button" onClick={resetFilters}>
                    Reset
                  </button>
                </div>
                <div className="case-table-scroll">
                  <table className="case-table">
                    <thead>
                      <tr>
                        <th aria-label="Selected case"></th>
                        <th>Case ID</th>
                        <th>Subject / Indicator</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Source</th>
                        <th>Analyst Notes</th>
                        <th>
                          <button
                            onClick={() => setSortDescending(!sortDescending)}
                          >
                            Last Updated{" "}
                            <ChevronDown
                              size={12}
                              style={{
                                transform: sortDescending
                                  ? undefined
                                  : "rotate(180deg)",
                              }}
                            />
                          </button>
                        </th>
                        <th aria-label="Case actions"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((c) => (
                        <tr
                          key={c.id}
                          className={selected?.id === c.id ? "selected" : ""}
                          onClick={() => setSelectedId(c.id)}
                        >
                          <td>
                            <button
                              className={`case-selector ${selected?.id === c.id ? "checked" : ""}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedId(c.id);
                              }}
                              aria-label={`Select ${c.id}`}
                              aria-pressed={selected?.id === c.id}
                            >
                              {selected?.id === c.id && <Check size={12} />}
                            </button>
                          </td>
                          <td className="case-id">{c.id}</td>
                          <td>
                            <span className="case-subject">
                              <CaseIcon source={c.source} />
                              <span>
                                <strong>{c.subject}</strong>
                                <small>
                                  {c.analysis.links?.[0]?.host ||
                                    c.analysis.email?.from ||
                                    "Submitted email"}
                                </small>
                              </span>
                            </span>
                          </td>
                          <td>
                            <Risk value={c.risk} />
                          </td>
                          <td>
                            <span
                              className={`case-pill case-status-${c.status.replaceAll(" ", "-").toLowerCase()}`}
                            >
                              {c.status}
                            </span>
                          </td>
                          <td>
                            <span className="case-source">
                              <CaseIcon source={c.source} />
                              {c.source}
                            </span>
                          </td>
                          <td>
                            <span className="case-notes-preview">
                              {c.notes || "Awaiting analyst review."}
                            </span>
                          </td>
                          <td className="case-date">
                            {dateTime(c.updated_at)}
                          </td>
                          <td>
                            <button
                              className="case-row-menu"
                              aria-label={`Actions for ${c.id}`}
                              onClick={(e) => {
                                e.stopPropagation();
                                setSelectedId(c.id);
                                setTab("Report Settings");
                              }}
                            >
                              <MoreHorizontal size={17} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!rows.length && (
                    <div className="case-empty">
                      <Folder size={34} />
                      <h3>
                        {cases.length
                          ? "No matching investigations"
                          : "Your investigation workspace is ready"}
                      </h3>
                      <p>
                        {cases.length
                          ? "Try changing the search or filters."
                          : "Analyze an email or URL, then save its evidence as an investigation."}
                      </p>
                      <button
                        className="button primary"
                        onClick={() => navigate("/analyze/email")}
                      >
                        <Plus size={16} />
                        Analyze an email
                      </button>
                    </div>
                  )}
                </div>
                <div className="case-pagination">
                  <span>
                    Showing{" "}
                    {filtered.length
                      ? (Math.min(page, pages) - 1) * pageSize + 1
                      : 0}
                    –{Math.min(page * pageSize, filtered.length)} of{" "}
                    {filtered.length.toLocaleString()} investigations
                  </span>
                  <div>
                    <label>
                      Rows per page:{" "}
                      <select
                        value={pageSize}
                        onChange={(e) => setPageSize(+e.target.value)}
                        aria-label="Rows per page"
                      >
                        <option value={6}>6</option>
                        <option value={25}>25</option>
                        <option value={50}>50</option>
                      </select>
                    </label>
                    <button
                      onClick={() => setPage(Math.max(1, page - 1))}
                      disabled={page <= 1}
                      aria-label="Previous page"
                    >
                      <ChevronLeft size={15} />
                    </button>
                    <span className="case-current-page">
                      {Math.min(page, pages)}
                    </span>
                    <span className="muted">of {pages}</span>
                    <button
                      onClick={() => setPage(Math.min(pages, page + 1))}
                      disabled={page >= pages}
                      aria-label="Next page"
                    >
                      <ChevronRight size={15} />
                    </button>
                  </div>
                </div>
              </>
            )}
          </section>
        </div>
        <aside
          className="panel case-report-preview"
          aria-label="Report preview"
        >
          <h2>
            <FileText size={19} />
            Report Preview & Generator
          </h2>
          {selected ? (
            <>
              <div className="case-preview-heading">
                <span className="case-kpi-icon">
                  <CaseIcon source={selected.source} />
                </span>
                <div>
                  <strong>
                    {selected.id} — {selected.subject}
                  </strong>
                  <small>Investigated: {dateTime(selected.created_at)}</small>
                </div>
                <Risk value={selected.risk} />
              </div>
              <div className="case-preview-tabs" role="tablist">
                {["Case Summary", "Evidence", "Report Settings"].map((t) => (
                  <button
                    role="tab"
                    aria-selected={tab === t}
                    className={tab === t ? "active" : ""}
                    key={t}
                    onClick={() => setTab(t)}
                  >
                    {t}
                    {t === "Evidence"
                      ? ` (${selected.analysis.evidence.length})`
                      : ""}
                  </button>
                ))}
              </div>
              <div className="case-preview-content">
                {tab === "Case Summary" && (
                  <>
                    <dl className="case-summary-fields">
                      <dt>Subject</dt>
                      <dd>{selected.subject}</dd>
                      <dt>Sender</dt>
                      <dd>
                        {selected.analysis.email?.from?.match(
                          /<([^>]+)>/,
                        )?.[1] ||
                          selected.analysis.email?.from ||
                          "Not applicable — URL input"}
                      </dd>
                      <dt>Primary Indicator</dt>
                      <dd>
                        {selected.analysis.links?.[0]?.host ||
                          "See extracted evidence"}
                      </dd>
                      <dt>Analysis Result</dt>
                      <dd>
                        <span className="case-result-label">
                          <TriangleAlert size={15} />
                          {selected.analysis.ml.available
                            ? finalSummary(selected.analysis)
                            : `${selected.risk} heuristic risk (${selected.score}/100 points)`}
                        </span>
                      </dd>
                      <dt>Evidence Count</dt>
                      <dd>
                        <Layers size={15} />
                        {selected.analysis.evidence.length} items
                      </dd>
                      <dt>Recommended Action</dt>
                      <dd className="case-recommendation">
                        <strong>
                          <ShieldCheck size={18} />
                          {selected.risk === "High"
                            ? "Escalate for review"
                            : "Review before interacting"}
                        </strong>
                        <p>
                          {selected.risk === "High"
                            ? "Avoid links and attachments. Share the evidence with your security team."
                            : "No result establishes safety. Verify the request through a trusted channel."}
                        </p>
                      </dd>
                    </dl>
                  </>
                )}
                {tab === "Evidence" && (
                  <div className="case-evidence-list">
                    <ModelDetails analysis={selected.analysis} />
                    {selected.analysis.evidence.length ? (
                      selected.analysis.evidence.map((e) => (
                        <article key={e.id}>
                          <div>
                            <strong>{e.title}</strong>
                            <Risk value={e.severity} />
                          </div>
                          <p>{e.detail}</p>
                          <small>
                            {e.source} · Rule weight {e.weight}
                          </small>
                        </article>
                      ))
                    ) : (
                      <p className="muted">
                        No known rule indicators were detected. This does not
                        verify safety.
                      </p>
                    )}
                  </div>
                )}
                {tab === "Report Settings" && (
                  <div className="case-report-settings">
                    <h3>Report contents</h3>
                    <p>
                      Metadata, deterministic rule score, evidence, analyst
                      notes, activity, and limitations are always included.
                    </p>
                    <label className="case-checkbox">
                      <input
                        type="checkbox"
                        checked={includeRaw}
                        onChange={(e) => setIncludeRaw(e.target.checked)}
                      />
                      Include raw submitted content
                    </label>
                    <small>
                      Raw email may contain personal or confidential
                      information. Keep exports private.
                    </small>
                    <label>
                      Case status
                      <select
                        value={selected.status}
                        disabled={busy}
                        onChange={(e) =>
                          perform(
                            () =>
                              api.updateCase(selected.id, {
                                status: e.target.value as CaseStatus,
                              }),
                            "Case status updated.",
                          )
                        }
                      >
                        {statuses.map((s) => (
                          <option key={s}>{s}</option>
                        ))}
                      </select>
                    </label>
                    {notesEditor}
                  </div>
                )}
              </div>
              <div className="case-preview-bottom">
                <button
                  className="button primary case-full-width"
                  disabled={busy}
                  onClick={exportReport}
                >
                  <FileText size={17} />
                  {busy ? "Working…" : "Generate Report (PDF)"}
                </button>
                <div>
                  <button className="button" onClick={openCase}>
                    <ExternalLink size={16} />
                    Open Case
                  </button>
                  <button
                    className="button"
                    disabled={busy || selected.status === "Archived"}
                    onClick={() => setConfirmation("archive")}
                  >
                    <Archive size={16} />
                    Archive
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div className="case-empty case-preview-empty">
              <ShieldCheck size={42} />
              <h3>Evidence belongs here</h3>
              <p>
                Select a saved investigation to inspect its findings, review its
                status, and generate a report.
              </p>
              <small>Private by default · stored on this computer</small>
            </div>
          )}
        </aside>
      </div>
      <div className="case-bottom-grid">
        <section className="panel case-timeline-panel">
          <div className="case-section-heading">
            <h2>
              <Activity size={21} />
              Case Timeline / Activity Feed
            </h2>
            <button
              className="case-text-button"
              onClick={() => navigate("/history")}
            >
              View Full History <ArrowRight size={14} />
            </button>
          </div>
          {timeline.length ? (
            <div className="case-timeline">
              {timeline.slice(-4).map((entry, i) => (
                <div className="case-timeline-entry" key={`${entry.at}-${i}`}>
                  <span className="case-timeline-dot" />
                  <time>{dateTime(entry.at)}</time>
                  <span className="case-event-icon">
                    {i === 0 ? (
                      <Mail size={19} />
                    ) : i === 1 ? (
                      <Search size={19} />
                    ) : (
                      <Layers size={19} />
                    )}
                  </span>
                  <div>
                    <strong>{entry.title}</strong>
                    <p>{entry.detail}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="case-empty case-small-empty">
              <Activity size={28} />
              <p>Activity appears when you create and review a case.</p>
            </div>
          )}
        </section>
        <section className="panel case-distribution-panel">
          <div className="case-section-heading">
            <h2>
              <Crosshair size={21} />
              Threat Categories Distribution <small>(Saved Cases)</small>
            </h2>
          </div>
          <div className="case-distribution-content">
            <div
              className={`case-donut ${categoryTotal ? "" : "empty"}`}
              style={{
                background: categoryTotal
                  ? `conic-gradient(${chartStops})`
                  : "#17343d",
              }}
              role="img"
              aria-label={`${categoryTotal} category observations across saved cases`}
            >
              <div>
                <strong>
                  {(metrics?.total ?? cases.length).toLocaleString()}
                </strong>
                <span>Cases</span>
              </div>
            </div>
            <div className="case-chart-legend">
              {categories.length ? (
                categories.map((c, i) => (
                  <div key={c.name}>
                    <span
                      className="case-color-key"
                      style={{ background: colors[i % colors.length] }}
                    />
                    <span>{c.name}</span>
                    <strong>
                      {categoryTotal
                        ? Math.round((c.value / categoryTotal) * 100)
                        : 0}
                      % ({c.value})
                    </strong>
                  </div>
                ))
              ) : (
                <>
                  <p className="muted">No categories to display yet.</p>
                  <small>
                    Distribution is calculated from saved case evidence. A case
                    is assigned one category by documented priority rules.
                  </small>
                </>
              )}
            </div>
          </div>
        </section>
      </div>
      {confirmation && selected && (
        <div
          className="case-modal-backdrop"
          onClick={() => setConfirmation(null)}
        >
          <section
            className="panel case-confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="case-confirm-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="case-confirm-title">
              {confirmation === "archive"
                ? "Archive this investigation?"
                : "Delete this investigation?"}
            </h2>
            <p>
              {confirmation === "archive"
                ? "The case remains available by choosing the Archived status filter."
                : "The investigation and its analyst notes will be deleted. The original analysis remains in History."}
            </p>
            <div>
              <button className="button" onClick={() => setConfirmation(null)}>
                Cancel
              </button>
              <button
                className={`button ${confirmation === "archive" ? "primary" : "case-danger"}`}
                disabled={busy}
                onClick={() =>
                  perform(
                    () =>
                      confirmation === "archive"
                        ? api.updateCase(selected.id, { status: "Archived" })
                        : api.deleteCase(selected.id),
                    confirmation === "archive"
                      ? "Investigation archived."
                      : "Investigation deleted.",
                  ).then((ok) => {
                    if (ok) setConfirmation(null);
                  })
                }
              >
                {confirmation === "archive" ? "Archive Case" : "Delete Case"}
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
