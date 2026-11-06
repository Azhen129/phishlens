import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Mail,
  Upload,
  Link2,
  ShieldCheck,
  Info,
  TriangleAlert,
  Layers,
  Paperclip,
  History,
  ArrowRight,
  Eye,
  FileText,
  ChartNoAxesColumnIncreasing,
  ScanLine,
  ExternalLink,
  Play,
  Check,
} from "lucide-react";
import { api } from "../api";
import { isPublicDemo } from "../environment";
import type { Analysis, Investigation, Metrics, ModelHealth } from "../types";
import { finalSummary, probabilityText, assessmentRisk } from "../ModelResult";
import { Badge, RiskRing, FindingList, LinkTable, Empty } from "../components";
export function TrendChart({
  data,
}: {
  data: { date: string; score: number }[];
}) {
  const pts = data
    .map(
      (p, i) =>
        `${34 + i * (286 / Math.max(1, data.length - 1))},${90 - p.score * 0.75}`,
    )
    .join(" ");
  return (
    <svg
      className="trend-svg"
      viewBox="0 0 334 108"
      role="img"
      aria-label={
        data.length
          ? `Saved investigation trend across ${data.length} days`
          : "No saved investigation trend yet"
      }
    >
      <defs>
        <linearGradient id="chartFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#00ddd7" stopOpacity=".3" />
          <stop offset="1" stopColor="#00ddd7" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[15, 40, 65, 90].map((y, i) => (
        <g key={y}>
          <line
            x1="24"
            x2="330"
            y1={y}
            y2={y}
            stroke="#173540"
            strokeDasharray="3 2"
          />
          <text x="0" y={y + 4} fill="#b8c8cd" fontSize="10">
            {100 - i * 25}
          </text>
        </g>
      ))}
      {data.length > 0 && (
        <>
          {data.length > 1 && (
            <polygon points={`34,95 ${pts} 320,95`} fill="url(#chartFill)" />
          )}
          <polyline points={pts} fill="none" stroke="#00e4df" strokeWidth="2" />
          {data.length === 1 && (
            <circle
              cx="34"
              cy={90 - data[0].score * 0.75}
              r="3"
              fill="#00e4df"
            />
          )}
        </>
      )}
      {!data.length && (
        <text x="169" y="60" textAnchor="middle" fill="#829ba6" fontSize="12">
          No saved cases yet
        </text>
      )}
    </svg>
  );
}
function Evidence({ analysis }: { analysis: Analysis | null }) {
  const [tab, setTab] = useState(0);
  const tabs = [
    ["Evidence & Findings", Layers],
    ["Email Details", Mail],
    [`Extracted Links (${analysis?.links.length || 0})`, Link2],
    [`Attachments (${analysis?.attachments.length || 0})`, Paperclip],
    ["Authentication", ShieldCheck],
  ] as const;
  return (
    <section className="panel evidence-panel">
      <div
        className="evidence-tabs"
        role="tablist"
        aria-label="Analysis evidence"
      >
        {tabs.map(([t, I], i) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === i}
            className={tab === i ? "active" : ""}
            onClick={() => setTab(i)}
          >
            <I size={20} />
            {t}
          </button>
        ))}
      </div>
      <div className="evidence-content" role="tabpanel">
        {tab === 0 ? (
          <FindingList analysis={analysis} />
        ) : !analysis ? (
          <Empty />
        ) : tab === 1 ? (
          <dl className="detail-grid">
            {Object.entries({
              Subject: analysis.subject,
              From: analysis.email?.from || "Not applicable",
              To: analysis.email?.to || "Not supplied",
              "Reply-To": analysis.email?.reply_to || "Not supplied",
              Date: analysis.email?.date || "Not supplied",
              Method: "Deterministic passive heuristics",
            }).map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        ) : tab === 2 ? (
          <LinkTable links={analysis.links} />
        ) : tab === 3 ? (
          <div className="attachments-list">
            {analysis.attachments.length ? (
              analysis.attachments.map((a, i) => (
                <article key={i}>
                  <Paperclip />
                  <div>
                    <strong>{a.filename}</strong>
                    <p>
                      {a.content_type} · {a.size.toLocaleString()} bytes ·
                      Static metadata only
                    </p>
                    <code>SHA-256: {a.sha256}</code>
                  </div>
                </article>
              ))
            ) : (
              <Empty>
                No attachments extracted. Attachment contents are never
                executed.
              </Empty>
            )}
          </div>
        ) : (
          <div className="auth-details">
            <p className="muted">
              Values are reported in supplied headers and are not independently
              verified by PhishLens.
            </p>
            {["spf", "dkim", "dmarc"].map((k) => (
              <div key={k}>
                <strong>{k.toUpperCase()}</strong>
                <span>
                  {analysis.email?.authentication?.[k.toUpperCase()] ||
                    "Not verified"}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
export default function Dashboard({
  analysis,
  cases,
  metrics,
  onAnalysis,
  onRefresh,
  notify,
}: {
  analysis: Analysis | null;
  cases: Investigation[];
  metrics: Metrics | null;
  onAnalysis: (a: Analysis) => void;
  onRefresh: () => void;
  notify: (s: string) => void;
}) {
  const [mode, setMode] = useState(0),
    [input, setInput] = useState(""),
    [loading, setLoading] = useState(false),
    [error, setError] = useState("");
  const [modelStatus, setModelStatus] = useState<ModelHealth | null>(null);
  useEffect(() => {
    api
      .health()
      .then(setModelStatus)
      .catch(() => setModelStatus({ status: "unavailable" }));
  }, []);
  const loadedCount = Object.values(modelStatus?.models || {}).filter(
    (model) => model.available,
  ).length;
  const classifierCount = Object.keys(modelStatus?.models || {}).length || 3;
  const fileRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();
  const finalRisk = assessmentRisk(analysis);
  async function run(file?: File) {
    setLoading(true);
    setError("");
    try {
      const result = file
        ? await api.uploadEmail(file)
        : mode === 2
          ? await api.analyzeUrl(input)
          : await api.analyzeEmail(input);
      onAnalysis(result);
      setInput("");
      onRefresh();
      notify("Passive analysis complete. Findings are evidence based.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }
  async function report() {
    if (!analysis) return;
    try {
      const r = await api.report({ analysis_id: analysis.id });
      api.downloadReport(r);
      onRefresh();
      notify("PDF report generated.");
    } catch (e) {
      notify((e as Error).message);
    }
  }
  async function save() {
    if (!analysis) return;
    try {
      await api.saveCase(analysis.id);
      onRefresh();
      notify("Investigation saved.");
      navigate("/investigations");
    } catch (e) {
      notify((e as Error).message);
    }
  }
  const severity = metrics?.severity || [];
  const total = severity.reduce((n, s) => n + s.value, 0);
  return (
    <div className="dashboard-layout">
      <div className="dashboard-main">
        <header className="page-heading">
          <h1>Threat Investigation Workspace</h1>
          <p>
            Analyze suspicious emails, links and attachments with security
            heuristics and explainable evidence.
          </p>
        </header>
        <section className="panel quick-input">
          <div className="input-tabs" role="tablist" aria-label="Input type">
            {[
              ["Paste Email", Mail],
              ["Upload .eml", Upload],
              ["Enter URL", Link2],
            ].map(([title, I], i) => {
              const C = I as typeof Mail;
              return (
                <button
                  role="tab"
                  aria-selected={mode === i}
                  className={mode === i ? "active" : ""}
                  key={i}
                  onClick={() => {
                    setMode(i);
                    setInput("");
                    setError("");
                  }}
                >
                  <C size={22} />
                  {String(title)}
                </button>
              );
            })}
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (mode === 1) fileRef.current?.click();
              else run();
            }}
          >
            <div className="quick-field">
              {mode === 1 ? (
                <button
                  type="button"
                  className="quick-upload"
                  onClick={() => fileRef.current?.click()}
                >
                  <Upload size={22} />
                  Choose an .eml file to inspect safely{" "}
                  <span className="muted">Maximum 25 MB</span>
                </button>
              ) : (
                <textarea
                  aria-label={mode === 2 ? "URL to analyze" : "Email content"}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder={
                    mode === 2
                      ? "Paste a URL for strictly passive syntax analysis…"
                      : "Paste the full email content (headers and body) here..."
                  }
                  required
                />
              )}
              <button
                type="submit"
                className="button primary"
                disabled={loading || (mode !== 1 && !input.trim())}
              >
                <ShieldCheck size={20} />
                {loading ? "Analyzing…" : "Analyze Safely"}
              </button>
            </div>
            <input
              hidden
              ref={fileRef}
              type="file"
              accept=".eml"
              aria-label="Upload email"
              onChange={(e) => {
                if (e.target.files?.[0]) run(e.target.files[0]);
                e.target.value = "";
              }}
            />
            <div className="helper">
              <Info size={17} />
              <span>
                Links are analyzed passively and never auto-opened. &nbsp;
                Attachments are inspected as metadata. &nbsp; ML:{" "}
                {modelStatus === null
                  ? isPublicDemo
                    ? "checking demo service"
                    : "checking local classifiers"
                  : loadedCount
                    ? `${loadedCount}/${classifierCount} local classifiers loaded`
                    : "unavailable; rules remain active"}
                .
              </span>
            </div>
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
          </form>
        </section>
        <section
          className={
            "panel threat-summary " +
            (analysis ? "has-result risk-" + finalRisk?.toLowerCase() : "")
          }
        >
          <RiskRing
            score={analysis?.score ?? null}
            size={150}
            label="Heuristic Points"
          />
          <div className="summary-info">
            <div className="summary-stats">
              <div>
                <span>
                  {analysis?.ml.available
                    ? "Final Assessment"
                    : "Heuristic Result"}
                </span>
                <strong
                  className={
                    analysis
                      ? "result-label " + finalRisk?.toLowerCase()
                      : "result-label pending"
                  }
                >
                  <TriangleAlert size={23} />
                  {analysis ? finalRisk + " Risk" : "Awaiting Analysis"}
                </strong>
              </div>
              <div>
                <span>
                  {analysis?.ml.available
                    ? "ML decision score"
                    : "Scoring Method"}
                </span>
                <strong
                  className="score-method"
                  title={
                    analysis?.ml.available
                      ? `${analysis.ml.model_name || "Validated local classifier"} · ${analysis.ml.model_version} · Language scope: ${analysis.ml.supported_languages?.join(", ") || "See model documentation"}`
                      : analysis?.ml.reason
                  }
                >
                  {analysis?.ml.available
                    ? `${probabilityText(analysis.ml.decision_score ?? analysis.ml.phishing_probability)} · ${analysis.ml.classification}`
                    : "Explainable rules"}{" "}
                  <Info size={15} />
                </strong>
              </div>
              <div>
                <span>Analysis Type</span>
                <strong className="analysis-type">
                  {analysis?.kind === "url" ? <Link2 /> : <Mail />}
                  {analysis
                    ? analysis.kind === "url"
                      ? "Passive URL"
                      : "Email (static inspection)"
                    : "No input selected"}
                </strong>
              </div>
            </div>
            <strong className="summary-label">
              {analysis?.ml.available
                ? analysis.ml.prediction_warning
                  ? `ML score: ${probabilityText(analysis.ml.decision_score ?? analysis.ml.phishing_probability)} · Research model · Not confidence`
                  : `ML score: ${probabilityText(analysis.ml.decision_score ?? analysis.ml.phishing_probability)} · Not confidence · Final: ${finalSummary(analysis)}`
                : "Summary"}
            </strong>
            <p>
              {analysis?.summary ||
                "Submit an email or URL above to reveal supported findings. Risk scores estimate observed indicators and do not establish whether content is malicious or safe."}
            </p>
          </div>
        </section>
        <Evidence analysis={analysis} />
        <section className="panel recent-panel">
          <div className="panel-heading">
            <h2>
              <History size={21} />
              Recent Investigations
            </h2>
            <Link to="/investigations">
              View All <ArrowRight size={15} />
            </Link>
          </div>
          <div className="table-scroll">
            <table className="recent-table">
              <thead>
                <tr>
                  <th>Date & Time</th>
                  <th>Type</th>
                  <th>Subject / Input</th>
                  <th>Rule Score</th>
                  <th>Result</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {cases.slice(0, 4).map((c) => (
                  <tr key={c.id}>
                    <td>{new Date(c.created_at).toLocaleString()}</td>
                    <td>
                      {c.source === "Email" ? (
                        <Mail size={16} />
                      ) : (
                        <Link2 size={16} />
                      )}{" "}
                      {c.source}
                    </td>
                    <td>{c.subject}</td>
                    <td>{c.score} / 100</td>
                    <td>
                      <Badge risk={c.risk}>{c.risk} Risk</Badge>
                    </td>
                    <td>
                      <button
                        className="icon-button"
                        aria-label={"Open " + c.id}
                        onClick={() => {
                          onAnalysis(c.analysis);
                          navigate(
                            c.source === "Email"
                              ? "/analyze/email"
                              : "/analyze/url",
                          );
                        }}
                      >
                        <Eye size={17} />
                      </button>
                      <button
                        className="icon-button"
                        aria-label={"Report " + c.id}
                        onClick={async () => {
                          try {
                            api.downloadReport(
                              await api.report({ case_id: c.id }),
                            );
                            onRefresh();
                          } catch (e) {
                            notify((e as Error).message);
                          }
                        }}
                      >
                        <FileText size={17} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!cases.length && (
            <Empty>
              No investigations yet. Analyze content, then create a case to
              track your findings.
            </Empty>
          )}
        </section>
      </div>
      <aside className="panel insights-panel">
        <h2>
          <ChartNoAxesColumnIncreasing />
          Investigation Insights
        </h2>
        <div className="insight-overview">
          <RiskRing
            score={analysis?.score ?? null}
            size={141}
            tone="cyan"
            label="Heuristic Points"
          />
          <dl>
            {[
              ["Threat Score", analysis ? analysis.score + " / 100" : "—"],
              [
                "Model Status",
                loadedCount
                  ? `${loadedCount}/${classifierCount} loaded`
                  : analysis?.ml.available
                    ? "Loaded for scan"
                    : "Unavailable",
              ],
              ["Indicators Found", analysis?.evidence.length ?? "—"],
              ["Extracted Links", analysis?.links.length ?? "—"],
              ["Attachments", analysis?.attachments.length ?? "—"],
            ].map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="insight-section">
          <h3>
            <ChartNoAxesColumnIncreasing size={18} />
            Heuristic Trend <small>(Saved Cases)</small>
          </h3>
          <TrendChart data={metrics?.trend || []} />
        </div>
        <div className="insight-section severity-section">
          <h3>
            <FileText size={18} />
            Severity Breakdown
          </h3>
          <div className="severity-bar">
            {total ? (
              severity.map((s) => (
                <span
                  key={s.name}
                  className={s.name.toLowerCase()}
                  style={{ width: (s.value / total) * 100 + "%" }}
                />
              ))
            ) : (
              <span className="no-data-bar" />
            )}
          </div>
          {["High", "Medium", "Low"].map((s) => {
            const count = severity.find((x) => x.name === s)?.value || 0;
            return (
              <div className="severity-row" key={s}>
                <span>
                  <i className={s.toLowerCase()} />
                  {s}
                </span>
                <strong>
                  {total ? Math.round((count / total) * 100) + "%" : "—"} (
                  {count})
                </strong>
              </div>
            );
          })}
        </div>
        <div className="insight-section action-section">
          <h3>
            <ScanLine size={21} />
            Recommended Next Action
          </h3>
          <div className="recommendation">
            <strong>
              {!analysis
                ? "Start a safe investigation"
                : finalRisk === "High"
                  ? "Treat this as a suspected phishing attempt."
                  : finalRisk === "Medium"
                    ? "Review the observed indicators."
                    : "Verify the sender through a trusted channel."}
            </strong>
            <p>
              {analysis
                ? "Do not use embedded links to verify a request. Preserve the original message and share evidence with your security team."
                : isPublicDemo
                  ? "Paste synthetic email content, upload an .eml fixture or enter a URL. Demo cases reset when you reload this tab."
                  : "Paste an email, upload an .eml file or enter a URL. Content stays in your local workspace."}
            </p>
          </div>
          <div className="insight-actions">
            <button className="button" disabled={!analysis} onClick={report}>
              <FileText size={16} />
              Generate Report (PDF)
            </button>
            <button className="button" disabled={!analysis} onClick={save}>
              <ExternalLink size={16} />
              Create Investigation
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
}
