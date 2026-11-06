import { useEffect, useState } from "react";
import {
  Link2,
  ShieldCheck,
  FileText,
  Trash2,
  Search,
  History,
  Database,
  Settings,
  Info,
  Eye,
  Download,
  Check,
} from "lucide-react";
import { api } from "../api";
import { isPublicDemo } from "../environment";
import type { Analysis, ModelHealth } from "../types";
import {
  modelSummary,
  finalSummary,
  ModelDetails,
  assessmentRisk,
} from "../ModelResult";
import { Badge, RiskRing, FindingList, LinkTable, Empty } from "../components";
export function UrlPage({
  analysis,
  onAnalysis,
  onRefresh,
  notify,
}: {
  analysis: Analysis | null;
  onAnalysis: (a: Analysis) => void;
  onRefresh: () => void;
  notify: (s: string) => void;
}) {
  const [url, setUrl] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const current = analysis?.kind === "url" ? analysis : null;
  return (
    <>
      <header className="page-heading">
        <h1>Analyze URL</h1>
        <p>
          Inspect URL syntax and domain structure without visiting, resolving or
          fetching the destination.
        </p>
      </header>
      <section className="panel utility-input">
        <h2>
          <Link2 />
          Passive URL Analysis
        </h2>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError("");
            try {
              onAnalysis(await api.analyzeUrl(url));
              onRefresh();
              notify("Passive URL analysis complete.");
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label htmlFor="url-input">URL to investigate</label>
          <div className="inline-form">
            <input
              id="url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/path"
              required
            />
            <button className="button primary" disabled={busy || !url.trim()}>
              <ShieldCheck size={18} />
              {busy ? "Analyzing…" : "Analyze Safely"}
            </button>
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <p className="helper">
            <Info size={17} />
            Strictly passive. No DNS resolution, redirects, network reputation
            lookup, or destination requests.
          </p>
        </form>
      </section>
      <section className="panel url-summary">
        <RiskRing score={current?.score ?? null} label="Heuristic Points" />
        <div>
          <h2>
            {current
              ? assessmentRisk(current) +
                (current.ml.available ? " Final Risk" : " Heuristic Risk")
              : "Awaiting URL"}
          </h2>
          <p>
            {current?.summary ||
              "Submit a URL to inspect its structure. The absence of syntax indicators does not establish safety."}
          </p>
          <p className="muted">
            {current?.ml.available
              ? `${modelSummary(current)} · Final: ${finalSummary(current)} · Model ${current.ml.model_version}`
              : "Heuristic score · ML unavailable for this analysis"}{" "}
            · Reputation and domain age not verified
          </p>
          <div className="inline-actions">
            <button
              disabled={!current}
              className="button primary"
              onClick={async () => {
                if (current)
                  try {
                    await api.saveCase(current.id);
                    onRefresh();
                    notify("Investigation saved.");
                  } catch (e) {
                    notify((e as Error).message);
                  }
              }}
            >
              Save Investigation
            </button>
            <button
              disabled={!current}
              className="button"
              onClick={async () => {
                if (current)
                  try {
                    api.downloadReport(
                      await api.report({ analysis_id: current.id }),
                    );
                    onRefresh();
                  } catch (e) {
                    notify((e as Error).message);
                  }
              }}
            >
              <Download size={17} />
              Export PDF
            </button>
          </div>
        </div>
      </section>
      {current && (
        <section className="panel" style={{ marginBottom: 14, padding: 16 }}>
          <details>
            <summary>Stored model version, scope &amp; limitations</summary>
            <ModelDetails analysis={current} />
          </details>
        </section>
      )}
      <section className="panel">
        <h2 className="section-title">Evidence & Findings</h2>
        <FindingList analysis={current} />
      </section>
      <section className="panel">
        <h2 className="section-title">
          <Link2 size={20} />
          Parsed URL
        </h2>
        <LinkTable links={current?.links || []} />
      </section>
    </>
  );
}
export function HistoryPage({
  analyses,
  onOpen,
  onRefresh,
  notify,
}: {
  analyses: Analysis[];
  onOpen: (a: Analysis) => void;
  onRefresh: () => void;
  notify: (s: string) => void;
}) {
  const [query, setQuery] = useState(""),
    [kind, setKind] = useState("all");
  const filtered = analyses.filter(
    (a) =>
      (kind === "all" || a.kind === kind) &&
      (a.subject + " " + a.id).toLowerCase().includes(query.toLowerCase()),
  );
  return (
    <>
      <header className="page-heading">
        <h1>Analysis History</h1>
        <p>
          Review {isPublicDemo ? "this tab's temporary" : "locally saved"}{" "}
          scans, preserve evidence, and remove sensitive records.
        </p>
      </header>
      <section className="panel history-page">
        <h2 className="section-title">
          <History />
          Saved Analyses <small>({filtered.length})</small>
        </h2>
        <div className="filter-row">
          <label className="search-field">
            <Search size={18} />
            <input
              aria-label="Search analysis history"
              placeholder="Search subject or analysis ID…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <select
            aria-label="History source"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="all">All Sources</option>
            <option value="email">Email</option>
            <option value="url">URL</option>
          </select>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Analyzed</th>
                <th>Subject / Input</th>
                <th>Source</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((a) => (
                <tr key={a.id}>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td>{a.subject}</td>
                  <td>{a.kind}</td>
                  <td>{a.score} / 100</td>
                  <td>
                    <Badge risk={a.risk} />
                  </td>
                  <td>
                    <button
                      className="icon-button"
                      aria-label={"Open analysis " + a.id}
                      onClick={() => onOpen(a)}
                    >
                      <Eye size={18} />
                    </button>
                    <button
                      className="icon-button"
                      aria-label={"Delete analysis " + a.id}
                      onClick={async () => {
                        if (
                          confirm(
                            "Delete this analysis? Linked investigations and report references may also be removed.",
                          )
                        )
                          try {
                            await api.deleteAnalysis(a.id);
                            onRefresh();
                            notify("Analysis deleted.");
                          } catch (e) {
                            notify((e as Error).message);
                          }
                      }}
                    >
                      <Trash2 size={18} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!filtered.length && (
          <Empty>
            No saved analyses match. New submissions are{" "}
            {isPublicDemo ? "kept in this tab after" : "saved locally after"}
            analysis.
          </Empty>
        )}
      </section>
    </>
  );
}
export function SettingsPage({
  onRefresh,
  onClear,
  notify,
}: {
  onRefresh: () => void;
  onClear: () => void;
  notify: (s: string) => void;
}) {
  const [compact, setCompact] = useState(
    localStorage.getItem("phishlens-compact") === "true",
  );
  const [modelStatus, setModelStatus] = useState<ModelHealth | null>(null);
  useEffect(() => {
    api
      .health()
      .then(setModelStatus)
      .catch(() => {});
  }, []);
  return (
    <>
      <header className="page-heading">
        <h1>Settings & Privacy</h1>
        <p>
          Manage your {isPublicDemo ? "temporary demo" : "local investigation"}{" "}
          workspace and understand its analysis capabilities.
        </p>
      </header>
      <div className="settings-grid">
        <section className="panel settings-card">
          <h2>
            <ShieldCheck />
            Analysis Capabilities
          </h2>
          <dl className="settings-list">
            <div>
              <dt>Analysis engine</dt>
              <dd>
                {isPublicDemo
                  ? "Passive heuristic analysis"
                  : "Evidence based heuristics + local archive classifiers when loaded"}
              </dd>
            </div>
            <div>
              <dt>Machine learning</dt>
              <dd>
                <Badge risk={modelStatus?.ml?.available ? "Low" : "Medium"}>
                  {modelStatus?.ml?.available
                    ? "Local archive models loaded"
                    : "Unavailable / rules active"}
                </Badge>
              </dd>
            </div>
            {modelStatus?.models &&
              Object.entries(modelStatus.models).map(([kind, model]) => (
                <div key={kind}>
                  <dt>
                    {kind === "email"
                      ? "Spanish email model"
                      : kind === "email_en"
                        ? "English email model"
                        : "URL model"}
                  </dt>
                  <dd title={model.reason}>
                    {model.available
                      ? `${model.model_version}${model.supported_languages?.length ? " · " + model.supported_languages.join(", ") : ""}`
                      : "Unavailable"}
                  </dd>
                </div>
              ))}
            <div>
              <dt>URL inspection</dt>
              <dd>Passive syntax only; no destination requests</dd>
            </div>
            <div>
              <dt>Email authentication</dt>
              <dd>Supplied header observations; unverified</dd>
            </div>
            <div>
              <dt>Attachment inspection</dt>
              <dd>Static metadata and SHA-256 only</dd>
            </div>
            <div>
              <dt>Domain age / reputation</dt>
              <dd>Unknown / not verified</dd>
            </div>
          </dl>
          <p className="muted">
            {isPublicDemo
              ? "The public demo runs heuristic analysis. The separate local research workspace includes evaluated classifiers with limited validation. A low heuristic score never verifies safety."
              : "Model status changes only after a local artifact passes integrity, compatibility, calibration and validation checks. Model decision scores use archive calibration, not validated field probability or confidence about future mail or URLs. Historical scans retain the model metadata that was originally stored."}
          </p>
        </section>
        <section className="panel settings-card">
          <h2>
            <Database />
            {isPublicDemo ? "Demo Data & Privacy" : "Local Data & Privacy"}
          </h2>
          <p>
            {isPublicDemo
              ? "Analysis and PDF inputs are sent to the hosted demo API for passive processing. Cases, analyst notes, and report copies are kept only in this tab's memory and reset on reload."
              : "Email text, parsed indicators, cases, notes and report references are stored in the local SQLite database. No email content is sent to an external analysis service."}
          </p>
          <p className="muted">
            {isPublicDemo
              ? "Use the synthetic examples or nonconfidential content. This guest demo has no permanent case storage or user accounts. Other tabs have their own temporary workspace."
              : "Use only on your own machine. This local application does not provide multi-user accounts or an exposed production service."}
          </p>
          <button
            className="button danger-button"
            onClick={async () => {
              if (
                confirm(
                  isPublicDemo
                    ? "Clear this tab's temporary analyses, investigations, notes and reports?"
                    : "Permanently delete ALL analyses, investigations, notes, and generated reports from this workspace?",
                )
              )
                try {
                  await api.clearData();
                  onClear();
                  onRefresh();
                  notify(
                    isPublicDemo
                      ? "This tab's demo data was cleared."
                      : "All local investigation data deleted.",
                  );
                } catch (e) {
                  notify((e as Error).message);
                }
            }}
          >
            <Trash2 size={17} />
            {isPublicDemo ? "Clear This Demo Tab" : "Delete All Local Data"}
          </button>
        </section>
        <section className="panel settings-card">
          <h2>
            <Settings />
            Workspace Preferences
          </h2>
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={compact}
              onChange={(e) => {
                setCompact(e.target.checked);
                localStorage.setItem(
                  "phishlens-compact",
                  String(e.target.checked),
                );
                document.documentElement.classList.toggle(
                  "compact-mode",
                  e.target.checked,
                );
              }}
            />
            Compact table rows
          </label>
          <p className="muted">
            Saved in this browser. System reduced-motion preference is respected
            automatically.
          </p>
        </section>
        <section className="panel settings-card">
          <h2>
            <Info />
            Interpreting Results
          </h2>
          <p>
            A score is a weighted sum of observable risk indicators, capped at
            100. It is not a calibrated probability. Missing evidence is
            reported as unknown.
          </p>
          <p>
            Always verify a sensitive request through a known, independent
            channel. A low score does not guarantee that an email, URL or
            attachment is safe.
          </p>
        </section>
      </div>
    </>
  );
}
