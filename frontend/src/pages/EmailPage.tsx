import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowRight,
  BarChart3,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clipboard,
  CloudUpload,
  Code2,
  Copy,
  Download,
  FileText,
  Globe,
  Layers,
  Link2,
  Mail,
  Paperclip,
  Play,
  Save,
  ShieldCheck,
  ShieldQuestion,
  UserRound,
  X,
} from "lucide-react";
import { api } from "../api";
import { isPublicDemo } from "../environment";
import type { Analysis } from "../types";
import {
  ModelDetails,
  modelSummary,
  probabilityText,
  assessmentRisk,
} from "../ModelResult";
import "./email.css";

type Props = {
  analysis: Analysis | null;
  onAnalysis: (analysis: Analysis) => void;
  onRefresh: () => void;
  notify: (message: string) => void;
};
const sizeText = (n: number) =>
  n >= 1024 * 1024
    ? `${(n / 1024 / 1024).toFixed(1)} MB`
    : n >= 1024
      ? `${(n / 1024).toFixed(1)} KB`
      : `${n} B`;
function EmailBadge({ value }: { value: string }) {
  return (
    <span className={`email-badge ${value.toLowerCase().replaceAll(" ", "-")}`}>
      {value}
    </span>
  );
}
function EmailRing({ score, risk }: { score?: number; risk?: string }) {
  return (
    <div className={`email-risk-ring ${risk?.toLowerCase() ?? ""}`}>
      <svg viewBox="0 0 140 140" aria-hidden="true">
        <circle cx="70" cy="70" r="60" className="track" />
        <circle
          cx="70"
          cy="70"
          r="60"
          className="value"
          strokeDasharray={`${(score ?? 0) * 3.77} 377`}
          transform="rotate(-90 70 70)"
        />
      </svg>
      <div>
        <strong>
          {score ?? "—"}
          <small>{score !== undefined ? "/100" : ""}</small>
        </strong>
        <span>Rule Points</span>
      </div>
    </div>
  );
}

function signalDistribution(evidence: Analysis["evidence"]) {
  const names = [
    "Sender / Identity",
    "Authentication",
    "Link Analysis",
    "Language / Content",
    "Attachment",
  ];
  const families = new Map<string, { category: number; weight: number }>();
  for (const finding of evidence) {
    if (finding.weight <= 0) continue;
    // Match the backend's maximum weight per rule family, before its 100-point cap.
    const family = finding.id.replace(/-\d+$/, "");
    const category =
      /^auth-/.test(family) ||
      /authentication|supplied headers/i.test(finding.source)
        ? 1
        : /^attachment/.test(family) || /attachment/i.test(finding.source)
          ? 4
          : /^url-|^display-mismatch/.test(family) ||
              /url|anchor/i.test(finding.source)
            ? 2
            : /^reply-to-|^sender-/.test(family) ||
                /email headers|sender|identity/i.test(finding.source)
              ? 0
              : 3;
    if (finding.weight > (families.get(family)?.weight ?? 0))
      families.set(family, { category, weight: finding.weight });
  }
  const points = names.map(() => 0);
  for (const finding of families.values())
    points[finding.category] += finding.weight;
  const total = points.reduce((sum, n) => sum + n, 0);
  if (!total) return [];
  const exact = points.map((n) => (n / total) * 100);
  const percentages = exact.map(Math.floor);
  const remainders = exact
    .map((n, i) => ({ i, remainder: n - percentages[i] }))
    .sort((a, b) => b.remainder - a.remainder || a.i - b.i);
  const remaining = 100 - percentages.reduce((sum, n) => sum + n, 0);
  for (let i = 0; i < remaining; i++) percentages[remainders[i].i]++;
  return names.map((name, i) => ({
    name,
    points: points[i],
    percentage: percentages[i],
  }));
}

export default function EmailPage({
  analysis: supplied,
  onAnalysis,
  onRefresh,
  notify,
}: Props) {
  const analysis = supplied?.kind === "email" ? supplied : null;
  const finalRisk = assessmentRisk(analysis);
  const email = analysis?.email;
  const [raw, setRaw] = useState(email?.raw ?? "");
  const [file, setFile] = useState<File | null>(null);
  const [tab, setTab] = useState("Raw Email");
  const [pasteOpen, setPasteOpen] = useState(false);
  const [paste, setPaste] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [artifact, setArtifact] = useState<string | null>(null);
  const [details, setDetails] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (email?.raw) setRaw(email.raw);
  }, [email?.raw]);
  useEffect(() => {
    if (!pasteOpen && !artifact && !details) return;
    const previous = document.activeElement as HTMLElement | null;
    const dialog = document.querySelector<HTMLElement>(".email-modal");
    const focusable = () =>
      Array.from(
        dialog?.querySelectorAll<HTMLElement>(
          'button:not(:disabled),textarea,input,a[href],[tabindex="0"]',
        ) ?? [],
      );
    focusable()[0]?.focus();
    function handleKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setPasteOpen(false);
        setArtifact(null);
        setDetails(false);
      }
      if (event.key !== "Tab") return;
      const nodes = focusable();
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("keydown", handleKey);
      previous?.focus();
    };
  }, [pasteOpen, artifact, details]);
  const hasInput = Boolean(raw.trim());
  const links = analysis?.links ?? [];
  const attachments = analysis?.attachments ?? [];
  const evidence = analysis?.evidence ?? [];
  const language = evidence.filter((e) =>
    /language|content|urgency|credential/i.test(`${e.source} ${e.title}`),
  );
  const senderSignals = evidence.filter((e) =>
    /sender|identity|reply|brand/i.test(`${e.source} ${e.title}`),
  );
  const suspiciousLinks = links.filter((l) => l.score > 0).length;
  const auth = email?.authentication ?? {};
  const sources = signalDistribution(evidence);
  const totalWeight = sources.reduce((sum, source) => sum + source.points, 0);
  const shownRaw =
    tab === "Headers"
      ? Object.entries(email?.headers ?? {})
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n")
      : tab === "Parsed View"
        ? (email?.body ?? "")
        : raw;
  const boundedLines = shownRaw.slice(0, 150_000).split("\n");
  const previewLines = boundedLines.slice(0, 2000);
  const previewTruncated =
    shownRaw.length > 150_000 || boundedLines.length > 2000;
  const inputChanged = Boolean(analysis && raw !== email?.raw);

  async function acceptFile(next?: File) {
    if (!next) return;
    if (!next.name.toLowerCase().endsWith(".eml")) {
      setError("Choose an RFC/MIME email file with the .eml extension.");
      return;
    }
    if (next.size > (isPublicDemo ? 256 * 1024 : 25 * 1024 * 1024)) {
      setError(
        isPublicDemo
          ? "The file exceeds the 256 KiB public demo limit."
          : "The file exceeds the 25 MB limit.",
      );
      return;
    }
    setError("");
    setFile(next);
    setRaw(await next.text());
    setTab("Raw Email");
  }
  async function run() {
    if (!hasInput || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = file
        ? await api.uploadEmail(file)
        : await api.analyzeEmail(raw);
      onAnalysis(result);
      onRefresh();
      notify(
        isPublicDemo
          ? "Passive email analysis complete. Findings are ready for review."
          : "Email analyzed locally. Findings are ready for review.",
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Email analysis failed.");
    } finally {
      setBusy(false);
    }
  }
  async function saveCase() {
    if (!analysis) return;
    try {
      await api.saveCase(analysis.id);
      onRefresh();
      notify("Investigation saved. Open Investigations to manage the case.");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Unable to save investigation.",
      );
    }
  }
  async function exportReport() {
    if (!analysis) return;
    try {
      const report = await api.report({ analysis_id: analysis.id });
      api.downloadReport(report);
      onRefresh();
      notify("PDF report generated from this analysis.");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to generate report.");
    }
  }
  async function copyRaw() {
    try {
      await navigator.clipboard.writeText(shownRaw);
      notify("Email view copied.");
    } catch {
      setError(
        "Clipboard permission was denied. Select and copy the text instead.",
      );
    }
  }

  return (
    <div className="email-page">
      <header className="email-heading">
        <h1>Analyze Email</h1>
        <p>
          Submit an email (.eml) or paste email content to analyze for phishing,
          fraud, and other email-borne threats.
        </p>
      </header>
      {error && (
        <div className="email-error" role="alert">
          {error}
          <button aria-label="Dismiss error" onClick={() => setError("")}>
            <X size={16} />
          </button>
        </div>
      )}
      <div className="email-workspace">
        <section className="email-intake email-panel" aria-label="Email intake">
          <div className="email-stepper">
            <span className="active">
              <b>1</b> Intake
            </span>
            <i />
            <span className={busy ? "active" : ""}>
              <b>2</b> Analyze
            </span>
            <i />
            <span className={analysis ? "complete" : ""}>
              <b>3</b> Triage &amp; Results
            </span>
          </div>
          <div className="email-intake-body">
            <div className="email-upload-row">
              <button
                className="email-dropzone"
                onClick={() => input.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => {
                  e.preventDefault();
                  void acceptFile(e.dataTransfer.files[0]);
                }}
              >
                <CloudUpload size={38} />
                <strong>Drag &amp; drop an .eml file here</strong>
                <span>or click to browse</span>
                <small>
                  Supports .eml (recommended). Max{" "}
                  {isPublicDemo ? "256 KiB" : "25 MB"}.
                </small>
              </button>
              <div className="email-or">
                <span>or</span>
              </div>
              <button
                className="email-outline email-paste"
                onClick={() => {
                  setPaste(raw);
                  setPasteOpen(true);
                }}
              >
                <Clipboard size={19} />
                Paste Email Text
              </button>
              <input
                aria-label="Upload email file"
                ref={input}
                type="file"
                accept=".eml,message/rfc822"
                hidden
                onChange={(e) => void acceptFile(e.target.files?.[0])}
              />
            </div>
            <div className="email-safety">
              <span>
                <ShieldCheck />
                URLs are never auto-opened.
              </span>
              <span>
                <FileText />
                HTML is converted to inert text.
              </span>
              <span>
                <Paperclip />
                Attachments: metadata only.
              </span>
            </div>
            <div className="email-file-status">
              <Mail size={22} />
              <span>
                <strong>
                  {file?.name ??
                    (hasInput ? "Pasted_Email.eml" : "No email loaded")}
                </strong>
                {hasInput && (
                  <small>
                    {" "}
                    ({sizeText(file?.size ?? new Blob([raw]).size)})
                  </small>
                )}
              </span>
              <small className={hasInput ? "email-ready" : "muted"}>
                {hasInput ? (
                  <>
                    <CheckCircle2 size={16} />
                    {inputChanged
                      ? "Changed · re-run analysis"
                      : analysis
                        ? "Analysis available"
                        : "Ready to analyze"}
                  </>
                ) : (
                  "Upload or paste to begin"
                )}
              </small>
              {hasInput && (
                <button
                  aria-label="Clear email input"
                  onClick={() => {
                    setRaw("");
                    setFile(null);
                  }}
                >
                  <X size={16} />
                </button>
              )}
            </div>
            <div className="email-content-panel">
              <div
                className="email-tabs"
                role="tablist"
                aria-label="Email view"
              >
                {[
                  ["Raw Email", Mail],
                  ["Parsed View", Layers],
                  ["Headers", Code2],
                ].map(([name, I]) => {
                  const TabIcon = I as typeof Mail;
                  return (
                    <button
                      key={String(name)}
                      role="tab"
                      aria-selected={tab === name}
                      className={tab === name ? "selected" : ""}
                      onClick={() => setTab(String(name))}
                    >
                      <TabIcon size={19} />
                      {String(name)}
                    </button>
                  );
                })}
              </div>
              <div className="email-raw" role="tabpanel" aria-label={tab}>
                {shownRaw ? (
                  <>
                    <button
                      className="email-copy"
                      aria-label="Copy email view"
                      onClick={() => void copyRaw()}
                    >
                      <Copy size={17} />
                    </button>
                    <pre>
                      {previewLines.map((line, i) => (
                        <span className="email-code-line" key={i}>
                          <span>{i + 1}</span>
                          <code>{line || " "}</code>
                        </span>
                      ))}
                      {previewTruncated && (
                        <span className="email-code-line">
                          <span>…</span>
                          <code>
                            Preview limited to 150,000 characters / 2,000 lines.
                            Analysis uses the full message.
                          </code>
                        </span>
                      )}
                    </pre>
                  </>
                ) : (
                  <div className="email-empty">
                    <Mail size={34} />
                    <strong>Your email workspace is ready</strong>
                    <span>
                      Load an email to inspect its original content.
                      <br />
                      Messages and embedded links are never opened.
                    </span>
                  </div>
                )}
              </div>
            </div>
            <section className="email-metadata email-panel">
              <h2>
                <FileText size={19} />
                Email Metadata
              </h2>
              <div className="email-meta-grid">
                <div>
                  <UserRound />
                  <span>
                    Sender
                    <strong title={email?.from}>
                      {email?.from ?? "Not supplied"}
                    </strong>
                  </span>
                </div>
                <div>
                  <Activity />
                  <span>
                    Received<strong>{email?.date || "Not supplied"}</strong>
                  </span>
                </div>
                <div>
                  <Download />
                  <span>
                    Size
                    <strong>
                      {hasInput ? sizeText(new Blob([raw]).size) : "—"}
                    </strong>
                  </span>
                </div>
                <div>
                  <FileText />
                  <span>
                    Format<strong>.eml / text</strong>
                  </span>
                </div>
              </div>
            </section>
            <section className="email-artifacts email-panel">
              <h2>
                <Paperclip size={21} />
                Extracted Artifacts ({analysis ? 4 : 0})
              </h2>
              {[
                ["Links", Link2, links.length],
                ["Attachments", Paperclip, attachments.length],
                ["Email addresses", Mail, email?.addresses?.length ?? 0],
                ["Domains", Globe, email?.domains?.length ?? 0],
              ].map(([name, I, n]) => {
                const ItemIcon = I as typeof Mail;
                return (
                  <button
                    key={String(name)}
                    onClick={() => setArtifact(String(name))}
                    disabled={!analysis}
                  >
                    <ItemIcon size={17} />
                    <span>{String(name)}</span>
                    <b>{Number(n)}</b>
                    <ChevronRight size={16} />
                  </button>
                );
              })}
            </section>
          </div>
        </section>

        <section
          className="email-results email-panel"
          aria-label="Analysis results"
        >
          <div className="email-results-title">
            <h2>
              <BarChart3 size={23} />
              Analysis Results
            </h2>
            <span>
              {busy ? (
                isPublicDemo ? (
                  "Analyzing passively…"
                ) : (
                  "Analyzing locally…"
                )
              ) : inputChanged ? (
                "Previous result · input changed"
              ) : analysis ? (
                <>
                  <CheckCircle2 size={20} />
                  Analyzed in {(analysis.duration_ms / 1000).toFixed(2)} seconds
                </>
              ) : (
                <>
                  <ShieldQuestion size={18} />
                  Awaiting submission
                </>
              )}
            </span>
          </div>
          <div
            className={`email-decision ${finalRisk?.toLowerCase() ?? "unscanned"}`}
          >
            <EmailRing score={analysis?.score} risk={analysis?.risk} />
            <div className="email-decision-text">
              <h3>
                Threat Decision ·{" "}
                {analysis?.ml.available
                  ? "ML assessment"
                  : "heuristic evidence"}
              </h3>
              {analysis ? (
                <>
                  <div
                    className={`email-risk-label ${finalRisk?.toLowerCase()}`}
                  >
                    <ShieldQuestion size={24} />
                    {finalRisk === "Low" ? "Low Risk" : `${finalRisk} Risk`}
                  </div>
                  <p
                    title={
                      analysis.ml.available
                        ? `${modelSummary(analysis)} · Model ${analysis.ml.model_version}`
                        : analysis.ml.reason
                    }
                  >
                    {isPublicDemo
                      ? `Rules-only demo. ${analysis.summary}`
                      : analysis.ml.available
                        ? analysis.ml.prediction_warning
                          ? `English research ML score: ${probabilityText(analysis.ml.decision_score ?? analysis.ml.phishing_probability)}. Archive estimate, not confidence; review evidence. Final: ${analysis.assessment?.label || analysis.ml.classification} (ML).`
                          : `${analysis.ml.detected_language === "en" ? "English " : analysis.ml.detected_language === "es" ? "Spanish " : ""}ML score: ${probabilityText(analysis.ml.decision_score ?? analysis.ml.phishing_probability)} (not confidence). Final: ${analysis.assessment?.label || analysis.ml.classification} (${analysis.assessment?.method === "validated_hybrid" ? "hybrid" : "ML"}).`
                        : analysis.ml.model_loaded ||
                            (analysis.ml.language_routing_status &&
                              analysis.ml.language_routing_status !==
                                "supported")
                          ? `ML abstained: ${analysis.ml.language_routing_status || "outside validated"} language scope. ${analysis.summary}`
                          : analysis.summary}
                  </p>
                </>
              ) : (
                <>
                  <div className="email-risk-label unscanned">
                    No analysis yet
                  </div>
                  <p>
                    Submit an email for explainable, passive analysis. Every
                    finding will be linked to evidence in your message.
                  </p>
                </>
              )}
            </div>
          </div>
          <div className="email-findings-grid">
            <section className="email-detail-card email-sender">
              <h2>
                <UserRound />
                <span>Sender Profile</span>
                <EmailBadge
                  value={senderSignals.length ? "Review" : "Unverified"}
                />
              </h2>
              <p>
                {senderSignals[0]?.detail ??
                  "Sender identity is not independently verified."}
              </p>
              <dl>
                <div>
                  <dt>Display Name</dt>
                  <dd>
                    {email?.from?.split("<")[0]?.replaceAll('"', "").trim() ||
                      "Not supplied"}
                  </dd>
                </div>
                <div>
                  <dt>Email</dt>
                  <dd title={email?.from}>
                    {email?.from?.match(/<(.+)>/)?.[1] ??
                      email?.from ??
                      "Not supplied"}
                  </dd>
                </div>
                <div>
                  <dt>Domain Age</dt>
                  <dd>Unknown · no lookup performed</dd>
                </div>
                <div>
                  <dt>Reputation</dt>
                  <dd>Not verified</dd>
                </div>
              </dl>
            </section>
            <section className="email-detail-card email-auth">
              <h2>
                <ShieldCheck />
                <span>Authentication Status</span>
              </h2>
              <dl>
                {["SPF", "DKIM", "DMARC"].map((key) => (
                  <div key={key}>
                    <dt>{key}</dt>
                    <dd
                      className={
                        String(
                          auth[key.toLowerCase()] ?? auth[key] ?? "",
                        ).includes("fail")
                          ? "email-danger"
                          : ""
                      }
                    >
                      {String(
                        auth[key.toLowerCase()] ?? auth[key] ?? "Not verified",
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
              <small>Reported headers only; unverified by PhishLens.</small>
            </section>
            <section className="email-detail-card email-language">
              <h2>
                <FileText />
                <span>Language Signals</span>
                <EmailBadge value={language.length ? "Review" : "Unverified"} />
              </h2>
              {language.length ? (
                <ul>
                  {language.slice(0, 3).map((e) => (
                    <li key={e.id}>
                      <Check size={15} />
                      <span title={e.detail}>{e.title}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p>
                  {analysis
                    ? "No weighted language indicators detected. This does not establish legitimacy."
                    : "Language observations appear after analysis."}
                </p>
              )}
            </section>
            <section className="email-detail-card email-links">
              <h2>
                <Link2 />
                <span>Link Safety</span>
                <EmailBadge value={suspiciousLinks ? "Review" : "Unverified"} />
              </h2>
              <p>
                {analysis
                  ? `${links.length} links extracted. ${suspiciousLinks} with indicators.`
                  : "No links extracted yet."}
              </p>
              <div className="email-link-bar">
                <span
                  style={{
                    flex: suspiciousLinks || 0,
                    display: suspiciousLinks ? undefined : "none",
                  }}
                >
                  {suspiciousLinks} Flagged
                </span>
                <span style={{ flex: links.length - suspiciousLinks || 1 }}>
                  {analysis ? links.length - suspiciousLinks : "—"} Unverified
                </span>
              </div>
            </section>
            <section className="email-detail-card email-attachments">
              <h2>
                <Paperclip />
                <span>Attachment Summary</span>
              </h2>
              <p>
                {attachments.length} attachment
                {attachments.length !== 1 ? "s" : ""} found. Static metadata
                only.
              </p>
              <button
                className="email-attachment-item"
                disabled={!attachments.length}
                onClick={() => setArtifact("Attachments")}
              >
                <FileText size={22} />
                <span>
                  {attachments[0]?.filename ?? "No attachments to inspect"}
                  <small>
                    {attachments[0]
                      ? `${sizeText(attachments[0].size)} · content not scanned`
                      : "Files are never executed or unpacked"}
                  </small>
                </span>
                <ChevronDown size={16} />
              </button>
            </section>
            <section className="email-detail-card email-distribution">
              <h2>
                <BarChart3 size={19} />
                <span>Threat Signal Distribution</span>
              </h2>
              <div className="email-distribution-body">
                <div
                  className="email-mini-chart"
                  style={{
                    position: "relative",
                    paddingBottom: sources.length ? 12 : undefined,
                  }}
                  title="Cumulative rule points across categories, after rule-family deduplication and before the 100-point score cap. This is not a time series."
                >
                  {sources.length ? (
                    <svg
                      viewBox="0 0 190 65"
                      preserveAspectRatio="none"
                      role="img"
                      aria-label={`Cumulative rule points: ${totalWeight} total before the score cap; not a time series`}
                    >
                      <title>
                        Cumulative points by evidence category; each rule family
                        counts once. Not a time series.
                      </title>
                      <defs>
                        <linearGradient
                          id="email-area"
                          x1="0"
                          y1="0"
                          x2="0"
                          y2="1"
                        >
                          <stop stopColor="#00e2d0" stopOpacity=".3" />
                          <stop
                            offset="1"
                            stopColor="#00e2d0"
                            stopOpacity="0"
                          />
                        </linearGradient>
                      </defs>
                      <path
                        d={`M0,65 ${sources.map((_, i) => `L${(i * 190) / (sources.length - 1)},${65 - (sources.slice(0, i + 1).reduce((sum, source) => sum + source.points, 0) / totalWeight) * 58}`).join(" ")} L190,65 Z`}
                        fill="url(#email-area)"
                      />
                      <polyline
                        points={sources
                          .map(
                            (_, i) =>
                              `${(i * 190) / (sources.length - 1)},${65 - (sources.slice(0, i + 1).reduce((sum, source) => sum + source.points, 0) / totalWeight) * 58}`,
                          )
                          .join(" ")}
                        stroke="#04e2d5"
                        strokeWidth="1.7"
                        fill="none"
                      />
                    </svg>
                  ) : (
                    <span className="muted">No signal data</span>
                  )}
                  {sources.length > 0 && (
                    <small
                      style={{
                        position: "absolute",
                        bottom: 0,
                        left: 0,
                        fontSize: 9,
                        color: "#8eabb7",
                      }}
                    >
                      Cumulative
                    </small>
                  )}
                </div>
                <ul aria-label="Rule points by evidence category">
                  {sources.length ? (
                    sources.map(({ name, points, percentage }, i) => (
                      <li
                        key={name}
                        title={`${name}: ${points} rule points before the score cap`}
                      >
                        <i
                          style={{
                            background: [
                              "#ff6468",
                              "#f9bd50",
                              "#8ac787",
                              "#55d8c7",
                              "#c6cf5a",
                            ][i],
                          }}
                        />
                        <span title={name}>{name}</span>
                        <b
                          aria-label={`${name}: ${points} rule points, ${percentage}%`}
                        >
                          {percentage}%
                        </b>
                      </li>
                    ))
                  ) : (
                    <li>Weights appear after analysis</li>
                  )}
                </ul>
              </div>
            </section>
          </div>
          <section className="email-extracted email-panel">
            <h2>
              <Link2 size={23} />
              Extracted Links ({links.length})
            </h2>
            <div className="email-link-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>URL</th>
                    <th>Analysis</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {links.map((link, i) => (
                    <tr key={`${link.url}-${i}`}>
                      <td>{i + 1}</td>
                      <td>
                        <button
                          className={link.score ? "email-danger" : ""}
                          title={link.url}
                          onClick={() => {
                            setArtifact("Links");
                          }}
                        >
                          {link.url}
                        </button>
                      </td>
                      <td>
                        <EmailBadge
                          value={link.score ? "Indicators" : "Unverified"}
                        />
                      </td>
                      <td title={link.reason}>{link.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!links.length && (
                <div className="email-no-links">
                  {analysis
                    ? "No URLs were extracted from this message."
                    : "Extracted links and supporting reasons will appear here."}
                </div>
              )}
            </div>
          </section>
          <div className="email-actions">
            <button
              className="email-primary"
              onClick={() => void run()}
              disabled={!hasInput || busy}
            >
              <Play size={20} />
              {busy
                ? "Analyzing…"
                : analysis
                  ? "Run Analysis (Re-analyze)"
                  : "Run Analysis"}
            </button>
            <button
              className="email-outline"
              onClick={() => void saveCase()}
              disabled={!analysis || busy}
            >
              <Save size={20} />
              Save Investigation
            </button>
            <button
              className="email-outline"
              onClick={() => void exportReport()}
              disabled={!analysis || busy}
            >
              <FileText size={21} />
              Export PDF
            </button>
            <button
              className="email-outline email-more"
              aria-label="Analysis details & limitations"
              onClick={() => setDetails(true)}
            >
              •••
            </button>
          </div>
        </section>
      </div>
      {pasteOpen && (
        <div
          className="email-modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setPasteOpen(false);
          }}
        >
          <section
            className="email-modal email-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="paste-title"
          >
            <h2 id="paste-title">
              <Clipboard size={22} />
              Paste Email Text
              <button
                aria-label="Close paste dialog"
                onClick={() => setPasteOpen(false)}
              >
                <X size={20} />
              </button>
            </h2>
            <p>Include the original headers and message body when available.</p>
            <textarea
              autoFocus
              aria-label="Raw email content"
              placeholder={
                "From: sender@example.com\nTo: recipient@example.com\nSubject: Message subject\n\nPaste the message here…"
              }
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              maxLength={isPublicDemo ? 256 * 1024 : 25 * 1024 * 1024}
            />
            <div>
              <button
                className="email-outline"
                onClick={() => setPasteOpen(false)}
              >
                Cancel
              </button>
              <button
                className="email-primary"
                disabled={!paste.trim()}
                onClick={() => {
                  setRaw(paste);
                  setFile(null);
                  setPasteOpen(false);
                  setTab("Raw Email");
                }}
              >
                Load Email
                <ArrowRight size={17} />
              </button>
            </div>
          </section>
        </div>
      )}
      {artifact && (
        <div className="email-modal-backdrop">
          <section
            className="email-modal email-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="artifact-title"
          >
            <h2 id="artifact-title">
              {artifact}
              <button
                aria-label="Close artifact details"
                onClick={() => setArtifact(null)}
              >
                <X size={20} />
              </button>
            </h2>
            {artifact === "Links" ? (
              links.length ? (
                links.map((l, i) => (
                  <article className="email-artifact-detail" key={i}>
                    <strong>{l.url}</strong>
                    <p>{l.reason}</p>
                    <small>
                      Passive syntax inspection only · never visited
                    </small>
                  </article>
                ))
              ) : (
                <p>No links found.</p>
              )
            ) : artifact === "Attachments" ? (
              attachments.length ? (
                attachments.map((a, i) => (
                  <article className="email-artifact-detail" key={i}>
                    <strong>{a.filename}</strong>
                    <p>
                      {a.content_type} · {sizeText(a.size)}
                    </p>
                    <small>SHA-256: {a.sha256}</small>
                    <p>
                      Metadata only. Malware safety has not been established.
                    </p>
                  </article>
                ))
              ) : (
                <p>No attachments found.</p>
              )
            ) : (
              <ul className="email-artifact-values">
                {(artifact === "Domains"
                  ? (email?.domains ?? [])
                  : (email?.addresses ?? [])
                ).map((v, i) => (
                  <li key={i}>{v}</li>
                ))}
              </ul>
            )}
            <button className="email-primary" onClick={() => setArtifact(null)}>
              Close
            </button>
          </section>
        </div>
      )}
      {details && (
        <div className="email-modal-backdrop">
          <section
            className="email-modal email-panel"
            role="dialog"
            aria-modal="true"
            aria-labelledby="limitations-title"
          >
            <h2 id="limitations-title">
              Analysis details &amp; limitations
              <button
                aria-label="Close analysis details"
                onClick={() => setDetails(false)}
              >
                <X size={20} />
              </button>
            </h2>
            <p>
              PhishLens computes deterministic rule weights from the submitted
              email. Scores are risk estimates, not calibrated probabilities or
              proof of compromise.
            </p>
            <p>
              ML component:{" "}
              {analysis?.ml.reason ??
                "Submit an email to store the loaded model result alongside its evidence."}
            </p>
            <p>
              Links are not visited. Domain age and reputation are unknown.
              Authentication values are reported from untrusted supplied
              headers. Attachments receive metadata inspection only.
            </p>
            {analysis && (
              <>
                <h3 style={{ marginTop: 18 }}>Current analysis summary</h3>
                <ModelDetails analysis={analysis} />
                <p>{analysis.summary}</p>
                <p>
                  Heuristic score: {analysis.score}/100. Each rule family
                  contributes its maximum weight once; the total is capped at
                  100. The chart shows uncapped category contributions, with
                  percentages rounded to a total of 100%.
                </p>
                <h3 style={{ marginTop: 18 }}>
                  All evidence observations ({evidence.length})
                </h3>
                {evidence.length ? (
                  evidence.map((finding) => (
                    <article className="email-artifact-detail" key={finding.id}>
                      <strong>{finding.title}</strong>
                      <p>{finding.detail}</p>
                      <small>
                        {finding.severity} severity · {finding.source} ·{" "}
                        {finding.weight} rule points
                      </small>
                    </article>
                  ))
                ) : (
                  <p>
                    No configured indicators detected. This does not establish
                    that the message is safe.
                  </p>
                )}
                <h3 style={{ marginTop: 18 }}>
                  Full authentication observations
                </h3>
                {Object.entries(auth).length ? (
                  Object.entries(auth).map(([method, observation]) => (
                    <article className="email-artifact-detail" key={method}>
                      <strong>{method.toUpperCase()}</strong>
                      <p>{observation}</p>
                    </article>
                  ))
                ) : (
                  <p>
                    Not verified. No authentication observations are available.
                  </p>
                )}
              </>
            )}
            <button className="email-primary" onClick={() => setDetails(false)}>
              Understood
            </button>
          </section>
        </div>
      )}
    </div>
  );
}
