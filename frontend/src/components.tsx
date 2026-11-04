import type { ReactNode } from "react";
import { useEffect, useRef, useState } from "react";
import {
  Link2,
  ShieldCheck,
  Mail,
  Paperclip,
  User,
  TriangleAlert,
  Info,
  Inbox,
  FileText,
  Layers,
} from "lucide-react";
import type { Analysis, ExtractedLink, Evidence } from "./types";
export function Panel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={"panel " + className}>{children}</section>;
}
export function Button({
  children,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button {...props} className={"button " + (props.className || "")}>
      {children}
    </button>
  );
}
export function Badge({
  risk,
  children,
}: {
  risk: string;
  children?: ReactNode;
}) {
  return (
    <span className={"badge " + risk.toLowerCase().replaceAll(" ", "-")}>
      {children || risk}
    </span>
  );
}
export function SectionTitle({ children }: { children: ReactNode }) {
  return <h2 className="section-title">{children}</h2>;
}
export function Empty({
  children = "Submit an email or URL to begin a passive analysis.",
}: {
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <Inbox size={25} />
      <span>{children}</span>
    </div>
  );
}
export function RiskRing({
  score,
  size = 144,
  label = "Threat Score",
  tone = "risk",
}: {
  score: number | null;
  size?: number;
  label?: string;
  tone?: "cyan" | "risk";
}) {
  const r = 60,
    c = 2 * Math.PI * r;
  const color =
    tone === "cyan"
      ? "#00e2d8"
      : score === null
        ? "#36505d"
        : score >= 60
          ? "#ff6268"
          : score >= 25
            ? "#ffbd35"
            : "#4ed59c";
  return (
    <div className="risk-ring" style={{ width: size, height: size }}>
      <svg viewBox="0 0 144 144" aria-hidden="true">
        <circle
          cx="72"
          cy="72"
          r={r}
          fill="none"
          stroke="#193b46"
          strokeWidth="13"
        />
        <circle
          cx="72"
          cy="72"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="13"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - (score || 0) / 100)}
          transform="rotate(-90 72 72)"
        />
      </svg>
      <div>
        <strong>
          {score ?? "—"}
          {score !== null && (
            <small>{tone === "cyan" ? " / 100" : "/100"}</small>
          )}
        </strong>
        <span>{label}</span>
      </div>
    </div>
  );
}
export function Icon({ name }: { name: string }) {
  const C = name.includes("auth")
    ? ShieldCheck
    : name.includes("attach")
      ? Paperclip
      : name.includes("sender")
        ? User
        : name.includes("language")
          ? Mail
          : Link2;
  return <C size={20} />;
}
export function LinkTable({ links }: { links: ExtractedLink[] }) {
  return (
    <div className="table-scroll">
      <table className="links-table">
        <thead>
          <tr>
            <th>#</th>
            <th>URL</th>
            <th>Analysis</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {links.map((l, i) => (
            <tr key={l.url}>
              <td>{i + 1}</td>
              <td className={l.score > 0 ? "danger" : "muted"}>
                <code>{l.url}</code>
              </td>
              <td>
                <Badge risk={l.risk}>
                  {l.score > 0 ? "Indicators" : "Unverified"}
                </Badge>
              </td>
              <td>
                {l.reason || "No known syntax indicators; not verified safe."}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!links.length && <Empty>No links extracted.</Empty>}
    </div>
  );
}
export function FindingList({ analysis }: { analysis: Analysis | null }) {
  const [selected, setSelected] = useState<Evidence | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    if (selected && !dialog.current?.open) dialog.current?.showModal();
  }, [selected]);
  return (
    <>
      <div className="finding-grid">
        {analysis?.evidence.length ? (
          analysis.evidence.map((e, i) => (
            <article className="finding" key={e.id || i}>
              <div className="finding-icon">
                {e.source.toLowerCase().includes("auth") ? (
                  <ShieldCheck />
                ) : e.source.toLowerCase().includes("attach") ? (
                  <Paperclip />
                ) : e.source.toLowerCase().includes("language") ? (
                  <Mail />
                ) : e.source.toLowerCase().includes("sender") ? (
                  <User />
                ) : (
                  <Link2 />
                )}
              </div>
              <div>
                <strong>
                  <button
                    className="finding-title-button"
                    onClick={() => setSelected(e)}
                  >
                    {e.title}
                  </button>
                </strong>
                <p title={e.detail}>{e.detail}</p>
              </div>
              <Badge risk={e.severity} />
            </article>
          ))
        ) : (
          <div className="finding-placeholder">
            <Layers />
            <strong>Evidence will appear here</strong>
            <span>
              Submit content to inspect sender identity, authentication
              observations, language, links and attachment metadata.
            </span>
          </div>
        )}
      </div>
      <dialog
        className="finding-dialog panel"
        ref={dialog}
        onClose={() => setSelected(null)}
        aria-labelledby="finding-dialog-title"
      >
        <h2 id="finding-dialog-title">{selected?.title}</h2>
        {selected && (
          <>
            <p>
              <Badge risk={selected.severity} />{" "}
              <span className="muted">
                Source: {selected.source} · {selected.weight} rule points
              </span>
            </p>
            <p>{selected.detail}</p>
            <p className="muted">
              A documented indicator is not proof of maliciousness. Repeated
              rule families count once in the total score.
            </p>
          </>
        )}
        <button
          className="button primary"
          onClick={() => dialog.current?.close()}
        >
          Close Evidence
        </button>
      </dialog>
    </>
  );
}
export const ResultIcon = TriangleAlert;
export { Info, FileText };
