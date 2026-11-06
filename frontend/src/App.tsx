import { useCallback, useEffect, useState } from "react";
import {
  NavLink,
  Routes,
  Route,
  useNavigate,
  useLocation,
} from "react-router-dom";
import {
  House,
  Mail,
  Link2,
  ScanLine,
  ChartNoAxesColumnIncreasing,
  History,
  Settings,
  Search,
  Bell,
  ChevronDown,
  Check,
  ShieldCheck,
  Menu,
  X,
  Info,
  LogOut,
} from "lucide-react";
import { api } from "./api";
import { isPublicDemo } from "./environment";
import { loadDemoExamples } from "./demoApi";
import type { Analysis, Investigation, Metrics } from "./types";
import Dashboard from "./pages/Dashboard";
import EmailPage from "./pages/EmailPage";
import InvestigationsPage from "./pages/InvestigationsPage";
import { UrlPage, HistoryPage, SettingsPage } from "./pages/UtilityPages";
const nav = [
  ["Dashboard", "/", House],
  ["Analyze Email", "/analyze/email", Mail],
  ["Analyze URL", "/analyze/url", Link2],
  ["Investigations", "/investigations", ScanLine],
  ["Reports", "/reports", ChartNoAxesColumnIncreasing],
  ["History", "/history", History],
  ["Settings", "/settings", Settings],
] as const;
export default function App() {
  const [analysis, setAnalysis] = useState<Analysis | null>(null),
    [analyses, setAnalyses] = useState<Analysis[]>([]),
    [cases, setCases] = useState<Investigation[]>([]),
    [metrics, setMetrics] = useState<Metrics | null>(null),
    [error, setError] = useState(""),
    [toast, setToast] = useState(""),
    [menu, setMenu] = useState(""),
    [search, setSearch] = useState(""),
    [mobile, setMobile] = useState(false),
    [loadingExamples, setLoadingExamples] = useState(false);
  const navigate = useNavigate(),
    location = useLocation();
  const notify = useCallback((s: string) => {
    setToast(s);
  }, []);
  const refresh = useCallback(async () => {
    try {
      const [a, c, m] = await Promise.all([
        api.analyses(),
        api.cases(),
        api.metrics(),
      ]);
      setAnalyses(a);
      setCases(c);
      setMetrics(m);
      setAnalysis((previous) =>
        previous ? a.find((x) => x.id === previous.id) || null : a[0] || null,
      );
      setError("");
    } catch (e) {
      setError(
        (isPublicDemo
          ? "The demo analysis service is unavailable. "
          : "Local API unavailable. Start the FastAPI server on port 8000. ") +
          (e as Error).message,
      );
    }
  }, []);
  useEffect(() => {
    refresh();
    document.documentElement.classList.toggle(
      "compact-mode",
      localStorage.getItem("phishlens-compact") === "true",
    );
  }, [refresh]);
  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(""), 5500);
      return () => clearTimeout(t);
    }
  }, [toast]);
  useEffect(() => {
    setMobile(false);
    setMenu("");
  }, [location.pathname]);
  const open = (a: Analysis) => {
    setAnalysis(a);
    navigate(a.kind === "email" ? "/analyze/email" : "/analyze/url");
  };
  return (
    <div className="app-shell">
      <aside className={"sidebar " + (mobile ? "mobile-open" : "")}>
        <a
          className="wordmark"
          href="/"
          onClick={(e) => {
            e.preventDefault();
            navigate("/");
          }}
          aria-label="PhishLens dashboard"
        >
          <svg width="37" height="42" viewBox="0 0 40 46" aria-hidden="true">
            <path
              d="M20 2 37 8v14c0 10-8 17-17 22C11 39 3 32 3 22V8Z"
              fill="none"
              stroke="currentColor"
              strokeWidth="3"
            />
            <circle
              cx="20"
              cy="20"
              r="7"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
            />
            <path d="m20 27-3 7" stroke="currentColor" strokeWidth="2.5" />
          </svg>
          <span>
            Phish<b>Lens</b>
          </span>
        </a>
        <p className="sidebar-subtitle">
          Passive Phishing Detector
          <br />& Email Investigation Platform
        </p>
        <nav aria-label="Main navigation">
          {nav.map(([title, to, I]) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                isActive ? "nav-item active" : "nav-item"
              }
            >
              <I size={23} />
              <span>{title}</span>
            </NavLink>
          ))}
        </nav>
        <svg className="sidebar-waves" viewBox="0 0 248 160" aria-hidden="true">
          {Array.from({ length: 22 }, (_, i) => (
            <path
              key={i}
              d={`M-15 ${103 + i * 2.1} C30 ${45 + i * 2},55 ${5 + i * 2},103 ${15 + i * 1.7} S185 ${77 + i * 1.2},267 ${21 + i}`}
              fill="none"
              stroke="#00ddd7"
              strokeWidth=".45"
              opacity={0.45 - i * 0.012}
            />
          ))}
        </svg>
        <section className="security-card">
          <h2>
            <ShieldCheck size={23} />
            Security-First Analysis
          </h2>
          <p>
            <Check />
            Links analyzed passively
            <br />
            (never auto-opened)
          </p>
          <p>
            <Check />
            Content inspected in a<br />
            {isPublicDemo ? "passive demo service" : "safe local environment"}
          </p>
          <p>
            <Check />
            Risk = estimated likelihood,
            <br />
            not proof of compromise
          </p>
        </section>
      </aside>
      <div className="app-content">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="Toggle navigation"
            onClick={() => setMobile(!mobile)}
          >
            {mobile ? <X /> : <Menu />}
          </button>
          <form
            className="global-search"
            onSubmit={(e) => {
              e.preventDefault();
              navigate("/investigations?q=" + encodeURIComponent(search));
              setSearch("");
            }}
          >
            <Search size={18} />
            <input
              aria-label="Search investigations and reports"
              placeholder="Search investigations, reports..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </form>
          <div className="utility-divider" />
          <div className="utility-wrap">
            <button
              className="icon-button notification-button"
              aria-label="Workspace activity"
              aria-expanded={menu === "notifications"}
              onClick={() =>
                setMenu(menu === "notifications" ? "" : "notifications")
              }
            >
              <Bell size={23} />
              {analyses.length > 0 && <i />}
            </button>
            {menu === "notifications" && (
              <div className="utility-menu">
                <strong>Workspace Activity</strong>
                <p>
                  {analyses.length} analyses · {cases.length} investigations
                </p>
                <p className="muted">
                  {isPublicDemo
                    ? "Cases and reports are temporary to this tab and reset on reload."
                    : "All records remain in your local workspace."}
                </p>
                <button onClick={() => navigate("/history")}>
                  View Analysis History <History size={16} />
                </button>
              </div>
            )}
          </div>
          <div className="utility-wrap">
            <button
              className="account-button"
              aria-label={
                isPublicDemo ? "Guest demo menu" : "Local workspace menu"
              }
              aria-expanded={menu === "account"}
              onClick={() => setMenu(menu === "account" ? "" : "account")}
            >
              <span>A</span>
              <ChevronDown size={17} />
            </button>
            {menu === "account" && (
              <div className="utility-menu">
                <strong>
                  {isPublicDemo ? "Guest Analyst" : "Local Analyst"}
                </strong>
                <p className="muted">
                  {isPublicDemo
                    ? "Temporary demo tab"
                    : "Single-user local workspace"}
                </p>
                <button onClick={() => navigate("/settings")}>
                  Settings & Privacy <Settings size={16} />
                </button>
              </div>
            )}
          </div>
        </header>
        <main className="page-content">
          {isPublicDemo && (
            <div
              className="demo-notice"
              role="note"
              aria-label="Public demo privacy"
            >
              <span>
                <strong>Public demo · Rules only</strong>
                <span>
                  Cases stay in this tab and reset on reload. Use synthetic
                  data.
                </span>
                <a
                  href="/third-party-notices.txt"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  Licenses
                </a>
              </span>
              <button
                className="button"
                disabled={loadingExamples}
                onClick={async () => {
                  setLoadingExamples(true);
                  try {
                    await loadDemoExamples();
                    await refresh();
                    notify(
                      "Synthetic examples analyzed. Every finding is computed from the fixture content.",
                    );
                  } catch (e) {
                    notify((e as Error).message);
                  } finally {
                    setLoadingExamples(false);
                  }
                }}
              >
                {loadingExamples
                  ? "Analyzing examples…"
                  : "Load synthetic examples"}
              </button>
            </div>
          )}
          {error && (
            <div role="alert" className="api-error">
              <Info size={18} />
              {error}
              <button onClick={refresh}>Retry</button>
            </div>
          )}
          <Routes>
            <Route
              path="/"
              element={
                <Dashboard
                  analysis={analysis}
                  cases={cases}
                  metrics={metrics}
                  onAnalysis={setAnalysis}
                  onRefresh={refresh}
                  notify={notify}
                />
              }
            />
            <Route
              path="/dashboard"
              element={
                <Dashboard
                  analysis={analysis}
                  cases={cases}
                  metrics={metrics}
                  onAnalysis={setAnalysis}
                  onRefresh={refresh}
                  notify={notify}
                />
              }
            />
            <Route
              path="/analyze/email"
              element={
                <EmailPage
                  analysis={analysis?.kind === "email" ? analysis : null}
                  onAnalysis={setAnalysis}
                  onRefresh={refresh}
                  notify={notify}
                />
              }
            />
            <Route
              path="/analyze/url"
              element={
                <UrlPage
                  analysis={analysis}
                  onAnalysis={setAnalysis}
                  onRefresh={refresh}
                  notify={notify}
                />
              }
            />
            <Route
              path="/investigations"
              element={
                <InvestigationsPage
                  cases={cases}
                  metrics={metrics}
                  onRefresh={refresh}
                  notify={notify}
                  onOpenAnalysis={open}
                />
              }
            />
            <Route
              path="/reports"
              element={
                <InvestigationsPage
                  cases={cases}
                  metrics={metrics}
                  onRefresh={refresh}
                  notify={notify}
                  onOpenAnalysis={open}
                  reportsMode
                />
              }
            />
            <Route
              path="/history"
              element={
                <HistoryPage
                  analyses={analyses}
                  onOpen={open}
                  onRefresh={refresh}
                  notify={notify}
                />
              }
            />
            <Route
              path="/settings"
              element={
                <SettingsPage
                  onRefresh={refresh}
                  onClear={() => setAnalysis(null)}
                  notify={notify}
                />
              }
            />
            <Route
              path="*"
              element={
                <div className="panel empty">
                  Page not found.{" "}
                  <button className="button" onClick={() => navigate("/")}>
                    Return to Dashboard
                  </button>
                </div>
              }
            />
          </Routes>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <Check size={19} />
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={16} />
          </button>
        </div>
      )}
    </div>
  );
}
