import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import EmailPage from "./EmailPage";
import { api } from "../api";
import type { Analysis } from "../types";

vi.mock("../api", () => ({
  api: {
    analyzeEmail: vi.fn(),
    uploadEmail: vi.fn(),
    saveCase: vi.fn(),
    report: vi.fn(),
    downloadReport: vi.fn(),
  },
}));
const fixture: Analysis = {
  id: "test-analysis",
  kind: "email",
  created_at: "2026-01-01T00:00:00Z",
  subject: "Test message",
  score: 0,
  risk: "Low",
  summary: "No weighted signals detected. Legitimacy is not established.",
  evidence: [],
  links: [],
  attachments: [],
  email: {
    from: "test@example.test",
    to: "analyst@example.test",
    reply_to: "",
    date: "",
    headers: { From: "test@example.test", Subject: "Test message" },
    body: '<img src="https://example.test/pixel" onerror="alert(1)">',
    raw: "From: test@example.test\nSubject: Test message\n\nTest message",
    addresses: ["test@example.test"],
    domains: ["example.test"],
    authentication: {},
  },
  ml: { available: false, reason: "Not trained / unavailable" },
  duration_ms: 4,
};
function setup(analysis: Analysis | null = null) {
  const onAnalysis = vi.fn(),
    onRefresh = vi.fn(),
    notify = vi.fn();
  render(
    <EmailPage
      analysis={analysis}
      onAnalysis={onAnalysis}
      onRefresh={onRefresh}
      notify={notify}
    />,
  );
  return { onAnalysis, onRefresh, notify };
}
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("Email workspace", () => {
  it("starts with unknown results and disables case and PDF actions", () => {
    setup();
    expect(screen.getByText("No analysis yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Run Analysis" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Save Investigation" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Export PDF" })).toBeDisabled();
    expect(screen.getAllByText("Not verified").length).toBeGreaterThan(0);
  });
  it("loads pasted content and analyzes through the local API", async () => {
    vi.mocked(api.analyzeEmail).mockResolvedValue(fixture);
    const { onAnalysis, onRefresh } = setup();
    fireEvent.click(screen.getByRole("button", { name: "Paste Email Text" }));
    fireEvent.change(
      screen.getByRole("textbox", { name: "Raw email content" }),
      { target: { value: fixture.email!.raw } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Load Email" }));
    fireEvent.click(screen.getByRole("button", { name: "Run Analysis" }));
    await waitFor(() =>
      expect(api.analyzeEmail).toHaveBeenCalledWith(fixture.email!.raw),
    );
    expect(onAnalysis).toHaveBeenCalledWith(fixture);
    expect(onRefresh).toHaveBeenCalled();
  });
  it("renders parsed HTML as inert text and explicitly preserves uncertainty", () => {
    setup(fixture);
    fireEvent.click(screen.getByRole("tab", { name: "Parsed View" }));
    expect(screen.getByText(fixture.email!.body)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(
      screen.getByText("Reported headers only; unverified by PhishLens."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Unknown · no lookup performed"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("0 attachments found. Static metadata only."),
    ).toBeInTheDocument();
  });
  it("rejects uploads with a non-email extension before any API request", async () => {
    setup();
    const file = new File(["test"], "test.html", { type: "text/html" });
    fireEvent.change(screen.getByLabelText("Upload email file"), {
      target: { files: [file] },
    });
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Choose an RFC/MIME email file",
    );
    expect(api.uploadEmail).not.toHaveBeenCalled();
  });
  it("includes attachment contributions and counts each rule family maximum once in a complete 100% distribution", () => {
    const observations = [
      ["sender-brand-demo", "Email headers", 20],
      ["auth-reported-failure", "Supplied headers (unverified)", 8],
      ["url-http-0", "Extracted URL 1", 8],
      ["url-http-1", "Extracted URL 2", 12],
      ["url-ip-0", "Extracted URL 1", 18],
      ["display-mismatch-0", "HTML anchor", 28],
      ["language-urgency", "Message language", 10],
      ["attachment-0", "Attachment metadata", 22],
      ["attachment-1", "Attachment metadata", 22],
    ] as const;
    setup({
      ...fixture,
      evidence: observations.map(([id, source, weight]) => ({
        id,
        source,
        weight,
        title: id,
        detail: `Observed ${id}`,
        severity: "Medium",
      })),
    });
    const legend = screen.getByRole("list", {
      name: "Rule points by evidence category",
    });
    expect(within(legend).getAllByRole("listitem")).toHaveLength(5);
    expect(
      within(legend).getByLabelText("Attachment: 22 rule points, 19%"),
    ).toBeInTheDocument();
    expect(
      within(legend).getByLabelText("Link Analysis: 58 rule points, 49%"),
    ).toBeInTheDocument();
    const percentages = Array.from(legend.querySelectorAll("b")).map((node) =>
      Number(node.textContent?.replace("%", "")),
    );
    expect(percentages.reduce((sum, n) => sum + n, 0)).toBe(100);
    expect(
      screen.getByRole("img", { name: /118 total before the score cap/ }),
    ).toBeInTheDocument();
    expect(screen.getByText("Cumulative")).toBeInTheDocument();
  });
  it("exposes every full rationale and authentication observation in the keyboard-accessible details dialog", () => {
    const detail =
      "A complete rationale that must remain readable even when the overview card has a limited number of lines.";
    const observation =
      "Reported fail in supplied headers; unverified by PhishLens. This text is fully available in the details dialog.";
    setup({
      ...fixture,
      evidence: [
        {
          id: "sender-review",
          source: "Email headers",
          weight: 14,
          severity: "Medium",
          title: "Sender needs review",
          detail,
        },
      ],
      email: { ...fixture.email!, authentication: { SPF: observation } },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Analysis details & limitations" }),
    );
    const dialog = screen.getByRole("dialog", {
      name: "Analysis details & limitations",
    });
    expect(within(dialog).getByText(fixture.summary)).toBeVisible();
    expect(within(dialog).getByText(detail)).toBeVisible();
    expect(within(dialog).getByText(observation)).toBeVisible();
    expect(
      within(dialog).getByText(
        "Medium severity · Email headers · 14 rule points",
      ),
    ).toBeVisible();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
