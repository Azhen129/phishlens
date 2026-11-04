import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import InvestigationsPage from "./InvestigationsPage";
import type { Analysis, Investigation, Metrics } from "../types";
import { api } from "../api";

vi.mock("../api", () => ({
  api: {
    updateCase: vi.fn(),
    deleteCase: vi.fn(),
    report: vi.fn(),
    downloadReport: vi.fn(),
    reports: vi.fn(),
  },
}));
const now = new Date().toISOString();
const analysis: Analysis = {
  id: "test-scan-1",
  kind: "email",
  created_at: now,
  subject: "Invoice needs review",
  score: 65,
  risk: "High",
  summary:
    "Test fixture: urgent language and a numeric hostname were observed.",
  evidence: [
    {
      id: "test-evidence",
      title: "Numeric hostname",
      detail:
        "The submitted URL uses an IP literal. This alone is not proof of phishing.",
      severity: "Medium",
      source: "URL syntax",
      weight: 20,
    },
  ],
  links: [
    {
      url: "http://192.0.2.1/invoice",
      host: "192.0.2.1",
      score: 20,
      risk: "Medium",
      reason: "IP literal observed",
    },
  ],
  attachments: [],
  email: {
    from: "sender@example.test",
    to: "recipient@example.test",
    reply_to: "",
    date: now,
    headers: {},
    body: "Test fixture only.",
    raw: "Subject: test",
    addresses: [],
    domains: ["example.test"],
    authentication: {},
  },
  ml: { available: false, reason: "No trained model" },
  duration_ms: 3,
};
const firstCase: Investigation = {
  id: "PL-TEST-1",
  analysis_id: analysis.id,
  subject: analysis.subject,
  score: 65,
  risk: "High",
  source: "Email",
  status: "Open",
  notes: "",
  created_at: now,
  updated_at: now,
  analysis,
  timeline: [
    {
      at: now,
      title: "Investigation created",
      detail: "Created from a test analysis.",
    },
  ],
};
const secondCase: Investigation = {
  ...firstCase,
  id: "PL-TEST-2",
  analysis_id: "test-scan-2",
  subject: "Team lunch",
  score: 0,
  risk: "Low",
  status: "Resolved",
  source: "URL",
  analysis: {
    ...analysis,
    id: "test-scan-2",
    kind: "url",
    subject: "Team lunch",
    score: 0,
    risk: "Low",
    evidence: [],
    email: null,
  },
};
const metrics: Metrics = {
  total: 2,
  high: 1,
  false_positives: 0,
  reports: 0,
  trend: [],
  severity: [],
  categories: [],
};
const onRefresh = vi.fn();
const notify = vi.fn();
function mount(
  cases: Investigation[] = [firstCase, secondCase],
  route = "/investigations",
) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <InvestigationsPage
        cases={cases}
        metrics={cases.length ? metrics : { ...metrics, total: 0, high: 0 }}
        onRefresh={onRefresh}
        notify={notify}
        onOpenAnalysis={vi.fn()}
      />
    </MemoryRouter>,
  );
}
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(api.updateCase).mockResolvedValue(firstCase);
  vi.mocked(api.deleteCase).mockResolvedValue(undefined);
});
afterEach(cleanup);

describe("investigation review", () => {
  it("reads global search from the URL and combines real filters without modifying records", () => {
    mount(undefined, "/investigations?q=invoice");
    const table = screen.getByRole("table");
    expect(
      screen.getByRole("textbox", { name: "Search investigations" }),
    ).toHaveValue("invoice");
    expect(within(table).getByText("Invoice needs review")).toBeInTheDocument();
    expect(within(table).queryByText("Team lunch")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reset" }));
    fireEvent.change(
      screen.getByRole("combobox", { name: "Filter severity" }),
      { target: { value: "Low" } },
    );
    expect(within(table).getByText("Team lunch")).toBeInTheDocument();
    expect(
      within(table).queryByText("Invoice needs review"),
    ).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter status" }), {
      target: { value: "Open" },
    });
    expect(screen.getByText("No matching investigations")).toBeInTheDocument();
    expect(api.updateCase).not.toHaveBeenCalled();
  });

  it("saves analyst notes and case status through the persistence API", async () => {
    mount();
    fireEvent.click(screen.getByRole("tab", { name: "Report Settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit notes" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Analyst notes" }), {
      target: {
        value: "Verified with the sender over an independent channel.",
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save Notes" }));
    await waitFor(() =>
      expect(api.updateCase).toHaveBeenCalledWith("PL-TEST-1", {
        notes: "Verified with the sender over an independent channel.",
      }),
    );
    await waitFor(() =>
      expect(notify).toHaveBeenCalledWith("Analyst notes saved."),
    );
    fireEvent.change(screen.getByRole("combobox", { name: "Case status" }), {
      target: { value: "Resolved" },
    });
    await waitFor(() =>
      expect(api.updateCase).toHaveBeenCalledWith("PL-TEST-1", {
        status: "Resolved",
      }),
    );
    expect(onRefresh).toHaveBeenCalled();
  });

  it("requires archive confirmation and preserves the record when cancelled", async () => {
    mount();
    fireEvent.click(screen.getByRole("button", { name: "Archive" }));
    expect(
      screen.getByRole("dialog", { name: "Archive this investigation?" }),
    ).toBeInTheDocument();
    expect(api.updateCase).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Archive" }));
    fireEvent.click(screen.getByRole("button", { name: "Archive Case" }));
    await waitFor(() =>
      expect(api.updateCase).toHaveBeenCalledWith("PL-TEST-1", {
        status: "Archived",
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("does not manufacture saved cases, category data, or analysis outcomes in an empty workspace", () => {
    mount([]);
    expect(
      screen.getByText("Your investigation workspace is ready"),
    ).toBeInTheDocument();
    expect(screen.getByText("Evidence belongs here")).toBeInTheDocument();
    expect(
      screen.getByText("No categories to display yet."),
    ).toBeInTheDocument();
    expect(screen.queryByText("1,248")).not.toBeInTheDocument();
    expect(
      screen.queryByText("High risk estimate (82/100)"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Generate Report" }),
    ).toBeDisabled();
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(
      1,
    );
  });
});
