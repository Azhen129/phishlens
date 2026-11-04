import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ModelDetails, finalSummary, assessmentRisk } from "./ModelResult";
import type { Analysis } from "./types";
afterEach(cleanup);
const base: Analysis = {
  id: "transport-fixture",
  kind: "email",
  subject: "Fixture",
  score: 28,
  risk: "Medium",
  created_at: "2026-11-02T00:00:00Z",
  summary: "Observed rules.",
  evidence: [],
  links: [],
  attachments: [],
  duration_ms: 1,
  ml: {
    available: true,
    reason: "Validated local unit fixture loaded",
    classification: "Phishing",
    phishing_probability: 0.825,
    classification_threshold: 0.61,
    model_version: "email-unit-version",
    calibrated: true,
    dataset_license: "CC BY 4.0",
    calibration_method: "Held-out sigmoid",
    limitations: ["Spanish dataset evaluation only."],
  },
  assessment: {
    method: "validated_hybrid",
    score: 78,
    risk: "High",
    label: "Phishing",
    phishing_probability: 0.78,
    classification_threshold: 0.6,
    limitations: [],
  },
};
describe("Stored ML metadata presentation", () => {
  it("uses the final validated risk for the decision while preserving separate rule points", () => {
    expect(assessmentRisk(base)).toBe("High");
    expect(base.risk).toBe("Medium");
    expect(
      assessmentRisk({
        ...base,
        ml: { available: false, reason: "Missing model" },
      }),
    ).toBe("Medium");
    expect(assessmentRisk(null)).toBeUndefined();
  });
  it("distinguishes ML decision score from confidence, hybrid and heuristic points", () => {
    render(<ModelDetails analysis={base} />);
    expect(screen.getByText("82.5%")).toBeInTheDocument();
    expect(screen.getByText(/ML classification:/)).toHaveTextContent(
      "ML decision score (not confidence)",
    );
    expect(screen.queryByText(/Calibrated ML phishing probability/)).toBeNull();
    expect(screen.getByText(/Heuristic score remains/)).toHaveTextContent(
      "28/100 rule points",
    );
    expect(screen.getByText("email-unit-version")).toBeInTheDocument();
    expect(finalSummary(base)).toContain("78.0%");
    expect(screen.getByText(/Spanish dataset/)).toBeInTheDocument();
  });
  it("shows abstention and loaded language scope without displaying a probability", () => {
    const unsupported: Analysis = {
      ...base,
      ml: {
        available: false,
        model_loaded: true,
        reason: "Unsupported language; heuristics retained",
        model_version: "spanish-model",
        supported_languages: ["es"],
      },
      assessment: {
        method: "heuristic_fallback",
        score: 28,
        risk: "Medium",
        label: "Medium heuristic risk",
        limitations: [],
      },
    };
    render(<ModelDetails analysis={unsupported} />);
    expect(screen.getByText(/Supported languages/)).toHaveTextContent("es");
    expect(screen.queryByText("82.5%")).toBeNull();
    expect(finalSummary(unsupported)).toBe("Heuristic assessment");
  });
  it("renders untrusted stored metadata as text", () => {
    render(
      <ModelDetails
        analysis={{
          ...base,
          ml: { ...base.ml, model_version: "<img src=x onerror=alert(1)>" },
        }}
      />,
    );
    expect(
      screen.getByText("<img src=x onerror=alert(1)>"),
    ).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });
  it("identifies the routed English classifier, version, scope and limitations", () => {
    render(
      <ModelDetails
        analysis={{
          ...base,
          ml: {
            ...base.ml,
            model_name: "English email classifier",
            model_version: "english-version",
            supported_languages: ["en"],
            detected_language: "en",
            language_routing_status: "supported",
            language_routing_limitation:
              "Language identification is imperfect.",
            limitations: ["New campaigns may differ from held-out evaluation."],
          },
        }}
      />,
    );
    expect(screen.getByText(/Email language:/)).toHaveTextContent(
      "Email language: en. Routing: supported.",
    );
    expect(screen.getByText(/Recorded classifier:/)).toHaveTextContent(
      "English email classifier. Model version: english-version. Supported languages: en.",
    );
    expect(screen.getByText(/New campaigns/)).toBeInTheDocument();
    expect(screen.queryByText(/language confidence/i)).toBeNull();
  });
  it("shows mixed-language fallback without claiming an active model or probability", () => {
    render(
      <ModelDetails
        analysis={{
          ...base,
          ml: {
            available: false,
            model_loaded: false,
            reason: "Mixed-language inputs use heuristic fallback.",
            detected_language: "mixed",
            language_routing_status: "mixed",
          },
          assessment: undefined,
        }}
      />,
    );
    expect(screen.getByText(/Email language:/)).toHaveTextContent(
      "Email language: mixed. Routing: mixed.",
    );
    expect(screen.queryByText(/Recorded classifier:/)).toBeNull();
    expect(screen.queryByText("82.5%")).toBeNull();
  });
});
