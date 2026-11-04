import type { Analysis } from "./types";

export function assessmentRisk(analysis: Analysis | null) {
  return analysis?.ml.available && analysis.assessment
    ? analysis.assessment.risk
    : analysis?.risk;
}

export function probabilityText(value?: number) {
  return typeof value === "number" && Number.isFinite(value)
    ? `${(100 * value).toFixed(1)}%`
    : "Not recorded";
}
export function modelSummary(analysis: Analysis | null) {
  if (!analysis?.ml.available) return "ML unavailable for this saved analysis";
  return `${analysis.ml.model_name ? analysis.ml.model_name + " · " : ""}${analysis.ml.classification} · ${probabilityText(analysis.ml.decision_score ?? analysis.ml.phishing_probability)} ML decision score (not confidence)${analysis.ml.prediction_warning ? " · limited archive calibration" : ""}${analysis.ml.supported_languages?.length ? " · Language scope: " + analysis.ml.supported_languages.join(", ") : ""}`;
}
export function finalSummary(analysis: Analysis | null) {
  if (
    !analysis?.assessment ||
    analysis.assessment.method === "heuristic_fallback"
  )
    return "Heuristic assessment";
  return `${analysis.assessment.label} (${probabilityText(analysis.assessment.decision_score ?? analysis.assessment.phishing_probability)} score, ${analysis.assessment.method === "validated_hybrid" ? "validated hybrid" : "ML"})`;
}
export function ModelDetails({ analysis }: { analysis: Analysis }) {
  const ml = analysis.ml;
  return (
    <section aria-label="Stored machine learning result">
      <h3 style={{ marginTop: 18 }}>Stored machine learning result</h3>
      <p>{ml.reason}</p>
      {ml.prediction_warning && (
        <p>
          <strong>{ml.prediction_warning}</strong>
        </p>
      )}
      {ml.detected_language && (
        <p>
          Email language:{" "}
          {ml.detected_language === "und"
            ? "Undetermined"
            : ml.detected_language}
          . Routing: {ml.language_routing_status}.
          {ml.model_name && <> Selected classifier: {ml.model_name}.</>}{" "}
          {ml.language_routing_limitation}
        </p>
      )}
      {ml.model_loaded && !ml.available && (
        <p>
          Loaded model: <code>{ml.model_version}</code>. Supported languages:{" "}
          {ml.supported_languages?.join(", ") || "See validation scope"}. This
          analysis abstained and retained its heuristic assessment.
        </p>
      )}
      {ml.available && (
        <>
          <p>
            ML classification: <strong>{ml.classification}</strong>. ML decision
            score (not confidence):{" "}
            <strong>
              {probabilityText(ml.decision_score ?? ml.phishing_probability)}
            </strong>
            . Classification threshold:{" "}
            {probabilityText(ml.classification_threshold)}.
          </p>
          <p>
            Recorded classifier: {ml.model_name || "See stored model version"}.{" "}
            Model version: <code>{ml.model_version}</code>. Supported languages:{" "}
            {ml.supported_languages?.join(", ") || "See validation scope"}.
            {ml.classifier_decision && (
              <> Review status: {ml.classifier_decision}.</>
            )}
          </p>
          <p>
            Dataset license: {ml.dataset_license}. Calibration:{" "}
            {ml.calibration_method}.
          </p>
          <p>
            Final assessment: {finalSummary(analysis)}. Heuristic score remains{" "}
            {analysis.score}/100 rule points.
          </p>
          {ml.input_truncated && (
            <p>
              Model input was limited to its documented text bound. The complete
              local email is retained separately.
            </p>
          )}
          <p>{ml.validation_scope}</p>
          {ml.limitations?.map((item, index) => (
            <p key={index}>Model limitation: {item}</p>
          ))}
        </>
      )}
      <p>
        Decision scores use archive calibration, which is not validated field
        probability or confidence. Historical probability fields are retained
        for saved-result compatibility. A low score does not verify safety.
        Model predictions do not establish SPF/DKIM/DMARC, reputation, domain
        age or attachment safety.
      </p>
    </section>
  );
}
