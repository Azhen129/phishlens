export type Severity = "High" | "Medium" | "Low";
export type Evidence = {
  id: string;
  title: string;
  detail: string;
  severity: Severity | "Info";
  source: string;
  weight: number;
};
export type ExtractedLink = {
  url: string;
  host: string;
  score: number;
  risk: Severity;
  reason: string;
};
export type Attachment = {
  filename: string;
  content_type: string;
  size: number;
  sha256: string;
};
export type EmailData = {
  from: string;
  to: string;
  reply_to: string;
  date: string;
  headers: Record<string, string>;
  body: string;
  raw: string;
  addresses: string[];
  domains: string[];
  authentication: Record<string, string>;
};
export type ModelPrediction = {
  available: boolean;
  reason: string;
  classification?: "Phishing" | "Legitimate";
  phishing_probability?: number;
  decision_score?: number;
  score_type?: string;
  probability_validated_for_deployment?: boolean;
  classification_threshold?: number;
  model_version?: string;
  model_key?: string;
  model_name?: string;
  detected_language?: string;
  language_routing_status?:
    "supported" | "unsupported" | "mixed" | "uncertain" | "too_short";
  language_routing_limitation?: string;
  language_routing_version?: string;
  calibrated?: boolean;
  limitations?: string[];
  validation_scope?: string;
  artifact_sha256?: string;
  input_truncated?: boolean;
  model_loaded?: boolean;
  supported_languages?: string[];
  dataset_source?: string;
  dataset_license?: string;
  calibration_method?: string;
  prediction_warning?: string;
  classifier_decision?: string;
  probability_scope?: string;
};
export type Assessment = {
  method: "heuristic_fallback" | "validated_hybrid" | "ml";
  score: number;
  risk: Severity;
  label: string;
  phishing_probability?: number;
  decision_score?: number;
  score_type?: string;
  probability_validated_for_deployment?: boolean;
  model_version?: string;
  classification_threshold?: number;
  limitations: string[];
};
export type ModelHealth = {
  status: string;
  ml?: { available: boolean; reason: string };
  models?: {
    email: ModelPrediction;
    email_en?: ModelPrediction;
    url: ModelPrediction;
  };
};
export type Analysis = {
  id: string;
  kind: "email" | "url";
  created_at: string;
  subject: string;
  score: number;
  heuristic_score?: number;
  risk: Severity;
  summary: string;
  evidence: Evidence[];
  links: ExtractedLink[];
  attachments: Attachment[];
  email?: EmailData | null;
  ml: ModelPrediction;
  assessment?: Assessment;
  duration_ms: number;
};
export type CaseStatus =
  | "Open"
  | "In Progress"
  | "In Review"
  | "Resolved"
  | "False Positive"
  | "Closed"
  | "Archived";
export type Investigation = {
  id: string;
  analysis_id: string;
  subject: string;
  score: number;
  risk: Severity;
  heuristic_score?: number;
  heuristic_risk?: Severity;
  assessment_method?: Assessment["method"];
  final_assessment?: Assessment;
  source: "Email" | "URL";
  status: CaseStatus;
  notes: string;
  created_at: string;
  updated_at: string;
  analysis: Analysis;
  timeline: { at: string; title: string; detail: string }[];
};
export type Metrics = {
  total: number;
  high: number;
  false_positives: number;
  reports: number;
  trend: { date: string; score: number }[];
  severity: { name: string; value: number }[];
  categories: { name: string; value: number }[];
};
export type Report = {
  id: string;
  filename: string;
  created_at: string;
  url: string;
  case_id?: string;
  analysis_id?: string;
};
