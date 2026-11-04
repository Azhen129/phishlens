# Local model inference contract

The complete local Phase 6 registry selects the unweighted English SVM `email-source-text-v6-609bba638c1d` for limited research use. The original Spanish and hostname URL models retain their documented scopes. The Phase 4 English baseline remains experimental, and the Phase 5 candidate remains rejected. The public source package starts with rules only. [Evaluation](../../MODEL_EVALUATION.md)

## Trusted loading and version selection

`backend/ml_runtime.py` loads the original model directories by default. The complete local review registry selects the admitted English version through `active-models.json`. The selector accepts one `email_en` key and a versioned Phase 5 or Phase 6 directory inside the trusted root. Invalid selection uses heuristic fallback. Uploads and API inputs cannot select artifact paths.

Before deserialization, loading checks artifact SHA-256, expected kind/format, manifest validation and historical calibration status, supported languages, installed scikit-learn version, shared feature version/code identity, matching metrics and bounded thresholds. Versioned structure-feature code is also hash-checked before pickle loading. Missing, corrupt, incompatible, unvalidated or failed models preserve heuristic fallback. The rejected Phase 5 model cannot be loaded merely by placing its directory in a selector. Phase 6 requires separate hash-bound admission metadata and checks its threshold against the loaded bundle.

A checksum detects corruption; it is not a signature against a local administrator replacing both manifest and artifact. Only trusted project-owned joblib files are accepted. A local cache and lock protect repeated loading; the cache identity includes the selected path, metadata/artifact changes and relevant feature-code files. Restart the API after intentional local code or release-note changes.

## Input scope and language routing

The original parser and security heuristics remain in place. `inspect_email(..., use_ml=False)` and `inspect_url_submission(..., use_ml=False)` bypass ML for offline rule extraction. Ordinary email inference receives a decoded subject and inert preferred body. Model input is bounded to 16,000 email characters or 8,192 URL characters. URL features use the hostname only; complete-URL heuristics remain separate. Inference never fetches destinations, resolves DNS, runs scripts, opens attachments or calls external services.

`backend/language_routing_v3.py`, version `language-format-v3`, uses all 97 offline langid languages. It prepares inert HTML/NFKC text and removes six known invisible format characters. The v2 router remains available for historical comparisons. The full message needs at least 40 letters and eight words, with an internal identification score of at least 0.90. Up to 12 disjoint meaningful windows check for substantial competing-language text. A competing language needs at least 80 letters, 16 words, 20% of considered letters and an internal window score of at least 0.95. These internal gates are language applicability signals, never phishing confidence.

Supported English selects `email_en`; supported Spanish selects `email`. Short, uncertain, mixed or unsupported inputs receive an explicit reason and heuristic fallback. Missing English never uses Spanish. Responses include `detected_language`, `language_routing_status`, `language_routing_version`, scope limitations and a selected model key when applicable. A loaded model and an applicable prediction are different states.

On the observed Spanish diagnostics, the v3 route selected Spanish for 130 of 139 messages. Two reviewed English-dominant messages also selected English, giving 132 supported routes. All previously supported expected-Spanish routes were retained. The targeted language review used a deliberately enriched sample. Technical and mixed-script text still caused errors. [Routing evidence and limitations](phase6/ROOT_CAUSES.md)

## Decision scores and assessment semantics

New API/UI/PDF results label values as **archive decision scores**, not confidence or verified inbox probabilities. `decision_score` and `score_type="archive_calibrated_decision_score"` expose the current meaning. `probability_validated_for_deployment=false` is explicit. Legacy `phishing_probability` fields remain numerically compatible, and `calibrated:true` describes historical sigmoid fitting and archive evaluation only. It does not assert representative contemporary calibration.

The Phase 6 English SVM meets the frozen limited-use gates on the primary holdout. It detected 16/19 reviewed phishing messages, with 17 false positives among 5,801 legitimate messages. The sample covers 10 lexical campaign groups, and recall uncertainty is wide. `classifier_decision` describes the documented use decision. Legacy saved objects can omit the field. [Evaluation](../../MODEL_EVALUATION.md)

`analysis.score`, `risk`, `summary` and `evidence` retain their original heuristic meanings. `heuristic_score`, `ml` and `assessment` remain separate. ML classification uses its stored, unrounded threshold; the displayed rounded score never determines the class. Final assessment records method, score semantics, threshold, version and limitations. The primary ring remains heuristic points. A low score or legitimate prediction never verifies safety or negates observed evidence.

Learned combinations, when eligible, use `[logit(base archive score), heuristic_score/100]`, with separate fitting and calibration partitions. No arbitrary score weights are assigned. Phase 5 measured their internal performance but admitted none independently. All active choices remain ML-only.

## Saved results, reports and bounds

Analyses, investigations and report snapshots retain the metadata captured at submission. Reads never reclassify old results or rewrite notes/statuses. Historical results lacking current fields keep their prior semantics and PDF renderer path. New PDFs distinguish archive decision score, heuristic points, final decision, model version, routing scope and limitations. UI model status reports actually loaded artifacts; a saved result displays its own captured version.

New case risk records its stored final assessment, while case score remains rule points and heuristic risk stays separate. Model failures and unsupported languages retain deterministic heuristic assessment. Artifact size is bounded at 64 MiB, ordinary manifest JSON at 2 MiB, active selector at 16 KiB and release notes at 64 KiB. These limits and fixed linear feature pipelines are resource controls; they do not make malicious model serialization safe.
