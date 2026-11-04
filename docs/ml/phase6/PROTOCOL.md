# Phase 6 prespecified reliability experiment

Frozen before fitting Phase 6 candidates or calculating any new final prediction. Old Phase 4 and Phase 5 evaluations are observed development evidence. Exactly three new candidate pipelines are permitted; failed admission ends this phase's training search and the remaining portfolio preparation proceeds.

## Data and independence

Use actual subject/body text only. Existing CC BY licensed Nazario/ham/MASC rows may support development. All University scam rows remain diagnostic/overlap-control only and never fit weights or calibrators. Add only original benign label 0 from the MeAJOR v2 curator release (CC BY 4.0); exclude every merged spam/phishing label 1 and the malformed blank record. Source/sender rights are inherited, labels historical and anonymization changes the text distribution.

Before grouping, cap new MeAJOR benign rows by label-blind normalized text SHA order: TREC-05 4,000 for development, TREC-06 3,000 for source-held-out selection validation, TREC-07 6,000 reserved for final evaluation. Add up to 6,000 hash-selected former CEAS ham rows to development. Previously fitted/observed Phase 4/5 rows remain in joint overlap controls even if not eligible for fitting. No new final row is used for vocabulary, calibration, threshold selection or candidate selection.

The Phishing Pot snapshot is pinned at commit `80a486701223f31e5c641024d6e45f2663f1b2cb`. Select the first 400 commit/path SHA-ordered .eml files with size at most 1,000,000 bytes, before content review or predictions. Verify every Git blob. A model-blind content review assigns language and separate strict phishing, financial scam, generic spam, malware-only, uncertain/unreadable categories. English apparent credential/payment-deception rows form the strict new-curator phishing subset; broad financial scams are a separately named stress, never silently narrow phishing. All exclusions/counts remain reported. Single-assistant content annotation is not expert consensus or proof of malicious infrastructure. No destination is visited. The CC BY-NC 4.0 collection is final local noncommercial evaluation only, never fitted into distributed weights or redistributed as raw mail.

Pretraining data-quality addendum: the fixed 400-file Pot sample contains relatively few clear English phishing messages, before any prediction is inspected. Add the previously unused author-licensed Nazario 2019 mailbox (243 raw emails, SHA256 `cab39d6fcb38cf80cdaabb3e6ffd1222777e2fcaac7e8480321b7f729c2e3c0e`) as a **separate supplementary strict-phishing stress**. It never enters fitting or selection, and cannot replace the primary new-curator result. This shares the training curator and predates some development mail; it does not establish new-curator or future-time generalization. Publish wide intervals and limited power rather than enlarging the primary subset based on favorable scores.

Joint grouping uses harmonized canonical text, full-message Jaccard >=0.90, body-template Jaccard >=0.80, meaningful normalized subject/thread identity, retained prior global constraints, and offline registered domains observed in 2..25 distinct rows. Preserve all transitive connections. Remove all fitting/validation rows touching final components, and remove final rows related to any previously observed/fitted Phase 4/5 component. Conflicting labels are quarantined. All groups are formed without model outcomes. Bound comparisons and fail closed if exceeded. These lexical controls cannot establish that every semantic campaign is unrelated.

## Development roles

Reserve all TREC-06 benign rows and Nazario 2022/2024/2025 positives for source/era-held-out selection validation. Also reserve deterministic hash-selected 20% of other development components for validation to observe multiple legitimate sources. Remove fitting/calibration components touching those reserved validation components. Within the remaining pool, use five stratified group folds with seed 20261103: fold 0 internal diagnostic test, fold 1 sigmoid calibration, folds 2..4 vocabulary/base fitting. Never refit on validation or final rows. Publish all role memberships as hashes, sources, labels and group identities.

## Three justified candidates

1. Word TF-IDF 1–2 grams (40,000 features), unweighted Logistic Regression C=0.25.
2. Word plus character-within-word TF-IDF 3–5 grams (40,000 character features), unweighted Linear SVM C=0.25.
3. The same union SVM with balanced class weights as the sole weighting ablation.

Use min_df=3, sublinear TF, fixed random seed and bounded 16,000-character input. A new versioned inert normalization removes only six known invisible format characters, harmonizes real URL/email literals and anonymization placeholders, and removes other known entity placeholders consistently across all inputs. Preserve scripts and Spanish diacritics; no global homoglyph transliteration. Omit explicit word/character counts, non-ASCII fractions and other structure branches. This is a measured response to observed source associations, not an assertion that every old error had one cause. Do not modify old feature code or trained artifacts.

Fit a regularized C=1 sigmoid on the separate calibration partition. Keep archive decision-score wording; no deployment-confidence claim. No new hybrid search is run: Phase 5 found no independently admitted combination. Existing heuristics remain unchanged and are evaluated separately at High >=60 and review >=25.

## Thresholds, selection and final admission

For each candidate, maximize validation phishing recall under pooled empirical benign FPR <=1% and Wilson 95% upper FPR <=2%. Require the same two bounds for every validation benign source with at least 200 examples; smaller sources are reported as insufficient for this bound, not declared safe. Ties prefer fewer pooled false positives, higher precision, proximity to 0.5, then deterministic candidate name. Publish infeasible/zero-recall results. Selection among these three uses validation recall, lower pooled FPR, lower validation logloss and name. Freeze all three artifacts/thresholds and the primary selection before final scoring.

Report every serious frozen candidate on the final corpus, but only the prespecified primary selection is eligible for admission. Do not switch to another candidate because its final F1 or threshold looks better. Compare original English baseline, inactive rejected Phase 5 candidate, each Phase 6 model, and complete routing/fallback pipelines. Compare archived v2 and new format-only v3 routing separately. A rejected artifact may be loaded only by the explicit offline evaluator after checksum/code verification, never by ordinary runtime.

Primary admission requires complete-pipeline strict-phishing recall improvement of at least 5 percentage points over the retained baseline, empirical final FPR <=1%, Wilson upper FPR <=2%, and FPR increase <=0.5 percentage points. All meaningful final benign-source subgroups with n>=200 must meet the same FPR bounds. Preserve previously supported Spanish diagnostic routes and test mixed/unsupported/short/obfuscated behavior. An admitted model would still be limited research, not production-ready or a source of verified inbox probabilities. Failed admission preserves the original active English model as experimental and retains new artifacts inactive.

## Required reporting

Record accuracy, precision, recall, F1, FPR, FNR, confusion matrix, average precision and trapezoidal PR-AUC, ROC-AUC, Brier, logloss, ECE, calibration bins, per-source counts and model-only versus end-to-end results. Publish row-wise Wilson 95% intervals and source-stratified group-bootstrap intervals (400 fixed-seed resamples) for operating metrics; note small/biased source collections and campaign uncertainty. Abstentions are never counted as correct predictions. No routing score is confidence, no low model or heuristic score verifies safety, and no metadata-only attachment inspection is malware scanning.

Once final results are observed, do not retune this corpus or describe it as untouched again. Publish failures, preserve originals, complete tests, screenshots, reports, security audit and sanitized GitHub preparation. No commit, push or deployment is authorized.
