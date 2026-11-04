# Phase 6: evidence behind the English reliability failures

The preserved English classifier and the rejected Phase 5 classifier are genuine trained models. Their strong internal scores did not establish reliable performance on unfamiliar sources. This report separates measured failures from explanations that remain hypotheses. All Phase 4/5 external data discussed below are **already observed development evidence** for Phase 6; none can provide a fresh independent improvement claim again.

## Source membership remains a near-perfect substitute for labels

Phase 4 trained English phishing from Nazario and legitimate messages from Enron, Ling and Assassin. Its reported source-only diagnostic reached 100% internal accuracy without examining email content. Withholding Enron in its development probe increased validation FPR from 1/642 to 27/642. Learned negative terms included `enron`, `2001` and `2002`; positive terms included older brands/years. These are measured source/era associations, not proof that every resulting decision is caused by those tokens. The detailed Phase 4 evaluation stays in the local research archive.

Phase 5 increased the source count but did not remove label/source confounding. Its fitting partition contains 14 named sources, each with only one label; every internal test source is already represented in fitting. A lookup that learns each source's majority class from fitting metadata alone classifies all 998 internal test records correctly: `[[874,0],[0,124]]`, accuracy/F1 1.0. The source identifier is not a proposed application feature. This deliberately artificial diagnostic demonstrates how an internal benchmark can be solved without learning phishing semantics. The exact split hash and calculation are recorded in [source-confounding.json](source-confounding.json).

Campaign-group-disjoint random partitions still share collection families, era, vocabulary, formatting and label policy. They answer whether related rows were separated under the grouping rules; they do not answer whether a model transfers to a new curator or legitimate-mail environment. More rows or more mailbox years from one positive curator alone cannot resolve that problem.

## Structure features dominate margins; the useful contrast is FP versus TN

The selected Phase 5 pipeline adds standardized text-structure features to word/character TF-IDF. The fixed error audit on all 9,682 then-held-out rows contains 641 model-only ham false positives, 4,359 true negatives, 1,391 positive false negatives and 3,291 true positives. Routing subsequently reduces the number of pipeline false positives to 566; those are different denominators/decision paths, not altered labels.

| Mean pre-sigmoid feature contribution | Ham false positives | Ham true negatives | Interpretation |
|---|---:|---:|---|
| Non-ASCII fraction | +5.393 | +0.081 | Strong measured contrast associated with false positives |
| Log word count | +5.955 | +5.975 | Large in both groups; magnitude alone does not distinguish errors |
| Mean word length | +4.450 | +4.090 | Positive in both; modest FP/TN difference |
| Log character count | -11.584 | -11.515 | Large cancellation in both groups |

Among missed positives, mean log-character-count contribution is -9.260 and unique-word fraction is -0.534. The branches' standardized numerical features contribute much larger absolute terms than most individual TF-IDF terms and can cancel each other. It would be incorrect to say that a large positive word-count contribution *caused* all false positives: its FP and TN means are almost identical. Non-ASCII contribution differs much more sharply. These are learned linear associations before calibration, not causal interventions, malware evidence or independently verified phishing indicators. The detailed Phase 5 feature audit stays in the local research archive.

This evidence justifies testing a representation without the entire explicit length/non-ASCII/ratio branch. It does not justify changing a threshold to make the observed CEAS errors disappear or declaring all Unicode text suspicious. Word/character text can still encode formatting or source shortcuts, so removal must itself be evaluated under source-separated controls.

## Training diversity and label definitions limit what the metrics mean

Phase 5 fitting had 4,370 ham and 618 phishing messages. Of those fitting ham messages, 3,280 came from Figshare Enron; only 21 were MASC-Enron and 17 MASC-W3C. Its validation ham was similarly dominated by the same older source families. A wholly new legitimate source was therefore a demanding and necessary false-positive stress, not an interchangeable sample from the fitted distribution.

The primary Phase 5 positives are university-archived **scam** messages, including job and financial lures. They are not uniformly narrow credential-phishing labels. The strict Nazario 2023 subgroup is reported separately. CEAS ham annotations and MASC routine-mail genre labels are inherited corpus annotations, not modern independent security adjudications. Some legitimate mail discusses passwords, payments or account recovery; such vocabulary is not sufficient evidence of a malicious request. Generic spam positives must remain excluded rather than silently relabeled phishing.

The rejected classifier's primary raw-model recall is 69.14%, versus 96.45% on the strict-phishing subgroup, but its raw ham FPR is 12.82% on the same 5,000 CEAS messages. This shows that task/source composition affects apparent performance. It does not identify which source labels are wrong or establish a corrected ground truth. No source disagreements were relabeled according to model predictions. The historical Phase 5 data provenance and evaluation document these boundaries in the local research archive.

New anonymized data can introduce another source marker. The Phase 6 English representation therefore harmonizes the same explicit entity-marker list on **every** source and inference input. `[URL]` and actual URL literals map to `urltoken`; `[EMAIL_ADDRESS]` and literal email addresses map to `emailtoken`; other known entity placeholders are removed. The transformation does not consume labels. This reduces a documented availability shortcut but cannot prove source independence or remove every source cue. Literal evidence is retained by the unchanged parser and heuristics.

## Threshold and calibration transfer both failed

On the primary Phase 5 source stress, the original baseline plus repaired routing has 23.34% recall, 1.62% FPR and F1 0.3731. The rejected candidate plus the same routing has 66.18% recall, 11.32% FPR and F1 0.7402. The higher F1 is not operational admission: the candidate exceeds the frozen 1% empirical FPR, 2% Wilson-upper-bound and allowed FPR-increase constraints. Preserving the baseline is also not a claim that its 1.62% FPR meets the new desired limit.

The selected Phase 5 threshold, 0.291513116021574, was chosen only on validation. It produced 8/874 validation ham false positives and 124/124 detected positives. The internal test was strong, `[[871,3],[2,122]]`, yet failed to transfer. A threshold validated only against familiar sources cannot guarantee the same FPR on a new one. Lowering it on an already observed external set would be development tuning, not independent validation.

The candidate's primary raw-score Brier/ECE/log loss are 0.1837/0.1729/0.8076, versus baseline 0.3304/0.3410/1.5166. These relative improvements coexist with excessive false positives and do not establish deployment probabilities. Phase 4's calibration mixture also differed substantially from fitting/test class balance. Curated evaluation prevalence, historical content, source confounding and unknown real-inbox prevalence prevent a representative calibration claim. A fitted sigmoid is a procedure, not confidence that a particular message is malicious. Current results must remain labeled decision scores.

## Routing loss is real, but it is not the entire model problem

On the old Phase 4 external set, the raw classifier missed 439 of 722 phishing messages. Routing suppressed a further 77 raw model-positive messages, reducing detected positives from 283 to 206. Thus routing explained an additional avoidable loss; it could not explain the 439 raw classifier misses. The Phase 5 route repair recovered bounded coverage without solving English classification.

Phase 5's targeted eight-row language review confirmed five wrong assignments: two technical English messages were labeled Latin, two format-obfuscated English messages Irish, and one English message with invisible/lookalike characters Chinese. Two genuine Spanish messages and one Chinese message also demonstrate why forcing every English-source record to English would invent language labels. This intentionally enriched audit cannot estimate global language accuracy.

The new `language-format-v3` wrapper keeps the Phase 5 bounds, all 97 identifier languages, meaningful-window policy and uncertainty/mixed fallbacks. It removes only soft hyphen, zero-width space/nonjoiner/joiner, word joiner and BOM from inert text. It does **not** remove Spanish accents or transliterate Cyrillic/lookalike scripts into English. The archived v2 module and original model preprocessing remain unchanged.

| Already observed parsed corpus | Phase 5 expected-language routes | Phase 6 routes | Previously supported expected routes lost |
|---|---:|---:|---:|
| English original internal test | 969/984 | 969/984 | 0 |
| English old external | 778/802 | 779/802 | 0 |
| Spanish original test | 129/139 | 130/139 | 0 |

The Spanish corpus additionally has two previously reviewed English-dominant messages still selecting English; total supported routing changes 131/139 to 132/139. These are observed applicability diagnostics, not a fresh Spanish classifier evaluation. All watched original models/code stayed unchanged during the [frozen routing comparison](routing-development-frozen.json). Earlier pre-entity-harmonization and pre-punctuation-harmonization runs are retained rather than overwritten; their routing counts are identical. URL/email sentence punctuation is preserved consistently for literals and anonymized markers, preventing a marker-availability punctuation shortcut.

Rechecking the exact eight already reviewed Phase 5 examples repairs both Irish-to-English format failures. The two technical English examples remain incorrectly Latin. The mixed-lookalike English example changes Chinese to Latin and still uses unsupported fallback. Both genuine Spanish examples and the genuine Chinese example retain their correct paths. Thus two of five known wrong assignments are repaired and three remain; this is **not** an overall error-rate claim. Six format-obfuscation software fixtures and other supported/unsupported/mixed/short/failed-identifier checks also pass; synthetic fixtures do not measure classifier accuracy.

## Campaign controls reduce observed overlap but have limits

Phase 5 jointly grouped canonical duplicates, normalized subjects, full-text/body near-duplicates and bounded rare-domain relationships. Both candidate-development/final and baseline-original/final component intersections were zero. This is evidence that the implemented controls separated those known relations. It does not prove that every paraphrased campaign, provider/footer relationship or semantic template is unrelated. Domain sharing alone is also not proof of leakage: legitimate brand/provider links can occur across otherwise unrelated messages.

Any Phase 6 final corpus must be newly frozen, excluded from fitting/calibration/threshold selection, and checked against **all** already observed sources and preserved model exposure. The prior external sets are now development evidence. Source-held-out evaluation and lexical campaign exclusion answer different questions; both should be reported. Row-wise Wilson intervals assume independent rows and can remain optimistic under campaign correlation. Per-source denominators and intervals must accompany pooled metrics; small sources cannot justify a tight population-FPR claim.

## Focused experiment and limits of the explanation

The justified small experiment is: word TF-IDF with unweighted Logistic Regression at C=0.25; normalized word+character TF-IDF with unweighted Linear SVM at C=0.25; and the same SVM with balanced weighting as the explicit class-weight ablation. These compare stronger regularization, a character representation and class weighting without searching dozens of pipelines or reusing the failed explicit structure branch. Exact fitted settings and selection policy belong in the frozen Phase 6 protocol/results, not an after-the-fact explanation.

The active original English classifier and rejected Phase 5 artifact must remain frozen comparisons. Vocabulary and classifiers fit only designated fitting rows, sigmoid fitting is separate, and thresholds use validation alone under declared FPR controls. Source-separated development checks and diverse legitimate messages are more informative than another random split from the same source mixture. A new independent final set is used once for the fixed comparisons; failed admission leaves the existing experimental fallback active. No arbitrary rule/ML weights are warranted by this diagnosis.

**Supported:** source/label confounding; measured source-out errors; dominant and contrasting feature contributions; label/task differences; calibration/threshold transfer failure; specific routing losses and bounded format repairs. **Still uncertain:** causal contribution of each feature/source to each error; true label noise; all hidden semantic campaigns; representative inbox prevalence, calibration and future-source performance. The Phase 6 experiments test these hypotheses; this report does not assume that their proposed remedies will succeed.
