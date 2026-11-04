# Model-blind Phishing Pot review

Before any Phase 6 final-model inference, one assistant reviewer examined all **400 prespecified, hash-sampled files** from pinned Phishing Pot commit `80a486701223f31e5c641024d6e45f2663f1b2cb`. The executed sample excludes empty files and files above 1,000,000 bytes. It was not selected by predicted class, model score or whether an email looked easy. [DATASET_RESEARCH.md](DATASET_RESEARCH.md) documents permission and acquisition scope.

The repository is a mixed collection, so membership alone was not accepted as strict-phishing ground truth. The reviewer read inert subject/body and static link context. No submitted destination was visited, attachment executed, active HTML rendered or classifier scored. Long random padding and malformed/incomplete message extraction were retained as explicit exclusions rather than assigned invented intent. URL hostname mismatch is contextual evidence, not independent proof that a remote site is malicious.

## Initial annotation counts before second review

| Reviewer category | All sampled files | Readable English category count |
|---|---:|---:|
| Apparent strict credential/payment deception | 61 | 29 |
| Generic promotional/spam content | 147 | 71 |
| Financial windfall/advance-fee/investment scam | 23 | 13 |
| Legitimate or insufficiently established intent | 42 | 32 |
| Unreadable or insufficient substantive content | 127 | 10 |
| Malware-only category (payload unverified) | 0 | 0 |
| Total | 400 | 155 |

Manual language categories are 155 English, 144 other-language, seven substantially mixed and 94 uncertain. Obfuscated English remains English when its actual wording is readable; mixed Unicode scripts do not by themselves establish multiple real languages.

All 29 initial English strict-phishing judgments received complete bounded-content review. Across all categories, 285 files had a complete review. The 115 remaining items were ineligible for strict English evaluation.

Model-blind second-review disagreements were recorded before data freezing. Preparation then applied deduplication and historical-overlap exclusions.

## Interpretation limits

These labels are **single-assistant judgments, not expert consensus or verified malicious-destination ground truth**. Apparent strict phishing includes account-security impersonation, wallet-seed/identity verification and payment/callback deception. Financial windfalls are separately categorized. Generic promotions may include legitimate subscribed marketing; neither those messages nor unknown cases become benign evaluation examples.

After second review, only 24 of the 400 files remain clear, fully reviewed English strict-phishing candidates, and multiple files repeat the same Microsoft-alert campaign. That small, selectively interpretable subset cannot establish broad inbox recall. Report actual post-deduplication sample/group counts and wide confidence intervals. Excluding ambiguous, non-English and poorly extracted messages changes the task distribution; it must not be advertised as coverage of the whole repository. Zero malware-only labels means no payload verdict was available, not that no malware exists in the source.

No annotation or inclusion decision used Phase 6 predictions. This corpus is local noncommercial evaluation under CC BY-NC 4.0, not training material for redistributed weights. Raw files, private annotations and excerpts remain outside source/review release packages.

## Pre-score second review and final eligible labels

A second assistant reviewed the 29 initially included English judgments. The original reviewer reread the disputed cases with full inert message context. Four moved to the unknown category and one to broader financial scam. The review assessed apparent intent. It provides neither expert consensus nor verified destination labels.

| Category | Final sample count | English count |
| --- | ---: | ---: |
| Apparent strict phishing | 56 | 24 |
| Generic promotion | 147 | 71 |
| Financial scam | 24 | 14 |
| Legitimate or unknown intent | 46 | 36 |
| Unreadable | 127 | 10 |

All 24 English strict-phishing cases and 11 of the 14 English financial-scam cases had a complete review. Removing duplicate or previously observed campaign components left 19 strict-phishing cases and seven financial-scam cases. These subsets answer separate evaluation questions. Unknown cases remain excluded. [Dataset provenance](../../../DATASET_PROVENANCE.md)
