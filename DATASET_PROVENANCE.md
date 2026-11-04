# Dataset provenance

PhishLens trains email classifiers on decoded subjects and bodies. Source labels establish the benchmark categories. Source identifiers support split design and error analysis. They are absent from model inputs, along with transport headers, attachments, and supplied engineered features. The URL model uses the hostname from the submitted string. Synthetic fixtures exercise application behavior only.

## Phase 6 sources and permission

| Source | Release and credit | Phase 6 use | Primary records |
| --- | --- | --- | --- |
| MeAJOR 2.0 | Francisco Cardoso, João Vitorino, Paulo Mendes, Eva Maia, and Isabel Praça. CC BY 4.0 curator release, DOI `10.5281/zenodo.18471483`. | Original benign `0.0` rows. TREC-05 contributes to the development pool, TREC-06 to source-held-out selection, and TREC-07 to final evaluation. The anonymized curator release carries inherited source and sender rights. | [Zenodo record](https://zenodo.org/records/18471483) · [License metadata](https://zenodo.org/api/records/18471483) |
| Phishing Pot | Maintainer `rf-peixoto`. Dataset-specific CC BY-NC 4.0 at commit `80a486701223f31e5c641024d6e45f2663f1b2cb`. | Local noncommercial final evaluation of reviewed apparent phishing and separate financial scams. | [Repository](https://github.com/rf-peixoto/phishing_pot) · [Maintainer](https://www.linkedin.com/in/rf-peixoto) · [Pinned dataset card](https://github.com/rf-peixoto/phishing_pot/blob/80a486701223f31e5c641024d6e45f2663f1b2cb/DATASET_CARD.md) · [Pinned license](https://github.com/rf-peixoto/phishing_pot/blob/80a486701223f31e5c641024d6e45f2663f1b2cb/LICENSE) |
| Nazario Phishing Corpus | José Nazario. Author CC BY 4.0. | Historical curator-labeled positives. Reserve 2022/2024/2025 for validation and the previously unused 2019 snapshot for a separate final stress. The 2019 mailbox shares the development curator. | [Author archive](https://www.monkey.org/~jose/phishing/) · [License](https://www.monkey.org/~jose/phishing/LICENSE.txt) |
| Seven Phishing Email Datasets | Arifa Islam Champa and Md Fazle Rabbi, CC BY 4.0 curator release, DOI `10.6084/m9.figshare.25432108`. See Champa, Rabbi, and Zibran for the accompanying research. | Inherited ham from Enron, Ling, Assassin and CEAS-08. Original spam positives excluded. Source and sender rights remain inherited. | [Figshare release](https://figshare.com/articles/dataset/Seven_Phishing_Email_Datasets/25432108) · [License metadata](https://api.figshare.com/v2/articles/25432108) |
| Manually Annotated Sub-Corpus (MASC) | American National Corpus Project, CC BY 3.0 US. | Observed Enron and W3C correspondence in the routine email genre. These inherited benign labels describe genre. | [MASC release](https://anc.org/data/masc/) |
| University Scam Emails Corpus | Grace Ciambrone and Shomir Wilson, CC BY-NC-SA 2.0. | Previously observed Phase 5 broad scam examples used for overlap control only. These examples never enter Phase 6 fitting, calibration, selection, or final evaluation. | [Author dataset and terms](https://shomir.net/data/university_scams/index.html) |

The direct TREC corpus has its own usage agreement. Phase 6 uses the anonymized MeAJOR curator release under its documented license. The MeAJOR entity markers, historical collection eras, and inherited ham labels constrain what this benchmark can measure. Dataset release permission leaves original sender rights subject to review. The distribution matrix records the project's decision for each set of weights. [Original TREC terms](https://trec.nist.gov/data/spam.html) · [Dataset research](docs/ml/phase6/DATASET_RESEARCH.md) · [Distribution matrix](backend/models/distribution-phase6.json)

## Acquisition and label review

| Pinned input | Acquired scope | SHA-256 |
| --- | --- | --- |
| MeAJOR CSV | 191,121,228 bytes, publisher MD5 `aa8f59e96787cbd696c0b650e5400dc9` | `5bf5371897ab4e4aa7ac6d8f499869e6c32e4456ed09636731e4069947b69f4f` |
| Nazario 2019 mailbox | 5,211,476 bytes, 243 messages | `cab39d6fcb38cf80cdaabb3e6ffd1222777e2fcaac7e8480321b7f729c2e3c0e` |
| Phishing Pot | 400 verified EMLs, 50,865,503 bytes combined | Pinned repository revision and verified local acquisition |

The MeAJOR snapshot contains 108,685 rows. The original benign counts are 29,929 TREC-05, 11,208 TREC-06 and 19,513 TREC-07. Preparation excluded all 48,034 original positive rows and one malformed blank record. The fixed normalized-text hash caps were 4,000 TREC-05, 3,000 TREC-06 and 6,000 TREC-07 benign rows. Phase 6 also considers a fixed additional sample of 6,000 CEAS-08 ham rows alongside the previously observed CEAS records.

Phishing Pot has 12,864 EMLs at the pinned revision. The 400-file sample was selected by commit/path hash from 12,842 nonempty files of at most 1,000,000 bytes. Two assistant reviewers resolved five disputed English labels before final prediction. The reviewed sample contains 24 fully reviewed English apparent strict-phishing examples and 11 fully reviewed English financial-scam examples before deduplication and overlap removal. Three incomplete English financial-scam records were excluded. The reviewers assessed inert message content and static context. The labels reflect apparent intent, and the source contains repeated campaigns, ambiguous messages, and multilingual material. [Review policy and aggregate counts](docs/ml/phase6/POT_ANNOTATION.md)

The reviewed sample membership, message hashes and annotations remain in the private research workspace. An isolated replay reproduced the parsed MIME input and both prepared CSVs byte for byte. The corpus-level checksums and replay prerequisites are documented separately. [Reproduction guide](docs/ml/phase6/COMMANDS.md)

## Preparation and partition boundaries

The preparer combines the frozen Phase 4/5 observed inputs and the new archives, screens new development inputs for English applicability, quarantines explicit source subject annotations, and deduplicates harmonized canonical text. The audit records 133 new development rows excluded for non-English or uncertain language, nine subject annotations quarantined, and 12,378 exact canonical copies removed. The 37,219 unique rows form 23,272 components after transitive grouping. Groups combine normalized subjects, full-message Jaccard ≥0.90, body-template Jaccard ≥0.80, prior campaign constraints, and shared offline registered domains present in 2–25 rows. The domain step adds 3,669 relations. This controls visible lexical and infrastructure overlap within the declared bounds. Hidden semantic or anonymized relationships can remain.

The preparer removes 202 final rows in components connected to observed Phase 4/5 inputs. These comprise 116 MeAJOR TREC-07 ham rows, 77 Nazario 2019 rows, five Phishing Pot strict-phishing rows and four Phishing Pot financial-scam rows. Development groups that touch a reserved final component are also excluded from candidate development. The measured development/final and previously observed/final component intersections are both zero. The final set retains inherited language labels where there is no independent language adjudication. Routing applicability and coverage are measured separately from those labels. [Frozen preparation audit](docs/ml/phase6/preparation-audit.json) · [Prespecified protocol](docs/ml/phase6/PROTOCOL.md)

| Development role | Benign | Phishing | Total | Groups |
| --- | ---: | ---: | ---: | ---: |
| Vocabulary and estimator fit | 8,948 | 374 | 9,322 | 6,329 |
| Sigmoid calibration | 2,983 | 125 | 3,108 | 2,110 |
| Internal diagnostic test | 2,983 | 125 | 3,108 | 2,100 |
| Source and era selection validation | 6,524 | 827 | 7,351 | 5,489 |
| **Development total** | **21,438** | **1,451** | **22,889** | **16,028** |

TREC-06 supplies 2,912 of the validation ham rows. The total retained development ham also includes 6,537 CEAS-08, 6,421 Figshare-Enron, 3,262 MeAJOR TREC-05, 1,237 Figshare-Assassin, 998 Figshare-Ling, 44 MASC-Enron and 27 MASC-W3C rows. Phishing counts by historical Nazario release and source-specific role assignments are recorded in the frozen provenance and selection record. Group-based roles preserve related messages and yield different class proportions across partitions. [Frozen provenance](docs/ml/phase6/provenance.json) · [Selection and split counts](docs/ml/phase6/selection.json)

| Final subset | Rows | Role |
| --- | ---: | --- |
| MeAJOR TREC-07 ham | 5,801 | Shared benign reference pool |
| Phishing Pot strict | 19 | Primary new-curator strict-phishing test |
| Nazario 2019 | 138 | Supplementary historical strict-phishing stress |
| Phishing Pot financial scam | 7 | Separate broad financial-scam stress |
| **Unique final total** | **5,965** | **4,067 groups** |

The 19 primary positives and repeated campaigns limit precision of the measured recall. Nazario 2019 predates some development mail and tests previously unused messages from the same curator. The final corpus has a curated prevalence and a historical, anonymized benign reference pool. Model calibration and operating-point metrics describe those conditions. [Phase 6 evaluation](MODEL_EVALUATION.md)

The trainer requires a documented permission basis and collection notes before fitting. The reviewed preparation and partition rules were frozen before training.

## Retained Spanish and URL provenance

The Spanish classifier uses Bustio-Martinez et al.'s SpaPhish v5, DOI `10.17632/hz2d6gz7pc.5`, CC BY 4.0. The acquired release contains 1,395 real anonymized Spanish emails, 664 legitimate and 731 phishing. PhishLens selects native subject/body and excludes supplied annotations and metadata from input features. [SpaPhish v5 release](https://data.mendeley.com/datasets/hz2d6gz7pc/5) · [Dataset attribution and adaptations](docs/ml/dataset-provenance.json)

The URL classifier uses Prasad and Chandra's UCI PhiUSIIL release, CC BY 4.0. It provides 235,795 rows, 134,850 legitimate and 100,945 phishing. The acquisition pipeline inverts the publisher's label convention. The retained model derives only hostname features, and the observed benign HTTPS/path/length artifacts limit the benchmark's practical scope. [UCI release](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) · [Dataset attribution and adaptations](docs/ml/dataset-provenance.json)

## Reproduction and distribution

Acquisition verifies repository hosts, redirects, size limits and checksums. Parsing decodes inert message content locally and never visits message destinations or executes attachments. The release preserves source-level attribution and aggregate results. Corpora, per-message review records, weights and SQLite records stay in the private workspace. [Reproduction guide](docs/ml/phase6/COMMANDS.md) · [Release scope](GITHUB_READINESS.md)
