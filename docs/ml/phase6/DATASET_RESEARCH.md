# Phase 6 dataset research and selection

Research date: 3 November 2026. This document records source and permission evidence before Phase 6 final-model scoring. It is a data-selection record, not an accuracy claim or legal clearance of every original sender's rights. Final prepared counts, exclusions and hashes belong in `DATASET_PROVENANCE.md` and the frozen preparation audit.

## Selected new evaluation source: Phishing Pot

The [maintainer's dataset card](https://github.com/rf-peixoto/phishing_pot/blob/80a486701223f31e5c641024d6e45f2663f1b2cb/DATASET_CARD.md) explicitly applies **CC BY-NC 4.0 to the dataset**, including noncommercial machine-learning research. The [pinned top-level license](https://github.com/rf-peixoto/phishing_pot/blob/80a486701223f31e5c641024d6e45f2663f1b2cb/LICENSE) agrees. This is data-specific permission, rather than assuming a software license covers raw mail. The maintainer describes samples from controlled or long-observed addresses, including honeypot collection. Attribution must link [the repository](https://github.com/rf-peixoto/phishing_pot) and [the maintainer](https://www.linkedin.com/in/rf-peixoto).

Use is restricted to **local noncommercial final evaluation**. Do not fit a deployable classifier on these messages, package raw messages, republish personal details, or imply commercial permission. Collection bias, campaign repetition, multilingual content and mixed phishing/spam/fraud/malware labels prevent treating every file as a verified strict-phishing example. Freeze model-blind manual label review before inference; disclose single-reviewer limitations. This is a newly used curator, not a representative inbox sample.

The [official pinned Git tree](https://api.github.com/repos/rf-peixoto/phishing_pot/git/trees/80a486701223f31e5c641024d6e45f2663f1b2cb?recursive=1) contains 12,864 `.eml` blobs totaling 1,576,217,980 bytes; 12,842 are nonempty and meet the actual acquisition cap of 1,000,000 bytes. The API reports `truncated=false`. These are file counts, not unique English phishing counts. Commit `80a486701223f31e5c641024d6e45f2663f1b2cb` is dated 28 October 2026. It is pinned rather than tracking mutable `main`.

The reviewed card is 5,425 bytes, Git blob `6710b36124e7450d6956df2340dbb47a45145192`; license is 19,347 bytes, blob `fe463e0f7888bbf8b82e42d55f5743508ddafb7e`. Acquisition verifies Git blob identity and records SHA-256 of each chosen file. The actual acquisition is 400 files from the fixed label-blind hash order under the decimal 1,000,000-byte cap; downloading the entire roughly 1.58 GB message tree is unnecessary. Earlier 512 KiB and 1 MiB research descriptions were not the executed sampling policy.

### Annotation policy fixed before model scores

Review inert decoded subject/body and static header/link context. Do not open destinations, execute attachment bytes or render active HTML. Record every sampled item's inclusion or exclusion, including unreadable/empty mail, unsupported language, mixed language, generic advertising spam, malware-only lures and ambiguous cases. Do not infer strict phishing merely from credential keywords or a repository filename. Retain clear apparent credential/payment deception as the strict-phishing subset, with hashed identifiers and concise categorical reasons; do not publish raw excerpts or sensitive addresses. Apparent intent is a reviewer judgment, not independently verified destination maliciousness or expert consensus.

The complete preselected sample can support an explicitly broader malicious/unsolicited stress description where appropriate. The strict reviewed subset must be reported separately. Neither sample membership nor annotations may depend on classifier scores or outcomes.

## Selected new ham source: anonymized MeAJOR v2.0

The [authors' Zenodo release](https://zenodo.org/records/18471483), DOI `10.5281/zenodo.18471483`, provides anonymized email text, source and labels. Official [record metadata](https://zenodo.org/api/records/18471483) explicitly declares `cc-by-4.0`. Cite Francisco Cardoso, João Vitorino, Paulo Mendes, Eva Maia and Isabel Praça. The version is 2.0, published February 2026. Its full 108,685 examples merge TREC-05/06/07, Nazario and Nigerian Fraud; that total is not the eligible ham count.

Only **original benign label 0** is eligible here. Discard all label 1 examples: source spam labels cannot be silently equated to phishing. Keep source identifiers to reserve TREC-07 ham for new final evaluation and use TREC-05/06 ham for development diversity. Ignore supplied engineered features and parse bounded subject/body only. Standard bracketed entity-removal tokens and historical collection eras differ from ordinary inbox text; disclose that distribution shift and inherited annotation uncertainty. The curator's CC BY release does not independently re-clear every original sender's rights. Raw TREC acquisition has separate agreement requirements and is not authorized by pretending a code license applies.

The reviewed CSV is `meajor_cleaned_preprocessed.csv`, **191,121,228 bytes**, publisher MD5 `aa8f59e96787cbd696c0b650e5400dc9`. Fixed [download](https://zenodo.org/api/records/18471483/files/meajor_cleaned_preprocessed.csv/content). Read as inert data; never execute accompanying dataset code. Record a SHA-256 after retrieval and verify source/class counts from the actual snapshot. Keep raw and prepared mail out of GitHub artifacts.

## Previously observed development sources

The Phase 4 main/external and Phase 5 development/final sets have influenced prior decisions. They are now **observed development evidence**, never an untouched Phase 6 final test. Licensed Nazario phishing and curator ham from Enron/Ling/Assassin/CEAS can augment development, with source labels retained. Do not fit University Scam Corpus data into distributable weights: its CC BY-NC-SA terms and broader scam labels remain separately documented; retain it as observed diagnostic evidence only.

The [Figshare authors' release](https://figshare.com/articles/dataset/Seven_Phishing_Email_Datasets/25432108), DOI `10.6084/m9.figshare.25432108`, declares CC BY 4.0 in its official API metadata. Previously acquired label-0 CEAS includes 17,312 ham rows before exclusions; Phase 5 scored 5,000 after overlap control. All former evaluation rows are observed now. Exclude every generic-spam positive and document inherited labels and original-source rights limitations. The [TREC 2006 primary overview](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication500-272.pdf) describes public English ham from web-crawled mail, underscoring that source-specific acquisition and historical formatting can matter.

## Alternatives examined and not used as new independent sources

| Source | Permission/label findings | Decision |
|---|---|---|
| [SpamAssassin original public corpus](https://spamassassin.apache.org/old/publiccorpus/readme.html) | The author offers mail for testing filtering systems and retains copyright with original senders. Software Apache licensing is not raw-mail licensing. Published ham counts are 2,500 easy, 250 hard and 1,400 easy-ham-2. | Local offline evaluation permission is explicit, but do not infer unrestricted redistribution/training rights. Existing Figshare-Assassin training already uses this underlying collection; new native copies would not be a wholly independent curator. |
| [Original TREC collections](https://trec.nist.gov/data/spam.html) | Direct raw acquisition has a usage agreement; public availability is not blanket reuse permission. Spam is not synonymous with phishing. | Do not download raw TREC or claim agreement acceptance. Use only the expressly licensed anonymized curator release above, with inherited-rights limits disclosed. |
| [CSDMC2010 third-party formatting repository](https://github.com/zrz1996/Spam-Email-Classifier-DataSet) | Its MIT license covers a formatting-code repository; no primary data-specific license was verified. | Not selected. Do not rely on a repository license to clear upstream email text. |
| [E-PhishGen](https://huggingface.co/datasets/pajola/e-phishGen/blob/main/README.md) | The authors describe generated English/Italian emails; software/data availability does not make them actual inbox mail. | Not a primary real-email independent benchmark. |
| [Enriched phishing communications features](https://data.mendeley.com/datasets/dbb83x5nzy/1) | Author release is CC BY 4.0, but derives from an unspecified Kaggle mixture and provides engineered features. | Not a genuinely new raw-email source with compatible text/label provenance. |

## Leakage and final-boundary requirements

Joint canonical, body-template, subject/thread and conservative rare-domain groups must connect old baseline data, all development rows and new reserved final rows **before fitting**. Anonymization can hide overlaps: normalize generic entity tokens consistently for cross-corpus comparison and report its bounds. Remove final components related to data used by either retained baseline or the rejected Phase 5 candidate, so comparisons do not benefit from historical training exposure. Remove candidate-development components touching reserved final components. Report exact counts and intersections; bounded lexical grouping cannot prove all semantic campaigns are unrelated.

Freeze selected source versions, sample IDs, annotations, preparation exclusions, data hashes, validation-only threshold rules and candidate settings before final inference. Once final results are observed, do not retune on that set and call it independent again. No raw messages, attachments, recipients, local databases or private backups belong in the portfolio release.
