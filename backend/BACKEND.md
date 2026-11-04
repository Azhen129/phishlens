# PhishLens backend

Run from the project root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-ml.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe -m pytest backend/tests -q
```

`PHISHLENS_DB` selects the SQLite file (default `backend/data/phishlens.sqlite3`). Schema v1 is created idempotently with `PRAGMA user_version=1`; there are no destructive automatic migrations. Stop the API before copying the database plus any `-wal` and `-shm` companions, or use SQLite's online backup API. Data and raw email remain on this computer; no remote provider integrations exist.

The app is designed for a single trusted local operator. Bind to loopback only. It has no remote authentication or multi-tenant isolation. Local Host/Origin checks reject browser requests from unrelated origins and include strict response headers. Request bodies are bounded at 26 MiB; email content at 25 MiB; MIME at 20 levels/200 parts; 1,000 headers, 200 unique HTTP(S) links; extracted body previews at 500,000 characters. Attachments are never opened, extracted, expanded, or written to disk. Their filename, declared MIME, decoded size and SHA-256 are metadata only. Raw email is retained until deleted. Individual scan deletion cascades to its cases and reports; delete-all also checkpoints and vacuums SQLite. Filesystem backups, OS caches, and forensic storage erasure are outside this application's control.

## Scoring

The original `analysis.score` and heuristic scores are deterministic rule points capped at 100, **not probabilities or confidence**. High >=60, Medium >=25, Low <25. ML and final assessment expose separate archive decision scores and their own stored thresholds, described below. Repeated occurrences of the same rule family only contribute the maximum weight once, so duplicate URLs cannot multiply the heuristic score. The evidence array still preserves occurrences for review. A low result means low observed heuristic risk; it never verifies safety.

| Rule family | Points |
|---|---:|
| URL user-info (credentials before @) |22|
| Numeric IP hostname |18|
| HTTP scheme |8|
| IDN / punycode hostname |15|
| >=5 hostname labels |10|
| Encoded separators / nested encoding |12|
| Path+query >250 characters |5|
| >=3 hostname hyphens |6|
| Brand text outside explicit configured brand domains |22|
| Exact one-edit brand hostname label |20|
| Visible URL hostname differs from anchor href hostname |28|
| Reply-To / From domain mismatch |14|
| Claimed brand display name outside configured domains |20|
| Urgency / account-language / service-loss / financial-language |10 / 8 / 10 / 6|
| Supplied authentication failures (always unverified) |8|
| Executable/active extension / macro-capable extension |22 / 12|

The finite brand allowlist and exact one-character comparison are explicit heuristics; they do not establish domain ownership, impersonation or abuse. Generic visible anchor labels such as “Verify account” do not imply a destination mismatch. Supplied Authentication-Results can be forged: all SPF/DKIM/DMARC values say reported and unverified, and missing headers say not verified. Domain age, reputation, live contents and malware status are unknown. There are no HTTP fetches or DNS calls for inputs.

## Local classifiers

The full local registry selects the Phase 6 English SVM `email-source-text-v6-609bba638c1d` for limited research use. The original Spanish and hostname URL classifiers remain loaded within their archive scopes. The historical English baseline stays available for comparison and local rollback. The rejected Phase 5 artifact and two unselected Phase 6 candidates stay inactive.

The loader checks trusted local paths, artifact SHA-256, manifests, metrics, scikit-learn version and exact feature-code identities before deserialization. The Phase 6 selector additionally requires a matching limited-use admission record and frozen threshold. A missing or incompatible artifact uses heuristics. The conservative source package omits weights and can run with `backend/requirements.txt`.

The `language-format-v3` route screens English and Spanish applicability using all 97 langid languages and the preserved mixed-language policy. Its bounded input removes six known invisible format characters. Short, uncertain, mixed and unsupported text uses explicit heuristic fallback. Mixed-script lookalikes and some technical wording still cause assignment errors.

The selected English pipeline flagged 16/19 reviewed phishing messages and 17/5,801 legitimate messages in the primary archive holdout. Its archive decision score, model version, classifier status and assessment are stored separately from rule points and observations. The deployment probability flag is false. Historical records keep their original metadata. [Evaluation](../MODEL_EVALUATION.md) · [Inference contract](../docs/ml/INFERENCE.md) · [Reproduction](../docs/ml/phase6/COMMANDS.md)

## Reports

PDF reports use ReportLab and escape user strings, with no active URL links, scripts or external images. Metadata/evidence and case notes are snapshotted at report creation so later edits cannot rewrite a saved report's claims. Historical model snapshots keep their prior renderer path; current snapshots distinguish heuristic points, archive decision scores, final assessment, model/routing versions and limitations. Generation time is recorded; repeated downloads of the same snapshot produce identical PDF bytes. No random/fake observations are added. A subject/input longer than 350 characters gets an explicitly labeled metadata preview and a separate page-breakable paragraph. Every individual printable field is capped at 20,000 characters with a visible truncation notice directing the reviewer to the complete local analysis; raw email inclusion is explicit and initially bounded at 50,000 characters, then subject to the same per-field cap. Default reports omit raw content. Rendering failures return an actionable HTTP 422 without leaking user input or library internals. Embedded Bitstream Vera (bundled with ReportLab) supports common Latin/Greek/Cyrillic text; scripts outside that font's coverage may render imperfectly. No remote fonts are downloaded.
