# Phase 6 reproduction commands

Use a fresh extracted PhishLens source copy with its working directory at the project root. The Windows commands below expect Python 3.11 and the lock file in that copy. The recorded training environment used Python 3.11.9, scikit-learn 1.9.1, NumPy 2.4.6, SciPy 1.17.1, and seed `20261103`. Keep all acquired data under ignored `work/` storage. Phase 6 includes a CC BY-NC 4.0 final evaluation source and uses the older CC BY-NC-SA 2.0 University archive only for overlap control. This procedure is for local noncommercial reproduction. [Dataset provenance](../../../DATASET_PROVENANCE.md) · [Python dependency lock](../../../backend/requirements-lock.txt)

## What the public package can reproduce

The package includes the frozen protocol, attributed dataset sources, aggregate evidence and research scripts. The plotted comparisons, confusion matrices and report tables can be regenerated from the included aggregate results. Use a scratch copy before regenerating documentation. After installing the pinned Python requirements in the next section, run `python scripts/summarize_phase6_evaluation.py` with that environment's interpreter. The generated research report has its original local evidence references. This package's report links to the supplied public evidence. The frozen protocol records the original reporting plan. This snapshot's privacy review limits distribution to aggregate results and keeps role memberships and per-message records local. [Packaged evaluation](../../../MODEL_EVALUATION.md)

The commands below document the **owner-only exact replay**. Start from a separate copy of the complete reviewed research workspace. The public package alone lacks the reviewed per-message annotation and acquisition records, prepared corpora and weights needed for that replay. If working from the public source, first supply the original reviewed files from a trusted local archive at their original relative paths. Use the exact originals for checks that bind an input by SHA-256.

| Stage | Private prerequisites |
| --- | --- |
| Acquisition and corpus preparation | Original Phase 4 train/external provenance files, Phase 5 raw snapshot list and provenance, and Phase 6 original acquisition record and label manifest. The prior prepared corpora can be reused after checksum verification. |
| Fitting | The reviewed Phase 6 provenance and regenerated development CSV with the matching corpus hash. |
| Frozen final evaluation | The original byte-identical Phase 6 selection, provenance, preparation audit and original trusted artifacts, plus the verified prepared CSVs. |

The private archive filenames named below are expected inputs for the replay. Model-blind annotation can be repeated under the documented policy, but a new annotation must be identified as a new review with its own results. [Annotation method and counts](POT_ANNOTATION.md) · [Frozen protocol](PROTOCOL.md)

## Prepare an isolated copy

```powershell
py -3.11 -m venv .venv
$PhishLensPython = (Resolve-Path -LiteralPath '.venv/Scripts/python.exe').Path
& $PhishLensPython -m pip install -r backend/requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed.' }
$env:OPENBLAS_NUM_THREADS = '1'
$env:OMP_NUM_THREADS = '1'

$Phase6Evidence = 'work/phase6/reviewed-evidence'
if (Test-Path -LiteralPath $Phase6Evidence) { throw 'Choose a fresh replay copy.' }
New-Item -ItemType Directory -Path $Phase6Evidence | Out-Null
Copy-Item -LiteralPath @(
    'docs/ml/phase6/provenance.json',
    'docs/ml/phase6/preparation-audit.json',
    'docs/ml/phase6/acquisition-v2.json'
) -Destination $Phase6Evidence
```

The copy preserves the reviewed identity because the preparers write their own generated evidence. Use a byte-preserving extraction for exact replay. The archived Windows provenance and preparation audit use CRLF, and line-ending conversion changes their SHA-256 identities. If an archive, dataset permission, or checksum differs, stop and review the discrepancy.

## Reconstruct the observed inputs and final corpus

Phase 6 groups against the prepared Phase 4 main/external and Phase 5 development/final corpora. Reuse verified copies of those four CSVs and the pinned CEAS-08 input if available locally. Otherwise the earlier scripts reconstruct the required files using their original sampling and grouping rules. The Phase 4 and Phase 5 training commands are unnecessary for this data preparation step. [Dataset roles and attribution](../../../DATASET_PROVENANCE.md)

```powershell
& $PhishLensPython scripts/acquire_english_dataset.py --output work/phase4/raw --min-english-probability 0.90
if ($LASTEXITCODE -ne 0) { throw 'Phase 4 acquisition failed.' }
& $PhishLensPython scripts/prepare_english_dataset.py --output work/phase4/raw --max-main-rows 10000 --max-comparisons 10000000
if ($LASTEXITCODE -ne 0) { throw 'Phase 4 preparation failed.' }
& $PhishLensPython scripts/acquire_phase5_data.py
if ($LASTEXITCODE -ne 0) { throw 'Phase 5 acquisition failed.' }
& $PhishLensPython scripts/prepare_phase5_data.py
if ($LASTEXITCODE -ne 0) { throw 'Phase 5 preparation failed.' }
& $PhishLensPython scripts/acquire_phase6_data.py
if ($LASTEXITCODE -ne 0) { throw 'Phase 6 acquisition failed.' }
& $PhishLensPython scripts/parse_phase6_pot.py
if ($LASTEXITCODE -ne 0) { throw 'Pinned Phishing Pot replay failed.' }
& $PhishLensPython scripts/prepare_phase6_data.py
if ($LASTEXITCODE -ne 0) { throw 'Phase 6 preparation failed.' }
```

The replay parser checks the archived acquisition manifest, the sample order, and every EML's size and SHA-256. It recreates `work/phase6/pot-parsed-private.json` from inert MIME text. It also creates `work/phase6/pot-annotations-adjudicated-private.json` using the original five reviewed label fields. The original private file includes reviewer reasons and remains in the research workspace. Replay preserves its reviewed label decisions and has a different annotation-file hash. This changes the replay audit and replay provenance hashes. The isolated replay regenerated both CSVs and the parsed Pot input byte for byte using verified local acquisitions. [Annotation method and counts](POT_ANNOTATION.md)

Verify the generated CSVs against the saved reviewed provenance before training or evaluation.

```powershell
$ReviewedPhase6 = Get-Content -Raw -LiteralPath (Join-Path $Phase6Evidence 'provenance.json') | ConvertFrom-Json
$ReplayDevelopment = (Get-FileHash -Algorithm SHA256 -LiteralPath 'work/phase6/raw/development.csv').Hash
$ReplayFinal = (Get-FileHash -Algorithm SHA256 -LiteralPath 'work/phase6/raw/final.csv').Hash
if ($ReplayDevelopment -ne $ReviewedPhase6.prepared.sha256 -or $ReplayFinal -ne $ReviewedPhase6.final.sha256) {
    throw 'Prepared data differs from the frozen corpus. Review before proceeding.'
}
```

| Prepared file | Rows | Expected SHA-256 |
| --- | ---: | --- |
| `work/phase6/raw/development.csv` | 22,889 | `904dfe0eb3963e72fd48263fc3cdcadfb4ea59db4b0aface62d065d87b7e455d` |
| `work/phase6/raw/final.csv` | 5,965 | `720d8d8b1d5108576e45dc8e52cde4de1f17c7ff39c3d284b2d8bfe1131ec660` |

The Phase 6 trainer also requires `permission_basis` and `collection_notes` in the provenance. The first preflight caught those missing fields and exited before fitting. The correction was applied before training and left both CSV hashes intact.

## Reproduce the three candidate fits

After both CSV digests match, the archived provenance can reproduce the reviewed training identity. Store the repeat outputs under `work/` with separate roots. The trainer reads only the development CSV and uses the fixed group roles and validation rules. It refuses to overwrite a checkpoint, selection record, or model version. The fitted models remain unvalidated research artifacts. [Frozen protocol](PROTOCOL.md)

```powershell
& $PhishLensPython -m backend.ml_training_v6 `
    --csv work/phase6/raw/development.csv `
    --provenance (Join-Path $Phase6Evidence 'provenance.json') `
    --model-root work/phase6/replay-training/models `
    --report-root work/phase6/replay-training/reports `
    --checkpoint-root work/phase6/replay-training/checkpoints
```

The original candidate versions are `email-source-text-v6-bb697598d76b`, `email-source-text-v6-609bba638c1d`, and `email-source-text-v6-3b1e4efb2bfa`. The unweighted word/character SVM at `email-source-text-v6-609bba638c1d` won validation at threshold `0.2095991955762941`. Cross-platform numeric behavior or serialization can change repeat artifact hashes. Record differences and retain the original selection and weights. The isolated fit outputs provide reproducibility evidence and remain separate from the frozen final comparison. [Reviewed selection](selection.json)

## Reproduce the frozen comparison

The final evaluator expects the exact project-owned English baseline, Spanish model, rejected Phase 5 artifact, and all three Phase 6 candidates in their recorded model directories. The portfolio source leaves model binaries out. An owner with the complete trusted local artifacts can perform this replay. Confirm their identities against the original manifests and selection records. Joblib loading executes trusted serialized objects, so use only verified project-owned bundles. [Model distribution decisions](../../../backend/models/distribution-phase6.json)

After the prepared CSVs match, save the regenerated replay audit and provenance separately in the isolated copy. The evaluator checks the reviewed audit/provenance identities linked to the original selection, so restore those copies before running the following command. The `--out` target must be new.

```powershell
$ReplayRecords = 'work/phase6/replayed-evidence'
if (Test-Path -LiteralPath $ReplayRecords) { throw 'Choose a fresh replay evidence directory.' }
New-Item -ItemType Directory -Path $ReplayRecords | Out-Null
Copy-Item -LiteralPath @(
    'docs/ml/phase6/provenance.json',
    'docs/ml/phase6/preparation-audit.json'
) -Destination $ReplayRecords
Copy-Item -LiteralPath (Join-Path $Phase6Evidence 'provenance.json') -Destination 'docs/ml/phase6/provenance.json'
Copy-Item -LiteralPath (Join-Path $Phase6Evidence 'preparation-audit.json') -Destination 'docs/ml/phase6/preparation-audit.json'
& $PhishLensPython scripts/evaluate_phase6_final.py --out work/phase6/replay-evaluation.json
```

The evaluator reads fixed thresholds and emits a separate evaluation record. The original results have already been observed, so replay assesses reproducibility. A fresh independent audit requires a prespecified unused holdout, a label review before inference, and frozen candidates and thresholds. [Final evaluation](../../../MODEL_EVALUATION.md)

The original local review registry already selects the admitted Phase 6 version. `scripts/admit_phase6_model.py` records the limited-use decision from the original frozen evaluation and Spanish routing evidence. It preserves the initial manifest before writing a reviewed manifest and local selector. Replayed training outputs and summary-only public evidence are separate from that reviewed registry. [Admission record](../../../backend/models/email_en_v6/email-source-text-v6-609bba638c1d/admission.json)

## Verify the application separately

Install the front-end lock with `npm ci`. Run the complete tests when the three trusted active models are present. With the source-only portfolio copy, use the explicitly limited commands below. The registry check distinguishes optional omissions from corrupt present files. [Installation and checks](../../../README.md) · [Release scope](../../../GITHUB_READINESS.md)

```powershell
& $PhishLensPython scripts/check_model_registry.py
& $PhishLensPython -m pytest backend/tests -m 'not real_models' -q
npm test
npm run typecheck
npm run build
npm run format:check
npx playwright test tests/e2e/application.spec.ts
```

For complete local coverage, run `& $PhishLensPython -m pytest backend/tests -q` and `npm run test:e2e` with the complete registry. Playwright uses a dedicated test-mode database and loopback services. The application's ordinary SQLite file stays separate from replay and verification.
