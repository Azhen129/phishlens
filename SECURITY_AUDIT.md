# PhishLens security audit

Reviewed on 4 November 2026. The audit covers the local application, persistence, model loading, dependency checks and the staged source candidate. It combines code inspection with executed regression tests. The owner approved publication of the source snapshot.

## Verified boundaries

| Area | Current behavior and evidence |
|---|---|
| Submitted URLs | `backend/analysis.py` parses HTTP(S) syntax without a network client or DNS resolver. Complete URL rules remain separate from hostname-only ML. Backend passive-network regression tests and browser workflows verify this boundary. |
| Submitted HTML | `InertHTML` extracts text/anchors without activating markup, images or scripts. Frontend components render user strings as React text; no submitted HTML uses `dangerouslySetInnerHTML`. |
| Attachments | MIME handling retains filename, declared MIME, decoded size and SHA-256 only. Attachments are not extracted, expanded, written out, executed or malware-scanned. |
| Bounds and errors | Requests are bounded to 26 MiB, email content to 25 MiB, MIME to 20 nesting levels/200 parts, headers to 1,000 and unique HTTP(S) links to 200. Inference and printable fields have additional documented limits. Known parser/model/layout failures return bounded user-facing errors. |
| Browser-to-local API | `LimitedLocalRequests` rejects unrelated Origins and cross-site browser requests; `TrustedHostMiddleware` restricts Host. The API emits no-store, nosniff and restrictive API CSP headers. These are browser-access controls, not remote authentication. |
| Persistence | Parameterized SQL treats submitted text as data. Tests cover save/reopen, notes/status changes, deletion, report snapshots and model versions. The original record and backup match, and future schema versions are refused before metadata writes. QA mode requires the dedicated isolated database path. |
| PDF | ReportLab text is escaped; reports have no active user links or external images. A report uses its saved evidence/notes/model snapshot rather than a new inference. Payload and rendered-page checks remain separate from native browser file delivery. |
| Learned models | Path, artifact hash, version, scope, feature-code compatibility and evaluation checks precede trusted-local joblib loading. Missing, incompatible, corrupt or rejected models fall back to heuristics. Uploaded text cannot select a model path. |

The application audit distinguishes fixture workflows, model validation, HTTP PDF delivery and native browser transfer. This source package carries the aggregate evidence and the browser procedure. [Verification guide](docs/ml/phase6/QA_VERIFICATION.md)

## Findings and remaining limits

| Finding | Assessment and disposition |
|---|---|
| Public source license | MIT covers the authorized original code and documentation. Third-party materials retain their respective terms. [License scope](LICENSE.NOTICE.md) |
| Published application screenshots | The owner confirmed publication rights for the branding, implemented design and the three screenshots of synthetic fixtures. Supplied design references are excluded from the public source. |
| Personal machine paths in historical evidence | The initial inventory found absolute user-profile paths in startup notes, test logs and provenance/experiment metadata. Historical hash-bound originals remain unchanged locally. A public copy must omit those files or redact identified copies with original/copy hash mapping. The scan reports path/line locations, not matched values. |
| No remote authentication or tenant isolation | The current app is for one trusted local operator. Native clients can access an allowed local endpoint without an Origin header. Do not expose this configuration to untrusted networks or describe Origin checks as login security. A hosted product needs authentication, authorization, TLS, isolated storage, quotas and an independent deployment review. |
| Trusted serialized model code | Joblib is pickle based. Integrity checks detect corruption and accidental mismatch; they do not sandbox a malicious artifact or defeat an administrator replacing both artifact and manifest. Only trusted project-owned weights may be installed. [scikit-learn's persistence guidance](https://scikit-learn.org/stable/model_persistence.html) explains this execution risk. |
| Resource controls are local bounds, not DoS protection | Bounded individual inputs still consume memory/CPU. There is no per-user quota, global request budget or hostile-client rate limiter. Record listings read local JSON records; large archives and concurrent operations are outside the demonstrated workload. |
| SQLite compatibility is deliberately narrow | The recorded schema is v1; there is no multi-version migration framework or concurrent edit conflict resolution. The final Phase 6 report records any implemented version guard. Do not assume an arbitrary future database is backward compatible. Application cascades and single-record transactions do not provide an all-record distributed transaction. |
| ML scope remains limited | Archive scores are not independently validated inbox probabilities or confidence. Authentication headers are supplied and unverified. Low points or a legitimate model result never establishes safety. Model admission is reported independently from software-test success. |
| Native browser download limits | Chrome initiated both email PDF downloads and canceled native file finalization in the Windows sandbox. A browser-only plain-text probe reproduced the cancellation. HTTP payloads and rendered pages passed separate checks. |

## Source and secret inspection

`scripts/audit_release.py` inventories candidate files using Git's tracked/untracked-but-not-ignored set, or an explicitly staged tree. It performs a bounded UTF-8 scan for common high-specificity credential formats and user-profile paths, identifies raw-mail/database/key containers, and flags serialized models and reference images for manual review. It never deserializes a model, opens a submitted link or changes the inspected files. Matched credential values are deliberately omitted from its JSON and console output.

The archived Phase 6 scan identified local machine paths, serialized models and reference images for review. This package has its own inventory. The scanner checks selected credential and personal-path patterns in the packaged files. Git history, outside services and unbundled files are outside that scan. [Package audit](PUBLIC_RELEASE_AUDIT.json)

The additional ignore rules cover raw `.mbox/.pst/.ost/.msg/.eml` mail, private-key containers and coverage/cache output. Only the three named synthetic `.eml` fixtures are excepted, and the audit requires their development marker. Recursive ignore rules cover every versioned model weight. The local integrity check still loads the trusted active artifacts, and the distribution registry records the hash and policy for all seven. No existing file was deleted.

Do not print credentials while reviewing a finding. If an actual credential is discovered, retain only the location in a report and treat rotation/history cleanup as a separate owner-authorized action. No such credential was identified by this initial scan.

## Dependencies and CI

The initial Phase 6 npm audit found four affected package entries in Vitest-related tooling and sharp. The refreshed lock uses Vitest 4.1.12 and sharp 0.35.5. The final audit reported zero npm advisories at verification time. `pip check` verified Python dependency consistency. [Vitest advisory](https://github.com/vitest-dev/vitest/security/advisories/GHSA-82fw-gwwq-j7x9) · [sharp release notes](https://sharp.pixelplumbing.com/changelog/v0.35.5/)

CI has read-only repository permissions, disables persisted checkout credentials, includes no deployment step, has a bounded job timeout and does not interpolate untrusted PR text into shell commands. It runs formatting, type checking, build, frontend/backend tests, compilation, dependency consistency, a redacted release inventory and Playwright. Linux installs Playwright Chromium. The four GitHub-owned actions are pinned to complete commit hashes resolved from their official v4/v5 tags on 3 November 2026, rather than invented or left as mutable tags. [GitHub's security guidance](https://docs.github.com/en/actions/reference/security/secure-use) supports immutable action identities. These pins are provenance controls, not a complete code audit of the actions. No remote Actions run is claimed without an actual repository execution.

`scripts/check_model_registry.py` checks every present trusted bundle through runtime integrity/loading. A corrupt present artifact, invalid selector or malformed/mismatched present metadata fails CI even if another model is intentionally omitted. When optional weights are absent, the workflow explicitly selects rules-only backend and browser application checks and states that learned-model workflow coverage was not run. It never treats this mode as a trained-classifier pass. The complete local working registry still requires the full backend suite and trained-model E2E workflows.

See [GITHUB_READINESS.md](GITHUB_READINESS.md) for the model/dataset distribution matrix and conservative public-copy procedure. The owner approved the public source and its selected assets.
