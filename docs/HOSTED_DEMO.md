# Public demonstration

The hosted build preserves the PhishLens interface while replacing the local database workflow with temporary state in each browser tab. It performs real offline rule checks. It never loads the private English, Spanish or hostname model weights and makes no ML prediction or model-confidence claim.

## Two entry points

| Mode | Frontend | FastAPI | Storage |
|---|---|---|---|
| Local investigation workspace | `npm run dev` or `npm run build` | `backend.main:app` | Private local SQLite |
| Public demonstration | Vite `demo` mode / `npm run build:demo` | `backend.demo:app`, exported by `api/index.py` | Browser-tab memory; no application database |

Do not replace the public entry point with `backend.main:app`. The unauthenticated local persistence API is unsuitable for public exposure. The normal local build retains its existing behavior.

## Guest workflow and privacy

Visitors can paste an email, upload a small `.eml`, or submit an HTTP(S) URL. The API applies the existing passive heuristics and returns actual findings. URLs are not visited, DNS is not queried, and attachments are never executed. Supplied authentication headers remain observations rather than independently verified SPF, DKIM or DMARC results.

Cases, status, notes, history and report metadata are held in module memory inside one tab. They are not placed in localStorage, sessionStorage, cookies, a shared service or SQLite. Reloading, closing the tab or clearing the demo resets this state. Separate tabs and visitors have separate state. The display-density preference may be retained locally; submitted content is not.

The example button explicitly loads synthetic fixtures and sends them through the actual rules engine. Dashboard totals are computed from the current tab's records. A low rule score does not establish safety. Guest cases and reports are limited to 20 each to bound browser memory.

PDF generation resubmits the bounded original input and optional analyst notes to the stateless API. The server recomputes the evidence instead of trusting client-supplied scores. The resulting PDF bytes are returned directly; the application does not save a server-side report. Downloaded PDFs persist on the visitor's device according to their browser settings. PDF font attribution accompanies demo reports and is also available in the bundled Bitstream Vera notice.

This is application-level non-persistence, not a claim that requests never reach infrastructure logs, memory, network intermediaries or browser caches. Vercel processes the request and may retain platform metadata under its policies. The application does not intentionally log submitted bodies. Use synthetic, non-sensitive content in the public demo.

## Bounded server surface

Only health, email analysis, email-file analysis, URL analysis and PDF generation are exposed. Saved-analysis, investigation, report-retrieval, settings and database-management routes are absent on the demo server. Browser-origin checks reduce cross-site requests; they do not authenticate a caller.

Limits include 256 KiB per email, 512 KiB per request, 8,192 characters per URL, 80 findings, 40 links, 20 attachments, 4,000 note characters and 20 timeline entries. A per-process semaphore permits two analyses/report jobs; it is not a distributed rate limiter. Vercel plan quotas and platform protection still apply. Heavy traffic, cold starts or platform limits can make this portfolio demo temporarily unavailable. No paid service is required or provisioned by this configuration.

## Vercel configuration

The project uses the Vite preset, `npm ci`, `npm run build:demo` and `dist/`. Python 3.12 runs the ASGI function at `api/index.py`; `/api/*` rewrites to that function and application routes fall back to `index.html`. The browser uses same-origin `/api` requests, with no production localhost dependency.

Root `requirements.txt` installs only the rules/PDF server dependencies. The deployment ignore list and function exclusions omit models, SQLite data, local persistence code, research scripts, datasets, test evidence, dependencies and development caches. Public GitHub source still includes the local application and aggregate research documentation; deployment packaging is narrower.

Deploy to a preview first. Verify health reports `mode: public-demo` and all classifiers unavailable; run browser checks and confirm `/api/investigations` and `/api/reports` return 404. Test a staged production build before promoting it and repeat checks on the final public domain. Keep the PhishLens and portfolio projects separate.

## Run the demo locally

From the project root, install the normal documented dependencies. Start the API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.demo:app --host 127.0.0.1 --port 8012 --no-access-log
```

In a separate PowerShell terminal:

```powershell
$env:PHISHLENS_API_TARGET = 'http://127.0.0.1:8012'
$env:PHISHLENS_FRONTEND_PORT = '5182'
npx vite --mode demo --host 127.0.0.1
```

Run the guest browser suite against those servers:

```powershell
$env:PHISHLENS_PUBLIC_DEMO_TESTS = '1'
$env:PHISHLENS_DEMO_BASE_URL = 'http://127.0.0.1:5182'
npm run test:demo
```

The suite separates HTTP PDF validity from actual browser download completion. A canceled native transfer must be disclosed even when the PDF HTTP response and rendering succeed. Deployment verification must not substitute local passes for live checks.

Official platform references: [Python functions](https://vercel.com/docs/functions/runtimes/python), [API directory](https://vercel.com/docs/functions/runtimes/python/api-directory), [deployment configuration](https://vercel.com/docs/project-configuration).

## Current verification and manual download check

The public deployment and its verification limits are recorded in [the hosted release review](HOSTED_RELEASE_REVIEW.md). Protected-preview tests can optionally read a temporary owner-created share credential from `PHISHLENS_PREVIEW_ACCESS_FILE`. That file belongs in ignored scratch, never in source or evidence artifacts. The test helper bootstraps same-origin cookies, disables redirects for the credential-bearing request, sanitizes failures and disables traces. Public-production checks run without that file. Revoke temporary access after testing.

Native PDF download completion remains unverified in the execution environment: automated Chrome reported `canceled`, and native Windows browser control was stopped because URL-policy enforcement is unsupported. HTTP PDF generation and page rendering passed. To verify manually in a normal browser:

1. Open the public demo and load the explicitly synthetic examples.
2. Open Investigations, select an example and optionally edit its notes/status under Report Settings.
3. Generate Report (PDF). Check that the browser's Downloads list reports completion and that the saved PDF opens with the selected case, evidence, notes and limitations.

Do not treat a successful HTTP response alone as proof that the file reached the browser's download folder.
