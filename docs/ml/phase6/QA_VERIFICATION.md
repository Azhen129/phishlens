# Browser and PDF verification

The three application captures show synthetic fixtures in the ML-enabled local workspace at 1672 × 941. They document the dashboard, email view and investigation view. This package starts with rules-only operation, with the same layout. The owner approved publication of these captures and visible branding. [Dashboard](screenshots/dashboard-en.png) · [Email](screenshots/email-en.png) · [Investigations](screenshots/investigation-en.png)

## Isolated Playwright servers on Windows

Run the rules-only checks from the extracted source root after installing the pinned test dependencies. The Playwright configuration normally starts its own services. If automatic teardown stalls, start the dedicated services in separate terminals. Leave `CI` unset in the test terminal so Playwright can reuse them. [Install and test](../../../README.md#tests-and-verification)

```powershell
# API terminal
$env:PHISHLENS_DB = 'work/phase6/e2e.sqlite3'
$env:PHISHLENS_TEST_MODE = '1'
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8010 --no-access-log
```

```powershell
# Frontend terminal
$env:PHISHLENS_FRONTEND_PORT = '5180'
$env:PHISHLENS_API_TARGET = 'http://127.0.0.1:8010'
npm run dev
```

```powershell
# Test terminal
npx playwright test tests/e2e/application.spec.ts
```

Stop the isolated services with Ctrl+C after the tests. The browser suite uses the dedicated test database and ports. Keep that database separate from any personal case records.

## Verify a native PDF download

The browser's download event and the HTTP PDF payload are separate checks. Native verification requires a finished transfer and an openable file on disk. The prior Windows Chrome automation reported cancellation after initiating the transfer. The review of the exact public archive records its own result.

1. Start the app from the extracted package on the ordinary loopback ports. Use a fresh local database in that directory. [Windows setup](../../../README.md#start-on-windows)
2. Open `http://127.0.0.1:5173/` in an ordinary Chrome, Edge or Firefox session. Submit `fixtures/suspicious-invoice.eml` from the email page and save the investigation.
3. Set the case to **In Review** and save a recognizable synthetic analyst note. Reload and confirm the values persisted.
4. Generate the report and confirm that the browser's download panel shows a completed PDF. Open the saved file and confirm the case ID, status, note, evidence and rule assessment. Record the browser version and result.
