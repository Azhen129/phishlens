# Hosted demo release review

Verified on 2026-11-06. Public URL: [PhishLens](https://phishlens-lovat.vercel.app).

## Released application

The deployed application source is commit `291fc0d8af48a73b5d9e92ed89a0b6ad63117bb3`, Git tree `d8ed220c8dc81beefc0d04eadec596dc27a5de53`. The isolated local candidate produced the identical Git tree before deployment. Subsequent documentation and protected-preview test-helper changes do not alter the deployed application code.

| Deployment | ID | Result |
|---|---|---|
| Protected preview | `dpl_FpwQr6MvmZ6JMhCceyxEWF3DkL4b` | READY; 23 API checks and 3 browser workflows passed |
| Tested production build | `dpl_6mi9TiLchUWysuD7zZA4348YCdao` | READY; 23 API checks and 3 browser workflows passed before promotion |
| Public production domain | `phishlens-lovat.vercel.app` | Promoted tested production build; repeated 23 API checks and 3 browser workflows without authentication |

The first deployment request defaulted to production and was canceled before completion. A separate explicit staging/preview was tested first. Custom-domain automatic assignment was disabled while the production build was verified and restored after promotion. No paid service was purchased or enabled.

## Automated verification

| Check | Actual result |
|---|---|
| Backend suite excluding unavailable private models | 206 passed; 12 real-model checks deselected; one upstream deprecation warning |
| Frontend unit suite | 24 passed |
| Existing local application browser suite | 6 passed against isolated test storage |
| New guest browser suite | 3 passed locally, on preview, on staged production and on the public domain |
| TypeScript | Passed |
| Normal production build and demo build | Passed |
| Formatting | Passed |
| GitHub Actions for deployed source | [Succeeded](https://github.com/Azhen129/phishlens/actions/runs/42214027791) |
| Source privacy pattern scan before deployment | 153 candidate files; zero blocking, review or credential-pattern findings |
| PDF HTTP response and rendering | Actual PDF response, all five sample pages rendered and inspected; notes/status, evidence, limitations and font notice present |
| Native PDF download completion | **Incomplete**: automated Chrome reported `canceled`; native Windows browser control was unavailable because URL-policy enforcement is unsupported |

The 23 live API checks cover demo/no-model health, absent persistence routes, all seven frontend routes, license assets, legitimate-email analysis, URL evidence, invalid-field redaction, size and origin rejection, and real PDF generation. Browser checks cover actual email upload, saved temporary cases, notes/status, separate tabs/visitors, reset on reload, inert URLs and desktop/mobile layouts. Submitted test messages are the explicitly synthetic software fixtures, not research emails.

The bounded privacy scanner checks current source candidates and known credential formats. It is not a guarantee against every possible secret or personal datum; its historical owner-decision defaults do not supersede the owner's explicit publication and MIT approvals. The deployment/source changes contain no trained weights, private datasets or SQLite records. Existing local research files were not used as the deployment source.

## Limits and operational scope

The demo runs genuine heuristic checks with no learned model inference. Its server has no saved-case API or application database. Guest content resides temporarily in the visitor's tab and in memory while processing a request. The hosting provider can retain infrastructure metadata under its own policies. Visitors should use synthetic, non-sensitive content.

The semaphore is per process, not a distributed abuse quota. Vercel cold starts, free-plan limits and platform protection can affect availability. No external monitoring or paid drain was provisioned. Error/fatal runtime-log inspection after verification found no matching application logs; this limited observation is not a long-term uptime guarantee.

The approved dashboard appearance, local application entry point, private model selection, research limitations and aggregate evaluation metrics are preserved. MIT covers authorized original code/documentation; separate Lucide, Feather, ReportLab and font terms remain in the notices. [Architecture, limits and manual PDF verification](HOSTED_DEMO.md)
