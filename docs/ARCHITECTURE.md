# Architecture

```
 Administrator / users
        |
        v
 Web application (browser)           Android app (Flutter, native UI)
        \                                   /
         \________ HTTPS/HTTP (LAN) ________/
                          |
                  FastAPI backend (Windows)
        +-----------------+------------------------------+
        | auth + roles    | users + audit                |
        | scan API        | dashboard / system / targets |
        | scan runner (thread pool, progress, cancel)    |
        |   +- builtin-web   (SSRF-safe client + checks) |
        |   +- builtin-source (safe ZIP + rules)         |
        |   +- Semgrep / Trivy / OSV / ZAP adapters      |
        | reports: PDF (ReportLab), JSON, CSV            |
        +-----------------+------------------------------+
                          |
                SQLite (SQLAlchemy 2, portable types)
```
One backend and one database serve both clients. The APK contains no scanner and no database.

## Backend modules
| Module | Purpose |
|---|---|
| `app/config.py` | all settings from environment / `.env`; auto-generated secret key in `data/.secret_key` |
| `app/models.py` | User, SessionToken, Scan, Finding, AuditLog, AuthorizedTarget |
| `app/api/*.py` | REST routers: auth, users, scans, system (dashboard, targets, engines, audit, health) |
| `app/services/security.py` | Argon2id, token hashing, password policy, rate limiter |
| `app/services/runner.py` | background execution, progress, cancellation, time limit, restart recovery |
| `app/scanners/netsafe.py` | SSRF-safe HTTP client, TLS inspection |
| `app/scanners/web_checks.py` | 8 passive + 4 active website checks |
| `app/scanners/source_scan.py` | hardened ZIP extraction and rules |
| `app/scanners/engines.py` | Semgrep, Trivy, OSV, ZAP adapters and honest status |
| `app/scanners/knowledge.py` | rule knowledge base (plain-language text, remediation, CWE), scoring constants |
| `app/reports/*` | PDF, JSON, CSV |
| `app/cli.py` | `init-admin`, `reset-password`, `serve`, `doctor`, `enable-lan`... |

## REST API (all JSON; `Authorization: Bearer <token>`)
| Method + path | Role | Purpose |
|---|---|---|
| `GET /api/health` | none | connection test (status, app, version only) |
| `POST /api/auth/login` | none | returns token + user (rate limited) |
| `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/change-password` | any | session |
| `GET/POST /api/users`, `PATCH/DELETE /api/users/{id}`, `POST /api/users/{id}/reset-password`, `GET /api/users/{id}/activity` | admin | user management |
| `POST /api/scans/website` | user+ | start website scan |
| `POST /api/scans/source` (multipart) | user+ | start source ZIP scan |
| `GET /api/scans`, `GET /api/scans/{id}` | any | history / details with findings |
| `POST /api/scans/{id}/cancel`, `DELETE /api/scans/{id}` | owner/admin | stop / delete |
| `GET /api/scans/{id}/report.{pdf,json,csv}` | any with access | reports |
| `GET /api/dashboard` | any | aggregates computed from the database |
| `GET /api/system/info`, `/engines`, `/checks` | any | configuration and engine status |
| `GET/POST/DELETE /api/targets` | read: user+, write: admin | authorization allowlist |
| `GET /api/audit` | admin | audit log |

## Roles
| Role | Scans | Sees | Manages |
|---|---|---|---|
| Super Administrator | yes | all scans | all users, allowlist |
| Administrator | yes | all scans | Standard / Read-only users, allowlist |
| Standard User | yes | own scans | - |
| Read-only User | no | all scans and reports (auditor) | - |

## Scan lifecycle
`queued -> running -> completed | failed | cancelled`. Progress and messages are written to the database; clients poll `GET /api/scans/{id}`. A server restart marks unfinished scans as failed.

## Scoring
See README "Security score" and `app/scanners/knowledge.py` (`SCORE_DEDUCTION`, `CONFIDENCE_WEIGHT`). The risk label is the highest effective severity; a low-confidence critical/high match counts as medium until reviewed.

## Database
SQLite file `data/securescan.db` (WAL mode). Only portable types are used (`String`, `Integer`, `Boolean`, `DateTime`, `JSON`, `Text`) so PostgreSQL can be adopted by setting `SSAI_DATABASE_URL`. Tables are created automatically at start; Alembic migrations are not included yet - add them before changing the schema in production.

## Web interface
Plain HTML/CSS/JavaScript served by the backend, no build step and no external requests (works offline on a LAN). All DOM is built with safe APIs (no `innerHTML` with data), under a strict Content-Security-Policy. Dark and light themes; sidebar on desktop, bottom navigation on phones.

## Android app
`mobile/lib`: `core/` (API client, models, URL rules, state), `ui/` (screens). State is held in `AppState` (ChangeNotifier via `AppScope`). Navigation: splash -> server setup -> login -> forced password change -> tabs (Dashboard, Scan, History, Profile).
