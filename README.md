# SecureScan AI

A private vulnerability-assessment platform you run on your own Windows computer.

* **Web application** (browser) and **Android app** (APK) that share one backend and one database.
* **Website scanner**: passive checks (headers, cookies, TLS certificate, redirects, forms, error pages) and optional low-impact active probes for hosts you explicitly authorize.
* **Source-code scanner**: upload a ZIP; it is safely inspected (never executed) for secrets, injection patterns, weak crypto, unsafe deserialization, insecure configuration and dependency manifests.
* **Beginner mode** (plain-language results) and **Advanced mode** (technical evidence, CWE/CVSS, individual checks and engines).
* **Reports** in PDF, JSON and CSV, generated from real stored scan results.
* **Users and roles**: Super Administrator, Administrator, Standard User, Read-only User. No public registration.
* **Optional engines**: Semgrep, Trivy, OSV.dev, OWASP ZAP. They are used only when really installed or reachable; otherwise the scan says "not installed / not performed".

> Use SecureScan AI only on systems you own or are explicitly authorized to test.
> Please read [docs/TEST_REPORT.md](docs/TEST_REPORT.md) for what has and has not been tested.

---

## 1. Install on Windows (about 10 minutes)

1. Install **Python 3.11 or newer** from <https://www.python.org/downloads/>. Tick **"Add python.exe to PATH"**.
2. Extract this project to a folder, for example `C:\SecureScanAI`.
3. Double-click **`install_windows.bat`**. It checks Python, creates a virtual environment, installs the dependencies, creates the database and asks you to create the **first administrator** (password: 12+ characters, letters and numbers; it is never stored in plain text and there is no default password).
4. Double-click **`start_server.bat`**. Leave the window open.
5. Open <http://127.0.0.1:8000> in your browser and sign in.

To stop the server close the window (or run `stop_server.bat`).

### Forgot the administrator password?
Open a Command Prompt in the folder and run: `.venv\Scripts\python.exe -m app.cli reset-password YOUR_USERNAME`

## 2. Use the Android app (same Wi-Fi)

1. Build the APK with GitHub Actions - see **[GITHUB_UPLOAD_GUIDE.md](GITHUB_UPLOAD_GUIDE.md)** and **[ANDROID_BUILD_GUIDE.md](ANDROID_BUILD_GUIDE.md)**. You do not need Android Studio.
2. On the Windows computer right-click **`allow_phone_access.bat`** > *Run as administrator*. It makes the server listen on your network and adds a Windows Firewall rule limited to the **Private** profile and your **local subnet**. Then restart the server.
3. Find the computer's address: open Command Prompt and run `ipconfig`. Copy the **IPv4 Address** of your Wi-Fi adapter (for example `192.168.1.20`).
4. In the app enter `http://192.168.1.20:8000` (your address), tap **Test connection**, **Save**, and sign in.

Never use `localhost` on the phone - it means the phone itself. Plain `http://` is accepted by the app **only for private/LAN addresses**; for anything else use `https://` (see [SECURITY.md](SECURITY.md)). Certificates are always verified.

## 3. Everyday use

| Task | How |
|---|---|
| Scan a website | **New scan > Website**, enter the address, tick the authorization box, **Start scan** |
| Scan source code | **New scan > Source code**, choose a `.zip`, tick the authorization box |
| Read results | Simple view explains each issue in plain language; Technical view shows evidence, rule IDs, CWE/CVSS |
| Download a report | On the results page: **PDF / JSON / CSV** |
| Add a user | **Users > Add user** (administrators only) |
| Allow active checks for a host | **Settings > Authorized targets** (administrators only) |

### Finding types (important)
* **Verified vulnerability** - confirmed by an engine (for example a CVE matched to an exact package version).
* **Misconfiguration** - a weakness directly observed (for example a cookie without `HttpOnly`).
* **Missing control** - a recommended protection is absent (for example no CSP). This is a hardening gap, not proof of an exploit.
* **Needs review (potential)** - a heuristic pattern match. Built-in source rules are always reported this way with a confidence level; they are never presented as confirmed vulnerabilities.
* **Observation** - informational.

### Security score
Starts at 100. Each distinct rule deducts points by severity (critical 25, high 12, medium 5, low 2) multiplied by confidence (high 1.0, medium 0.75, low 0.4). Repeats count once; observations are not scored. It is an indicator, not a guarantee.

## 4. Configuration

All settings live in `.env` (created from `.env.example`). Highlights: `SSAI_HOST`, `SSAI_PORT`, TLS files, session length, upload/extraction limits, request budgets, optional engine settings. Every option is documented in `.env.example`.

## 5. Optional scanning engines
Semgrep, Trivy, OSV.dev and OWASP ZAP - see **[docs/ENGINES.md](docs/ENGINES.md)**. The application is fully usable without them.

## 6. Project layout

```
app/                    FastAPI backend
  api/                  REST routers (auth, users, scans, system)
  services/             security, audit, scan runner, serializers
  scanners/             SSRF-safe HTTP client, website checks, source scanner, engine adapters
  reports/              PDF, JSON, CSV builders
  static/               web interface (HTML, CSS, JavaScript - no external dependencies)
  tests/                backend tests (pytest)
mobile/                 Flutter Android app (native UI, same backend)
  android_overrides/    Android manifest, icon, network config (applied by scripts/prepare_android.py)
scripts/                Android prepare/signing helpers, UI smoke test
.github/workflows/      android-build.yml (APK), backend-tests.yml
docs/                   architecture, engines, troubleshooting, test report, manifest
install_windows.bat  start_server.bat  stop_server.bat  allow_phone_access.bat
```

## 7. Developer commands

```
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest                # backend tests
.venv\Scripts\python.exe -m app.cli doctor        # configuration and engine status
.venv\Scripts\python.exe -m app.cli --help
```
Optional browser-less UI smoke test: `cd scripts/ui_smoke && npm install && python run_ui_smoke.py`.

## 8. Known limitations
* The database is SQLite (PostgreSQL migration is possible later; Alembic migrations are not included yet).
* Rate limiting and scan scheduling are in-memory and single-process (right for one Windows server).
* Plain HTTP on a LAN exposes tokens to anyone on that network. Use HTTPS (`SSAI_SSL_CERTFILE` / `SSAI_SSL_KEYFILE`) when that matters.
* Automated scanning finds only a subset of problems and can produce false positives. It is not a penetration test.

License: MIT (see [LICENSE](LICENSE)). Change it if you prefer a private licence.
