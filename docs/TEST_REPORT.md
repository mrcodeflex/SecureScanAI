# Test report

This report lists only what was **actually executed** while the project was built, and what was **not**. Nothing here is assumed.

Environment used for the tests: Linux sandbox, Python 3.12, Node 22, Dart SDK 3.14.1 (no Flutter SDK), no access to the public internet and no Windows or Android device.

## Executed and passed

| Area | What was run | Result |
|---|---|---|
| Backend (pytest) | `python -m pytest` | **60 passed** |
| - startup, health, security headers | app start-up with real DB, `/api/health`, CSP/XFO/nosniff | passed |
| - authentication | login/logout, token revocation, generic errors, lockout + 429, Argon2id storage, tokens not stored in plain text, forced password change, password policy | passed |
| - authorization & user management | all four roles, admin cannot create/modify admins, last Super Administrator protected, self-delete/disable blocked, reset password, activity, audit log | passed |
| - URL validation / SSRF | 22 hostile URLs rejected (localhost, 127.x, `[::1]`, `0.0.0.0`, RFC1918, link-local/metadata `169.254.169.254`, decimal/hex IPs, IPv4-mapped IPv6, 100.64/10, `.local`/`.internal`, `file:`, `ftp:`, `gopher:`, `javascript:`, credentials in URL, spaces); public+private DNS mix rejected; connection pinned to the validated IP; redirect to an internal host blocked; request limit and cancel | passed |
| - real TLS | local HTTPS server with a self-signed certificate: verification refused (never bypassed), reported as finding `WEB-TLS-001`; same certificate trusted via the trust store: protocol/issuer/expiry inspected, 2-day expiry flagged, HSTS recognised | passed |
| - website scans end to end | passive scan of a deliberately weak local site (missing headers, cookie flags, password form over HTTP, stack-trace disclosure, version disclosure); cookie values not stored; beginner mode never runs active checks; active checks refused unless allowlisted; active probes found exposed `.env` (contents not stored), TRACE, reflective CORS, input reflection; unreachable host fails cleanly | passed |
| - source scans end to end | ZIP upload -> findings with file/line/CWE/confidence; secrets redacted; "potential" labelling; honest engine states (Semgrep/Trivy `not_installed`, OSV `skipped`); upload and extracted files deleted afterwards | passed |
| - ZIP safety | path traversal variants (`../`, absolute, drive letter, backslash), ZIP bomb, too many files, non-ZIP, oversize upload (413), symlink skipped, vendor/binary/oversize files skipped, no executable bits, bad extension, missing authorization | passed |
| - reports | PDF (valid `%PDF`), JSON (structure, methodology, limitations, disclaimer), CSV (header, formula-injection neutralised), PDF with hostile text (markup, NUL, non-Latin), access control (owner, admin, auditor, other user 404, no token 401) | passed |
| - dashboard | counts equal the real database contents; own-vs-all scope; activity only for admins | passed |
| - scoring, OSV parser, CLI `.env` editing | deterministic score cases; OSV request/response parsing with a **mocked** API | passed |
| Web UI smoke test (jsdom, real server) | `scripts/ui_smoke`: login (bad + good), dashboard, website scan with real findings, finding expand, Simple/Technical views, search filter, ZIP upload scan, history, reports page, dashboard totals, add user, engines page honesty, audit page, help, theme toggle, sign out, no uncaught script errors | **28 checks passed** |
| Web UI static checks | CSS parsed with tinycss2 (0 syntax errors, all custom properties defined, every class used by the JS has a rule); `node --check` on all scripts | passed |
| PDF layout | sample report rendered to an image and inspected; two layout defects (score box, label overlap) were found and fixed | passed |
| Flutter code (without Flutter SDK) | `dart format` (all 20 files parse and are formatted); `dart analyze` on the pure-Dart core (`url_rules`, `models`, `format`): no issues; the 24 assertions of `test/url_rules_test.dart` and `test/models_test.dart` executed on the Dart VM through a small shim | passed |
| Android helper scripts | `prepare_android.py` and `configure_android_signing.py` run against a **simulated** Flutter Gradle template: application id rewrite, overrides copied, no-secret / partial-secret / full-secret modes, secrets not printed | passed |
| Workflows | both YAML files parsed; actions pinned to commit SHAs obtained from GitHub | syntax valid |

## NOT TESTED (be aware)

* **`flutter pub get`, `flutter analyze`, `flutter test`, `flutter build apk` - NOT TESTED.** The Flutter SDK and pub.dev are not reachable from the build sandbox. The Flutter UI/API code (about 2,500 lines using Material, `http`, `file_selector`, `flutter_secure_storage`, `open_filex`, `path_provider`, `shared_preferences`) was written carefully and parses, but **has never been compiled**. A compile or analyzer error is possible on the first cloud build; the workflow uploads logs so it can be fixed quickly.
* **No APK was built.** Nothing was installed or run on an Android device (file picker, secure storage, opening PDFs, back navigation, connectivity to a LAN server are untested on a phone).
* **The GitHub Actions workflows have never run** on GitHub. The real Flutter-generated Gradle template may differ from the one simulated for `prepare_android.py`.
* **Windows batch files were not run on Windows** (`install_windows.bat`, `start_server.bat`, `stop_server.bat`, `allow_phone_access.bat`). The backend and CLI they call are tested on Linux. Windows Firewall rule creation is untested.
* **Visual appearance in real browsers** (desktop/mobile layout, dark/light, animations) was not inspected; only DOM behaviour (jsdom) and CSS syntax were tested.
* **Semgrep, Trivy and OWASP ZAP** were not available: their command lines, API calls and output parsing are **not tested against real tools**. OSV was tested only with a mocked API.
* **Public internet sites** could not be scanned from the sandbox; scanning was tested against local fixture servers (including real TLS).
* No load/performance testing, no penetration test of SecureScan AI itself, no accessibility audit with assistive technology.
* PostgreSQL was not tested (SQLite only).
