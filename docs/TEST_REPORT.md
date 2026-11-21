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

## First real GitHub Actions run (log supplied by the project owner)
The first cloud build ran on Ubuntu 24.04 with **Flutter 3.50.1 / Dart 3.14.0** and Java 17. What that log proved:

| Step | Result |
|---|---|
| Locate Flutter project, set up Java and Flutter | passed |
| `scripts/prepare_android.py` (`flutter create`, application id `com.securescanai.app`, overrides) | passed |
| Signing step with no secrets | passed (testing build) |
| `flutter pub get` | passed (all packages resolved) |
| Dart format check | reported 12 files as differently formatted (advisory step; cause: CI formats with the package language version, 3.7 at that time) |
| `flutter analyze --no-fatal-infos` | **failed - but only because of a file generated by Flutter**, `test/widget_test.dart` (Flutter's sample test refers to a `MyApp` class). The app's own code (`lib/`) had **0 errors and 0 warnings**, only informational notes |

Fixes made after that run: the prepare script now deletes Flutter's sample test, the project ships real widget tests (`mobile/test/widget_test.dart`), unbraced `if` statements were wrapped (lint notes), and the SDK floor was raised to 3.10 so formatting matches CI.

Still **not verified** after that run: `flutter test`, `flutter build apk`, and everything on a phone. The informational note "package:flutter/material.dart is deprecated" comes from Flutter 3.50 moving Material into a separate `material_ui` package; the old import still works and does not fail the build.

## NOT TESTED (be aware)

* **`flutter test` and `flutter build apk` - NOT VERIFIED.** The Flutter SDK is not reachable from the build sandbox. The first GitHub run (see above) confirmed `pub get` and that `lib/` analyzes cleanly, but the test and APK steps had not run yet when this report was written.
* **No APK was built.** Nothing was installed or run on an Android device (file picker, secure storage, opening PDFs, back navigation, connectivity to a LAN server are untested on a phone).
* **The GitHub Actions workflows have never run** on GitHub. The real Flutter-generated Gradle template may differ from the one simulated for `prepare_android.py`.
* **Windows batch files were not run on Windows** (`install_windows.bat`, `start_server.bat`, `stop_server.bat`, `allow_phone_access.bat`). The backend and CLI they call are tested on Linux. Windows Firewall rule creation is untested.
* **Visual appearance in real browsers** (desktop/mobile layout, dark/light, animations) was not inspected; only DOM behaviour (jsdom) and CSS syntax were tested.
* **Semgrep, Trivy and OWASP ZAP** were not available: their command lines, API calls and output parsing are **not tested against real tools**. OSV was tested only with a mocked API.
* **Public internet sites** could not be scanned from the sandbox; scanning was tested against local fixture servers (including real TLS).
* No load/performance testing, no penetration test of SecureScan AI itself, no accessibility audit with assistive technology.
* PostgreSQL was not tested (SQLite only).
