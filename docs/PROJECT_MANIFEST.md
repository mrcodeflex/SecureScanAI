# Project file manifest

100 files (generated). Folders: `app/` backend + web UI, `mobile/` Android app, `scripts/`, `docs/`, `.github/`.

| File | Purpose |
|---|---|
| `.env.example` |  |
| `.gitattributes` |  |
| `.github/workflows/android-build.yml` | Cloud APK build |
| `.github/workflows/backend-tests.yml` | Backend tests in CI |
| `.gitignore` |  |
| `ANDROID_BUILD_GUIDE.md` |  |
| `GITHUB_UPLOAD_GUIDE.md` |  |
| `LICENSE` |  |
| `README.md` |  |
| `SECURITY.md` |  |
| `allow_phone_access.bat` | Enable LAN/phone access + firewall rule |
| `app/__init__.py` |  |
| `app/api/__init__.py` |  |
| `app/api/auth.py` | Login, logout, password change |
| `app/api/deps.py` | Auth dependencies |
| `app/api/scans.py` | Scan API and reports |
| `app/api/system.py` | Dashboard, health, engines, targets, audit |
| `app/api/users.py` | User management |
| `app/cli.py` | Command line: init-admin, serve, doctor, enable-lan... |
| `app/config.py` | Settings from environment/.env |
| `app/database.py` | SQLAlchemy engine/session |
| `app/main.py` | FastAPI application, security middleware, static mount |
| `app/models.py` | Database models and roles |
| `app/reports/__init__.py` |  |
| `app/reports/common.py` | Shared report text |
| `app/reports/exports.py` | JSON and CSV reports |
| `app/reports/pdf.py` | PDF report |
| `app/scanners/__init__.py` |  |
| `app/scanners/base.py` | Scan context, scoring |
| `app/scanners/engines.py` | Semgrep/Trivy/OSV/ZAP adapters |
| `app/scanners/knowledge.py` | Rule knowledge base and scoring constants |
| `app/scanners/netsafe.py` | SSRF-safe HTTP client + TLS inspection |
| `app/scanners/source_scan.py` | Safe ZIP extraction + source rules |
| `app/scanners/web_checks.py` | Website checks (passive + active) |
| `app/services/__init__.py` |  |
| `app/services/audit.py` | Audit logging |
| `app/services/runner.py` | Background scan runner |
| `app/services/security.py` | Argon2id, tokens, password policy, rate limiter |
| `app/services/serializers.py` | JSON serializers |
| `app/static/assets/logo.svg` |  |
| `app/static/css/app.css` | Web UI styles |
| `app/static/index.html` |  |
| `app/static/js/app.js` | Web UI script |
| `app/static/js/charts.js` | Web UI script |
| `app/static/js/core.js` | Web UI script |
| `app/static/js/view-admin.js` | Web UI script |
| `app/static/js/view-auth.js` | Web UI script |
| `app/static/js/view-dashboard.js` | Web UI script |
| `app/static/js/view-results.js` | Web UI script |
| `app/static/js/view-scan.js` | Web UI script |
| `app/tests/__init__.py` | Backend tests |
| `app/tests/conftest.py` | Backend tests |
| `app/tests/test_auth_and_users.py` | Backend tests |
| `app/tests/test_scans_and_reports.py` | Backend tests |
| `app/tests/test_security_controls.py` | Backend tests |
| `docs/ARCHITECTURE.md` | Documentation |
| `docs/ENGINES.md` | Documentation |
| `docs/TEST_REPORT.md` | Documentation |
| `docs/TROUBLESHOOTING.md` | Documentation |
| `install_windows.bat` | Windows installer |
| `mobile/analysis_options.yaml` |  |
| `mobile/android_overrides/app/src/main/AndroidManifest.xml` | Android platform customisation |
| `mobile/android_overrides/app/src/main/kotlin/com/securescanai/app/MainActivity.kt` | Android platform customisation |
| `mobile/android_overrides/app/src/main/res/drawable/ic_launcher_foreground.xml` | Android platform customisation |
| `mobile/android_overrides/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml` | Android platform customisation |
| `mobile/android_overrides/app/src/main/res/values/ic_launcher_background.xml` | Android platform customisation |
| `mobile/android_overrides/app/src/main/res/xml/network_security_config.xml` | Android platform customisation |
| `mobile/lib/app.dart` | Root widget and screen selection |
| `mobile/lib/core/api_client.dart` | Flutter core (API client, models, state) |
| `mobile/lib/core/app_info.dart` | Flutter core (API client, models, state) |
| `mobile/lib/core/app_state.dart` | Flutter core (API client, models, state) |
| `mobile/lib/core/format.dart` | Flutter core (API client, models, state) |
| `mobile/lib/core/models.dart` | Flutter core (API client, models, state) |
| `mobile/lib/core/settings_store.dart` | Flutter core (API client, models, state) |
| `mobile/lib/core/url_rules.dart` | Flutter core (API client, models, state) |
| `mobile/lib/main.dart` | App entry point |
| `mobile/lib/ui/auth_screens.dart` | Flutter screens and widgets |
| `mobile/lib/ui/dashboard_screen.dart` | Flutter screens and widgets |
| `mobile/lib/ui/history_screen.dart` | Flutter screens and widgets |
| `mobile/lib/ui/home_shell.dart` | Flutter screens and widgets |
| `mobile/lib/ui/new_scan_screen.dart` | Flutter screens and widgets |
| `mobile/lib/ui/profile_screen.dart` | Flutter screens and widgets |
| `mobile/lib/ui/scan_detail_screen.dart` | Flutter screens and widgets |
| `mobile/lib/ui/theme.dart` | Flutter screens and widgets |
| `mobile/lib/ui/widgets.dart` | Flutter screens and widgets |
| `mobile/pubspec.yaml` | Flutter dependencies |
| `mobile/test/models_test.dart` | Flutter unit tests |
| `mobile/test/url_rules_test.dart` | Flutter unit tests |
| `pytest.ini` |  |
| `requirements-dev.txt` |  |
| `requirements.txt` |  |
| `scripts/configure_android_signing.py` | Optional release signing |
| `scripts/prepare_android.py` | Generate/prepare Android platform in CI |
| `scripts/ui_smoke/fixture_site.py` | UI smoke test (jsdom) |
| `scripts/ui_smoke/package-lock.json` | UI smoke test (jsdom) |
| `scripts/ui_smoke/package.json` | UI smoke test (jsdom) |
| `scripts/ui_smoke/run_ui_smoke.py` | UI smoke test (jsdom) |
| `scripts/ui_smoke/smoke.js` | UI smoke test (jsdom) |
| `start_server.bat` | Start the server |
| `stop_server.bat` | Stop the server |
