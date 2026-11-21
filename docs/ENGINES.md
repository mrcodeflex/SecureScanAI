# Optional scanning engines

SecureScan AI works fully with its **built-in** engines. Optional engines add depth. The app always shows the true state of each engine (Settings > Scan engines, or `python -m app.cli doctor`):

| State | Meaning |
|---|---|
| installed | found and usable |
| not installed | not found - a scan that selects it records "scan not performed" |
| disabled | turned off by configuration (OSV, by default) |
| unreachable | configured but not answering (ZAP) |

Nothing is simulated: if an engine is missing, no results are invented.

## Semgrep (source code)
* Docs: <https://semgrep.dev/docs/>
* Detection: `semgrep` on the PATH. Command run: `semgrep scan --config <SSAI_SEMGREP_CONFIG> --json --quiet --metrics=off ...`
* Default ruleset `p/default` is downloaded from the Semgrep registry (needs internet). For offline use point `SSAI_SEMGREP_CONFIG` to a local rules folder.
* Windows: check Semgrep's current installation page. If `semgrep --version` works in a normal Windows Command Prompt, SecureScan AI will use it automatically. If it only runs inside WSL, it is not visible to the Windows server and will be shown as *not installed*.
* Results are reported as "potential" findings with Semgrep's own confidence.

## Trivy (dependencies, secrets, misconfiguration)
* Docs: <https://trivy.dev/latest/docs/>
* Install: `winget install AquaSecurity.Trivy` (or download the Windows zip from the Trivy releases page and add it to PATH). Check with `trivy --version`.
* Command run: `trivy fs --format json --scanners vuln,secret,misconfig <extracted folder>`; the first run downloads its vulnerability database.
* Vulnerabilities matched to exact package versions are reported as **verified vulnerabilities** with CVSS when Trivy provides it.

## OSV.dev dependency lookup (built-in, opt-in)
* Docs: <https://google.github.io/osv.dev/api/>
* Enable with `SSAI_ENABLE_OSV=true`. **Privacy:** exact package names and versions are sent to `api.osv.dev`.
* Reads exactly pinned dependencies from `requirements.txt`, `package-lock.json` and `package.json`.

## OWASP ZAP (websites, allowlisted targets only)
* Docs: <https://www.zaproxy.org/docs/>
* Install ZAP, start it in daemon mode, for example: `zap.bat -daemon -port 8090 -config api.key=CHOOSE_A_LONG_RANDOM_KEY`
* In `.env`: `SSAI_ZAP_URL=http://127.0.0.1:8090` and `SSAI_ZAP_API_KEY=CHOOSE_A_LONG_RANDOM_KEY`
* Used only when the scan is **Advanced**, the host is on the **authorization allowlist** and ZAP is selected. SecureScan AI runs spider + passive scan (and ZAP's active scan when active checks are enabled), then imports the alerts.
* ZAP sends its own HTTP traffic and follows links itself, so the SSRF protections of the built-in scanner do not apply to it. Use it only on targets you own.

## Honest status of these integrations
The adapters are implemented against the engines' documented command lines and APIs. In the development environment Semgrep, Trivy and ZAP could **not** be run, so their output parsing is **not tested against real tool output** (OSV parsing is tested with a mocked API). See `docs/TEST_REPORT.md`.
