# Security

SecureScan AI is a security tool, so it is built to be safe to run and hard to misuse.

## Implemented controls

| Area | Control |
|---|---|
| Passwords | Argon2id hashing (argon2-cffi), 12+ character policy, no default password, no plaintext storage |
| Sessions | Random 256-bit tokens, stored only as HMAC-SHA256 digests, absolute expiry (default 8 h), server-side revocation on logout / disable / password change |
| Authentication abuse | Sliding-window rate limits per username and per IP (HTTP 429 with Retry-After), generic error messages, constant-time dummy hash for unknown users |
| Authorization | Role checks on every endpoint; users see only their own scans; admins cannot manage administrators; last Super Administrator is protected |
| Registration | No public registration; only administrators create accounts; first admin created by a one-time CLI command |
| SSRF / DNS rebinding | Targets are resolved once; **every** address must be globally routable; the TCP connection is made to the validated IP (no second DNS lookup); redirects are followed manually and re-validated; localhost, private, loopback, link-local, reserved, multicast, shared (100.64/10), 6to4/Teredo and IPv4-mapped addresses are blocked; credentials in URLs and non-http(s) schemes are rejected |
| Outbound limits | Timeouts, response-size cap, redirect cap, per-scan request budget, delay between requests, cancellation and global scan time limit |
| TLS | Certificate validation is never disabled - not in scans, not in the Android app. Invalid certificates are reported as findings |
| Active checks | Off unless the host is on the administrator-maintained allowlist **and** the user ticks the authorization box. Only harmless probes; no exploit payloads, brute force, stealth or destructive tests |
| ZIP uploads | Size limit while streaming; ZIP magic check; path traversal, absolute paths, symlinks and encrypted entries rejected; entry-count, total-size and compression-ratio (ZIP bomb) limits; only text/manifest files are extracted; extracted files are never executable; nothing is executed or installed; upload and extracted copy are deleted after the scan |
| Secrets in results | Secret values are redacted before storage; cookie values are never stored; exposed-file contents are never stored |
| Reports | Access checked per scan; `Cache-Control: no-store`; CSV formula-injection neutralised; PDF text escaped |
| HTTP hardening | Strict CSP (no inline script/style), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, HSTS when served over HTTPS, request-size limits, no API docs exposed |
| Audit | Sign-ins, failures, user changes, scans, cancellations, report downloads, allowlist changes (never passwords or tokens) |
| Android | Only the `INTERNET` permission; token in the Android Keystore (flutter_secure_storage); `allowBackup=false`; system CA store only; app refuses `http://` except for private/LAN hosts and refuses `localhost` |

## Things you must do
1. **Keep it on a trusted network.** `allow_phone_access.bat` opens the port for the Private profile and local subnet only. Never port-forward it to the internet.
2. **Use HTTPS when it matters.** Plain HTTP on a LAN lets anyone on that network read tokens. Put a certificate in `.env` (`SSAI_SSL_CERTFILE`, `SSAI_SSL_KEYFILE`) or use a reverse proxy. The server refuses to listen on the network over HTTP unless you set `SSAI_ALLOW_INSECURE_HTTP=true`.
3. **Protect `.env` and `data/`** (database, secret key). They are excluded from Git by `.gitignore`. Back up `data/`.
4. **Never commit a keystore or passwords.** Signing secrets belong in GitHub *Secrets* only.
5. **Only scan what you are authorized to scan.**

## Known limitations
* `SSAI_ALLOW_PRIVATE_TARGETS=true` disables the private-address protection; it exists for development and must stay `false`.
* OWASP ZAP sends its own traffic. SecureScan AI validates the starting URL, but ZAP follows links itself; use it only for allowlisted targets.
* Rate limits and scan queues are in memory (single process).
* OSV lookups (opt-in) send package names and versions to api.osv.dev.
* No automated penetration testing was performed on SecureScan AI itself beyond the tests listed in `docs/TEST_REPORT.md`.

## Reporting a vulnerability
Open a private security advisory in your repository (Security > Advisories) or contact the maintainer directly. Please do not publish details before a fix exists.
