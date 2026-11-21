"""Built-in website checks: passive analysis plus low-impact active probes.

Passive checks only observe normal responses. Active checks send a handful of
harmless requests (no exploit payloads, no brute force) and are only run for
targets on the administrator-maintained authorization allowlist.
"""
from __future__ import annotations

import re
import secrets
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .base import Ctx, ScanError
from .netsafe import FetchError, inspect_tls, parse_target

CHECKS: dict[str, dict] = {
    "availability": {"label": "Availability and HTTPS", "kind": "passive",
                     "description": "Reachability, HTTP status, HTTPS use and HTTP-to-HTTPS redirect."},
    "headers": {"label": "Security headers", "kind": "passive",
                "description": "CSP, HSTS, X-Content-Type-Options, clickjacking, Referrer and Permissions policies."},
    "cookies": {"label": "Cookie flags", "kind": "passive",
                "description": "Secure, HttpOnly and SameSite attributes on cookies set by the site."},
    "tls": {"label": "TLS certificate", "kind": "passive",
            "description": "Certificate validity, expiry date, protocol and cipher."},
    "redirects": {"label": "Redirect behaviour", "kind": "passive",
                  "description": "HTTPS downgrades, cross-domain redirects and long chains."},
    "errors": {"label": "Error disclosure", "kind": "passive",
               "description": "Stack traces and database errors on the page and on a 404 response."},
    "forms": {"label": "Forms and page content", "kind": "passive",
              "description": "Insecure forms, mixed content and third-party scripts without integrity checks."},
    "tech": {"label": "Technology disclosure", "kind": "passive",
             "description": "Server, framework and generator information visible to visitors."},
    "methods": {"label": "HTTP methods", "kind": "active",
                "description": "OPTIONS and TRACE probes (2 requests)."},
    "exposure": {"label": "Sensitive files", "kind": "active",
                 "description": "Checks about 10 well-known paths such as /.git/HEAD and /.env, validating content."},
    "cors": {"label": "CORS policy", "kind": "active",
             "description": "One request with a foreign Origin header."},
    "reflection": {"label": "Input reflection", "kind": "active",
                   "description": "One request with a harmless marker to see whether input is echoed unencoded."},
}
PASSIVE_IDS = [k for k, v in CHECKS.items() if v["kind"] == "passive"]
ACTIVE_IDS = [k for k, v in CHECKS.items() if v["kind"] == "active"]


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.scripts: list[dict] = []
        self.resources: list[tuple[str, str]] = []
        self.generator = ""
        self.hints: set[str] = set()
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form" and len(self.forms) < 50:
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(),
                          "inputs": [], "hidden_names": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            itype = a.get("type", "text").lower()
            self._form["inputs"].append(itype)
            if itype == "hidden":
                self._form["hidden_names"].append(a.get("name", "").lower())
        elif tag == "script" and a.get("src") and len(self.scripts) < 200:
            self.scripts.append({"src": a["src"], "integrity": a.get("integrity", "")})
            self.resources.append(("script", a["src"]))
        elif tag == "iframe" and a.get("src"):
            self.resources.append(("iframe", a["src"]))
        elif tag == "link" and a.get("href") and "stylesheet" in a.get("rel", "").lower():
            self.resources.append(("stylesheet", a["href"]))
        elif tag in ("img", "source", "audio", "video") and a.get("src"):
            self.resources.append(("media", a["src"]))
        elif tag == "meta" and a.get("name", "").lower() == "generator":
            self.generator = a.get("content", "")[:120]
        if "/wp-content/" in (a.get("src", "") + a.get("href", "")):
            self.hints.add("WordPress")

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _page(ctx: Ctx) -> PageParser | None:
    if "parser" not in ctx.info:
        parser = None
        if ctx.main is not None and ctx.main.is_html:
            parser = PageParser()
            try:
                parser.feed(ctx.main.text[:600_000])
            except Exception:  # malformed markup must never fail the scan
                pass
        ctx.info["parser"] = parser
    return ctx.info["parser"]


def _final_scheme(ctx: Ctx) -> str:
    return urlsplit(ctx.main.url).scheme


# ---------------------------------------------------------------- passive
def check_availability(ctx: Ctx) -> None:
    m = ctx.main
    ctx.info["status_line"] = f"HTTP {m.status} {m.reason} in {m.elapsed_ms} ms"
    if m.status >= 500:
        ctx.add("WEB-ERR-002", ctx.info["status_line"], url=m.url, http_status=m.status)
    first = urlsplit(ctx.target_url)
    if _final_scheme(ctx) == "http":
        ctx.add("WEB-HTTPS-001", f"Final address {m.url} uses http://. {ctx.info['status_line']}.",
                url=m.url, http_status=m.status)
    elif first.scheme == "https":
        host = first.netloc
        try:
            probe = ctx.client.request(f"http://{first.hostname}/", follow_redirects=False)
            r = probe.response
            loc = r.header("location") or ""
            if r.status < 300 or r.status >= 400:
                if r.status < 500:
                    ctx.add("WEB-HTTPS-002", f"http://{first.hostname}/ answered HTTP {r.status} without redirecting.",
                            url=f"http://{first.hostname}/", http_status=r.status, confidence="medium")
            elif not loc.lower().startswith("https://"):
                ctx.add("WEB-HTTPS-002", f"http://{first.hostname}/ redirects to {loc[:200]}, which is not HTTPS.",
                        url=f"http://{first.hostname}/", http_status=r.status)
        except FetchError:
            ctx.notes.append(f"Port 80 on {host} did not answer, so the HTTP-to-HTTPS redirect could not be checked.")


def _csp_issues(csp: str) -> list[str]:
    directives: dict[str, list[str]] = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives[bits[0].lower()] = [b.lower() for b in bits[1:]]
    src = directives.get("script-src") or directives.get("default-src")
    if src is None:
        return ["No script-src or default-src directive is defined."]
    issues = []
    strict = any(t.startswith("'nonce-") or t.startswith("'sha") or t == "'strict-dynamic'" for t in src)
    if "'unsafe-inline'" in src and not strict:
        issues.append("script-src allows 'unsafe-inline'.")
    if "'unsafe-eval'" in src:
        issues.append("script-src allows 'unsafe-eval'.")
    if any(t in ("*", "http:", "https:", "data:") for t in src):
        issues.append("script-src allows a wildcard or whole-scheme source.")
    return issues


def check_headers(ctx: Ctx) -> None:
    m, url = ctx.main, ctx.main.url
    https = _final_scheme(ctx) == "https"
    csp = m.header("content-security-policy")
    if not csp:
        report_only = m.header("content-security-policy-report-only")
        ev = "No Content-Security-Policy header in the response."
        if report_only:
            ev += " Only Content-Security-Policy-Report-Only is present, which does not enforce anything."
        ctx.add("WEB-HDR-001", ev, url=url, http_status=m.status)
    else:
        issues = _csp_issues(csp)
        if issues:
            ctx.add("WEB-HDR-002", " ".join(issues) + f"\nContent-Security-Policy: {csp[:600]}", url=url)
    if https:
        hsts = m.header("strict-transport-security")
        if not hsts:
            ctx.add("WEB-HDR-003", "No Strict-Transport-Security header on the HTTPS response.", url=url)
        else:
            age = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            if not age or int(age.group(1)) < 15552000:
                ctx.add("WEB-HDR-004", f"Strict-Transport-Security: {hsts[:200]}", url=url)
    if (m.header("x-content-type-options") or "").lower().strip() != "nosniff":
        ctx.add("WEB-HDR-005", f"X-Content-Type-Options: {m.header('x-content-type-options') or '(missing)'}", url=url)
    has_fa = "frame-ancestors" in (csp or "").lower()
    if not m.header("x-frame-options") and not has_fa and m.is_html:
        ctx.add("WEB-HDR-006", "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.", url=url)
    if not m.header("referrer-policy"):
        ctx.add("WEB-HDR-007", "No Referrer-Policy header in the response.", url=url)
    if not m.header("permissions-policy") and not m.header("feature-policy"):
        ctx.add("WEB-HDR-008", "No Permissions-Policy header in the response.", url=url)


_SESSIONISH = re.compile(r"(sess|sid|auth|token|jwt|login|csrf|xsrf)", re.I)


def check_cookies(ctx: Ctx) -> None:
    problems: dict[str, list[str]] = {}
    seen: set[str] = set()
    for resp in ctx.chain:
        for raw in resp.header_all("set-cookie"):
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=", 1)[0].strip()
            if not name or name in seen:
                continue
            seen.add(name)
            attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip().lower() if "=" in p else "")
                     for p in parts[1:]}
            shown = f"Set-Cookie: {name}=<redacted>; " + "; ".join(parts[1:])[:200]
            sess = bool(_SESSIONISH.search(name))
            if "secure" not in attrs:
                problems.setdefault("WEB-COOKIE-001", []).append((shown, sess))
            if "httponly" not in attrs:
                problems.setdefault("WEB-COOKIE-002", []).append((shown, sess))
            if "samesite" not in attrs:
                problems.setdefault("WEB-COOKIE-003", []).append((shown, sess))
            elif attrs.get("samesite") == "none" and "secure" not in attrs:
                problems.setdefault("WEB-COOKIE-004", []).append((shown, sess))
    ctx.info["cookie_count"] = len(seen)
    for rule, items in problems.items():
        any_sess = any(s for _, s in items)
        sev = None if any_sess or rule in ("WEB-COOKIE-003",) else "low"
        ctx.add(rule, "\n".join(e for e, _ in items[:10]), url=ctx.main.url, severity=sev,
                confidence="high" if any_sess else "medium")


def check_tls(ctx: Ctx) -> None:
    final = urlsplit(ctx.main.url)
    host = final.hostname or ""
    port = final.port or 443 if final.scheme == "https" else 443
    try:
        t = parse_target(f"https://{host}:{port}/", ctx.client.allow_private, resolve=True)
    except Exception as exc:  # unresolvable / unsafe
        ctx.notes.append(f"TLS inspection skipped: {exc}")
        return
    info = inspect_tls(t.host, t.port, t.ips[0], ctx.client.timeout)
    ctx.info["tls"] = info
    if "error" in info:
        if final.scheme == "https" or "certificate" in info["error"].lower():
            ctx.add("WEB-TLS-001", info["error"], url=f"https://{host}:{port}/")
        else:
            ctx.notes.append("HTTPS is not available on port 443 for this host.")
        return
    days = info.get("days_left")
    if days is not None and days <= 30:
        ctx.add("WEB-TLS-002", f"Certificate expires {info.get('not_after')} ({days} days left).",
                url=f"https://{host}:{port}/", severity="high" if days <= 7 else None)
    ctx.add("WEB-TLS-010",
            f"Protocol: {info.get('protocol')}; cipher: {info.get('cipher')}; issuer: {info.get('issuer')}; "
            f"subject: {info.get('subject')}; expires: {info.get('not_after')} ({days} days left).")


def check_redirects(ctx: Ctx) -> None:
    chain = ctx.chain
    hops = [r for r in chain if r.status in (301, 302, 303, 307, 308)]
    if len(hops) > 3:
        ctx.add("WEB-REDIR-003", " -> ".join(f"{r.status} {r.url[:80]}" for r in chain[:8]), url=chain[0].url)
    for prev, nxt in zip(chain, chain[1:]):
        a, b = urlsplit(prev.url), urlsplit(nxt.url)
        if a.scheme == "https" and b.scheme == "http":
            ctx.add("WEB-REDIR-001", f"{prev.url[:150]} redirected to {nxt.url[:150]}", url=prev.url)
        if (a.hostname or "").removeprefix("www.") != (b.hostname or "").removeprefix("www."):
            ctx.add("WEB-REDIR-002", f"{a.hostname} redirected to {b.hostname}", url=prev.url)


ERROR_PATTERNS = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"(?:Fatal error|Parse error|Warning)</b>:.{0,200}on line <b>\d+|(?:Fatal error|Parse error): .{0,200} on line \d+",
     "PHP error message"),
    (r"at [\w$.]+\([\w$]+\.java:\d+\)", "Java stack trace"),
    (r"Server Error in '[^']*' Application", "ASP.NET error page"),
    (r"You have an error in your SQL syntax|SQLSTATE\[\w+\]|ORA-\d{5}|PSQLException|Microsoft OLE DB Provider",
     "Database error message"),
    (r"You're seeing this error because you have <code>DEBUG = True|Werkzeug Debugger|Rails\.root:",
     "Framework debug page"),
]


def check_errors(ctx: Ctx) -> None:
    bodies = [("the page", ctx.main.text[:300_000], ctx.main.url)]
    probe_url = urljoin(ctx.main.url, f"/ssai-not-found-{secrets.token_hex(4)}")
    try:
        probe = ctx.client.request(probe_url, follow_redirects=False).response
        ctx.info["soft404"] = probe.status == 200
        bodies.append((f"a 404 probe (HTTP {probe.status})", probe.text[:300_000], probe_url))
    except FetchError:
        pass
    for where, text, url in bodies:
        for pattern, label in ERROR_PATTERNS:
            m = re.search(pattern, text, re.S)
            if m:
                snippet = re.sub(r"\s+", " ", text[max(0, m.start() - 40): m.end() + 120])[:260]
                ctx.add("WEB-ERR-001", f"{label} found in {where}: ...{snippet}...", url=url)
                break


def check_forms(ctx: Ctx) -> None:
    page = _page(ctx)
    if page is None:
        ctx.notes.append("The main response is not HTML, so form and content checks were skipped.")
        return
    https = _final_scheme(ctx) == "https"
    base = ctx.main.url
    for form in page.forms:
        has_pw = "password" in form["inputs"]
        action = urljoin(base, form["action"]) if form["action"] else base
        if has_pw and not https:
            ctx.add("WEB-FORM-001", f"Form with password field at {base}.", url=base)
        if urlsplit(action).scheme == "http" and (https or has_pw):
            ctx.add("WEB-FORM-002", f"Form action: {action[:300]}", url=base)
        if has_pw and form["method"] == "get":
            ctx.add("WEB-FORM-003", f"Form action {action[:200]} uses method GET.", url=base)
        if form["method"] == "post" and not any(
                re.search(r"csrf|xsrf|token|nonce|authenticity", n) for n in form["hidden_names"]):
            ctx.add("WEB-FORM-004", f"POST form to {action[:200]} has no hidden field that looks like a CSRF token.",
                    url=base, confidence="low")
    host = urlsplit(base).hostname
    active_mixed, passive_mixed = [], []
    for kind, ref in page.resources:
        full = urljoin(base, ref)
        if https and full.lower().startswith("http://"):
            (passive_mixed if kind == "media" else active_mixed).append(f"{kind}: {full[:200]}")
    if active_mixed:
        ctx.add("WEB-MIXED-001", "\n".join(active_mixed[:10]), url=base)
    if passive_mixed:
        ctx.add("WEB-MIXED-002", "\n".join(passive_mixed[:10]), url=base)
    no_sri = []
    for s in page.scripts:
        full = urljoin(base, s["src"])
        sh = urlsplit(full).hostname
        if sh and host and sh != host and not s["integrity"]:
            no_sri.append(full[:200])
    if no_sri:
        ctx.add("WEB-SRI-001", "\n".join(no_sri[:10]), url=base, confidence="medium")


def check_tech(ctx: Ctx) -> None:
    m = ctx.main
    detected: list[str] = []
    server = m.header("server")
    if server:
        detected.append(f"Server: {server}")
        if re.search(r"\d+\.\d+|/\d", server):
            ctx.add("WEB-DISC-001", f"Server: {server}", url=m.url)
    for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        v = m.header(h)
        if v:
            detected.append(f"{h}: {v}")
            ctx.add("WEB-DISC-002", f"{h}: {v}", url=m.url, severity="low" if re.search(r"\d", v) else "info")
    page = _page(ctx)
    if page and page.generator:
        detected.append(f"Generator meta tag: {page.generator}")
    if page:
        detected.extend(sorted(page.hints))
    for resp in ctx.chain:
        for raw in resp.header_all("set-cookie"):
            name = raw.split("=", 1)[0].strip()
            hint = {"PHPSESSID": "PHP", "JSESSIONID": "Java servlet container",
                    "ASP.NET_SessionId": "ASP.NET", "laravel_session": "Laravel", "csrftoken": "Django"}.get(name)
            if hint and hint not in detected:
                detected.append(hint)
    ctx.info["technologies"] = detected
    if detected:
        ctx.add("WEB-TECH-001", "\n".join(detected[:20]), url=m.url)


# ----------------------------------------------------------------- active
def check_methods(ctx: Ctx) -> None:
    origin = f"{urlsplit(ctx.main.url).scheme}://{urlsplit(ctx.main.url).netloc}/"
    try:
        r = ctx.client.request(origin, method="OPTIONS", follow_redirects=False).response
        allow = r.header("allow") or ""
        risky = [x.strip() for x in allow.split(",") if x.strip().upper() in ("PUT", "DELETE", "PATCH", "CONNECT")]
        if risky:
            ctx.add("WEB-ACT-002", f"OPTIONS / returned Allow: {allow[:200]}", url=origin, confidence="low",
                    severity="low", finding_type="potential")
    except FetchError:
        pass
    try:
        probe = secrets.token_hex(6)
        r = ctx.client.request(origin, method="TRACE", headers={"X-SSAI-Probe": probe}, follow_redirects=False).response
        if r.status == 200 and probe in r.text:
            ctx.add("WEB-ACT-002", "TRACE / returned HTTP 200 and echoed the request headers back.", url=origin,
                    http_status=200)
    except FetchError:
        pass


EXPOSURE = [
    ("/.git/HEAD", lambda b: b.lstrip().startswith(b"ref:"), "Git repository metadata", "high"),
    ("/.env", lambda b: re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}=.+", b) is not None, "Environment file", "high"),
    ("/.htpasswd", lambda b: re.match(rb"^[\w.@-]+:(\$|\{)?\w", b.lstrip()) is not None, "Password file", "high"),
    ("/backup.sql", lambda b: b"CREATE TABLE" in b[:200000] or b"INSERT INTO" in b[:200000], "SQL dump", "high"),
    ("/database.sql", lambda b: b"CREATE TABLE" in b[:200000] or b"INSERT INTO" in b[:200000], "SQL dump", "high"),
    ("/phpinfo.php", lambda b: b"phpinfo()" in b or b"PHP Version" in b, "phpinfo() output", "medium"),
    ("/server-status", lambda b: b"Apache Server Status" in b, "Apache server-status page", "medium"),
    ("/.DS_Store", lambda b: b.startswith(b"\x00\x00\x00\x01Bud1"), "macOS directory metadata", "low"),
]


def check_exposure(ctx: Ctx) -> None:
    sp = urlsplit(ctx.main.url)
    base = f"{sp.scheme}://{sp.netloc}"
    for path, validator, label, sev in EXPOSURE:
        try:
            r = ctx.client.request(base + path, follow_redirects=False).response
        except FetchError:
            continue
        if r.status == 200 and r.body and validator(r.body):
            ctx.add("WEB-ACT-001", f"{label} is readable at {base + path} (HTTP 200, {len(r.body)} bytes). "
                    "Contents are intentionally not stored.", url=base + path, severity=sev, http_status=200,
                    title=f"Sensitive file exposed: {path}")
    try:
        r = ctx.client.request(base + "/.well-known/security.txt", follow_redirects=False).response
        if not (r.status == 200 and b"contact:" in r.body.lower()):
            ctx.add("WEB-INFO-001", "/.well-known/security.txt did not return a valid file.", url=base)
    except FetchError:
        pass


def check_cors(ctx: Ctx) -> None:
    probe = "https://ssai-probe.invalid"
    try:
        r = ctx.client.request(ctx.main.url, headers={"Origin": probe}, follow_redirects=False).response
    except FetchError:
        return
    acao = r.header("access-control-allow-origin") or ""
    creds = (r.header("access-control-allow-credentials") or "").lower() == "true"
    if acao == probe:
        ctx.add("WEB-ACT-003", f"Origin {probe} was reflected in Access-Control-Allow-Origin"
                + (" together with Allow-Credentials: true." if creds else "."),
                url=ctx.main.url, severity="high" if creds else "medium")
    elif acao == "*":
        ctx.add("WEB-ACT-003", "Access-Control-Allow-Origin: * (any website may read public responses).",
                url=ctx.main.url, severity="info", finding_type="observation",
                title="CORS allows any origin (*)")


def check_reflection(ctx: Ctx) -> None:
    marker = "ssai" + secrets.token_hex(4)
    payload = f'{marker}"\'<ssai>'
    sep = "&" if "?" in ctx.main.url else "?"
    url = f"{ctx.main.url.split('#')[0]}{sep}ssai_probe={payload.replace(chr(34), '%22').replace(chr(39), '%27').replace('<', '%3C').replace('>', '%3E')}"
    try:
        r = ctx.client.request(url, follow_redirects=False).response
    except FetchError:
        return
    if r.is_html and payload in r.text:
        i = r.text.index(payload)
        snippet = re.sub(r"\s+", " ", r.text[max(0, i - 60): i + len(payload) + 60])
        ctx.add("WEB-ACT-004", f"Harmless marker with special characters was echoed unencoded: ...{snippet}...",
                url=url, confidence="low")


STEPS = [
    ("availability", check_availability), ("headers", check_headers), ("cookies", check_cookies),
    ("tls", check_tls), ("redirects", check_redirects), ("errors", check_errors),
    ("forms", check_forms), ("tech", check_tech),
    ("methods", check_methods), ("exposure", check_exposure), ("cors", check_cors),
    ("reflection", check_reflection),
]


def run_web_checks(ctx: Ctx) -> None:
    ctx.progress(5, "Connecting to the target")
    try:
        result = ctx.client.request(ctx.target_url)
    except FetchError as exc:
        if exc.kind == "tls":
            ctx.add("WEB-TLS-001", str(exc), url=ctx.target_url)
            ctx.notes.append("Page checks were skipped because the TLS certificate failed validation.")
            return
        raise ScanError(f"Could not reach the target: {exc}") from exc
    ctx.main, ctx.chain = result.response, result.chain
    selected = [(cid, fn) for cid, fn in STEPS
                if cid in ctx.selected_checks and (CHECKS[cid]["kind"] == "passive" or ctx.active_allowed)]
    for i, (cid, fn) in enumerate(selected):
        ctx.progress(10 + int(80 * i / max(1, len(selected))), f"Checking: {CHECKS[cid]['label']}")
        try:
            fn(ctx)
        except FetchError as exc:
            ctx.notes.append(f"Check '{CHECKS[cid]['label']}' was incomplete: {exc}")
    skipped = [cid for cid in ctx.selected_checks if CHECKS[cid]["kind"] == "active" and not ctx.active_allowed]
    if skipped:
        ctx.notes.append("Active checks were not performed (target is not on the authorization allowlist).")
