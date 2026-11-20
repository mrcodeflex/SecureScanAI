"""Optional external scanning engines: Semgrep, Trivy, OSV.dev and OWASP ZAP.

Each engine reports an honest state. Nothing here is simulated: if a tool is
missing or unreachable, the scan records 'not installed' / 'scan not performed'.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from ..config import settings

DOCS = {
    "semgrep": "https://semgrep.dev/docs/",
    "trivy": "https://trivy.dev/latest/docs/",
    "zap": "https://www.zaproxy.org/docs/",
    "osv": "https://google.github.io/osv.dev/api/",
}
_cache: dict[str, tuple[float, dict]] = {}


def _run(cmd: list[str], timeout: int, should_cancel: Callable[[], bool], cwd: Path | None = None):
    """Run a command (never through a shell) with timeout and cancellation support."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, text=True,
                            encoding="utf-8", errors="replace")
    deadline = time.monotonic() + timeout
    out = err = ""
    while True:
        try:
            out, err = proc.communicate(timeout=1)
            return proc.returncode, out, err
        except subprocess.TimeoutExpired:
            if should_cancel() or time.monotonic() > deadline:
                proc.kill()
                proc.communicate()
                raise TimeoutError("cancelled" if should_cancel() else f"timed out after {timeout}s")


def _version(binary: str, args: list[str]) -> str:
    try:
        res = subprocess.run([binary, *args], capture_output=True, text=True, timeout=20)
        match = re.search(r"\d+\.\d+(?:\.\d+)?", res.stdout + res.stderr)
        return match.group(0) if match else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _zap_get(path: str, params: dict | None = None, timeout: int = 30) -> dict:
    query = dict(params or {})
    if settings.zap_api_key:
        query["apikey"] = settings.zap_api_key
    url = f"{settings.zap_url.rstrip('/')}{path}?{urllib.parse.urlencode(query)}"
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # URL is administrator-configured
        return json.loads(resp.read().decode("utf-8", "replace"))


def engines_overview() -> list[dict]:
    cached = _cache.get("overview")
    if cached and time.monotonic() - cached[0] < 30:
        return cached[1]["data"]
    data: list[dict] = [
        {"id": "builtin-web", "name": "SecureScan built-in website checks", "kind": "website",
         "state": "installed", "version": "1.0", "detail": "Always available.", "install_hint": "", "docs": ""},
        {"id": "builtin-source", "name": "SecureScan built-in source rules", "kind": "source",
         "state": "installed", "version": "1.0", "detail": "Pattern rules; findings need review.",
         "install_hint": "", "docs": ""},
    ]
    sg = shutil.which("semgrep")
    data.append({"id": "semgrep", "name": "Semgrep", "kind": "source",
                 "state": "installed" if sg else "not_installed",
                 "version": _version(sg, ["--version"]) if sg else "",
                 "detail": f"Ruleset: {settings.semgrep_config}" if sg else "Not found on PATH.",
                 "install_hint": "pip install semgrep   (Linux/macOS/WSL; see docs/ENGINES.md for Windows)",
                 "docs": DOCS["semgrep"]})
    tv = shutil.which("trivy")
    data.append({"id": "trivy", "name": "Trivy", "kind": "source",
                 "state": "installed" if tv else "not_installed",
                 "version": _version(tv, ["--version"]) if tv else "",
                 "detail": "Dependency vulnerabilities, secrets and misconfigurations." if tv else "Not found on PATH.",
                 "install_hint": "winget install AquaSecurity.Trivy   (or download from the Trivy releases page)",
                 "docs": DOCS["trivy"]})
    data.append({"id": "osv", "name": "OSV.dev dependency lookup", "kind": "source",
                 "state": "available" if settings.osv_enabled else "disabled", "version": "",
                 "detail": ("Enabled. Package names and versions are sent to api.osv.dev."
                            if settings.osv_enabled else "Disabled by default for privacy."),
                 "install_hint": "Set SSAI_ENABLE_OSV=true in .env to allow lookups against api.osv.dev.",
                 "docs": DOCS["osv"]})
    if settings.zap_url:
        try:
            ver = _zap_get("/JSON/core/view/version/", timeout=4).get("version", "unknown")
            state, detail = "installed", f"Connected to {settings.zap_url}"
        except (OSError, ValueError, urllib.error.URLError):
            ver, state, detail = "", "unreachable", f"Could not reach ZAP at {settings.zap_url}"
    else:
        ver, state, detail = "", "not_installed", "SSAI_ZAP_URL is not configured."
    data.append({"id": "zap", "name": "OWASP ZAP", "kind": "website", "state": state, "version": ver,
                 "detail": detail, "install_hint": "Start ZAP in daemon mode and set SSAI_ZAP_URL / SSAI_ZAP_API_KEY.",
                 "docs": DOCS["zap"]})
    _cache["overview"] = (time.monotonic(), {"data": data})
    return data


def engine_state(engine_id: str) -> str:
    for e in engines_overview():
        if e["id"] == engine_id:
            return e["state"]
    return "not_installed"


def _rel(path: str, root: Path) -> str:
    p = path.replace("\\", "/")
    r = root.as_posix().rstrip("/") + "/"
    return p[len(r):] if p.startswith(r) else p.lstrip("/")


# ----------------------------------------------------------------- Semgrep
def run_semgrep(root: Path, should_cancel) -> tuple[str, str, list[dict]]:
    exe = shutil.which("semgrep")
    if not exe:
        return "not_installed", "Semgrep is not installed; scan not performed.", []
    cmd = [exe, "scan", "--config", settings.semgrep_config, "--json", "--quiet", "--metrics=off",
           "--disable-version-check", "--timeout", "20", "--max-target-bytes", "2000000", str(root)]
    try:
        rc, out, err = _run(cmd, settings.semgrep_timeout, should_cancel)
    except TimeoutError as exc:
        return "failed", f"Semgrep {exc}.", []
    if rc not in (0, 1) or not out.strip():
        return "failed", f"Semgrep exited with code {rc}: {err.strip()[-300:]}", []
    try:
        data = json.loads(out)
    except ValueError:
        return "failed", "Semgrep returned unreadable output.", []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    conf_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for r in data.get("results", [])[:1000]:
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwe = meta.get("cwe")
        if isinstance(cwe, list):
            cwe = ", ".join(str(c).split(":")[0] for c in cwe[:3])
        elif isinstance(cwe, str):
            cwe = cwe.split(":")[0]
        lines = extra.get("lines") or ""
        findings.append({
            "rule_id": str(r.get("check_id", ""))[-120:], "title": (extra.get("message") or r.get("check_id", ""))[:200].split("\n")[0],
            "severity": sev_map.get(str(extra.get("severity", "")).upper(), "low"),
            "category": str(meta.get("category") or "Static analysis").title()[:80],
            "finding_type": "potential", "confidence": conf_map.get(str(meta.get("confidence", "")).upper(), "medium"),
            "engine": "semgrep", "cwe": cwe, "file_path": _rel(r.get("path", ""), root),
            "line": (r.get("start") or {}).get("line"),
            "evidence": ("" if lines.startswith("requires login") else lines)[:400],
            "description": extra.get("message", "")[:1500], "simple_explanation": extra.get("message", "")[:500],
            "why_it_matters": "Reported by a Semgrep rule; review the code path to confirm exploitability.",
            "remediation": str(meta.get("fix") or extra.get("fix") or "See the rule documentation for the recommended fix.")[:600],
            "references": [str(u) for u in (meta.get("references") or [])[:3]],
        })
    return "completed", f"{len(findings)} result(s) from ruleset {settings.semgrep_config}.", findings


# ------------------------------------------------------------------- Trivy
def run_trivy(root: Path, should_cancel) -> tuple[str, str, list[dict]]:
    exe = shutil.which("trivy")
    if not exe:
        return "not_installed", "Trivy is not installed; scan not performed.", []
    cmd = [exe, "fs", "--quiet", "--format", "json", "--scanners", "vuln,secret,misconfig",
           "--skip-dirs", "node_modules,.git", str(root)]
    try:
        rc, out, err = _run(cmd, settings.trivy_timeout, should_cancel)
    except TimeoutError as exc:
        return "failed", f"Trivy {exc}.", []
    if rc != 0 or not out.strip():
        return "failed", f"Trivy exited with code {rc}: {err.strip()[-300:]}", []
    try:
        data = json.loads(out)
    except ValueError:
        return "failed", "Trivy returned unreadable output.", []
    sev = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info"}
    findings = []
    for res in data.get("Results", []) or []:
        target = _rel(res.get("Target", ""), root)
        for v in (res.get("Vulnerabilities") or [])[:500]:
            score, vector = None, None
            for src in (v.get("CVSS") or {}).values():
                if src.get("V3Score") and (score is None or src["V3Score"] > score):
                    score, vector = src["V3Score"], src.get("V3Vector")
            fixed = v.get("FixedVersion")
            cwes = ", ".join(v.get("CweIDs") or [])[:200] or None
            findings.append({
                "rule_id": v.get("VulnerabilityID", ""), "severity": sev.get(v.get("Severity", "UNKNOWN"), "info"),
                "title": f"{v.get('VulnerabilityID')}: {v.get('PkgName')} {v.get('InstalledVersion')}"[:300],
                "category": "Dependencies", "finding_type": "vulnerability", "confidence": "high",
                "engine": "trivy", "cwe": cwes, "file_path": target, "line": None,
                "evidence": f"{v.get('PkgName')} {v.get('InstalledVersion')} is affected. " + (v.get("Title") or ""),
                "description": (v.get("Description") or v.get("Title") or "")[:1500],
                "simple_explanation": "A package used by this project has a publicly known security flaw.",
                "why_it_matters": "Attackers scan for known flaws in popular packages and exploit them automatically.",
                "remediation": f"Upgrade {v.get('PkgName')} to {fixed}." if fixed else
                               "No fixed version is published yet; consider an alternative package or mitigations.",
                "cvss_score": score, "cvss_vector": vector,
                "references": [u for u in [v.get("PrimaryURL")] if u],
            })
        for s in (res.get("Secrets") or [])[:200]:
            findings.append({
                "rule_id": s.get("RuleID", ""), "title": s.get("Title", "Secret detected")[:300],
                "severity": sev.get(s.get("Severity", "HIGH"), "high"), "category": "Secrets",
                "finding_type": "potential", "confidence": "medium", "engine": "trivy", "cwe": "CWE-798",
                "file_path": target, "line": s.get("StartLine"), "evidence": (s.get("Match") or "")[:300],
                "description": "Trivy found a value that matches a known secret format.",
                "simple_explanation": "A password or key appears to be stored in the project files.",
                "why_it_matters": "Anyone with access to the code can use the secret.",
                "remediation": "Rotate the secret and load it from the environment or a secrets manager.",
                "references": [],
            })
        for m in (res.get("Misconfigurations") or [])[:200]:
            findings.append({
                "rule_id": m.get("ID", ""), "title": (m.get("Title") or m.get("ID", ""))[:300],
                "severity": sev.get(m.get("Severity", "MEDIUM"), "medium"), "category": "Misconfiguration",
                "finding_type": "misconfiguration", "confidence": "medium", "engine": "trivy", "cwe": None,
                "file_path": target, "line": (m.get("CauseMetadata") or {}).get("StartLine"),
                "evidence": (m.get("Message") or "")[:400], "description": (m.get("Description") or "")[:1500],
                "simple_explanation": (m.get("Description") or "")[:500],
                "why_it_matters": "Insecure infrastructure settings are a common cause of breaches.",
                "remediation": (m.get("Resolution") or "See the rule documentation.")[:600],
                "references": [u for u in [m.get("PrimaryURL")] if u],
            })
    return "completed", f"{len(findings)} result(s).", findings


# --------------------------------------------------------------------- OSV
OSV_URL = "https://api.osv.dev/v1"


def _osv_http(path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(OSV_URL + path, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def collect_dependencies(root: Path) -> list[tuple[str, str, str, str]]:
    """Returns (ecosystem, name, version, manifest) for exactly pinned dependencies."""
    deps: dict[tuple, str] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        name, rel = p.name.lower(), p.relative_to(root).as_posix()
        try:
            if name == "requirements.txt":
                for line in p.read_text("utf-8", "replace").splitlines():
                    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.\-+!]+)", line)
                    if m:
                        deps[("PyPI", m.group(1), m.group(2))] = rel
            elif name == "package-lock.json":
                doc = json.loads(p.read_text("utf-8", "replace"))
                for path, meta in (doc.get("packages") or {}).items():
                    if path.startswith("node_modules/") and meta.get("version"):
                        deps[("npm", path.split("node_modules/")[-1], meta["version"])] = rel
            elif name == "package.json":
                doc = json.loads(p.read_text("utf-8", "replace"))
                for sect in ("dependencies", "devDependencies"):
                    for pkg, ver in (doc.get(sect) or {}).items():
                        if re.fullmatch(r"\d+\.\d+\.\d+", str(ver)):
                            deps[("npm", pkg, ver)] = rel
        except (OSError, ValueError):
            continue
    return [(e, n, v, m) for (e, n, v), m in deps.items()][:1500]


def run_osv(root: Path, should_cancel, http=_osv_http) -> tuple[str, str, list[dict]]:
    if not settings.osv_enabled:
        return "skipped", "OSV lookups are disabled (SSAI_ENABLE_OSV=false); scan not performed.", []
    deps = collect_dependencies(root)
    if not deps:
        return "completed", "No exactly pinned dependencies were found to look up.", []
    hits: list[tuple[tuple, str]] = []
    try:
        for i in range(0, len(deps), 500):
            if should_cancel():
                return "failed", "Cancelled.", []
            chunk = deps[i:i + 500]
            res = http("/querybatch", {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v}
                                                   for e, n, v, _ in chunk]})
            for dep, r in zip(chunk, res.get("results", [])):
                for vuln in (r.get("vulns") or [])[:20]:
                    hits.append((dep, vuln["id"]))
        details: dict[str, dict] = {}
        for vid in {h[1] for h in hits[:200]}:
            details[vid] = http(f"/vulns/{urllib.parse.quote(vid)}")
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return "failed", f"OSV lookup failed: {exc.__class__.__name__}. Scan not performed.", []
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for (eco, name, ver, manifest), vid in hits:
        d = details.get(vid, {})
        sev = sev_map.get(str((d.get("database_specific") or {}).get("severity", "")).upper(), "medium")
        fixed = next((ev["fixed"] for a in d.get("affected", []) for r in a.get("ranges", [])
                      for ev in r.get("events", []) if "fixed" in ev), None)
        vector = next((s.get("score") for s in d.get("severity", []) if str(s.get("type", "")).startswith("CVSS")), None)
        findings.append({
            "rule_id": vid, "title": f"{vid}: {name} {ver}"[:300], "severity": sev, "category": "Dependencies",
            "finding_type": "vulnerability", "confidence": "high", "engine": "osv", "cwe": None,
            "file_path": manifest, "line": None, "cvss_vector": vector,
            "evidence": f"{eco} package {name}=={ver}. " + (d.get("summary") or "")[:300],
            "description": (d.get("details") or d.get("summary") or "")[:1500],
            "simple_explanation": "A package used by this project has a publicly known security flaw.",
            "why_it_matters": "Known flaws in dependencies are exploited automatically at scale.",
            "remediation": f"Upgrade {name} to {fixed} or later." if fixed else "No fixed version listed; check the advisory.",
            "references": [f"https://osv.dev/vulnerability/{vid}"],
        })
    return "completed", f"{len(deps)} dependencies checked, {len(findings)} advisories matched.", findings


# --------------------------------------------------------------------- ZAP
def run_zap(target_url: str, active: bool, should_cancel, progress) -> tuple[str, str, list[dict]]:
    if not settings.zap_url:
        return "not_installed", "OWASP ZAP is not configured (SSAI_ZAP_URL); scan not performed.", []
    deadline = time.monotonic() + settings.zap_timeout
    try:
        _zap_get("/JSON/core/view/version/", timeout=5)

        def wait(path: str, params: dict, key: str, label: str, lo: int, hi: int) -> None:
            while True:
                if should_cancel():
                    raise TimeoutError("cancelled")
                if time.monotonic() > deadline:
                    raise TimeoutError("ZAP time limit reached")
                pct = int(_zap_get(path, params).get(key, 0))
                progress(lo + (hi - lo) * pct // 100, f"ZAP: {label} {pct}%")
                if pct >= 100:
                    return
                time.sleep(2)

        sid = _zap_get("/JSON/spider/action/scan/", {"url": target_url, "maxChildren": 30, "recurse": "true"})["scan"]
        wait("/JSON/spider/view/status/", {"scanId": sid}, "status", "spidering", 20, 50)
        while int(_zap_get("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0)) > 0:
            if should_cancel() or time.monotonic() > deadline:
                raise TimeoutError("cancelled or time limit reached")
            time.sleep(2)
        if active:
            aid = _zap_get("/JSON/ascan/action/scan/", {"url": target_url, "recurse": "true"})["scan"]
            wait("/JSON/ascan/view/status/", {"scanId": aid}, "status", "active scan", 50, 90)
        alerts = _zap_get("/JSON/core/view/alerts/", {"baseurl": target_url, "start": 0, "count": 500}).get("alerts", [])
    except (OSError, ValueError, KeyError, urllib.error.URLError, TimeoutError) as exc:
        return "failed", f"ZAP scan did not complete: {exc}", []
    sev = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    conf = {"High": "high", "Medium": "medium", "Low": "low", "User Confirmed": "high"}
    findings = []
    for a in alerts:
        if a.get("confidence") == "False Positive":
            continue
        risk = sev.get(a.get("risk", ""), "info")
        findings.append({
            "rule_id": f"ZAP-{a.get('pluginId', a.get('alertRef', ''))}", "title": (a.get("alert") or a.get("name", ""))[:300],
            "severity": risk, "category": "ZAP alert", "finding_type": "observation" if risk == "info" else "potential",
            "confidence": conf.get(a.get("confidence", ""), "medium"), "engine": "zap",
            "cwe": f"CWE-{a['cweid']}" if str(a.get("cweid", "")).isdigit() and int(a["cweid"]) > 0 else None,
            "url": a.get("url"), "evidence": " ".join(filter(None, [a.get("param") and f"Parameter: {a['param']}.",
                                                                      a.get("evidence")]))[:600],
            "description": re.sub(r"<[^>]+>", "", a.get("description", ""))[:1500],
            "simple_explanation": re.sub(r"<[^>]+>", "", a.get("description", ""))[:500],
            "why_it_matters": "Reported by OWASP ZAP; confirm the issue before treating it as exploitable.",
            "remediation": re.sub(r"<[^>]+>", "", a.get("solution", ""))[:800] or "See the ZAP alert documentation.",
            "references": [u for u in re.split(r"\s+", a.get("reference", "")) if u.startswith("http")][:3],
        })
    return "completed", f"{len(findings)} alert(s) ({'active + passive' if active else 'spider + passive'}).", findings
