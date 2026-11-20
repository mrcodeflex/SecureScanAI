"""Source-code scanning: hardened ZIP extraction and built-in pattern rules.

Uploaded code is NEVER executed and its dependencies are NEVER installed.
Pattern rules are heuristics: they are reported as 'potential' findings with a
confidence level and must be reviewed by a person. Secret values are redacted
before they reach the database or a report.
"""
from __future__ import annotations

import math
import re
import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
             "vendor", "target", ".idea", ".gradle", "site-packages", ".next", "bower_components", "Pods"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".go", ".rb", ".php",
            ".cs", ".c", ".h", ".cpp", ".hpp", ".cc", ".rs", ".swift", ".m", ".scala", ".sh", ".bash", ".ps1",
            ".bat", ".sql", ".html", ".htm", ".vue", ".svelte", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg",
            ".conf", ".env", ".properties", ".xml", ".gradle", ".tf", ".dart", ".lua", ".pl", ".txt", ".md",
            ".cshtml", ".erb", ".jsp", ".asp", ".aspx", ".twig"}
SPECIAL_NAMES = {"dockerfile", "makefile", ".env", "requirements.txt", "gemfile", "pipfile", "composer.json",
                 "composer.lock", "go.mod", "go.sum", "cargo.toml", "cargo.lock", "package.json",
                 "package-lock.json", "yarn.lock", "pom.xml", "build.gradle", "pyproject.toml", "poetry.lock",
                 ".npmrc", ".htaccess"}
MANIFESTS = {"requirements.txt", "pipfile", "pyproject.toml", "poetry.lock", "package.json", "package-lock.json",
             "yarn.lock", "pom.xml", "build.gradle", "go.mod", "composer.json", "composer.lock", "gemfile",
             "cargo.toml", "cargo.lock"}


class ArchiveError(Exception):
    """The uploaded archive is unsafe or invalid."""


def safe_extract(zip_path: Path, dest: Path, *, max_files: int, max_total_bytes: int,
                 max_file_bytes: int, max_ratio: int) -> dict:
    if not zipfile.is_zipfile(zip_path):
        raise ArchiveError("The uploaded file is not a valid ZIP archive.")
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    stats = {"extracted": 0, "bytes": 0, "skipped_vendor": 0, "skipped_binary": 0, "skipped_large": 0,
             "skipped_links": 0, "manifests": []}
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > max_files * 4:
            raise ArchiveError("The archive contains too many entries.")
        declared = sum(i.file_size for i in infos)
        packed = sum(i.compress_size for i in infos)
        if declared > max_total_bytes:
            raise ArchiveError(f"The archive expands to more than {max_total_bytes // (1024 * 1024)} MB.")
        if declared > 10 * 1024 * 1024 and declared / max(packed, 1) > max_ratio:
            raise ArchiveError("The archive compression ratio is suspiciously high (possible ZIP bomb).")
        candidates = []
        for info in infos:
            name = info.filename.replace("\\", "/")
            if "\x00" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name) \
                    or any(p == ".." for p in name.split("/")):
                raise ArchiveError("The archive contains an unsafe path (path traversal) and was rejected.")
            if info.flag_bits & 0x1:
                raise ArchiveError("Encrypted ZIP archives are not supported.")
            if info.is_dir():
                continue
            if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                stats["skipped_links"] += 1
                continue
            parts = [p for p in name.split("/") if p not in ("", ".")]
            if not parts:
                continue
            if any(p in SKIP_DIRS for p in parts[:-1]):
                stats["skipped_vendor"] += 1
                continue
            fname = parts[-1].lower()
            if Path(fname).suffix not in TEXT_EXT and fname not in SPECIAL_NAMES:
                stats["skipped_binary"] += 1
                continue
            if info.file_size > max_file_bytes:
                stats["skipped_large"] += 1
                continue
            candidates.append((info, parts))
        if len(candidates) > max_files:
            raise ArchiveError(f"The archive has more than {max_files} scannable files.")
        for info, parts in candidates:
            target = dest.joinpath(*parts).resolve()
            if dest not in target.parents:
                raise ArchiveError("The archive contains an unsafe path and was rejected.")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with zf.open(info) as src, open(target, "wb") as out:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_file_bytes:
                        raise ArchiveError("A file exceeded its declared size (corrupt or malicious archive).")
                    out.write(chunk)
            stats["extracted"] += 1
            stats["bytes"] += written
            if parts[-1].lower() in MANIFESTS:
                stats["manifests"].append("/".join(parts))
    return stats


def cleanup(*paths: Path) -> None:
    for p in paths:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink()
        except OSError:
            pass


# ------------------------------------------------------------------ rules
@dataclass
class Rule:
    id: str
    title: str
    severity: str
    category: str
    cwe: str
    patterns: list[str]
    simple: str
    why: str
    fix: str
    confidence: str = "low"
    mask: bool = False
    ext: set[str] | None = None


R = Rule
RULES: list[Rule] = [
    R("SRC-SEC-001", "Possible AWS access key in source", "high", "Secrets", "CWE-798",
      [r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"],
      "A string that looks like an Amazon Web Services access key is stored in the code.",
      "Anyone who can read the code can use the key. Keys in repositories are found by automated scanners within minutes.",
      "Revoke the key, create a new one, load it from the environment or a secrets manager and remove it from Git history.",
      "medium", True),
    R("SRC-SEC-002", "Private key committed to source", "high", "Secrets", "CWE-321",
      [r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"],
      "A private cryptographic key is stored in the code.",
      "Whoever has the key can impersonate your servers or decrypt your data.",
      "Remove the key, generate a new key pair, and store keys outside the repository.", "high", True),
    R("SRC-SEC-003", "Possible access token for GitHub or Slack", "high", "Secrets", "CWE-798",
      [r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", r"\bxox[baprs]-[0-9A-Za-z-]{10,}"],
      "A string that looks like a service access token is stored in the code.",
      "The token may give access to private repositories or workspaces.",
      "Revoke the token and use environment variables or a secrets manager.", "medium", True),
    R("SRC-SEC-004", "Possible payment or API provider key", "high", "Secrets", "CWE-798",
      [r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b", r"\bAIza[0-9A-Za-z_\-]{35}\b"],
      "A string that looks like a live API key (Stripe or Google) is stored in the code.",
      "Live keys can be abused to spend money or read data.",
      "Rotate the key and keep it in environment variables.", "medium", True),
    R("SRC-SEC-005", "Possible hard-coded API key or secret", "medium", "Secrets", "CWE-798",
      [r"""(?i)(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-/+=]{16,})["']"""],
      "A value that looks like a secret is assigned directly in the code.",
      "Secrets in source code end up in backups, forks and build logs.",
      "Read secrets from environment variables or a secrets manager, and rotate this value.", "low", True),
    R("SRC-SEC-006", "Possible hard-coded password", "medium", "Secrets", "CWE-259",
      [r"""(?i)\b(?:password|passwd|pwd)\b["']?\s*[:=]\s*["']([^"'\s]{4,})["']""",
       r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]{3,}@"],
      "A password is written directly in the code or a connection string.",
      "Anyone with access to the code can log in with it.",
      "Move the password to configuration outside the repository and change it.", "low", True),
    R("SRC-CRY-001", "Weak hash algorithm (MD5 / SHA-1)", "medium", "Cryptography", "CWE-328",
      [r"hashlib\.(?:md5|sha1)\(", r"""MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-?1)["']""",
       r"""createHash\(\s*['"](?:md5|sha1)['"]\)""", r"\b(?:md5|sha1)\(\s*\$"],
      "The code uses an old hash function that is no longer considered safe.",
      "MD5 and SHA-1 can be broken; they must not be used for passwords or signatures.",
      "Use SHA-256 or stronger for integrity, and Argon2id, bcrypt or scrypt for passwords.", "low"),
    R("SRC-CRY-002", "Weak or unsafe cipher mode", "medium", "Cryptography", "CWE-327",
      [r"AES/ECB|MODE_ECB", r"""Cipher\.getInstance\(\s*["'](?:DES|RC4|RC2)""", r"\bDES\.new\(|\bARC4\.new\("],
      "The code uses an outdated encryption algorithm or a mode that leaks patterns.",
      "Weak ciphers can be broken, exposing the protected data.",
      "Use AES-GCM or ChaCha20-Poly1305 from a maintained library.", "medium"),
    R("SRC-CRY-003", "Non-cryptographic random value used for a secret", "low", "Cryptography", "CWE-338",
      [r"(?i)(?:token|secret|password|nonce|session|otp).{0,40}(?:Math\.random|random\.random|\brand\()"],
      "A secret or token seems to be generated with an ordinary random function.",
      "Predictable tokens can be guessed by attackers.",
      "Use secrets.token_urlsafe (Python), crypto.randomBytes (Node) or SecureRandom (Java).", "low"),
    R("SRC-CRY-004", "TLS certificate verification disabled", "medium", "Cryptography", "CWE-295",
      [r"verify\s*=\s*False", r"rejectUnauthorized\s*:\s*false", r"InsecureSkipVerify\s*:\s*true",
       r"check_hostname\s*=\s*False", r"_create_unverified_context",
       r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)", r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"],
      "The code turns off the check that proves a server is who it claims to be.",
      "Without verification, attackers on the network can read or alter 'secure' connections.",
      "Remove the override and fix the certificate problem instead.", "medium"),
    R("SRC-DES-001", "Unsafe deserialization", "high", "Deserialization", "CWE-502",
      [r"\b(?:c?[Pp]ickle|marshal|dill)\.loads?\(", r"yaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?C?Safe)",
       r"\bunserialize\(\s*\$", r"\bObjectInputStream\(", r"\bBinaryFormatter\b", r"jsonpickle\.decode"],
      "The code rebuilds objects from data in a way that can run attacker-supplied code.",
      "If the data comes from a user, an attacker may be able to execute commands on your server.",
      "Use JSON or another data-only format; for YAML use safe_load; never deserialize untrusted data.", "low"),
    R("SRC-EXE-001", "Dynamic code evaluation", "medium", "Code injection", "CWE-95",
      [r"(?<![.\w])eval\s*\(\s*(?![\"'`])", r"(?<![.\w])exec\s*\(\s*(?![\"'`])", r"new Function\("],
      "The code runs text as program code.",
      "If any part of that text comes from a user, they can run their own code.",
      "Avoid eval/exec; use parsers or lookup tables instead.", "low", ext={".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".rb"}),
    R("SRC-SQL-001", "SQL built from string concatenation or formatting", "high", "Injection", "CWE-89",
      [r"""(?i)\b(?:execute|executemany|query|raw|exec)\s*\(\s*f["']""",
       r"""(?i)\b(?:execute|query|raw)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:\+|%|\.format)""",
       r"""(?i)\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^;\n]{0,120}["']\s*\+\s*\w+""",
       r"""(?i)f["']\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{""",
       r"(?i)`\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{",
       r"mysqli?_query\([^)]*\$_(?:GET|POST|REQUEST)"],
      "A database query appears to be assembled by joining text together, possibly with user input.",
      "This is how SQL injection happens: an attacker can read or change your database.",
      "Use parameterised queries / prepared statements and never join user input into SQL.", "low"),
    R("SRC-CMD-001", "Operating-system command built from dynamic input", "high", "Injection", "CWE-78",
      [r"\bos\.(?:system|popen)\(", r"subprocess\.\w+\([^)]*shell\s*=\s*True",
       r"child_process\.(?:exec|execSync)\(", r"Runtime\.getRuntime\(\)\.exec\(",
       r"\b(?:shell_exec|passthru|system|exec|popen|proc_open)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)",
       r"""exec\.Command\(\s*["'](?:sh|bash|cmd)["']"""],
      "The code runs a system command, which is dangerous if any part of it comes from a user.",
      "Command injection lets an attacker run their own commands on your server.",
      "Pass arguments as a list without a shell, validate input against an allowlist, or use a library instead.", "low"),
    R("SRC-FILE-001", "File path built from request input", "medium", "File handling", "CWE-22",
      [r"(?i)\b(?:open|send_file|send_from_directory|readFile(?:Sync)?|file_get_contents|include|require)(?:_once)?\s*\(?[^\n]{0,80}(?:request\.(?:args|form|GET|POST|params|query)|req\.(?:query|params|body)|\$_(?:GET|POST|REQUEST))"],
      "A file is opened using a name that comes from the request.",
      "Attackers can use ../ sequences to read files outside the intended folder (path traversal).",
      "Resolve the path, ensure it stays inside an allowed folder, or map ids to files.", "low"),
    R("SRC-FILE-002", "Archive extraction without path checks", "medium", "File handling", "CWE-22",
      [r"\.extractall\("],
      "The code unpacks an archive in one step without checking file names.",
      "A crafted archive can overwrite files anywhere on disk ('Zip Slip').",
      "Validate each member path before extracting, or use a safe extraction helper.", "low"),
    R("SRC-NET-001", "Insecure http:// URL", "low", "Transport security", "CWE-319",
      [r"""["']http://(?!localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\]|www\.w3\.org|schemas\.|[^"']*\.local\b|[^"']*example\.(?:com|org))[\w.-]+"""],
      "The code talks to a website over an unencrypted address.",
      "Data sent that way can be read or altered by anyone on the path.",
      "Use https:// for all external endpoints.", "low"),
    R("SRC-CFG-001", "Debug mode enabled in configuration", "medium", "Configuration", "CWE-489",
      [r"(?i)\bDEBUG\s*=\s*True\b", r"app\.run\([^)]*debug\s*=\s*True", r"(?i)\bAPP_DEBUG\s*=\s*true",
       r"(?i)display_errors\s*=\s*(?:On|1)", r"(?i)\bFLASK_DEBUG\s*=\s*1"],
      "The application is set to run in debug mode.",
      "Debug mode can expose source code, variables and sometimes remote code execution.",
      "Turn debug off in production and control it through environment variables.", "low"),
    R("SRC-CFG-002", "Permissive CORS configuration", "medium", "Configuration", "CWE-942",
      [r"(?i)Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']?\*", r"allow_origins\s*=\s*\[\s*[\"']\*[\"']",
       r"origins?\s*:\s*[\"']\*[\"']", r"CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True",
       r"AllowAnyOrigin\(\)", r"origin\s*:\s*true"],
      "The code lets any website call this application from a visitor's browser.",
      "Combined with logins, other sites could read private data.",
      "List only the trusted origins explicitly.", "medium"),
    R("SRC-AUTH-001", "Weak authentication or token validation", "high", "Authentication", "CWE-287",
      [r"""algorithms\s*=\s*\[\s*["']none["']""", r"verify_signature[\"']?\s*:\s*False",
       r"jwt\.decode\([^)]*verify\s*=\s*False", r"""["']admin["']\s*[,:]\s*["']admin["']"""],
      "Login or token checking appears to be switched off or uses default credentials.",
      "Attackers could forge tokens or log in as an administrator.",
      "Always verify token signatures with a fixed algorithm list and remove default credentials.", "low"),
    R("SRC-AUTH-002", "Insecure cookie or CSRF setting", "low", "Authentication", "CWE-614",
      [r"(?i)(?:SESSION_COOKIE_SECURE|SESSION_COOKIE_HTTPONLY|CSRF_COOKIE_SECURE)\s*=\s*False",
       r"(?i)\bhttponly\s*[:=]\s*false", r"WTF_CSRF_ENABLED\s*=\s*False", r"csrf_exempt", r"csrf\(\)\.disable"],
      "A protective setting for cookies or forgery protection is turned off.",
      "Cookies could be stolen or forms abused from other sites.",
      "Enable Secure, HttpOnly and SameSite cookie settings and keep CSRF protection on.", "low"),
]
_COMPILED = [(r, [re.compile(p) for p in r.patterns]) for r in RULES]
_PLACEHOLDER = re.compile(
    r"(?i)(changeme|change_me|your[_-]|example|placeholder|dummy|sample|xxxx|\*{3,}|<[^>]+>|\$\{|\{\{|%\(|"
    r"process\.env|os\.environ|getenv|env\[|^password$|^secret$|^test|^todo|^none$|^null$|^true$|^false$)")
_TESTPATH = re.compile(r"(?i)(^|/)(tests?|spec|__tests__|examples?|samples?|mocks?|fixtures?|docs?)(/|$)|\.(test|spec)\.")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def scan_tree(root: Path, progress: Callable[[int, str], None] | None = None, should_cancel=None,
              max_findings: int = 400) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    files = sorted(p for p in root.rglob("*") if p.is_file())
    per_rule_file: dict[tuple[str, str], int] = {}
    for idx, path in enumerate(files):
        if should_cancel and should_cancel():
            break
        if progress and idx % 50 == 0:
            progress(int(100 * idx / max(1, len(files))), f"Scanning files ({idx}/{len(files)})")
        rel = path.relative_to(root).as_posix()
        ext = path.suffix.lower()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_test = bool(_TESTPATH.search(rel))
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                line = line[:2000]
            stripped = line.strip()
            if not stripped:
                continue
            is_comment = stripped.startswith(("#", "//", "*", "/*", "--"))
            for rule, regexes in _COMPILED:
                if rule.ext and ext not in rule.ext:
                    continue
                if is_comment and rule.category != "Secrets":
                    continue
                for rx in regexes:
                    m = rx.search(line)
                    if not m:
                        continue
                    if rule.category == "Secrets":
                        value = m.group(1) if m.groups() else m.group(0)
                        if _PLACEHOLDER.search(value) and rule.id in ("SRC-SEC-005", "SRC-SEC-006"):
                            continue
                        if rule.id == "SRC-SEC-005" and _entropy(value) < 3.0:
                            continue
                    key = (rule.id, rel)
                    per_rule_file[key] = per_rule_file.get(key, 0) + 1
                    if per_rule_file[key] > 5:
                        break
                    snippet = line.strip()
                    if rule.mask:
                        secret = m.group(1) if m.groups() else m.group(0)
                        snippet = snippet.replace(secret, secret[:4] + "...[redacted]")
                    confidence = "low" if in_test else rule.confidence
                    if in_test:
                        snippet += "   (test/example path, lower confidence)"
                    findings.append({
                        "rule_id": rule.id, "title": rule.title, "severity": rule.severity,
                        "category": rule.category, "finding_type": "potential", "confidence": confidence,
                        "engine": "builtin-source", "cwe": rule.cwe, "file_path": rel, "line": lineno,
                        "evidence": snippet[:400], "description": rule.simple,
                        "simple_explanation": rule.simple, "why_it_matters": rule.why,
                        "remediation": rule.fix, "references": [],
                    })
                    break
            if len(findings) >= max_findings:
                notes.append(f"Built-in scanner stopped after {max_findings} findings; review and rescan.")
                return findings, notes
    return findings, notes


def manifest_finding(manifests: list[str]) -> dict | None:
    if not manifests:
        return None
    return {
        "rule_id": "SRC-DEP-001", "title": "Dependency manifests detected", "severity": "info",
        "category": "Dependencies", "finding_type": "observation", "confidence": "high",
        "engine": "builtin-source", "cwe": None, "file_path": manifests[0], "line": None,
        "evidence": "\n".join(manifests[:30]),
        "description": "Files that list the third-party packages this project depends on.",
        "simple_explanation": "The project uses third-party packages. Old versions of packages often contain known vulnerabilities.",
        "why_it_matters": "Most real-world breaches use known flaws in outdated dependencies.",
        "remediation": "Run a dependency vulnerability scan (Trivy or OSV in SecureScan AI) and keep packages updated.",
        "references": [],
    }
