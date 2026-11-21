"""Central configuration. Every setting comes from an environment variable
(optionally loaded from a .env file in the project root)."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "SecureScan AI"
APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, lo: int = 1, hi: int = 10**9) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except ValueError:
        value = default
    return max(lo, min(hi, value))


def _str(name: str, default: str = "") -> str:
    raw = os.environ.get(name)
    return raw.strip() if raw not in (None, "") else default


def _load_secret_key(data_dir: Path) -> str:
    env_value = _str("SSAI_SECRET_KEY")
    if len(env_value) >= 32:
        return env_value
    key_file = data_dir / ".secret_key"
    if key_file.is_file():
        stored = key_file.read_text(encoding="utf-8").strip()
        if len(stored) >= 32:
            return stored
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_url: str
    secret_key: str = field(repr=False)
    host: str
    port: int
    ssl_certfile: str
    ssl_keyfile: str
    allow_insecure_http: bool
    allowed_origins: list[str]
    session_minutes: int
    login_max_attempts: int
    login_window_seconds: int
    scans_per_minute: int
    allow_private_targets: bool
    require_allowlist_for_all: bool
    http_timeout: int
    max_requests_per_scan: int
    request_delay_ms: int
    max_concurrent_scans: int
    scan_timeout_seconds: int
    max_upload_mb: int
    max_extract_mb: int
    max_files: int
    max_file_kb: int
    max_zip_ratio: int
    semgrep_config: str
    semgrep_timeout: int
    trivy_timeout: int
    osv_enabled: bool
    zap_url: str
    zap_api_key: str = field(repr=False)
    zap_timeout: int
    log_level: str

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"


def load_settings() -> Settings:
    _load_dotenv(BASE_DIR / ".env")
    data_dir = Path(_str("SSAI_DATA_DIR", str(BASE_DIR / "data"))).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "uploads").mkdir(exist_ok=True)
    (data_dir / "work").mkdir(exist_ok=True)
    default_db = "sqlite:///" + (data_dir / "securescan.db").as_posix()
    origins = [o.strip() for o in _str("SSAI_ALLOWED_ORIGINS").split(",") if o.strip()]
    return Settings(
        data_dir=data_dir,
        database_url=_str("SSAI_DATABASE_URL", default_db),
        secret_key=_load_secret_key(data_dir),
        host=_str("SSAI_HOST", "127.0.0.1"),
        port=_int("SSAI_PORT", 8000, 1, 65535),
        ssl_certfile=_str("SSAI_SSL_CERTFILE"),
        ssl_keyfile=_str("SSAI_SSL_KEYFILE"),
        allow_insecure_http=_bool("SSAI_ALLOW_INSECURE_HTTP", False),
        allowed_origins=origins,
        session_minutes=_int("SSAI_SESSION_MINUTES", 480, 5, 60 * 24 * 14),
        login_max_attempts=_int("SSAI_LOGIN_MAX_ATTEMPTS", 5, 3, 50),
        login_window_seconds=_int("SSAI_LOGIN_WINDOW_SECONDS", 900, 60, 86400),
        scans_per_minute=_int("SSAI_SCANS_PER_MINUTE", 10, 1, 600),
        allow_private_targets=_bool("SSAI_ALLOW_PRIVATE_TARGETS", False),
        require_allowlist_for_all=_bool("SSAI_REQUIRE_ALLOWLIST_FOR_ALL", False),
        http_timeout=_int("SSAI_HTTP_TIMEOUT", 10, 2, 60),
        max_requests_per_scan=_int("SSAI_MAX_REQUESTS_PER_SCAN", 120, 10, 2000),
        request_delay_ms=_int("SSAI_REQUEST_DELAY_MS", 150, 0, 5000),
        max_concurrent_scans=_int("SSAI_MAX_CONCURRENT_SCANS", 2, 1, 16),
        scan_timeout_seconds=_int("SSAI_SCAN_TIMEOUT_SECONDS", 900, 30, 7200),
        max_upload_mb=_int("SSAI_MAX_UPLOAD_MB", 50, 1, 1024),
        max_extract_mb=_int("SSAI_MAX_EXTRACT_MB", 200, 1, 4096),
        max_files=_int("SSAI_MAX_FILES", 5000, 10, 100000),
        max_file_kb=_int("SSAI_MAX_FILE_KB", 1024, 16, 20480),
        max_zip_ratio=_int("SSAI_MAX_ZIP_RATIO", 100, 5, 10000),
        semgrep_config=_str("SSAI_SEMGREP_CONFIG", "p/default"),
        semgrep_timeout=_int("SSAI_SEMGREP_TIMEOUT", 300, 30, 3600),
        trivy_timeout=_int("SSAI_TRIVY_TIMEOUT", 300, 30, 3600),
        osv_enabled=_bool("SSAI_ENABLE_OSV", False),
        zap_url=_str("SSAI_ZAP_URL"),
        zap_api_key=_str("SSAI_ZAP_API_KEY"),
        zap_timeout=_int("SSAI_ZAP_TIMEOUT", 600, 60, 7200),
        log_level=_str("SSAI_LOG_LEVEL", "INFO").upper(),
    )


settings = load_settings()
