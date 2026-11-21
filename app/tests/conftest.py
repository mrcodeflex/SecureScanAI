"""Test configuration. Environment variables must be set BEFORE the app is imported."""
import http.server
import os
import tempfile
import threading
import time

_TMP = tempfile.mkdtemp(prefix="ssai_tests_")
os.environ.update({
    "SSAI_DATA_DIR": _TMP, "SSAI_ALLOW_PRIVATE_TARGETS": "true",  # lets tests scan a local fixture server
    "SSAI_REQUEST_DELAY_MS": "0", "SSAI_LOG_LEVEL": "WARNING", "SSAI_SCANS_PER_MINUTE": "1000",
    "SSAI_MAX_UPLOAD_MB": "2", "SSAI_MAX_EXTRACT_MB": "20",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import ROLE_ADMIN, ROLE_READONLY, ROLE_SUPER, ROLE_USER, User  # noqa: E402
from app.services import security  # noqa: E402

PASSWORD = "Correct-Horse-Battery9"


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


def make_user(username: str, role: str, password: str = PASSWORD, must_change: bool = False) -> User:
    with SessionLocal() as db:
        u = User(username=username, role=role, full_name=username.title(), password_hash=security.hash_password(password),
                 must_change_password=must_change)
        db.add(u)
        db.commit()
        return u


def login(client, username: str, password: str = PASSWORD) -> dict:
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture(scope="session")
def users(client):
    for name, role in (("super1", ROLE_SUPER), ("admin1", ROLE_ADMIN), ("user1", ROLE_USER), ("user2", ROLE_USER),
                       ("viewer1", ROLE_READONLY)):
        make_user(name, role)
    return {n: login(client, n) for n in ("super1", "admin1", "user1", "user2", "viewer1")}


@pytest.fixture(autouse=True)
def _reset_limiters():
    security.login_ip_limiter._events.clear()
    security.login_user_limiter._events.clear()
    yield


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_GET(self):
        path = self.path
        origin = self.headers.get("Origin")
        cors = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
        if path.startswith("/ssai-not-found"):
            return self._send(404, "<pre>Traceback (most recent call last):\n  File app.py, line 3</pre>")
        if path == "/.env":
            return self._send(200, "DB_PASSWORD=hunter2hunter2\nSECRET_KEY=abcdef\n", "text/plain")
        if path.startswith("/.") or path in ("/backup.sql", "/database.sql", "/phpinfo.php", "/server-status"):
            return self._send(404, "nope")
        extra = {"Set-Cookie": "PHPSESSID=abc123; Path=/", **cors}
        page = ('<html><body><form method="post" action="/login"><input type="password" name="p"></form>'
                "<p>" + (path.split("ssai_probe=")[-1].replace("%22", '"').replace("%27", "'").replace("%3C", "<").replace("%3E", ">") if "ssai_probe" in path else "hi") + "</p></body></html>")
        self._send(200, page, extra=extra)

    def do_OPTIONS(self):
        self._send(200, "", extra={"Allow": "GET, HEAD, PUT, DELETE"})

    def do_TRACE(self):
        body = f"TRACE / HTTP/1.1\r\nX-SSAI-Probe: {self.headers.get('X-SSAI-Probe', '')}\r\n"
        self._send(200, body, "message/http")


@pytest.fixture(scope="session")
def local_site():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()


def wait_scan(client, headers, scan_id, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        r = client.get(f"/api/scans/{scan_id}", headers=headers)
        assert r.status_code == 200, r.text
        if r.json()["status"] in ("completed", "failed", "cancelled"):
            return r.json()
        time.sleep(0.25)
    raise AssertionError("scan did not finish in time")
