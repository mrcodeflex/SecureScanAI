import dataclasses
import io
import struct
import zipfile
from pathlib import Path

import pytest

from app.scanners import netsafe, source_scan
from app.scanners.netsafe import FetchError, SafeClient, UnsafeTargetError, parse_target


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.1/", "http://[::1]/", "http://0.0.0.0/", "http://10.1.2.3/",
    "http://172.16.0.9/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
    "http://2130706433/", "http://0x7f000001/", "http://[::ffff:127.0.0.1]/", "http://100.64.0.1/",
    "http://printer.local/", "http://db.internal/", "file:///etc/passwd", "ftp://example.com/",
    "javascript:alert(1)", "http://user:pass@example.com/", "http://exa mple.com/", "", "http://",
    "gopher://127.0.0.1:6379/_PING",
])
def test_unsafe_urls_rejected(url):
    with pytest.raises(UnsafeTargetError):
        parse_target(url, allow_private=False)


def test_public_ip_resolution_accepted_and_private_mix_rejected(monkeypatch):
    monkeypatch.setattr(netsafe, "_resolve", lambda h, p: ["93.184.216.34"])
    assert parse_target("https://good.test/x?y=1").ips == ["93.184.216.34"]
    monkeypatch.setattr(netsafe, "_resolve", lambda h, p: ["93.184.216.34", "10.0.0.5"])  # rebinding-style mix
    with pytest.raises(UnsafeTargetError):
        parse_target("https://mixed.test/")


class _FakeResp:
    def __init__(self, status, headers, body=b""):
        self.status, self.reason, self._h, self._b = status, "X", headers, body

    def getheaders(self):
        return self._h

    def read(self, n=-1):
        b, self._b = self._b[:n], self._b[n:]
        return b


def test_connection_is_pinned_to_validated_ip_and_redirects_revalidated(monkeypatch):
    mapping = {"good.test": "93.184.216.34", "evil.test": "10.0.0.5"}
    monkeypatch.setattr(netsafe, "_resolve", lambda h, p: [mapping[h]])
    connected = []

    class FakeConn:
        def __init__(self, host, port, ip, timeout):
            connected.append((host, ip))

        def request(self, *a, **k):
            pass

        def getresponse(self):
            return _FakeResp(302, [("Location", "http://evil.test/admin")])

        def close(self):
            pass

    monkeypatch.setattr(netsafe, "_PinnedHTTP", FakeConn)
    client = SafeClient(allow_private=False)
    with pytest.raises(UnsafeTargetError):  # second hop resolves to a private address
        client.request("http://good.test/")
    assert connected == [("good.test", "93.184.216.34")]  # connected to the IP, not re-resolved


def test_request_limit_and_cancel():
    c = SafeClient(allow_private=True, max_requests=0)
    with pytest.raises(netsafe.ScanLimitError):
        c.request("http://127.0.0.1:9/")
    c2 = SafeClient(allow_private=True, should_cancel=lambda: True)
    with pytest.raises(netsafe.ScanCancelled):
        c2.request("http://127.0.0.1:9/")


def _zip_bytes(entries: dict[str, bytes | str], *, symlink: str | None = None) -> Path:
    import tempfile
    p = Path(tempfile.mkstemp(suffix=".zip")[1])
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
    return p


LIMITS = dict(max_files=100, max_total_bytes=5 * 1024 * 1024, max_file_bytes=1024 * 1024, max_ratio=100)


def test_zip_path_traversal_rejected(tmp_path):
    for bad in ("../evil.py", "a/../../evil.py", "/abs/evil.py", "C:/evil.py", "..\\evil.py"):
        with pytest.raises(source_scan.ArchiveError):
            source_scan.safe_extract(_zip_bytes({bad: "x"}), tmp_path / "o", **LIMITS)
    assert not list(tmp_path.glob("**/evil.py"))


def test_zip_bomb_and_limits_rejected(tmp_path):
    bomb = _zip_bytes({"big.txt": b"0" * (30 * 1024 * 1024)})
    with pytest.raises(source_scan.ArchiveError):
        source_scan.safe_extract(bomb, tmp_path / "b", **LIMITS)
    many = _zip_bytes({f"f{i}.py": "x=1" for i in range(150)})
    with pytest.raises(source_scan.ArchiveError):
        source_scan.safe_extract(many, tmp_path / "m", **LIMITS)


def test_not_a_zip_rejected(tmp_path):
    f = tmp_path / "x.zip"
    f.write_bytes(b"this is not a zip")
    with pytest.raises(source_scan.ArchiveError):
        source_scan.safe_extract(f, tmp_path / "o", **LIMITS)


def test_safe_extract_filters_and_never_executes(tmp_path):
    z = _zip_bytes({"src/app.py": "print(1)", "node_modules/x/index.js": "x", "logo.png": b"\x89PNG",
                    "big.txt": b"a" * (2 * 1024 * 1024), "requirements.txt": "flask==2.0.0"}, symlink="link.py")
    stats = source_scan.safe_extract(z, tmp_path / "o", **LIMITS)
    names = sorted(p.relative_to(tmp_path / "o").as_posix() for p in (tmp_path / "o").rglob("*") if p.is_file())
    assert names == ["requirements.txt", "src/app.py"]
    assert stats["skipped_vendor"] == 1 and stats["skipped_binary"] == 1 and stats["skipped_large"] == 1
    assert stats["skipped_links"] == 1 and stats["manifests"] == ["requirements.txt"]
    assert not any(p.stat().st_mode & 0o111 for p in (tmp_path / "o").rglob("*") if p.is_file())


def test_secrets_are_redacted_in_findings(tmp_path):
    (tmp_path / "c.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\npassword = "Sup3rS3cret!"\n')
    findings, _ = source_scan.scan_tree(tmp_path)
    blob = " ".join(f["evidence"] for f in findings)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob and "Sup3rS3cret!" not in blob and "[redacted]" in blob
    assert all(f["finding_type"] == "potential" for f in findings)  # regex hits are never called 'confirmed'


def test_upload_validation_api(client, users):
    h = users["user1"]
    r = client.post("/api/scans/source", headers=h, data={"authorization_confirmed": "true"},
                    files={"file": ("code.txt", b"hello", "text/plain")})
    assert r.status_code == 400
    r = client.post("/api/scans/source", headers=h, data={"authorization_confirmed": "true"},
                    files={"file": ("code.zip", b"not really a zip", "application/zip")})
    assert r.status_code == 400
    r = client.post("/api/scans/source", headers=h, data={"authorization_confirmed": "true"},
                    files={"file": ("code.zip", b"PK" + b"0" * (3 * 1024 * 1024), "application/zip")})
    assert r.status_code == 413
    r = client.post("/api/scans/source", headers=h, data={},
                    files={"file": ("code.zip", b"PK\x03\x04", "application/zip")})
    assert r.status_code == 400  # missing authorization confirmation


def test_scan_api_blocks_private_targets_when_policy_on(client, users, monkeypatch):
    from app.api import scans as scans_api
    monkeypatch.setattr(scans_api, "settings", dataclasses.replace(scans_api.settings, allow_private_targets=False))
    for url in ("http://127.0.0.1:8000/", "http://localhost/", "http://169.254.169.254/", "http://192.168.0.1/"):
        r = client.post("/api/scans/website", headers=users["user1"], json={"url": url, "authorization_confirmed": True})
        assert r.status_code == 400, url
    r = client.post("/api/scans/website", headers=users["user1"], json={"url": "http://example.com", "authorization_confirmed": False})
    assert r.status_code == 400


def test_csv_formula_injection_neutralised():
    from app.reports.exports import _safe_cell
    assert _safe_cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    assert _safe_cell("+1+1") == "'+1+1" and _safe_cell("@SUM(A1)") == "'@SUM(A1)" and _safe_cell("normal") == "normal"


# ------------------------------------------------------------------ real TLS behaviour
import http.server
import shutil
import ssl
import subprocess
import threading


def _tls_server(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl is not available")
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True)

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"<html><body>secure</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, crt


def test_untrusted_certificate_is_rejected_never_bypassed(tmp_path, client, users):
    server, _crt = _tls_server(tmp_path)
    try:
        port = server.server_address[1]
        with pytest.raises(FetchError) as exc:
            SafeClient(allow_private=True).request(f"https://127.0.0.1:{port}/")
        assert exc.value.kind == "tls"  # certificate verification is ON: self-signed cert refused
    finally:
        server.shutdown()


def test_website_scan_reports_untrusted_certificate(tmp_path, client, users):
    from .conftest import wait_scan
    server, _crt = _tls_server(tmp_path)
    try:
        r = client.post("/api/scans/website", headers=users["user1"],
                        json={"url": f"https://127.0.0.1:{server.server_address[1]}/", "authorization_confirmed": True})
        scan = wait_scan(client, users["user1"], r.json()["id"])
        assert scan["status"] == "completed"
        assert any(f["rule_id"] == "WEB-TLS-001" and f["severity"] == "high" for f in scan["findings"])
        assert any("certificate" in n.lower() for n in scan["notes"])
    finally:
        server.shutdown()


def test_trusted_https_scan_inspects_certificate(tmp_path, client, users, monkeypatch):
    from .conftest import wait_scan
    server, crt = _tls_server(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(crt))  # trust only this test certificate, via the normal trust store
    try:
        r = client.post("/api/scans/website", headers=users["user1"],
                        json={"url": f"https://127.0.0.1:{server.server_address[1]}/", "authorization_confirmed": True})
        scan = wait_scan(client, users["user1"], r.json()["id"])
        assert scan["status"] == "completed", scan.get("error")
        rules = {f["rule_id"] for f in scan["findings"]}
        assert "WEB-TLS-010" in rules                       # protocol / issuer / expiry observation
        assert "WEB-TLS-002" in rules                       # certificate expires in 2 days
        assert "WEB-HDR-003" not in rules and "WEB-HDR-004" not in rules  # good HSTS header recognised
        assert "WEB-HDR-001" in rules                       # but CSP is still missing
        tls = next(f for f in scan["findings"] if f["rule_id"] == "WEB-TLS-010")["evidence"]
        assert "TLSv1.3" in tls or "TLSv1.2" in tls
    finally:
        server.shutdown()
