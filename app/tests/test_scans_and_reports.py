import io
import json
import zipfile

from sqlalchemy import select

from app.database import SessionLocal
from app.models import AuthorizedTarget, Finding, Scan
from app.scanners.base import compute_score
from .conftest import wait_scan


def _rules(scan):
    return {f["rule_id"] for f in scan["findings"]}


def test_passive_website_scan_end_to_end(client, users, local_site):
    h = users["user1"]
    r = client.post("/api/scans/website", headers=h, json={"url": local_site, "mode": "beginner",
                                                             "authorization_confirmed": True})
    assert r.status_code == 201
    scan = wait_scan(client, h, r.json()["id"])
    assert scan["status"] == "completed", scan.get("error")
    rules = _rules(scan)
    assert {"WEB-HTTPS-001", "WEB-HDR-001", "WEB-HDR-003" if False else "WEB-HDR-005", "WEB-COOKIE-002",
            "WEB-FORM-001", "WEB-ERR-001", "WEB-DISC-001", "WEB-DISC-002"} <= rules
    assert not any(x.startswith("WEB-ACT") for x in rules)  # passive scan never runs active probes
    assert 0 <= scan["score"] < 100 and scan["risk_level"] in ("high", "medium")
    assert scan["summary"]["total"] == len(scan["findings"])
    assert scan["engines"][0]["status"] == "completed"
    cookie_ev = next(f for f in scan["findings"] if f["rule_id"] == "WEB-COOKIE-002")["evidence"]
    assert "abc123" not in cookie_ev and "<redacted>" in cookie_ev  # cookie values are never stored
    assert all(f["simple_explanation"] and f["remediation"] for f in scan["findings"])


def test_active_checks_require_allowlist(client, users, local_site):
    h = users["user1"]
    body = {"url": local_site, "mode": "advanced", "active_checks": True, "authorization_confirmed": True}
    assert client.post("/api/scans/website", headers=h, json=body).status_code == 403  # not allowlisted
    r = client.post("/api/targets", headers=users["user1"], json={"pattern": "127.0.0.1"})
    assert r.status_code == 403  # only admins manage the allowlist
    assert client.post("/api/targets", headers=users["admin1"], json={"pattern": "127.0.0.1", "note": "tests"}).status_code == 201
    assert client.post("/api/targets", headers=users["admin1"], json={"pattern": "not a host!"}).status_code == 400
    r = client.post("/api/scans/website", headers=h, json=body)
    assert r.status_code == 201
    scan = wait_scan(client, h, r.json()["id"])
    assert scan["status"] == "completed", scan.get("error")
    rules = _rules(scan)
    assert {"WEB-ACT-001", "WEB-ACT-002", "WEB-ACT-003", "WEB-ACT-004"} <= rules
    env = next(f for f in scan["findings"] if f["rule_id"] == "WEB-ACT-001")
    assert "hunter2" not in json.dumps(env)  # exposed file contents are not stored
    assert scan["active_checks"] is True
    audit = client.get("/api/audit?limit=300", headers=users["admin1"]).json()
    assert any(e["action"] == "scan_created" and "active=True" in e["detail"] for e in audit)


def test_beginner_mode_never_runs_active_checks(client, users, local_site):
    body = {"url": local_site, "mode": "beginner", "active_checks": True, "authorization_confirmed": True}
    r = client.post("/api/scans/website", headers=users["user2"], json=body)
    assert r.status_code == 201 and r.json()["active_checks"] is False


def test_unknown_check_rejected(client, users, local_site):
    r = client.post("/api/scans/website", headers=users["user1"], json={
        "url": local_site, "mode": "advanced", "checks": ["headers", "rm-rf"], "authorization_confirmed": True})
    assert r.status_code == 400


def test_unreachable_target_fails_cleanly(client, users):
    r = client.post("/api/scans/website", headers=users["user1"],
                    json={"url": "http://127.0.0.1:1/", "authorization_confirmed": True})
    scan = wait_scan(client, users["user1"], r.json()["id"])
    assert scan["status"] == "failed" and "Could not reach" in scan["error"]


def _vulnerable_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("app/main.py", 'import os, hashlib\nAPI_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
                    'def run(name):\n    os.system("ping " + name)\n    return hashlib.md5(b"x")\n'
                    'DEBUG = True\ncur.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
        zf.writestr("requirements.txt", "flask==1.0\n")
    return buf.getvalue()


def test_source_scan_end_to_end_and_cleanup(client, users):
    h = users["user1"]
    r = client.post("/api/scans/source", headers=h, data={"mode": "beginner", "authorization_confirmed": "true"},
                    files={"file": ("project.zip", _vulnerable_zip(), "application/zip")})
    assert r.status_code == 201
    scan = wait_scan(client, h, r.json()["id"])
    assert scan["status"] == "completed", scan.get("error")
    rules = _rules(scan)
    assert {"SRC-SEC-001", "SRC-CMD-001", "SRC-CRY-001", "SRC-CFG-001", "SRC-SQL-001", "SRC-DEP-001"} <= rules
    f = next(x for x in scan["findings"] if x["rule_id"] == "SRC-CMD-001")
    assert f["file_path"] == "app/main.py" and f["line"] == 4 and f["finding_type"] == "potential"
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(scan)
    statuses = {e["id"]: e["status"] for e in scan["engines"]}
    assert statuses["semgrep"] == "not_installed" and statuses["trivy"] == "not_installed"  # honest labelling
    assert statuses["osv"] == "skipped"
    assert any("NOT performed" in n for n in scan["notes"])
    from app.config import settings
    assert not list(settings.uploads_dir.glob(f"{scan['id']}*")) and not (settings.work_dir / scan["id"]).exists()


def test_malicious_zip_fails_scan(client, users):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.py", "print('pwn')")
    r = client.post("/api/scans/source", headers=users["user1"], data={"authorization_confirmed": "true"},
                    files={"file": ("evil.zip", buf.getvalue(), "application/zip")})
    scan = wait_scan(client, users["user1"], r.json()["id"])
    assert scan["status"] == "failed" and "path traversal" in scan["error"]


def test_reports_and_access_control(client, users, local_site):
    h = users["user1"]
    scans = client.get("/api/scans?status=completed&scan_type=website", headers=h).json()["items"]
    sid = scans[0]["id"]
    pdf = client.get(f"/api/scans/{sid}/report.pdf", headers=h)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and len(pdf.content) > 3000
    assert "attachment" in pdf.headers["content-disposition"] and pdf.headers["cache-control"] == "no-store"
    js = client.get(f"/api/scans/{sid}/report.json", headers=h).json()
    assert js["report"]["id"].startswith("SSAI-") and js["findings"] and js["disclaimer"] and js["limitations"]
    assert js["score"]["methodology"] and js["scan"]["target"] == scans[0]["target"]
    csv_text = client.get(f"/api/scans/{sid}/report.csv", headers=h).content.decode("utf-8-sig")
    assert csv_text.splitlines()[0].startswith("report_id,scan_id,target,severity") and len(csv_text.splitlines()) > 3
    assert client.get(f"/api/scans/{sid}/report.exe", headers=h).status_code == 404
    assert client.get(f"/api/scans/{sid}/report.pdf").status_code == 401            # no token
    assert client.get(f"/api/scans/{sid}/report.pdf", headers=users["user2"]).status_code == 404  # not the owner
    assert client.get(f"/api/scans/{sid}/report.pdf", headers=users["admin1"]).status_code == 200  # admin sees all
    assert client.get(f"/api/scans/{sid}/report.json", headers=users["viewer1"]).status_code == 200  # auditor role
    assert client.delete(f"/api/scans/{sid}", headers=users["viewer1"]).status_code == 403


def test_pdf_survives_hostile_text(client, users):
    from app.reports.pdf import build_pdf
    from app.models import new_id, utcnow
    with SessionLocal() as db:
        scan = Scan(id=new_id(), created_at=utcnow(), scan_type="website", mode="beginner", target="http://x.test/<b>&",
                    status="completed", owner_name="x\u202e",
                    summary={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1}, score=50,
                    risk_level="high", engines=[{"name": "n<", "status": "completed", "findings": 1, "detail": "<&>"}])
        f = Finding(scan_id=scan.id, finding_type="misconfiguration", confidence="high", engine="x", title="<script>alert(1)</script> \u4e2d\u6587 \x00", severity="high",
                    evidence="A" * 5000 + "\n<b>x</b> &amp; \u2603", remediation="<i>fix</i>", category="X")
        out = build_pdf(scan, [f])
    assert out.startswith(b"%PDF")


def test_users_only_see_own_scans_and_dashboard_matches_db(client, users):
    mine = client.get("/api/scans?limit=100", headers=users["user2"]).json()
    assert all(s["owner"] == "user2" for s in mine["items"])
    dash = client.get("/api/dashboard", headers=users["user2"]).json()
    assert dash["totals"]["scans"] == mine["total"] and dash["scope"] == "own"
    with SessionLocal() as db:
        done = [s for s in db.scalars(select(Scan)).all() if s.status == "completed"]
        expected = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for s in done:
            for f in db.scalars(select(Finding).where(Finding.scan_id == s.id)).all():
                expected[f.severity] += 1
    admin_dash = client.get("/api/dashboard", headers=users["admin1"]).json()
    assert admin_dash["severity"] == expected and admin_dash["totals"]["completed"] == len(done)
    assert admin_dash["activity"] and "activity" not in dash
    assert len(admin_dash["scans_per_day"]) == 14


def test_cancel_and_delete(client, users):
    h = users["user1"]
    with SessionLocal() as db:
        s = Scan(user_id=1, owner_name="user1", scan_type="website", target="http://x.test", status="queued")
        db.add(s)
        db.commit()
        sid = s.id
    me = client.get("/api/auth/me", headers=h).json()
    with SessionLocal() as db:
        db.get(Scan, sid).user_id = me["id"]
        db.commit()
    assert client.post(f"/api/scans/{sid}/cancel", headers=h).json()["status"] == "cancelled"
    assert client.post(f"/api/scans/{sid}/cancel", headers=h).status_code == 409
    assert client.delete(f"/api/scans/{sid}", headers=h).status_code == 200
    assert client.get(f"/api/scans/{sid}", headers=h).status_code == 404


def test_scoring_method_is_deterministic():
    f = lambda sev, rid, conf="high", t="misconfiguration": {"severity": sev, "rule_id": rid, "confidence": conf, "finding_type": t, "title": rid}
    assert compute_score([]) == (100, "minimal")
    assert compute_score([f("high", "A"), f("high", "A")]) == (88, "high")  # repeated rule counts once
    assert compute_score([f("medium", "B"), f("low", "C")]) == (93, "medium")
    assert compute_score([f("info", "D", t="observation")]) == (100, "minimal")
    assert compute_score([f("critical", "E")])[1] == "critical"
    assert compute_score([f("high", "F", "low", "potential")]) == (95, "medium")  # low confidence: smaller deduction, needs review


def test_osv_parser_and_lookup_with_mock_http(tmp_path, monkeypatch):
    import dataclasses
    from app.scanners import engines
    monkeypatch.setattr(engines, "settings", dataclasses.replace(engines.settings, osv_enabled=True))
    (tmp_path / "requirements.txt").write_text("flask==1.0\nrequests>=2\n# comment\nDjango[argon2]==2.2.0\n")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.15", "x": "^1.0.0"}}))
    deps = {(e, n, v) for e, n, v, _ in engines.collect_dependencies(tmp_path)}
    assert deps == {("PyPI", "flask", "1.0"), ("PyPI", "Django", "2.2.0"), ("npm", "lodash", "4.17.15")}

    def fake_http(path, payload=None):
        if path == "/querybatch":
            return {"results": [{"vulns": [{"id": "GHSA-test-0001"}]} if q["package"]["name"] == "flask" else {}
                                for q in payload["queries"]]}
        return {"summary": "Test advisory", "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}]}
    status, detail, findings = engines.run_osv(tmp_path, lambda: False, http=fake_http)
    assert status == "completed" and len(findings) == 1
    assert findings[0]["severity"] == "high" and "1.0.1" in findings[0]["remediation"]
