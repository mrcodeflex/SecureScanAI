from app.models import ROLE_USER
from .conftest import PASSWORD, login, make_user


def test_health_and_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_protected_endpoints_require_auth(client):
    for path in ("/api/auth/me", "/api/scans", "/api/dashboard", "/api/users", "/api/system/engines", "/api/audit"):
        assert client.get(path).status_code == 401, path


def test_login_logout_flow(client, users):
    r = client.post("/api/auth/login", json={"username": "user1", "password": PASSWORD})
    assert r.status_code == 200 and "password" not in r.text.lower().replace("must_change_password", "")
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    assert client.get("/api/auth/me", headers=h).json()["username"] == "user1"
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401  # token revoked


def test_bad_login_is_generic_and_rate_limited(client, users):
    make_user("lockme", ROLE_USER)
    for _ in range(5):
        r = client.post("/api/auth/login", json={"username": "lockme", "password": "wrong-password-1"})
        assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password."
    r = client.post("/api/auth/login", json={"username": "lockme", "password": PASSWORD})
    assert r.status_code == 429 and "Retry-After" in r.headers  # even the right password is blocked
    r = client.post("/api/auth/login", json={"username": "no-such-user", "password": "wrong-password-1"})
    assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password."


def test_password_hash_is_argon2_and_tokens_not_stored_plain(client, users):
    from sqlalchemy import select
    from app.database import SessionLocal
    from app.models import SessionToken, User
    with SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == "user1"))
        assert u.password_hash.startswith("$argon2id$") and PASSWORD not in u.password_hash
        token = users["user1"]["Authorization"].split()[1]
        assert all(token != s.token_hash for s in db.scalars(select(SessionToken)).all())


def test_change_password_policy_and_forced_change(client, users):
    make_user("fresh1", ROLE_USER, must_change=True)
    h = login(client, "fresh1")
    assert client.get("/api/scans", headers=h).status_code == 403  # blocked until password changed
    assert client.get("/api/auth/me", headers=h).json()["must_change_password"] is True
    bad = client.post("/api/auth/change-password", headers=h, json={"current_password": PASSWORD, "new_password": "short1"})
    assert bad.status_code == 400
    ok = client.post("/api/auth/change-password", headers=h,
                     json={"current_password": PASSWORD, "new_password": "A-brand-new-Pass-77"})
    assert ok.status_code == 200
    assert client.get("/api/scans", headers=h).status_code == 200
    assert client.post("/api/auth/login", json={"username": "fresh1", "password": PASSWORD}).status_code == 401


def test_roles_enforced(client, users):
    assert client.get("/api/users", headers=users["user1"]).status_code == 403
    assert client.get("/api/users", headers=users["viewer1"]).status_code == 403
    assert client.get("/api/users", headers=users["admin1"]).status_code == 200
    assert client.get("/api/audit", headers=users["user1"]).status_code == 403
    r = client.post("/api/scans/website", headers=users["viewer1"],
                    json={"url": "http://example.com", "authorization_confirmed": True})
    assert r.status_code == 403  # read-only cannot scan


def test_user_management_rules(client, users):
    body = {"username": "newbie", "role": "user", "password": "Another-Strong-Pass1", "full_name": "New Bie"}
    r = client.post("/api/users", headers=users["admin1"], json=body)
    assert r.status_code == 201 and r.json()["must_change_password"] is True
    assert client.post("/api/users", headers=users["admin1"], json=body).status_code == 409
    assert client.post("/api/users", headers=users["admin1"], json={**body, "username": "adm2", "role": "admin"}).status_code == 403
    assert client.post("/api/users", headers=users["super1"], json={**body, "username": "adm2", "role": "admin"}).status_code == 201
    assert client.post("/api/users", headers=users["admin1"], json={**body, "username": "weakling", "password": "abc"}).status_code == 400
    uid = r.json()["id"]
    assert client.patch(f"/api/users/{uid}", headers=users["admin1"], json={"is_active": False}).status_code == 200
    assert client.post("/api/auth/login", json={"username": "newbie", "password": body["password"]}).status_code == 401
    reset = client.post(f"/api/users/{uid}/reset-password", headers=users["admin1"], json={})
    assert reset.status_code == 200 and len(reset.json()["temporary_password"]) >= 16
    assert client.get(f"/api/users/{uid}/activity", headers=users["admin1"]).status_code == 200
    assert client.delete(f"/api/users/{uid}", headers=users["admin1"]).status_code == 200


def test_user_management_safeguards(client, users):
    me = client.get("/api/auth/me", headers=users["super1"]).json()
    assert client.delete(f"/api/users/{me['id']}", headers=users["super1"]).status_code == 400
    assert client.patch(f"/api/users/{me['id']}", headers=users["super1"], json={"is_active": False}).status_code == 400
    assert client.patch(f"/api/users/{me['id']}", headers=users["super1"], json={"role": "user"}).status_code == 400
    admin = client.get("/api/auth/me", headers=users["admin1"]).json()
    assert client.delete(f"/api/users/{me['id']}", headers=users["admin1"]).status_code == 403  # admin vs super
    assert client.patch(f"/api/users/{admin['id']}", headers=users["admin1"], json={"role": "super_admin"}).status_code in (400, 403)


def test_audit_log_records_events(client, users):
    events = client.get("/api/audit?limit=200", headers=users["admin1"]).json()
    actions = {e["action"] for e in events}
    assert {"login", "login_failed", "user_created"} <= actions
    assert all("password" not in e["detail"].lower() or e["action"].startswith("password") for e in events)


def test_cli_env_editing_keeps_comments_and_updates_keys(tmp_path):
    from app.cli import set_env_values
    env = tmp_path / ".env"
    env.write_text("# my settings\nSSAI_PORT=9000\nSSAI_HOST=127.0.0.1\n\nOTHER=1\n")
    set_env_values(env, {"SSAI_HOST": "0.0.0.0", "SSAI_ALLOW_INSECURE_HTTP": "true"})
    lines = env.read_text().splitlines()
    assert lines[0] == "# my settings" and "SSAI_PORT=9000" in lines and "OTHER=1" in lines
    assert lines.count("SSAI_HOST=0.0.0.0") == 1 and "SSAI_HOST=127.0.0.1" not in lines
    assert "SSAI_ALLOW_INSECURE_HTTP=true" in lines
