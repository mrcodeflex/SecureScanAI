"""Starts the real server + a fixture target, then drives the web UI with jsdom (node smoke.js)."""
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))
import fixture_site  # noqa: E402


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    data = tempfile.mkdtemp(prefix="ssai_ui_")
    env = {**os.environ, "SSAI_DATA_DIR": data, "SSAI_ALLOW_PRIVATE_TARGETS": "true", "SSAI_REQUEST_DELAY_MS": "0",
           "SSAI_LOG_LEVEL": "WARNING", "PYTHONPATH": str(ROOT)}
    admin_env = {**env, "SSAI_ADMIN_USERNAME": "uiadmin", "SSAI_ADMIN_PASSWORD": "Smoke-Test-Pass-42"}
    subprocess.run([sys.executable, "-m", "app.cli", "init-admin"], cwd=ROOT, env=admin_env, check=True, capture_output=True)
    # the bootstrap flag forces a password change; clear it so the smoke test can start from the dashboard
    subprocess.run([sys.executable, "-c",
                    "from app.database import SessionLocal;from app.models import User;"
                    "s=SessionLocal();u=s.query(User).first();u.must_change_password=False;s.commit()"],
                   cwd=ROOT, env=env, check=True)
    port = free_port()
    site = fixture_site.serve()
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
                              cwd=ROOT, env=env)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        else:
            print("server did not start")
            return 1
        res = subprocess.run(["node", "smoke.js"], cwd=Path(__file__).parent,
                             env={**os.environ, "BASE": base, "FIXTURE": f"http://127.0.0.1:{site.server_address[1]}/",
                                  "ADMIN_USER": "uiadmin", "ADMIN_PASS": "Smoke-Test-Pass-42"})
        return res.returncode
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
