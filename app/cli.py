"""Command line helper:  python -m app.cli <command>

  init-db           create the database tables
  init-admin        create the first Super Administrator (interactive, or via SSAI_ADMIN_* variables)
  reset-password    set a new password for a user (account recovery)
  list-users        show all accounts
  serve             start the web server using the settings in .env
  doctor            show configuration and scanner-engine status
  enable-lan        let phones on your private network connect (edits .env: listen on all interfaces, allow HTTP)
  disable-lan       back to this-computer-only (edits .env)
  show-port         print the configured port
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import socket
import sys

from sqlalchemy import select, update

from .config import APP_NAME, APP_VERSION, BASE_DIR, settings
from .database import SessionLocal, init_db
from .models import ROLE_SUPER, SessionToken, User, utcnow
from .services.security import hash_password, password_problems

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


def _ask_password(username: str) -> str:
    while True:
        pw = getpass.getpass("Password (min 12 characters, letters and numbers): ")
        problems = password_problems(pw, username)
        if problems:
            print("  - " + "\n  - ".join(problems))
            continue
        if pw != getpass.getpass("Repeat password: "):
            print("  The passwords do not match.")
            continue
        return pw


def cmd_init_db(_args) -> int:
    init_db()
    print(f"Database ready: {settings.database_url.split('///')[-1] if 'sqlite' in settings.database_url else 'configured database'}")
    return 0


def cmd_init_admin(args) -> int:
    init_db()
    env_user, env_pass = os.environ.get("SSAI_ADMIN_USERNAME", ""), os.environ.get("SSAI_ADMIN_PASSWORD", "")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.role == ROLE_SUPER)) and not args.force:
            print("A Super Administrator already exists. Use 'reset-password' to recover an account "
                  "or --force to add another one.")
            return 0
        from_env = bool(env_user and env_pass)
        username = (env_user or args.username or input("Administrator username: ")).strip().lower()
        if not USERNAME_RE.match(username):
            print("Username must be 3-32 characters: lowercase letters, digits, dot, dash or underscore.")
            return 1
        if db.scalar(select(User).where(User.username == username)):
            print(f"The user '{username}' already exists.")
            return 1
        password = env_pass if from_env else _ask_password(username)
        problems = password_problems(password, username)
        if problems:
            print("Password rejected: " + " ".join(problems))
            return 1
        db.add(User(username=username, full_name="Administrator", role=ROLE_SUPER,
                    password_hash=hash_password(password), must_change_password=from_env,
                    password_changed_at=utcnow()))
        db.commit()
    print(f"Super Administrator '{username}' created." + (
        " You must change the password at first sign-in. Remove SSAI_ADMIN_PASSWORD from your environment now." if from_env else ""))
    return 0


def cmd_reset_password(args) -> int:
    init_db()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == args.username.strip().lower()))
        if user is None:
            print("No such user.")
            return 1
        password = os.environ.get("SSAI_NEW_PASSWORD") or _ask_password(user.username)
        problems = password_problems(password, user.username)
        if problems:
            print("Password rejected: " + " ".join(problems))
            return 1
        user.password_hash = hash_password(password)
        user.must_change_password = False
        user.is_active = True
        user.password_changed_at = utcnow()
        db.execute(update(SessionToken).where(SessionToken.user_id == user.id).values(revoked=True))
        db.commit()
    print(f"Password updated for '{args.username}'. All existing sessions were signed out.")
    return 0


def cmd_list_users(_args) -> int:
    init_db()
    with SessionLocal() as db:
        for u in db.scalars(select(User).order_by(User.username)).all():
            print(f"{u.username:<24}{u.role:<12}{'active' if u.is_active else 'DISABLED'}")
    return 0


def _lan_ips() -> list[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            if not info[4][0].startswith("127."):
                ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ips)


def cmd_serve(_args) -> int:
    import uvicorn

    init_db()
    tls = bool(settings.ssl_certfile and settings.ssl_keyfile)
    loopback = settings.host in ("127.0.0.1", "localhost", "::1")
    if not tls and not loopback and not settings.allow_insecure_http:
        print("Refusing to listen on the network without TLS.\n"
              "  - Provide SSAI_SSL_CERTFILE and SSAI_SSL_KEYFILE, or\n"
              "  - set SSAI_ALLOW_INSECURE_HTTP=true in .env to allow plain HTTP on a trusted local network, or\n"
              "  - set SSAI_HOST=127.0.0.1 to listen on this computer only.")
        return 2
    scheme = "https" if tls else "http"
    print(f"\n{APP_NAME} {APP_VERSION}")
    print(f"  This computer : {scheme}://127.0.0.1:{settings.port}")
    if not loopback:
        for ip in _lan_ips():
            print(f"  Phone / LAN   : {scheme}://{ip}:{settings.port}")
        if not tls:
            print("  WARNING: plain HTTP. Use only on a trusted private network.")
    print("  Press Ctrl+C to stop.\n")
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, ssl_certfile=settings.ssl_certfile or None,
                ssl_keyfile=settings.ssl_keyfile or None, log_level=settings.log_level.lower(),
                proxy_headers=False, server_header=False)
    return 0


def cmd_doctor(_args) -> int:
    from .scanners.engines import engines_overview

    print(f"{APP_NAME} {APP_VERSION}")
    print(f"Data directory      : {settings.data_dir}")
    print(f"Listen address      : {settings.host}:{settings.port} ({'TLS' if settings.ssl_certfile else 'plain HTTP'})")
    print(f"Private targets     : {'ALLOWED (development only)' if settings.allow_private_targets else 'blocked'}")
    print("Scanner engines:")
    for e in engines_overview():
        print(f"  {e['name']:<40}{e['state']:<14}{e['version']}")
    return 0


def set_env_values(path, values: dict[str, str]) -> None:
    """Update or append KEY=value lines in a .env file, keeping comments and other lines untouched."""
    from pathlib import Path

    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    remaining = dict(values)
    out = []
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in remaining.items()]
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def cmd_enable_lan(_args) -> int:
    set_env_values(BASE_DIR / ".env", {"SSAI_HOST": "0.0.0.0", "SSAI_ALLOW_INSECURE_HTTP": "true"})
    print("Phone access enabled in .env (listening on all network interfaces, plain HTTP allowed on a trusted LAN).")
    print("Restart the server for this to take effect.")
    return 0


def cmd_disable_lan(_args) -> int:
    set_env_values(BASE_DIR / ".env", {"SSAI_HOST": "127.0.0.1", "SSAI_ALLOW_INSECURE_HTTP": "false"})
    print("Phone access disabled: the server will listen on this computer only. Restart the server.")
    return 0


def cmd_show_port(_args) -> int:
    print(settings.port)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description=APP_NAME)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db").set_defaults(fn=cmd_init_db)
    p = sub.add_parser("init-admin")
    p.add_argument("--username")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init_admin)
    p = sub.add_parser("reset-password")
    p.add_argument("username")
    p.set_defaults(fn=cmd_reset_password)
    sub.add_parser("list-users").set_defaults(fn=cmd_list_users)
    sub.add_parser("serve").set_defaults(fn=cmd_serve)
    sub.add_parser("doctor").set_defaults(fn=cmd_doctor)
    sub.add_parser("enable-lan").set_defaults(fn=cmd_enable_lan)
    sub.add_parser("disable-lan").set_defaults(fn=cmd_disable_lan)
    sub.add_parser("show-port").set_defaults(fn=cmd_show_port)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
