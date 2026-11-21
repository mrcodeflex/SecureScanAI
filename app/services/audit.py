"""Audit logging. Never pass passwords or tokens in `detail`."""
from __future__ import annotations

import logging

from fastapi import Request
from sqlalchemy.orm import Session

from ..models import AuditLog, User

log = logging.getLogger("securescan.audit")


def client_ip(request: Request | None) -> str:
    if request is None or request.client is None:
        return ""
    return request.client.host or ""


def audit(db: Session, request: Request | None, user: User | None, action: str,
          detail: str = "", username: str | None = None) -> None:
    entry = AuditLog(
        user_id=user.id if user else None,
        username=(user.username if user else (username or ""))[:64],
        action=action[:64],
        detail=detail[:2000],
        ip=client_ip(request),
    )
    db.add(entry)
    db.commit()
    log.info("audit action=%s user=%s ip=%s", action, entry.username, entry.ip)
