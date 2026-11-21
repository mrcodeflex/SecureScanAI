from __future__ import annotations

import ipaddress
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import APP_NAME, APP_VERSION, settings
from ..database import get_db
from ..models import (ROLE_ADMIN, ROLE_RANK, ROLE_READONLY, ROLE_USER, SEVERITIES, AuditLog, AuthorizedTarget,
                      Finding, Scan, User, utcnow)
from ..scanners import engines
from ..scanners.knowledge import SCORE_METHODOLOGY
from ..scanners.web_checks import CHECKS
from ..services.audit import audit
from ..services.serializers import iso, scan_out
from .deps import current_user, require_role

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health():
    """Unauthenticated, minimal: lets the Android app test the connection."""
    return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}


@router.get("/system/info")
def system_info(user: User = Depends(current_user)):
    return {"app": APP_NAME, "version": APP_VERSION, "max_upload_mb": settings.max_upload_mb,
            "allow_private_targets": settings.allow_private_targets,
            "require_allowlist_for_all": settings.require_allowlist_for_all,
            "session_minutes": settings.session_minutes, "score_methodology": SCORE_METHODOLOGY,
            "max_requests_per_scan": settings.max_requests_per_scan}


@router.get("/system/engines")
def system_engines(user: User = Depends(current_user)):
    return engines.engines_overview()


@router.get("/system/checks")
def system_checks(user: User = Depends(current_user)):
    return [{"id": k, **v} for k, v in CHECKS.items()]


@router.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(get_db)):
    see_all = ROLE_RANK[user.role] >= ROLE_RANK[ROLE_ADMIN] or user.role == ROLE_READONLY
    scope = [] if see_all else [Scan.user_id == user.id]
    count = lambda *c: db.scalar(select(func.count()).select_from(Scan).where(*scope, *c)) or 0
    sev_rows = db.execute(select(Finding.severity, func.count()).join(Scan, Scan.id == Finding.scan_id)
                          .where(*scope, Scan.status == "completed").group_by(Finding.severity)).all()
    severity = {s: 0 for s in SEVERITIES}
    severity.update({k: v for k, v in sev_rows})
    cats = db.execute(select(Finding.category, func.count().label("n")).join(Scan, Scan.id == Finding.scan_id)
                      .where(*scope, Scan.status == "completed", Finding.finding_type != "observation")
                      .group_by(Finding.category).order_by(func.count().desc()).limit(8)).all()
    since = utcnow() - timedelta(days=13)
    created = db.scalars(select(Scan.created_at).where(*scope, Scan.created_at >= since)).all()
    per_day = {}
    for i in range(14):
        per_day[(since + timedelta(days=i)).strftime("%Y-%m-%d")] = 0
    for c in created:
        key = c.strftime("%Y-%m-%d")
        if key in per_day:
            per_day[key] += 1
    recent = db.scalars(select(Scan).where(*scope).order_by(Scan.created_at.desc()).limit(8)).all()
    avg = db.scalar(select(func.avg(Scan.score)).where(*scope, Scan.status == "completed"))
    data = {
        "totals": {"scans": count(), "completed": count(Scan.status == "completed"),
                   "failed": count(Scan.status == "failed"), "running": count(Scan.status.in_(["queued", "running"])),
                   "average_score": round(avg) if avg is not None else None},
        "severity": severity, "categories": [{"name": n, "count": c} for n, c in cats],
        "scans_per_day": [{"date": d, "count": c} for d, c in per_day.items()],
        "recent_scans": [scan_out(s) for s in recent], "scope": "all" if see_all else "own",
    }
    if ROLE_RANK[user.role] >= ROLE_RANK[ROLE_ADMIN]:
        events = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(10)).all()
        data["activity"] = [{"created_at": iso(e.created_at), "username": e.username, "action": e.action,
                             "detail": e.detail} for e in events]
    return data


# ------------------------------------------------------- authorized targets
_PATTERN_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


class TargetIn(BaseModel):
    pattern: str = Field(min_length=1, max_length=253)
    note: str = Field(default="", max_length=255)


def _target_out(t: AuthorizedTarget) -> dict:
    return {"id": t.id, "pattern": t.pattern, "note": t.note, "created_by": t.created_by,
            "created_at": iso(t.created_at)}


@router.get("/targets")
def list_targets(user: User = Depends(require_role(ROLE_USER)), db: Session = Depends(get_db)):
    return [_target_out(t) for t in db.scalars(select(AuthorizedTarget).order_by(AuthorizedTarget.pattern)).all()]


@router.post("/targets", status_code=201)
def add_target(body: TargetIn, request: Request, user: User = Depends(require_role(ROLE_ADMIN)),
               db: Session = Depends(get_db)):
    pattern = body.pattern.strip().lower()
    valid = bool(_PATTERN_RE.match(pattern))
    try:
        ipaddress.ip_address(pattern.strip("[]"))
        valid = True
    except ValueError:
        pass
    if not valid or pattern in ("*.", "*"):
        raise HTTPException(400, "Enter a host name (example.com), a wildcard (*.example.com) or an IP address.")
    if db.scalar(select(AuthorizedTarget).where(AuthorizedTarget.pattern == pattern)):
        raise HTTPException(409, "That target is already on the list.")
    t = AuthorizedTarget(pattern=pattern, note=body.note.strip(), created_by=user.username)
    db.add(t)
    db.commit()
    audit(db, request, user, "target_added", pattern)
    return _target_out(t)


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, request: Request, user: User = Depends(require_role(ROLE_ADMIN)),
                  db: Session = Depends(get_db)):
    t = db.get(AuthorizedTarget, target_id)
    if t is None:
        raise HTTPException(404, "Target not found.")
    db.delete(t)
    db.commit()
    audit(db, request, user, "target_removed", t.pattern)
    return {"ok": True}


@router.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), action: str | None = Query(None, max_length=64),
              user: User = Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    q = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if action:
        q = q.where(AuditLog.action == action)
    return [{"id": e.id, "created_at": iso(e.created_at), "username": e.username, "action": e.action,
             "detail": e.detail, "ip": e.ip} for e in db.scalars(q).all()]
