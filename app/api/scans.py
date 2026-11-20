from __future__ import annotations

import ipaddress
import re
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import (ROLE_ADMIN, ROLE_RANK, ROLE_READONLY, ROLE_USER, SEVERITY_RANK, AuthorizedTarget, Finding,
                      Scan, User, utcnow)
from ..reports.exports import build_csv, build_json
from ..reports.pdf import build_pdf
from ..scanners.netsafe import UnsafeTargetError, parse_target
from ..scanners.web_checks import ACTIVE_IDS, CHECKS, PASSIVE_IDS
from ..services import runner
from ..services.audit import audit
from ..services.security import scan_limiter
from ..services.serializers import scan_out
from .deps import current_user, require_role

router = APIRouter(prefix="/api/scans", tags=["scans"])
SOURCE_ENGINES = {"semgrep", "trivy", "osv"}


class WebsiteScanIn(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    mode: Literal["beginner", "advanced"] = "beginner"
    checks: list[str] | None = None
    active_checks: bool = False
    engines: list[str] = []
    authorization_confirmed: bool = False


def host_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().strip(), host.lower().strip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return pattern == host


def is_authorized(db: Session, host: str) -> bool:
    return any(host_matches(t.pattern, host) for t in db.scalars(select(AuthorizedTarget)).all())


def _can_see_all(user: User) -> bool:
    return ROLE_RANK[user.role] >= ROLE_RANK[ROLE_ADMIN] or user.role == ROLE_READONLY


def _visible(user: User):
    return [] if _can_see_all(user) else [Scan.user_id == user.id]


def _get_scan(db: Session, scan_id: str, user: User) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or (not _can_see_all(user) and scan.user_id != user.id):
        raise HTTPException(404, "Scan not found.")
    return scan


def _throttle(user: User) -> None:
    wait = scan_limiter.consume(f"scan:{user.id}")
    if wait:
        raise HTTPException(429, f"You are starting scans too quickly. Try again in {wait} seconds.",
                            headers={"Retry-After": str(wait)})


@router.post("/website", status_code=201)
def create_website_scan(body: WebsiteScanIn, request: Request, user: User = Depends(require_role(ROLE_USER)),
                        db: Session = Depends(get_db)):
    if not body.authorization_confirmed:
        raise HTTPException(400, "Confirm that you are authorized to scan this target.")
    try:
        target = parse_target(body.url, settings.allow_private_targets, resolve=True)
    except UnsafeTargetError as exc:
        raise HTTPException(400, str(exc))
    allowlisted = is_authorized(db, target.host)
    if settings.require_allowlist_for_all and not allowlisted:
        raise HTTPException(403, "This server only scans targets on the authorization allowlist.")
    active = False
    engines: list[str] = []
    if body.mode == "advanced":
        chosen = [c for c in (body.checks or PASSIVE_IDS) if c in CHECKS]
        unknown = [c for c in (body.checks or []) if c not in CHECKS]
        if unknown:
            raise HTTPException(400, f"Unknown check(s): {', '.join(unknown)}")
        engines = [e for e in body.engines if e == "zap"]
        if body.active_checks or engines:
            if not allowlisted:
                raise HTTPException(403, "Active checks require the target host to be on the authorization "
                                         "allowlist (Settings > Authorized targets).")
            active = True
        if not active:
            chosen = [c for c in chosen if c in PASSIVE_IDS]
            engines = []
        elif body.active_checks and not any(c in ACTIVE_IDS for c in chosen):
            chosen += ACTIVE_IDS
        if not chosen:
            chosen = list(PASSIVE_IDS)
    else:
        chosen = list(PASSIVE_IDS)
    _throttle(user)
    scan = Scan(user_id=user.id, owner_name=user.username, scan_type="website", mode=body.mode,
                target=body.url.strip(), authorization_confirmed=True, active_checks=active,
                config={"checks": chosen, "engines": engines, "allowlisted": allowlisted})
    db.add(scan)
    db.commit()
    audit(db, request, user, "scan_created", f"website {scan.id} {target.host} active={active}")
    runner.submit(scan.id)
    return scan_out(scan)


@router.post("/source", status_code=201)
def create_source_scan(request: Request, file: UploadFile = File(...), mode: str = Form("beginner"),
                       engines: str = Form(""), authorization_confirmed: bool = Form(False),
                       user: User = Depends(require_role(ROLE_USER)), db: Session = Depends(get_db)):
    if not authorization_confirmed:
        raise HTTPException(400, "Confirm that you own this code or are authorized to assess it.")
    if mode not in ("beginner", "advanced"):
        raise HTTPException(400, "Mode must be beginner or advanced.")
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", (file.filename or "upload.zip"))[-120:]
    if not name.lower().endswith(".zip"):
        raise HTTPException(400, "Upload a .zip file.")
    chosen: list[str] | None = None
    if mode == "advanced":
        chosen = [e for e in engines.split(",") if e in SOURCE_ENGINES]
    _throttle(user)
    scan = Scan(user_id=user.id, owner_name=user.username, scan_type="source", mode=mode, target=name,
                authorization_confirmed=True, config={"engines": chosen})
    dest = settings.uploads_dir / f"{scan.id}.zip"
    limit = settings.max_upload_mb * 1024 * 1024
    size = 0
    try:
        head = file.file.read(4)
        if head[:2] != b"PK":
            raise HTTPException(400, "The file is not a ZIP archive.")
        file.file.seek(0)
        with open(dest, "wb") as out:
            while True:
                chunk = file.file.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"The archive is larger than {settings.max_upload_mb} MB.")
                out.write(chunk)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    scan.config = {**scan.config, "upload_path": str(dest), "size_bytes": size}
    db.add(scan)
    db.commit()
    audit(db, request, user, "scan_created", f"source {scan.id} {name} ({size // 1024} KB)")
    runner.submit(scan.id)
    return scan_out(scan)


@router.get("")
def list_scans(status: str | None = None, scan_type: str | None = None, q: str | None = Query(None, max_length=100),
               limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0),
               user: User = Depends(current_user), db: Session = Depends(get_db)):
    conds = _visible(user)
    if status:
        conds.append(Scan.status == status)
    if scan_type in ("website", "source"):
        conds.append(Scan.scan_type == scan_type)
    if q:
        conds.append(Scan.target.ilike(f"%{q.replace('%', '').replace('_', '')}%"))
    total = db.scalar(select(func.count()).select_from(Scan).where(*conds)) or 0
    rows = db.scalars(select(Scan).where(*conds).order_by(Scan.created_at.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "items": [scan_out(s) for s in rows]}


@router.get("/{scan_id}")
def get_scan(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, user)
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.title))
    return scan_out(scan, findings)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: str, request: Request, user: User = Depends(require_role(ROLE_USER)),
                db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, user)
    if scan.user_id != user.id and ROLE_RANK[user.role] < ROLE_RANK[ROLE_ADMIN]:
        raise HTTPException(403, "You can only cancel your own scans.")
    if scan.status not in ("queued", "running"):
        raise HTTPException(409, "This scan is not running.")
    scan.cancel_requested = True
    if scan.status == "queued":
        scan.status, scan.progress_message, scan.finished_at = "cancelled", "Cancelled", utcnow()
    db.commit()
    audit(db, request, user, "scan_cancelled", scan.id)
    return scan_out(scan)


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, request: Request, user: User = Depends(require_role(ROLE_USER)),
                db: Session = Depends(get_db)):
    scan = _get_scan(db, scan_id, user)
    if scan.user_id != user.id and ROLE_RANK[user.role] < ROLE_RANK[ROLE_ADMIN]:
        raise HTTPException(403, "You can only delete your own scans.")
    if scan.status in ("queued", "running"):
        raise HTTPException(409, "Cancel the scan before deleting it.")
    db.delete(scan)
    db.commit()
    audit(db, request, user, "scan_deleted", scan_id)
    return {"ok": True}


_REPORTS = {
    "pdf": ("application/pdf", build_pdf), "json": ("application/json", build_json),
    "csv": ("text/csv; charset=utf-8", build_csv),
}


@router.get("/{scan_id}/report.{fmt}")
def download_report(scan_id: str, fmt: str, request: Request, user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    if fmt not in _REPORTS:
        raise HTTPException(404, "Unknown report format.")
    scan = _get_scan(db, scan_id, user)
    if scan.status != "completed":
        raise HTTPException(409, "Reports are available once a scan has completed.")
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.title))
    media, builder = _REPORTS[fmt]
    content = builder(scan, findings)
    audit(db, request, user, "report_downloaded", f"{scan.report_id} {fmt}")
    return Response(content, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="SecureScanAI-{scan.report_id}.{fmt}"',
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
