from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import (ROLE_ADMIN, ROLE_RANK, ROLE_READONLY, ROLE_SUPER, ROLE_USER, AuditLog, Scan, SessionToken,
                      User, utcnow)
from ..services.audit import audit
from ..services.security import generate_temp_password, hash_password, password_problems
from ..services.serializers import iso, scan_out, user_out
from .deps import require_role

router = APIRouter(prefix="/api/users", tags=["users"])
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
ROLES = set(ROLE_RANK)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    full_name: str = Field(default="", max_length=128)
    email: str = Field(default="", max_length=254)
    role: str = ROLE_USER
    password: str = Field(min_length=1, max_length=256)
    must_change_password: bool = True


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=254)
    role: str | None = None
    is_active: bool | None = None


class ResetIn(BaseModel):
    new_password: str | None = Field(default=None, max_length=256)


def _assignable(actor: User) -> set[str]:
    return set(ROLES) if actor.role == ROLE_SUPER else {ROLE_USER, ROLE_READONLY}


def _check_email(value: str) -> None:
    if value and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise HTTPException(400, "The email address is not valid.")


def _load_target(db: Session, actor: User, user_id: int) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found.")
    if actor.role != ROLE_SUPER and target.role not in (ROLE_USER, ROLE_READONLY) and target.id != actor.id:
        raise HTTPException(403, "Only a Super Administrator can manage administrator accounts.")
    return target


def _active_supers(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == ROLE_SUPER, User.is_active.is_(True))) or 0


@router.get("")
def list_users(actor: User = Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.username)).all()
    counts = dict(db.execute(select(Scan.user_id, func.count()).group_by(Scan.user_id)).all())
    return [{**user_out(u), "scan_count": counts.get(u.id, 0)} for u in users]


@router.post("", status_code=201)
def create_user(body: UserCreate, request: Request, actor: User = Depends(require_role(ROLE_ADMIN)),
                db: Session = Depends(get_db)):
    username = body.username.strip().lower()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "Username must be 3-32 characters: lowercase letters, digits, dot, dash or underscore.")
    if body.role not in _assignable(actor):
        raise HTTPException(403, "You cannot assign that role.")
    _check_email(body.email)
    problems = password_problems(body.password, username)
    if problems:
        raise HTTPException(400, " ".join(problems))
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(409, "That username is already taken.")
    user = User(username=username, full_name=body.full_name.strip(), email=body.email.strip(), role=body.role,
                password_hash=hash_password(body.password), must_change_password=body.must_change_password,
                password_changed_at=utcnow())
    db.add(user)
    db.commit()
    audit(db, request, actor, "user_created", f"{username} ({body.role})")
    return user_out(user)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request,
                actor: User = Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    target = _load_target(db, actor, user_id)
    is_self = target.id == actor.id
    changes = []
    if body.role is not None and body.role != target.role:
        if is_self:
            raise HTTPException(400, "You cannot change your own role.")
        if body.role not in _assignable(actor):
            raise HTTPException(403, "You cannot assign that role.")
        if target.role == ROLE_SUPER and target.is_active and _active_supers(db) <= 1:
            raise HTTPException(400, "At least one active Super Administrator must remain.")
        target.role = body.role
        changes.append(f"role={body.role}")
    if body.is_active is not None and body.is_active != target.is_active:
        if is_self:
            raise HTTPException(400, "You cannot disable your own account.")
        if not body.is_active and target.role == ROLE_SUPER and _active_supers(db) <= 1:
            raise HTTPException(400, "At least one active Super Administrator must remain.")
        target.is_active = body.is_active
        changes.append(f"active={body.is_active}")
        if not body.is_active:
            db.execute(update(SessionToken).where(SessionToken.user_id == target.id).values(revoked=True))
    if body.full_name is not None:
        target.full_name = body.full_name.strip()
        changes.append("name")
    if body.email is not None:
        _check_email(body.email)
        target.email = body.email.strip()
        changes.append("email")
    db.commit()
    audit(db, request, actor, "user_updated", f"{target.username}: {', '.join(changes) or 'no change'}")
    return user_out(target)


@router.post("/{user_id}/reset-password")
def reset_password(user_id: int, body: ResetIn, request: Request,
                   actor: User = Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    target = _load_target(db, actor, user_id)
    if target.id == actor.id:
        raise HTTPException(400, "Use Change password for your own account.")
    generated = body.new_password in (None, "")
    password = generate_temp_password() if generated else body.new_password
    problems = password_problems(password, target.username)
    if problems:
        raise HTTPException(400, " ".join(problems))
    target.password_hash = hash_password(password)
    target.must_change_password = True
    target.password_changed_at = utcnow()
    db.execute(update(SessionToken).where(SessionToken.user_id == target.id).values(revoked=True))
    db.commit()
    audit(db, request, actor, "password_reset", target.username)
    return {"ok": True, "temporary_password": password if generated else None}


@router.delete("/{user_id}")
def delete_user(user_id: int, request: Request, actor: User = Depends(require_role(ROLE_ADMIN)),
                db: Session = Depends(get_db)):
    target = _load_target(db, actor, user_id)
    if target.id == actor.id:
        raise HTTPException(400, "You cannot delete your own account.")
    if target.role == ROLE_SUPER and target.is_active and _active_supers(db) <= 1:
        raise HTTPException(400, "At least one active Super Administrator must remain.")
    name = target.username
    db.execute(delete(SessionToken).where(SessionToken.user_id == target.id))
    db.execute(update(Scan).where(Scan.user_id == target.id).values(user_id=None))
    db.delete(target)
    db.commit()
    audit(db, request, actor, "user_deleted", name)
    return {"ok": True}


@router.get("/{user_id}/activity")
def user_activity(user_id: int, actor: User = Depends(require_role(ROLE_ADMIN)), db: Session = Depends(get_db)):
    target = _load_target(db, actor, user_id)
    events = db.scalars(select(AuditLog).where(AuditLog.user_id == target.id)
                        .order_by(AuditLog.id.desc()).limit(100)).all()
    scans = db.scalars(select(Scan).where(Scan.user_id == target.id).order_by(Scan.created_at.desc()).limit(20)).all()
    return {
        "user": user_out(target),
        "events": [{"id": e.id, "created_at": iso(e.created_at), "action": e.action, "detail": e.detail, "ip": e.ip}
                   for e in events],
        "scans": [scan_out(s) for s in scans],
    }
