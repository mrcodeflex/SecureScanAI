from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import SessionToken, User, utcnow
from ..services.audit import audit, client_ip
from ..services.security import (DUMMY_HASH, hash_password, hash_token, login_ip_limiter, login_user_limiter,
                                 needs_rehash, new_token, password_problems, verify_password)
from ..services.serializers import iso, user_out
from .deps import current_session, current_user_any

router = APIRouter(prefix="/api/auth", tags=["authentication"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    uname = body.username.strip().lower()
    for limiter, key in ((login_user_limiter, f"user:{uname}"), (login_ip_limiter, f"ip:{ip}")):
        wait = limiter.retry_after(key)
        if wait:
            audit(db, request, None, "login_blocked", "Too many attempts", username=uname)
            raise HTTPException(429, f"Too many sign-in attempts. Try again in {wait // 60 + 1} minute(s).",
                                headers={"Retry-After": str(wait)})
    user = db.scalar(select(User).where(User.username == uname))
    password_ok = verify_password(user.password_hash if user else DUMMY_HASH, body.password)
    if not (user and password_ok and user.is_active):
        login_user_limiter.hit(f"user:{uname}")
        login_ip_limiter.hit(f"ip:{ip}")
        audit(db, request, user if user else None, "login_failed",
              "Account disabled" if user and password_ok and not user.is_active else "Bad credentials",
              username=uname)
        raise HTTPException(401, "Invalid username or password.")
    login_user_limiter.reset(f"user:{uname}")
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    token = new_token()
    expires = utcnow() + timedelta(minutes=settings.session_minutes)
    db.add(SessionToken(user_id=user.id, token_hash=hash_token(token), expires_at=expires, ip=ip,
                        user_agent=(request.headers.get("user-agent") or "")[:255]))
    user.last_login_at = utcnow()
    db.commit()
    audit(db, request, user, "login", "Signed in")
    return {"token": token, "token_type": "bearer", "expires_at": iso(expires), "user": user_out(user)}


@router.post("/logout")
def logout(request: Request, session=Depends(current_session), db: Session = Depends(get_db)):
    user, row = session
    row.revoked = True
    db.commit()
    audit(db, request, user, "logout", "Signed out")
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user_any)):
    return user_out(user)


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, session=Depends(current_session),
                    db: Session = Depends(get_db)):
    user, current = session
    if not verify_password(user.password_hash, body.current_password):
        audit(db, request, user, "password_change_failed", "Wrong current password")
        raise HTTPException(400, "The current password is not correct.")
    problems = password_problems(body.new_password, user.username)
    if problems:
        raise HTTPException(400, " ".join(problems))
    if body.new_password == body.current_password:
        raise HTTPException(400, "Choose a password different from the current one.")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    db.execute(update(SessionToken).where(SessionToken.user_id == user.id, SessionToken.id != current.id)
               .values(revoked=True))
    db.commit()
    audit(db, request, user, "password_changed", "Password changed")
    return {"ok": True, "user": user_out(user)}
