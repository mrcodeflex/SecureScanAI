"""Shared FastAPI dependencies: authentication and role checks."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ROLE_RANK, SessionToken, User, utcnow
from ..services.security import hash_token


def _extract_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    token = authorization[7:].strip()
    if not token or len(token) > 200:
        raise HTTPException(401, "Authentication required.", headers={"WWW-Authenticate": "Bearer"})
    return token


def _load_user(db: Session, authorization: str | None) -> tuple[User, SessionToken]:
    token = _extract_token(authorization)
    row = db.scalar(select(SessionToken).where(SessionToken.token_hash == hash_token(token)))
    if row is None or row.revoked or row.expires_at <= utcnow():
        raise HTTPException(401, "Session expired. Please sign in again.",
                            headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, row.user_id)
    if user is None or not user.is_active:
        raise HTTPException(401, "Account is disabled.", headers={"WWW-Authenticate": "Bearer"})
    return user, row


def current_session(request: Request, db: Session = Depends(get_db),
                    authorization: str | None = Header(default=None)) -> tuple[User, SessionToken]:
    return _load_user(db, authorization)


def current_user_any(session=Depends(current_session)) -> User:
    """Authenticated user, even if a password change is still pending."""
    return session[0]


def current_user(user: User = Depends(current_user_any)) -> User:
    if user.must_change_password:
        raise HTTPException(403, "You must change your password before continuing.")
    return user


def require_role(minimum: str) -> Callable[[User], User]:
    def checker(user: User = Depends(current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(403, "You do not have permission to do this.")
        return user

    return checker
