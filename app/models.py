"""Database models. Only portable column types are used so the schema can move to PostgreSQL."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base

ROLE_SUPER = "super_admin"
ROLE_ADMIN = "admin"
ROLE_USER = "user"
ROLE_READONLY = "read_only"
ROLE_RANK = {ROLE_READONLY: 1, ROLE_USER: 2, ROLE_ADMIN: 3, ROLE_SUPER: 4}
ROLE_LABEL = {
    ROLE_SUPER: "Super Administrator",
    ROLE_ADMIN: "Administrator",
    ROLE_USER: "Standard User",
    ROLE_READONLY: "Read-only User",
}

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def utcnow() -> datetime:
    """Naive UTC timestamp (portable across SQLite and PostgreSQL)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    email: Mapped[str] = mapped_column(String(254), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default=ROLE_USER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SessionToken(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    owner_name: Mapped[str] = mapped_column(String(64), default="")
    scan_type: Mapped[str] = mapped_column(String(16))  # website | source
    mode: Mapped[str] = mapped_column(String(16), default="beginner")
    target: Mapped[str] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    progress_message: Mapped[str] = mapped_column(String(255), default="Queued")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    engines: Mapped[list] = mapped_column(JSON, default=list)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[list] = mapped_column(JSON, default=list)
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    active_checks: Mapped[bool] = mapped_column(Boolean, default=False)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def report_id(self) -> str:
        return f"SSAI-{self.created_at:%Y%m%d}-{self.id[:8].upper()}"


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), default="")
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    category: Mapped[str] = mapped_column(String(80), default="General", index=True)
    finding_type: Mapped[str] = mapped_column(String(20), default="misconfiguration")
    confidence: Mapped[str] = mapped_column(String(10), default="medium")
    engine: Mapped[str] = mapped_column(String(40), default="builtin")
    description: Mapped[str] = mapped_column(Text, default="")
    simple_explanation: Mapped[str] = mapped_column(Text, default="")
    why_it_matters: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)
    references: Mapped[list] = mapped_column(JSON, default=list)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    pattern: Mapped[str] = mapped_column(String(255), unique=True)
    note: Mapped[str] = mapped_column(String(255), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
