"""Convert ORM rows to JSON-safe dictionaries (timestamps are UTC with a trailing Z)."""
from __future__ import annotations

from datetime import datetime

from ..models import ROLE_LABEL, Finding, Scan, User


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def user_out(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "full_name": u.full_name, "email": u.email, "role": u.role,
        "role_label": ROLE_LABEL.get(u.role, u.role), "is_active": u.is_active,
        "must_change_password": u.must_change_password, "created_at": iso(u.created_at),
        "last_login_at": iso(u.last_login_at),
    }


def finding_out(f: Finding) -> dict:
    return {
        "id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity, "category": f.category,
        "finding_type": f.finding_type, "confidence": f.confidence, "engine": f.engine,
        "description": f.description, "simple_explanation": f.simple_explanation,
        "why_it_matters": f.why_it_matters, "remediation": f.remediation, "evidence": f.evidence,
        "url": f.url, "http_status": f.http_status, "file_path": f.file_path, "line": f.line, "cwe": f.cwe,
        "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector, "references": f.references or [],
    }


def scan_out(s: Scan, findings: list[Finding] | None = None) -> dict:
    data = {
        "id": s.id, "report_id": s.report_id, "scan_type": s.scan_type, "mode": s.mode, "target": s.target,
        "status": s.status, "progress": s.progress, "progress_message": s.progress_message,
        "created_at": iso(s.created_at), "started_at": iso(s.started_at), "finished_at": iso(s.finished_at),
        "owner": s.owner_name, "user_id": s.user_id, "score": s.score, "risk_level": s.risk_level,
        "summary": s.summary or {}, "engines": s.engines or [], "notes": s.notes or [], "error": s.error,
        "active_checks": s.active_checks, "config": {k: v for k, v in (s.config or {}).items() if k != "upload_path"},
    }
    if findings is not None:
        data["findings"] = [finding_out(f) for f in findings]
    return data
