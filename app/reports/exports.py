"""JSON and CSV report builders. All data comes from stored scan results."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from ..config import APP_NAME, APP_VERSION
from ..models import Finding, Scan
from ..services.serializers import finding_out, scan_out
from .common import DISCLAIMER, LIMITATIONS, METHODOLOGY

CSV_COLUMNS = ["report_id", "scan_id", "target", "severity", "title", "category", "finding_type", "confidence",
               "engine", "rule_id", "cwe", "cvss_score", "url", "file_path", "line", "http_status", "evidence",
               "remediation"]


def build_report_dict(scan: Scan, findings: list[Finding]) -> dict:
    s = scan_out(scan)
    return {
        "report": {"id": scan.report_id, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "generator": f"{APP_NAME} {APP_VERSION}"},
        "scan": {k: s[k] for k in ("id", "scan_type", "mode", "target", "status", "created_at", "started_at",
                                   "finished_at", "owner", "active_checks", "config")},
        "score": {"value": scan.score, "risk_level": scan.risk_level, "methodology": METHODOLOGY},
        "summary": scan.summary or {}, "engines": scan.engines or [], "notes": scan.notes or [],
        "findings": [finding_out(f) for f in findings],
        "limitations": LIMITATIONS.get(scan.scan_type, []), "disclaimer": DISCLAIMER,
    }


def build_json(scan: Scan, findings: list[Finding]) -> bytes:
    return json.dumps(build_report_dict(scan, findings), indent=2, ensure_ascii=False).encode("utf-8")


def _safe_cell(value):
    """Neutralise spreadsheet formula injection (CSV injection)."""
    if isinstance(value, str) and value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def build_csv(scan: Scan, findings: list[Finding]) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for f in findings:
        row = {
            "report_id": scan.report_id, "scan_id": scan.id, "target": scan.target, "severity": f.severity,
            "title": f.title, "category": f.category, "finding_type": f.finding_type, "confidence": f.confidence,
            "engine": f.engine, "rule_id": f.rule_id, "cwe": f.cwe or "", "cvss_score": f.cvss_score or "",
            "url": f.url or "", "file_path": f.file_path or "", "line": f.line or "",
            "http_status": f.http_status or "", "evidence": (f.evidence or "").replace("\r", " "),
            "remediation": f.remediation,
        }
        writer.writerow([_safe_cell(row[c]) for c in CSV_COLUMNS])
    return ("\ufeff" + buf.getvalue()).encode("utf-8")  # BOM so Excel detects UTF-8
