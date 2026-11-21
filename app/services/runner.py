"""Background scan execution with progress reporting, cancellation and time limits."""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import select, update

from ..config import settings
from ..database import SessionLocal
from ..models import Finding, Scan, utcnow
from ..scanners import engines, source_scan, web_checks
from ..scanners.base import Ctx, ScanError, compute_score, sort_findings, summarize
from ..scanners.netsafe import (FetchError, SafeClient, ScanCancelled, ScanLimitError,
                                UnsafeTargetError)

log = logging.getLogger("securescan.runner")
_executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_scans, thread_name_prefix="scan")
_FINDING_FIELDS = {
    "rule_id", "title", "severity", "category", "finding_type", "confidence", "engine", "description",
    "simple_explanation", "why_it_matters", "remediation", "evidence", "url", "http_status", "file_path",
    "line", "cwe", "cvss_score", "cvss_vector", "references",
}
MAX_FINDINGS = 3000


def submit(scan_id: str) -> None:
    _executor.submit(_safe_execute, scan_id)


def recover_interrupted() -> int:
    with SessionLocal() as db:
        rows = db.scalars(select(Scan).where(Scan.status.in_(["queued", "running"]))).all()
        for s in rows:
            s.status, s.error, s.finished_at = "failed", "Interrupted by a server restart.", utcnow()
        db.commit()
        return len(rows)


def _set(scan_id: str, **values) -> None:
    with SessionLocal() as db:
        db.execute(update(Scan).where(Scan.id == scan_id).values(**values))
        db.commit()


def _cancel_requested(scan_id: str) -> bool:
    with SessionLocal() as db:
        return bool(db.scalar(select(Scan.cancel_requested).where(Scan.id == scan_id)))


def _safe_execute(scan_id: str) -> None:
    try:
        _execute(scan_id)
    except Exception:  # last line of defence: never leave a scan stuck in 'running'
        log.exception("Unexpected scan failure for %s", scan_id)
        _set(scan_id, status="failed", error="An internal error occurred while scanning. See the server log.",
             finished_at=utcnow())


def _execute(scan_id: str) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "queued":
            return
        scan_type, target, cfg = scan.scan_type, scan.target, dict(scan.config or {})
        active = scan.active_checks
    _set(scan_id, status="running", started_at=utcnow(), progress=2, progress_message="Starting")
    deadline = time.monotonic() + settings.scan_timeout_seconds
    state = {"timeout": False}

    def cancelled() -> bool:
        if time.monotonic() > deadline:
            state["timeout"] = True
            return True
        return _cancel_requested(scan_id)

    def progress(pct: int, msg: str) -> None:
        _set(scan_id, progress=max(2, min(98, pct)), progress_message=msg[:250])

    engine_log: list[dict] = []
    notes: list[str] = []
    findings: list[dict] = []
    try:
        if scan_type == "website":
            findings, notes = _website(target, cfg, active, cancelled, progress, engine_log)
        else:
            findings, notes = _source(scan_id, cfg, cancelled, progress, engine_log)
    except (ScanCancelled,):
        if state["timeout"]:
            _set(scan_id, status="failed", error="The scan exceeded its time limit.", finished_at=utcnow(),
                 engines=engine_log)
        else:
            _set(scan_id, status="cancelled", progress_message="Cancelled", finished_at=utcnow(), engines=engine_log)
        return
    except (ScanError, UnsafeTargetError, source_scan.ArchiveError, ScanLimitError) as exc:
        _set(scan_id, status="failed", error=str(exc)[:1000], finished_at=utcnow(), engines=engine_log)
        return
    if _cancel_requested(scan_id):
        _set(scan_id, status="cancelled", progress_message="Cancelled", finished_at=utcnow(), engines=engine_log)
        return

    if len(findings) > MAX_FINDINGS:
        notes.append(f"Only the first {MAX_FINDINGS} findings were stored.")
    findings = sort_findings(findings)[:MAX_FINDINGS]
    score, risk = compute_score(findings)
    with SessionLocal() as db:
        for f in findings:
            clean = {k: v for k, v in f.items() if k in _FINDING_FIELDS}
            clean.setdefault("references", [])
            db.add(Finding(scan_id=scan_id, **clean))
        db.execute(update(Scan).where(Scan.id == scan_id).values(
            status="completed", progress=100, progress_message="Completed", finished_at=utcnow(),
            summary=summarize(findings), score=score, risk_level=risk, engines=engine_log, notes=notes))
        db.commit()


def _website(target, cfg, active, cancelled, progress, engine_log):
    client = SafeClient(allow_private=settings.allow_private_targets, timeout=settings.http_timeout,
                        max_requests=settings.max_requests_per_scan, delay_ms=settings.request_delay_ms,
                        should_cancel=cancelled)
    selected = set(cfg.get("checks") or web_checks.PASSIVE_IDS)
    ctx = Ctx(client=client, target_url=target, selected_checks=selected, active_allowed=active,
              progress=progress)
    web_checks.run_web_checks(ctx)
    engine_log.append({"id": "builtin-web", "name": "SecureScan built-in website checks", "status": "completed",
                       "detail": f"{client.request_count} HTTP request(s); checks: {', '.join(sorted(selected))}.",
                       "findings": len(ctx.findings)})
    findings = list(ctx.findings)
    notes = list(ctx.notes)
    if ctx.info.get("technologies"):
        notes.append("Detected technologies: " + "; ".join(ctx.info["technologies"][:8]))
    if "zap" in (cfg.get("engines") or []):
        if not active:
            engine_log.append({"id": "zap", "name": "OWASP ZAP", "status": "skipped", "findings": 0,
                               "detail": "Requires an authorized (allowlisted) target; scan not performed."})
        else:
            progress(20, "Running OWASP ZAP")
            status, detail, extra = engines.run_zap(target, active, cancelled, progress)
            engine_log.append({"id": "zap", "name": "OWASP ZAP", "status": status, "detail": detail,
                               "findings": len(extra)})
            findings += extra
    return findings, notes


def _source(scan_id, cfg, cancelled, progress, engine_log):
    upload = Path(cfg["upload_path"])
    work = settings.work_dir / scan_id
    try:
        progress(5, "Validating and extracting the archive")
        stats = source_scan.safe_extract(
            upload, work, max_files=settings.max_files, max_total_bytes=settings.max_extract_mb * 1024 * 1024,
            max_file_bytes=settings.max_file_kb * 1024, max_ratio=settings.max_zip_ratio)
        notes = [f"Extracted {stats['extracted']} file(s) ({stats['bytes'] // 1024} KB). Skipped: "
                 f"{stats['skipped_vendor']} vendor/build, {stats['skipped_binary']} binary/other, "
                 f"{stats['skipped_large']} oversize, {stats['skipped_links']} symlink(s)."]
        if cancelled():
            raise ScanCancelled()

        def sub(pct):
            return lambda p, m: progress(10 + int(pct * p / 100), m)

        findings, scan_notes = source_scan.scan_tree(work, sub(40), cancelled)
        notes += scan_notes
        engine_log.append({"id": "builtin-source", "name": "SecureScan built-in source rules",
                           "status": "completed", "detail": "Pattern rules; findings are potential issues that need review.",
                           "findings": len(findings)})
        selected = cfg.get("engines")
        want = ["semgrep", "trivy", "osv"] if selected is None else list(selected)
        runners = {"semgrep": engines.run_semgrep, "trivy": engines.run_trivy, "osv": engines.run_osv}
        names = {"semgrep": "Semgrep", "trivy": "Trivy", "osv": "OSV.dev dependency lookup"}
        for i, eid in enumerate(want):
            if eid not in runners:
                continue
            progress(55 + i * 12, f"Running {names[eid]}")
            status, detail, extra = runners[eid](work, cancelled)
            engine_log.append({"id": eid, "name": names[eid], "status": status, "detail": detail, "findings": len(extra)})
            findings += extra
            if cancelled():
                raise ScanCancelled()
        dep_engines_ran = any(e["id"] in ("trivy", "osv") and e["status"] == "completed" for e in engine_log)
        mf = source_scan.manifest_finding(stats["manifests"])
        if mf:
            findings.append(mf)
            if not dep_engines_ran:
                notes.append("Dependency vulnerability check was NOT performed (Trivy and OSV are not available).")
        return findings, notes
    finally:
        source_scan.cleanup(work, upload)
