"""PDF report built with ReportLab from stored scan results."""
from __future__ import annotations

import io
import re
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Path, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from ..config import APP_NAME, APP_VERSION
from ..models import Finding, Scan
from .common import (DISCLAIMER, LIMITATIONS, METHODOLOGY, RISK_LABEL, SEV_LABEL, SEV_ORDER, TYPE_LABEL)

NAVY, BLUE, INK, MUTED = colors.HexColor("#0B1B3A"), colors.HexColor("#2F6FED"), colors.HexColor("#17233B"), colors.HexColor("#5B6B8A")
SEV_COLOR = {"critical": "#C62828", "high": "#E65100", "medium": "#B58100", "low": "#1565C0", "info": "#546E7A"}
MAX_PDF_FINDINGS = 300


def _t(value, limit: int | None = None) -> str:
    """Escape for ReportLab paragraphs and drop characters the built-in fonts cannot draw."""
    s = "" if value is None else str(value)
    if limit and len(s) > limit:
        s = s[:limit] + "..."
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", s).encode("cp1252", "replace").decode("cp1252")
    return escape(s)


def _styles():
    base = getSampleStyleSheet()
    mk = lambda name, **kw: ParagraphStyle(name, parent=base["Normal"], **kw)
    return {
        "h1": mk("h1", fontName="Helvetica-Bold", fontSize=20, textColor=NAVY, leading=24, spaceAfter=4),
        "h2": mk("h2", fontName="Helvetica-Bold", fontSize=13, textColor=NAVY, leading=16, spaceBefore=12, spaceAfter=6),
        "body": mk("body", fontSize=9.2, leading=13, textColor=INK, alignment=TA_LEFT),
        "small": mk("small", fontSize=8, leading=11, textColor=MUTED),
        "ftitle": mk("ftitle", fontName="Helvetica-Bold", fontSize=10.5, leading=14, textColor=INK, keepWithNext=1),
        "code": mk("code", fontName="Courier", fontSize=7.8, leading=10, textColor=INK, wordWrap="CJK",
                   backColor=colors.HexColor("#F1F4FA"), borderPadding=4, leftIndent=2, spaceAfter=6),
        "label": mk("label", fontName="Helvetica-Bold", fontSize=8.5, textColor=MUTED, leading=11, spaceBefore=5, spaceAfter=6, keepWithNext=1),
        "score": mk("score", fontSize=11, leading=38, textColor=INK),
    }


def _logo() -> Drawing:
    d = Drawing(34, 40)
    shield = Path(fillColor=BLUE, strokeColor=None)
    shield.moveTo(17, 39); shield.lineTo(33, 33); shield.lineTo(33, 20)
    shield.curveTo(33, 9, 25, 3, 17, 0); shield.curveTo(9, 3, 1, 9, 1, 20); shield.lineTo(1, 33); shield.closePath()
    d.add(shield)
    check = Path(strokeColor=colors.white, strokeWidth=3, fillColor=None)
    check.moveTo(9, 19); check.lineTo(15, 12); check.lineTo(26, 27)
    d.add(check)
    return d


def _bars(summary: dict) -> Drawing:
    total = max(1, max(summary.get(s, 0) for s in SEV_ORDER))
    d = Drawing(170 * mm, 38 * mm)
    for i, sev in enumerate(SEV_ORDER):
        y = 38 * mm - (i + 1) * 7 * mm
        n = summary.get(sev, 0)
        d.add(String(0, y + 1.5, SEV_LABEL[sev], fontName="Helvetica", fontSize=8.5, fillColor=INK))
        d.add(Rect(28 * mm, y, 120 * mm, 4.5 * mm, fillColor=colors.HexColor("#E7ECF5"), strokeColor=None))
        if n:
            d.add(Rect(28 * mm, y, max(1.5 * mm, 120 * mm * n / total), 4.5 * mm,
                       fillColor=colors.HexColor(SEV_COLOR[sev]), strokeColor=None))
        d.add(String(151 * mm, y + 1.5, str(n), fontName="Helvetica-Bold", fontSize=9, fillColor=INK))
    return d


def build_pdf(scan: Scan, findings: list[Finding]) -> bytes:
    st = _styles()
    buf = io.BytesIO()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 10 * mm, f"{APP_NAME} - Report {scan.report_id} - Confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.setStrokeColor(colors.HexColor("#D5DCEA"))
        canvas.line(18 * mm, 13 * mm, A4[0] - 18 * mm, 13 * mm)
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"{APP_NAME} report {scan.report_id}", author=APP_NAME)
    s: list = []
    head = Table([[_logo(), [Paragraph(APP_NAME, st["h1"]),
                             Paragraph("Vulnerability Assessment Report", st["body"])]]],
                 colWidths=[16 * mm, 150 * mm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -1), 1.2, BLUE),
                              ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    s += [head, Spacer(1, 8)]

    fmt = lambda d: d.strftime("%Y-%m-%d %H:%M UTC") if isinstance(d, datetime) else "-"
    engines = ", ".join(f"{e.get('name')} ({e.get('status')})" for e in (scan.engines or [])) or "-"
    meta = [
        ["Report ID", scan.report_id], ["Target", _t(scan.target, 200)],
        ["Scan type", "Website" if scan.scan_type == "website" else "Source code (ZIP)"],
        ["Scan mode", scan.mode.title()], ["Status", scan.status.title()],
        ["Started", fmt(scan.started_at)], ["Finished", fmt(scan.finished_at)],
        ["Requested by", _t(scan.owner_name or "-")],
        ["Active checks", "Yes (authorized target)" if scan.active_checks else "No (passive only)"],
        ["Engines", Paragraph(_t(engines), st["body"])],
    ]
    mt = Table([[Paragraph(f"<b>{k}</b>", st["small"]), v if not isinstance(v, str) else Paragraph(v, st["body"])]
                for k, v in meta], colWidths=[32 * mm, 134 * mm])
    mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 0), (-1, -1),
                            [colors.white, colors.HexColor("#F6F8FC")]), ("TOPPADDING", (0, 0), (-1, -1), 3),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    s += [mt, Paragraph("Executive summary", st["h2"])]

    score = scan.score if scan.score is not None else 0
    risk = RISK_LABEL.get(scan.risk_level or "", "-")
    score_color = "#2E7D32" if score >= 80 else "#B58100" if score >= 50 else "#C62828"
    box = Table([[Paragraph(f'<font size="30" color="{score_color}"><b>{score}</b></font><font size="11" color="#5B6B8A"> / 100</font>', st["score"]),
                  [Paragraph(f"<b>Overall risk: {risk}</b>", st["body"]),
                   Paragraph(f"{(scan.summary or {}).get('total', 0)} finding(s) recorded.", st["body"])]]],
                colWidths=[55 * mm, 111 * mm])
    box.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#D5DCEA")),
                             ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F6F8FC")),
                             ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                             ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    s += [box, Spacer(1, 6), Paragraph("<b>How the score is calculated.</b> " + _t(METHODOLOGY), st["small"]),
          Spacer(1, 8), _bars(scan.summary or {})]
    if scan.error:
        s.append(Paragraph(f"<b>Scan error:</b> {_t(scan.error)}", st["body"]))

    if scan.engines:
        s.append(Paragraph("Scan engines", st["h2"]))
        rows = [["Engine", "Status", "Findings", "Detail"]] + [
            [Paragraph(_t(e.get("name")), st["body"]), e.get("status", ""), str(e.get("findings", 0)),
             Paragraph(_t(e.get("detail"), 240), st["small"])] for e in scan.engines]
        et = Table(rows, colWidths=[46 * mm, 24 * mm, 16 * mm, 80 * mm], repeatRows=1)
        et.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D5DCEA"))]))
        s.append(et)

    s.append(Paragraph("Detailed findings", st["h2"]))
    if not findings:
        s.append(Paragraph("No findings were recorded for the checks that were run.", st["body"]))
    for i, f in enumerate(findings[:MAX_PDF_FINDINGS], 1):
        col = SEV_COLOR.get(f.severity, "#546E7A")
        loc = f.url or ((f.file_path or "") + (f":{f.line}" if f.line else ""))
        meta_bits = [f"Category: {f.category}", TYPE_LABEL.get(f.finding_type, f.finding_type),
                     f"Confidence: {f.confidence}", f"Engine: {f.engine}"]
        if f.cwe:
            meta_bits.append(f.cwe)
        if f.cvss_score:
            meta_bits.append(f"CVSS {f.cvss_score}")
        block = [Paragraph(f'<font color="{col}"><b>[{SEV_LABEL.get(f.severity, f.severity).upper()}]</b></font> '
                           f"{i}. {_t(f.title, 220)}", st["ftitle"]),
                 Paragraph(_t(" | ".join(meta_bits)), st["small"])]
        if loc:
            block.append(Paragraph(f"<b>Location:</b> {_t(loc, 300)}", st["body"]))
        if f.http_status:
            block.append(Paragraph(f"<b>HTTP status:</b> {f.http_status}", st["body"]))
        block.append(Paragraph(_t(f.description or f.simple_explanation, 900), st["body"]))
        if f.evidence:
            block += [Paragraph("Evidence", st["label"]),
                      Paragraph(_t(f.evidence, 1200).replace("\n", "<br/>"), st["code"])]
        if f.remediation:
            block += [Paragraph("Recommended fix", st["label"]), Paragraph(_t(f.remediation, 700), st["body"])]
        s.append(KeepTogether(block[:3]))
        s += block[3:]
        s.append(Spacer(1, 9))
    if len(findings) > MAX_PDF_FINDINGS:
        s.append(Paragraph(f"Only the first {MAX_PDF_FINDINGS} of {len(findings)} findings are shown in this PDF. "
                           "Download the JSON or CSV report for the complete list.", st["body"]))

    s.append(Paragraph("Scan limitations", st["h2"]))
    for text in [*(scan.notes or []), *LIMITATIONS.get(scan.scan_type, [])]:
        s.append(Paragraph("- " + _t(text), st["body"]))
    s += [Paragraph("Disclaimer", st["h2"]), Paragraph(_t(DISCLAIMER), st["small"])]
    doc.build(s, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
