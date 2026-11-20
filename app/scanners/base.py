"""Shared scan context, finding construction and scoring."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..models import SEVERITIES, SEVERITY_RANK
from .knowledge import CONFIDENCE_WEIGHT, SCORE_DEDUCTION, WEB_RULES
from .netsafe import ScanCancelled, ScanLimitError  # noqa: F401  (re-exported)


class ScanError(Exception):
    """Fatal problem that makes the scan fail with a readable message."""


def make_finding(rule_id: str, evidence: str = "", **overrides) -> dict:
    title, severity, category, ftype, cwe, simple, why, fix = WEB_RULES[rule_id]
    data = {
        "rule_id": rule_id, "title": title, "severity": severity, "category": category,
        "finding_type": ftype, "cwe": cwe, "simple_explanation": simple, "why_it_matters": why,
        "description": simple, "remediation": fix, "confidence": "high", "engine": "builtin-web",
        "evidence": evidence[:4000], "references": [],
    }
    data.update({k: v for k, v in overrides.items() if v is not None})
    return data


@dataclass
class Ctx:
    """State shared by all website checks in one scan."""
    client: object
    target_url: str
    selected_checks: set[str]
    active_allowed: bool
    progress: Callable[[int, str], None]
    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    info: dict = field(default_factory=dict)
    main: object = None
    chain: list = field(default_factory=list)

    def add(self, rule_id: str, evidence: str = "", **overrides) -> None:
        for f in self.findings:  # same rule + same evidence is reported once
            if f["rule_id"] == rule_id and f["evidence"] == evidence[:4000]:
                return
        self.findings.append(make_finding(rule_id, evidence, **overrides))


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["title"]))


def summarize(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    counts["total"] = len(findings)
    return counts


def compute_score(findings: list[dict]) -> tuple[int, str]:
    seen: dict[str, float] = {}
    for f in findings:
        if f["finding_type"] == "observation" or f["severity"] == "info":
            continue
        key = f.get("rule_id") or f["title"]
        points = SCORE_DEDUCTION[f["severity"]] * CONFIDENCE_WEIGHT.get(f["confidence"], 0.75)
        seen[key] = max(seen.get(key, 0), points)
    score = max(0, round(100 - sum(seen.values())))
    # a low-confidence critical/high pattern match needs review; it counts one level lower for the risk label
    severities = {("medium" if f["confidence"] == "low" and f["severity"] in ("critical", "high") else f["severity"])
                  for f in findings if f["finding_type"] != "observation"}
    if "critical" in severities:
        risk = "critical"
    elif "high" in severities or score < 50:
        risk = "high"
    elif "medium" in severities or score < 80:
        risk = "medium"
    elif "low" in severities:
        risk = "low"
    else:
        risk = "minimal"
    return score, risk
