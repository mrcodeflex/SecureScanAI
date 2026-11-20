"""Texts shared by all report formats."""
from ..scanners.knowledge import SCORE_METHODOLOGY

DISCLAIMER = (
    "This report was generated automatically by SecureScan AI. Automated scanning finds only a subset of "
    "possible weaknesses and may report false positives or miss real issues. It is not a penetration test or "
    "a guarantee of security. Use it only for systems you own or are explicitly authorized to assess, and "
    "have findings reviewed by a qualified person before acting on them."
)
LIMITATIONS = {
    "website": [
        "Only the checks listed in the scan configuration were run; the application was not crawled in depth.",
        "Missing security headers and similar controls are reported as hardening gaps, not as proof of an exploitable vulnerability.",
        "Authenticated areas, business logic and client-side code were not tested.",
        "TLS checks cover the negotiated protocol and certificate only; they are not a full cipher-suite audit.",
    ],
    "source": [
        "Built-in rules are pattern-based heuristics and are reported as potential issues that need human review.",
        "Uploaded code was never executed and dependencies were never installed; only text and manifest files were read.",
        "Vendor, build and binary files were skipped; see the scan notes for counts.",
        "Dependency vulnerability results depend on the availability of Trivy or OSV lookups (see Engines).",
    ],
}
TYPE_LABEL = {
    "vulnerability": "Verified vulnerability", "misconfiguration": "Misconfiguration",
    "missing_control": "Missing security control", "potential": "Potential issue (needs review)",
    "observation": "Observation",
}
RISK_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "minimal": "Minimal"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}
METHODOLOGY = SCORE_METHODOLOGY
