"""
scoring.py

Deterministic scoring (Parts 28-31 of the manual). We never ask the AI to
invent a score - we calculate it ourselves from the combined findings so the
number is reproducible and explainable.
"""

from __future__ import annotations

from dataclasses import dataclass

from static_analysis import Finding

OVERALL_PENALTIES = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SECURITY_PENALTIES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 0}
QUALITY_PENALTIES = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0}
MAINTAINABILITY_PENALTIES = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0}
RELIABILITY_PENALTIES = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}

CATEGORY_PENALTY_TABLES = {
    "SECURITY": SECURITY_PENALTIES,
    "CODE_QUALITY": QUALITY_PENALTIES,
    "MAINTAINABILITY": MAINTAINABILITY_PENALTIES,
    "RELIABILITY": RELIABILITY_PENALTIES,
    "BUG": RELIABILITY_PENALTIES,
    "PERFORMANCE": QUALITY_PENALTIES,
}


@dataclass
class ScoreBreakdown:
    overall: int
    security: int
    code_quality: int
    maintainability: int
    reliability: int
    counts_by_severity: dict[str, int]


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def calculate_scores(findings: list[Finding]) -> ScoreBreakdown:
    counts_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    overall = 100
    security = 100
    quality = 100
    maintainability = 100
    reliability = 100

    for finding in findings:
        severity = finding.severity.upper() if finding.severity else "INFO"
        if severity not in counts_by_severity:
            severity = "INFO"
        counts_by_severity[severity] += 1

        overall -= OVERALL_PENALTIES.get(severity, 0)

        category = (finding.category or "").upper()
        table = CATEGORY_PENALTY_TABLES.get(category)
        if category == "SECURITY" or table is SECURITY_PENALTIES:
            security -= SECURITY_PENALTIES.get(severity, 0)
        elif table is not None:
            quality -= table.get(severity, 0) if table is QUALITY_PENALTIES else 0
            maintainability -= table.get(severity, 0) if table is MAINTAINABILITY_PENALTIES else 0
            reliability -= table.get(severity, 0) if table is RELIABILITY_PENALTIES else 0
        else:
            # Unknown category: apply a mild generic penalty everywhere.
            quality -= QUALITY_PENALTIES.get(severity, 0) // 2

    return ScoreBreakdown(
        overall=_clamp(overall),
        security=_clamp(security),
        code_quality=_clamp(quality),
        maintainability=_clamp(maintainability),
        reliability=_clamp(reliability),
        counts_by_severity=counts_by_severity,
    )
