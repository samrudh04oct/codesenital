"""
static_analysis.py

Runs deterministic, non-AI tools over the extracted project *before* we ever
talk to Gemini (Part 25-27 of the manual):

- Ruff       -> general Python code-quality issues
- Bandit     -> Python-specific security issues

Both tools are invoked as subprocesses with JSON output, then normalized
into a single `Finding` shape shared with the Gemini findings.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

SEVERITY_MAP_BANDIT = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}

# Ruff doesn't assign severities itself, so we bucket by rule prefix.
RUFF_SEVERITY_OVERRIDES = {
    "S": "HIGH",     # flake8-bandit rules surfaced via ruff
    "E9": "HIGH",    # syntax errors
    "F82": "HIGH",   # undefined name
}


@dataclass
class Finding:
    source: str          # "ruff" | "bandit" | "gemini"
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    file: str
    line: int | None
    title: str
    explanation: str
    fix: str = ""
    confidence: str | None = None


def _run(cmd: list[str], cwd: Path) -> str:
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.stdout or ""
    except FileNotFoundError:
        # Tool isn't installed; treat as "no findings" rather than crashing.
        return ""
    except subprocess.TimeoutExpired:
        return ""


def run_ruff(project_dir: Path) -> list[Finding]:
    """Run Ruff with JSON output and normalize the results."""
    output = _run(
        ["ruff", "check", ".", "--output-format", "json", "--exit-zero"],
        cwd=project_dir,
    )
    if not output.strip():
        return []

    try:
        raw_findings = json.loads(output)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in raw_findings:
        code = item.get("code") or ""
        severity = "LOW"
        for prefix, sev in RUFF_SEVERITY_OVERRIDES.items():
            if code.startswith(prefix):
                severity = sev
                break

        location = item.get("location", {}) or {}
        findings.append(
            Finding(
                source="ruff",
                severity=severity,
                category="CODE_QUALITY",
                file=item.get("filename", "unknown"),
                line=location.get("row"),
                title=f"[{code}] {item.get('message', 'Issue detected')}",
                explanation=item.get("message", ""),
                fix="Follow the Ruff rule documentation for this code: "
                    f"https://docs.astral.sh/ruff/rules/#{code.lower()}"
                    if code else "Review and fix the flagged code.",
            )
        )
    return findings


def run_bandit(project_dir: Path) -> list[Finding]:
    """Run Bandit with JSON output and normalize the results."""
    output = _run(
        ["bandit", "-r", ".", "-f", "json", "-q"],
        cwd=project_dir,
    )
    if not output.strip():
        return []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in data.get("results", []):
        severity = SEVERITY_MAP_BANDIT.get(
            (item.get("issue_severity") or "LOW").upper(), "LOW"
        )
        findings.append(
            Finding(
                source="bandit",
                severity=severity,
                category="SECURITY",
                file=item.get("filename", "unknown"),
                line=item.get("line_number"),
                title=item.get("test_name", "Security issue"),
                explanation=item.get("issue_text", ""),
                fix="See Bandit documentation for "
                    f"{item.get('test_id', 'this check')}: "
                    "https://bandit.readthedocs.io/en/latest/plugins/",
                confidence=item.get("issue_confidence"),
            )
        )
    return findings


def run_all_static_analysis(project_dir: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(run_ruff(project_dir))
    findings.extend(run_bandit(project_dir))
    return findings
