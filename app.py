"""
CodeSentinel AI - AI-Powered Code Review Assistant

Pipeline (Part 40 of the manual):

  Upload ZIP -> Validate -> Safe extract -> Discover source files
  -> Redact secrets -> Static analysis (Ruff + Bandit) -> Gemini review
  -> Merge findings -> Deterministic scoring -> Dashboard
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv
from google import genai

from gemini_review import GeminiReviewError, review_project
from scoring import calculate_scores
from static_analysis import Finding, run_all_static_analysis
from utils import (
    ZipValidationError,
    build_project_code_blob,
    discover_source_files,
    safe_extract_zip,
    validate_zip_bytes,
)

# --------------------------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------------------------

load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

st.set_page_config(page_title="CodeSentinel AI", page_icon="🛡️", layout="wide")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


@st.cache_resource
def get_client(api_key: str) -> genai.Client:
    return genai.Client(api_key=api_key)


def analyze_project(uploaded_file) -> dict:
    """Run the full pipeline and return everything the UI needs to render."""
    workspace = Path(tempfile.mkdtemp(prefix="codesentinel_"))
    try:
        zip_path = workspace / uploaded_file.name
        zip_bytes = uploaded_file.getbuffer()
        validate_zip_bytes(len(zip_bytes))

        with open(zip_path, "wb") as f:
            f.write(zip_bytes)

        extract_dir = workspace / "project"
        extract_dir.mkdir(parents=True, exist_ok=True)

        with st.status("Analyzing project...", expanded=True) as status:
            status.write("📦 Extracting ZIP safely...")
            safe_extract_zip(zip_path, extract_dir)

            status.write("🔎 Discovering source files...")
            extraction = discover_source_files(extract_dir)

            if not extraction.source_files:
                status.update(label="No source files found.", state="error")
                return {"error": "No supported source files (.py, .js, .ts, .tsx, .jsx) were found in this ZIP."}

            status.write(
                f"Found {len(extraction.source_files)} source file(s) "
                f"out of {extraction.all_files_count} total file(s)."
            )
            if extraction.skipped_secret_files:
                status.write(
                    f"🔒 Skipped {len(extraction.skipped_secret_files)} file(s) "
                    "that looked like secrets/credentials (never read or sent to AI)."
                )

            status.write("🧹 Running static analysis (Ruff + Bandit)...")
            static_findings = run_all_static_analysis(extract_dir)
            status.write(f"Static analysis found {len(static_findings)} finding(s).")

            status.write("✂️ Redacting any secrets found inside source files...")
            project_code, truncated = build_project_code_blob(extraction.source_files)
            if truncated:
                status.write("⚠️ Project is large — only part of the code was sent to Gemini.")

            gemini_findings: list[Finding] = []
            summary = ""
            gemini_error = None
            if API_KEY:
                status.write("🤖 Gemini is reviewing the code...")
                try:
                    client = get_client(API_KEY)
                    result = review_project(client, project_code, static_findings)
                    gemini_findings = result.findings
                    summary = result.summary
                except GeminiReviewError as exc:
                    gemini_error = str(exc)
                    status.write(f"⚠️ Gemini review failed: {gemini_error}")
            else:
                status.write("⚠️ No GEMINI_API_KEY set — showing static-analysis results only.")

            all_findings = static_findings + gemini_findings
            scores = calculate_scores(all_findings)

            status.update(label="✅ Analysis completed!", state="complete")

        return {
            "error": None,
            "summary": summary,
            "gemini_error": gemini_error,
            "findings": all_findings,
            "scores": scores,
            "source_file_count": len(extraction.source_files),
            "total_file_count": extraction.all_files_count,
            "skipped_secret_files": extraction.skipped_secret_files,
            "truncated": truncated,
        }
    except ZipValidationError as exc:
        return {"error": str(exc)}
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def render_dashboard(result: dict) -> None:
    scores = result["scores"]

    st.divider()
    st.header("📊 Project Score")

    top = st.columns([1, 1, 1, 1, 1])
    top[0].metric("Overall", f"{scores.overall}/100")
    top[1].metric("Security", f"{scores.security}/100")
    top[2].metric("Code Quality", f"{scores.code_quality}/100")
    top[3].metric("Maintainability", f"{scores.maintainability}/100")
    top[4].metric("Reliability", f"{scores.reliability}/100")

    st.write("")
    counts = scores.counts_by_severity
    badge_cols = st.columns(5)
    for i, sev in enumerate(SEVERITY_ORDER):
        badge_cols[i].metric(f"{SEVERITY_EMOJI[sev]} {sev.title()}", counts.get(sev, 0))

    if result.get("summary"):
        st.info(result["summary"])

    if result.get("gemini_error"):
        st.warning(
            "Gemini review could not be completed, so this report only "
            f"includes static-analysis results. Details: {result['gemini_error']}"
        )

    if result.get("skipped_secret_files"):
        with st.expander(f"🔒 {len(result['skipped_secret_files'])} file(s) excluded as likely secrets"):
            for f in result["skipped_secret_files"]:
                st.code(f, language=None)

    st.divider()
    st.header("🗂️ Findings")

    findings: list[Finding] = result["findings"]
    if not findings:
        st.success("No issues found! 🎉")
        return

    # Group by file for the file-by-file view (Part 34).
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    sort_key = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    findings_sorted = sorted(findings, key=lambda f: sort_key.get(f.severity, 99))

    tab_all, tab_by_file = st.tabs(["All issues", "By file"])

    with tab_all:
        for finding in findings_sorted:
            _render_finding(finding)

    with tab_by_file:
        for filename, file_findings in sorted(by_file.items(), key=lambda kv: -len(kv[1])):
            with st.expander(f"📄 {filename} — {len(file_findings)} issue(s)"):
                for finding in sorted(file_findings, key=lambda f: sort_key.get(f.severity, 99)):
                    _render_finding(finding, show_file=False)


def _render_finding(finding: Finding, show_file: bool = True) -> None:
    emoji = SEVERITY_EMOJI.get(finding.severity, "⚪")

    location = ""
    if show_file:
        location = f" — `{finding.file}:{finding.line}`" if finding.line else f" — `{finding.file}`"

    header = f"{emoji} **{finding.severity}** · {finding.category} · {finding.title}{location}"

    with st.expander(header):
        if not show_file and finding.line:
            st.caption(f"Line {finding.line}")
        st.markdown(f"**Problem:** {finding.explanation}")
        if getattr(finding, "confidence", None):
            st.caption(f"Confidence: {finding.confidence}")
        if finding.fix:
            st.markdown(f"**Suggested fix:** {finding.fix}")
        st.caption(f"Detected by: {finding.source}")


# --------------------------------------------------------------------------
# UI
# --------------------------------------------------------------------------

st.title("🛡️ CodeSentinel AI")
st.subheader("AI-Powered Code Review Assistant")
st.write(
    "Upload a ZIP file containing your programming project. "
    "CodeSentinel runs Ruff and Bandit locally, then asks Gemini to review "
    "what static analysis can't catch — all without ever sending secrets "
    "or executing your code."
)

if not API_KEY:
    st.warning(
        "No `GEMINI_API_KEY` found in your `.env` file. You can still run "
        "static analysis (Ruff + Bandit), but the AI review step will be skipped. "
        "See the README for setup instructions."
    )

uploaded_file = st.file_uploader("Upload your project ZIP file", type=["zip"])

if uploaded_file is not None:
    st.success(f"File uploaded: {uploaded_file.name}")

    if st.button("🔍 Analyze Project", type="primary"):
        result = analyze_project(uploaded_file)
        if result.get("error"):
            st.error(result["error"])
        else:
            render_dashboard(result)

st.divider()
with st.expander("ℹ️ How this works / safety notes"):
    st.markdown(
        """
- Your code is **never executed** — only read and analyzed.
- `.env` files, `.pem`/`.key` files, and similar credential files are
  skipped entirely and never sent anywhere.
- Detected secret-looking strings inside regular source files (API keys,
  passwords, tokens) are replaced with `[REDACTED]` before anything is
  sent to Gemini.
- ZIP uploads are capped at 100 MB, 500 files, and 2 MB per file, and are
  extracted with protection against path-traversal ("zip-slip") attacks.
- Static analysis (Ruff, Bandit) runs locally and is combined with the
  Gemini review; the final score is calculated deterministically from the
  combined findings, not invented by the AI.
        """
    )
