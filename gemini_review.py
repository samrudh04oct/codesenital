"""
gemini_review.py

Calls Gemini with a JSON response schema (Part 32) so the app gets
predictable, machine-readable findings instead of a free-form essay.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from google import genai
from google.genai import types

from static_analysis import Finding

MODEL_CANDIDATES = [
    "gemini-2.5-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.8-flash",
    "gemini-flash-latest",
]

RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "summary": {"type": "STRING"},
        "issues": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "severity": {
                        "type": "STRING",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    },
                    "category": {
                        "type": "STRING",
                        "enum": [
                            "SECURITY", "BUG", "CODE_QUALITY",
                            "PERFORMANCE", "MAINTAINABILITY", "RELIABILITY",
                        ],
                    },
                    "file": {"type": "STRING"},
                    "line": {"type": "INTEGER", "nullable": True},
                    "title": {"type": "STRING"},
                    "explanation": {"type": "STRING"},
                    "why_it_matters": {"type": "STRING"},
                    "fix": {"type": "STRING"},
                    "confidence": {"type": "STRING"},
                },
                "required": [
                    "severity", "category", "file", "title",
                    "explanation", "why_it_matters", "fix",
                ],
            },
        },
    },
    "required": ["summary", "issues"],
}


@dataclass
class GeminiReviewResult:
    summary: str
    findings: list[Finding]
    raw_json: dict


class GeminiReviewError(Exception):
    pass


def _build_prompt(project_code: str, static_findings: list[Finding]) -> str:
    static_summary = "\n".join(
        f"- [{f.source.upper()}] {f.severity} | {f.category} | "
        f"{f.file}:{f.line or '?'} | {f.title}"
        for f in static_findings
    ) or "(no static-analysis findings)"

    return f"""You are a senior software engineer and security reviewer.

Static analysis tools (Ruff and Bandit) have already scanned this project
and found the issues listed below. Do NOT repeat these unless you have
something meaningful to add (e.g. more context on *why* it matters).
Focus your own review on things static analysis cannot catch: logic bugs,
architectural problems, unsafe data flow, missing error handling, and
maintainability concerns.

STATIC ANALYSIS FINDINGS:
{static_summary}

Review the following project source code and identify additional problems:
1. Bugs
2. Security vulnerabilities
3. Poor coding practices
4. Performance problems
5. Maintainability problems
6. Missing error handling
7. Potential reliability problems

Rules:
- Do not invent files or code that do not exist in the project below.
- If you are uncertain about something, say so in the explanation rather
  than stating it as fact.
- Give a realistic line number only if you can identify it from the code
  shown; otherwise omit it.
- Respond ONLY with JSON matching the provided schema.

PROJECT CODE:
{project_code}
"""


def _generate_with_fallback(client: "genai.Client", prompt: str):
    last_error = None
    for model_name in MODEL_CANDIDATES:
        try:
            return client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=RESPONSE_SCHEMA,
                    temperature=0.2,
                ),
            )
        except Exception as exc:  # network / auth / quota / model availability
            last_error = exc
            continue

    if last_error is not None:
        raise GeminiReviewError(str(last_error))
    raise GeminiReviewError("No Gemini models were available for this request.")


def review_project(
    client: "genai.Client",
    project_code: str,
    static_findings: list[Finding],
) -> GeminiReviewResult:
    prompt = _build_prompt(project_code, static_findings)

    try:
        response = _generate_with_fallback(client, prompt)
    except Exception as exc:  # network / auth / quota errors
        raise GeminiReviewError(str(exc)) from exc

    try:
        data = json.loads(response.text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise GeminiReviewError(
            f"Gemini did not return valid JSON: {exc}"
        ) from exc

    findings = []
    for item in data.get("issues", []):
        findings.append(
            Finding(
                source="gemini",
                severity=(item.get("severity") or "INFO").upper(),
                category=(item.get("category") or "CODE_QUALITY").upper(),
                file=item.get("file", "unknown"),
                line=item.get("line"),
                title=item.get("title", "Issue detected"),
                explanation=item.get("explanation", ""),
                fix=item.get("fix", ""),
                confidence=item.get("confidence"),
            )
        )

    return GeminiReviewResult(
        summary=data.get("summary", ""),
        findings=findings,
        raw_json=data,
    )
