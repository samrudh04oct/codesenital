"""
utils.py

Safety-critical helpers for CodeSentinel AI:

- Safe ZIP extraction (blocks zip-slip / path traversal, enforces size limits)
- Secret detection & redaction (so API keys / passwords never reach Gemini)
- Source file discovery
"""

from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# LIMITS  (Part 39 of the manual)
# --------------------------------------------------------------------------

MAX_ZIP_SIZE_BYTES = 100 * 1024 * 1024      # 100 MB
MAX_FILES_IN_ZIP = 500
MAX_INDIVIDUAL_FILE_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_TOTAL_SOURCE_CHARACTERS = 60_000          # sent to Gemini per request
MAX_FILES_TO_READ = 30

ALLOWED_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx"}

IGNORED_DIRECTORIES = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".mypy_cache", ".pytest_cache", "site-packages",
}

# Files that should NEVER be read or sent to the AI, no matter what.
SECRET_FILENAME_PATTERNS = [
    re.compile(r"^\.env(\..*)?$", re.IGNORECASE),
    re.compile(r".*\.pem$", re.IGNORECASE),
    re.compile(r".*\.key$", re.IGNORECASE),
    re.compile(r".*\.p12$", re.IGNORECASE),
    re.compile(r".*\.pfx$", re.IGNORECASE),
    re.compile(r"^credentials\.json$", re.IGNORECASE),
    re.compile(r"^service[_-]?account.*\.json$", re.IGNORECASE),
    re.compile(r"^id_rsa$", re.IGNORECASE),
    re.compile(r"^id_ed25519$", re.IGNORECASE),
]

# Regex patterns used to mask secrets that show up *inside* otherwise
# legitimate source files (Part 38 of the manual).
SECRET_VALUE_PATTERNS = [
    # KEY = "value"  /  KEY: value  /  KEY=value
    re.compile(
        r"(?im)^(?P<prefix>\s*\w*"
        r"(?:SECRET|PASSWORD|PASSWD|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)"
        r"\w*\s*[:=]\s*)(?P<value>[\"']?[^\s\"'#]{4,}[\"']?)"
    ),
    # Common cloud provider key shapes
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),                     # Google API key
    re.compile(r"AKIA[0-9A-Z]{16}"),                            # AWS access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                         # OpenAI-style secret key
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),                        # GitHub PAT
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]


class ZipValidationError(Exception):
    """Raised when an uploaded ZIP fails a safety check."""


@dataclass
class DiscoveredFile:
    absolute_path: Path
    relative_path: Path
    skipped_as_secret: bool = False


@dataclass
class ExtractionResult:
    extract_dir: Path
    all_files_count: int = 0
    source_files: list[DiscoveredFile] = field(default_factory=list)
    skipped_secret_files: list[str] = field(default_factory=list)


def validate_zip_bytes(size_bytes: int) -> None:
    """Reject oversized uploads before we even touch the disk."""
    if size_bytes > MAX_ZIP_SIZE_BYTES:
        raise ZipValidationError(
            f"ZIP file is {size_bytes / (1024*1024):.1f} MB, which exceeds the "
            f"{MAX_ZIP_SIZE_BYTES / (1024*1024):.0f} MB limit."
        )


def _is_within_directory(directory: Path, target: Path) -> bool:
    """Zip-slip protection: make sure `target` cannot escape `directory`."""
    try:
        directory = directory.resolve()
        target = target.resolve()
    except OSError:
        return False
    return directory in target.parents or directory == target


def safe_extract_zip(zip_path: Path, extract_to: Path) -> None:
    """
    Extract a ZIP file while defending against:
      - Zip-slip / path traversal (../../etc/passwd)
      - Absolute paths
      - Too many files
      - Any single file that is too large
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()

        if len(infos) > MAX_FILES_IN_ZIP:
            raise ZipValidationError(
                f"ZIP contains {len(infos)} files, which exceeds the "
                f"{MAX_FILES_IN_ZIP}-file limit."
            )

        for info in infos:
            if info.file_size > MAX_INDIVIDUAL_FILE_BYTES:
                raise ZipValidationError(
                    f"File '{info.filename}' is larger than "
                    f"{MAX_INDIVIDUAL_FILE_BYTES / (1024*1024):.0f} MB."
                )

            member_path = Path(info.filename)

            if member_path.is_absolute() or ".." in member_path.parts:
                raise ZipValidationError(
                    f"Refusing to extract unsafe path inside ZIP: {info.filename}"
                )

            destination = extract_to / member_path
            if not _is_within_directory(extract_to, destination):
                raise ZipValidationError(
                    f"Refusing to extract path that escapes the workspace: "
                    f"{info.filename}"
                )

        zf.extractall(extract_to)


def is_secret_file(filename: str) -> bool:
    return any(pattern.match(filename) for pattern in SECRET_FILENAME_PATTERNS)


def redact_secrets(text: str) -> str:
    """Mask likely secret values before code is sent to the AI (Part 38)."""
    redacted = text
    for pattern in SECRET_VALUE_PATTERNS:
        if pattern.groups and "value" in pattern.groupindex:
            redacted = pattern.sub(lambda m: m.group("prefix") + "[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def discover_source_files(extract_dir: Path) -> ExtractionResult:
    """Walk the extracted project and classify files."""
    result = ExtractionResult(extract_dir=extract_dir)

    for root, dirs, files in os.walk(extract_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES and not d.startswith(".")]

        for filename in files:
            result.all_files_count += 1
            file_path = Path(root) / filename

            if is_secret_file(filename):
                result.skipped_secret_files.append(
                    str(file_path.relative_to(extract_dir))
                )
                continue

            if file_path.suffix in ALLOWED_EXTENSIONS:
                result.source_files.append(
                    DiscoveredFile(
                        absolute_path=file_path,
                        relative_path=file_path.relative_to(extract_dir),
                    )
                )

    return result


def build_project_code_blob(
    files: list[DiscoveredFile],
    max_files: int = MAX_FILES_TO_READ,
    max_characters: int = MAX_TOTAL_SOURCE_CHARACTERS,
) -> tuple[str, bool]:
    """
    Read source files, redact secrets, and concatenate them into one blob
    for the AI prompt. Returns (blob, was_truncated).
    """
    blob = ""
    for discovered in files[:max_files]:
        try:
            content = discovered.absolute_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        content = redact_secrets(content)
        blob += f"\n\n===== FILE: {discovered.relative_path.as_posix()} =====\n\n{content}"

    truncated = len(blob) > max_characters
    if truncated:
        blob = blob[:max_characters]

    return blob, truncated
