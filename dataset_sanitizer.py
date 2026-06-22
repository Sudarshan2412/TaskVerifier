"""
dataset_sanitizer.py — Pre-pipeline sanitizer for benchmark integrity.

Strips fields from CVE dataset entries that would constitute information
leakage during benchmark evaluation.  Must be called BEFORE the agent
loop sees the CVE entry.

Leakage categories handled
--------------------------
1. **Solution hints**: ``hint`` contains human-authored PoC instructions.
2. **Fix metadata**: ``fix_commit``, ``docker_image_fix`` reveal the patch.
3. **Ground-truth flags**: ``real_crash``, ``exit_code_vul`` leak whether
   a crash is reproducible and what exit code to expect.
4. **Debugging paths**: ``crash_log_path`` points to local files that
   shouldn't influence the agent.
5. **Editorial comments in target_source**: inline comments like
   ``/* VULNERABLE: ... */`` describe the vulnerability mechanism.

Public API
----------
    sanitize_entry(cve_entry: dict) -> dict
        Returns a COPY with leakage fields removed.

    validate_crash_description(crash_desc: str) -> list[str]
        Returns a list of warnings if the description lacks ASAN markers.
"""

from __future__ import annotations

import copy
import re
import logging

logger = logging.getLogger(__name__)

# Fields that must NEVER reach the agent or critic LLM.
_LEAKAGE_FIELDS: set[str] = {
    "hint",
    "fix_commit",
    "docker_image_fix",
    "real_crash",
    "exit_code_vul",
    "crash_log_path",
}

# Patterns in target_source comments that describe the vulnerability.
# These are editorial annotations, not real source code.
_EDITORIAL_COMMENT_PATTERNS: list[re.Pattern] = [
    re.compile(r"/\*\s*VULNERABLE\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*stale\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*BUG\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*FIX\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*HACK\b[^*]*\*/", re.IGNORECASE),
]

# Sanitizer markers in crash descriptions that indicate a real stacktrace.
_SANITIZER_MARKERS: list[str] = [
    "AddressSanitizer",
    "MemorySanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "ThreadSanitizer",
    "SUMMARY:",
    "#0 ",
    "#1 ",
]


def sanitize_entry(cve_entry: dict) -> dict:
    """
    Return a sanitised copy of *cve_entry* with leakage fields removed.

    The original dict is NOT modified.
    """
    cleaned = copy.deepcopy(cve_entry)

    # ── Strip leakage fields ──────────────────────────────────────────────
    removed = []
    for field in _LEAKAGE_FIELDS:
        if field in cleaned:
            del cleaned[field]
            removed.append(field)

    if removed:
        cve_id = cve_entry.get("cve_id") or cve_entry.get("id", "unknown")
        logger.info(
            "Sanitizer: stripped %s from %s", ", ".join(removed), cve_id
        )

    # ── Strip editorial comments from target_source ───────────────────────
    target_source = cleaned.get("target_source", "")
    if target_source:
        for pattern in _EDITORIAL_COMMENT_PATTERNS:
            target_source = pattern.sub("", target_source)
        # Collapse any resulting double-blank lines
        target_source = re.sub(r"\n{3,}", "\n\n", target_source)
        cleaned["target_source"] = target_source

    return cleaned


def validate_crash_description(crash_desc: str) -> list[str]:
    """
    Return a list of warnings if *crash_desc* doesn't look like a real
    sanitizer stacktrace.

    An empty list means no issues detected.
    """
    warnings = []

    if not crash_desc or not crash_desc.strip():
        warnings.append("crash_description is empty")
        return warnings

    has_marker = any(m in crash_desc for m in _SANITIZER_MARKERS)
    if not has_marker:
        warnings.append(
            "crash_description contains no ASAN/MSAN/UBSAN markers — "
            "may be a human-written description rather than a real stacktrace"
        )

    return warnings


def sanitize_dataset(entries: list[dict]) -> list[dict]:
    """
    Sanitize a full list of CVE entries.  Returns sanitized copies.
    Logs warnings for entries with suspicious crash descriptions.
    """
    sanitized = []
    for entry in entries:
        cve_id = entry.get("cve_id") or entry.get("id", "unknown")

        # Warn on real_crash: false BEFORE stripping it
        if entry.get("real_crash") is False:
            logger.warning(
                "Sanitizer: %s has real_crash=false — crash may not be "
                "reproducible in this container",
                cve_id,
            )

        cleaned = sanitize_entry(entry)

        # Validate crash description
        crash_warnings = validate_crash_description(
            cleaned.get("crash_description", "")
        )
        for w in crash_warnings:
            logger.warning("Sanitizer: %s — %s", cve_id, w)

        sanitized.append(cleaned)

    return sanitized
