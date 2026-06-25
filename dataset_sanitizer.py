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
import os

logger = logging.getLogger(__name__)

# Fields that must NEVER reach the agent or critic LLM.
_LEAKAGE_FIELDS: set[str] = {
    "hint",
    "fix_commit",
    "docker_image_fix",
    "real_crash",
    "exit_code_vul",
    "crash_log_path",
    # Potential future enrichment fields — strip defensively
    "fix_description",
    "call_chain",
    "vulnerable_function",
    "root_cause",
    "patch_diff",
    "reproduction_steps",
}

# Patterns in target_source comments that describe the vulnerability.
# These are editorial annotations, not real source code.
_EDITORIAL_COMMENT_PATTERNS: list[re.Pattern] = [
    re.compile(r"/\*\s*VULNERABLE\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*stale\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*BUG\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*FIX\b[^*]*\*/", re.IGNORECASE),
    re.compile(r"/\*\s*HACK\b[^*]*\*/", re.IGNORECASE),
    # Block comments containing vulnerability-describing words anywhere inside
    re.compile(r"/\*[^*]*\b(?:vulnerable|stale\s+pointer|use.after.free|heap.use|overflow(?!\s+check)|exploit)\b[^*]*\*/", re.IGNORECASE),
    # Line comments that describe the vulnerability mechanism
    re.compile(r"//[^\n]*\b(?:VULNERABLE|stale|use.after.free|overflow(?!\s+check)|exploit|HACK|BUG)\b[^\n]*", re.IGNORECASE),
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



# Sentence patterns that indicate a post-analysis narrative rather than ASAN output.
_NARRATIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bFix\s+adjust", re.IGNORECASE),
    re.compile(r"\btriggered\s+by\s+two\b", re.IGNORECASE),
    re.compile(r"\brealloc\s+moves\s+the\s+buffer\b", re.IGNORECASE),
    re.compile(r"\bfix\s+commits?\b", re.IGNORECASE),
    re.compile(r"\broot\s+cause\b", re.IGNORECASE),
    re.compile(r"\bvulnerability\s+requires\b", re.IGNORECASE),
    re.compile(r"\bthe\s+bug\s+is\b", re.IGNORECASE),
]


def sanitize_crash_description(crash_desc: str) -> str:
    """
    Strip narrative prose from crash_description, retaining only the ASAN/MSAN/UBSAN
    output block.

    If the description looks like a human-written post-analysis essay (contains
    explanation sentences), truncate to the ASAN summary line and top stack frames.

    If the description looks like a raw sanitizer output, return it unchanged.

    Format-agnostic: works for any ASAN/MSAN stacktrace.
    """
    if not crash_desc:
        return crash_desc

    is_narrative = any(p.search(crash_desc) for p in _NARRATIVE_PATTERNS)
    if not is_narrative:
        return crash_desc  # raw ASAN output — safe as-is

    # Extract only the ASAN/sanitizer portion
    lines = crash_desc.splitlines()
    asan_lines = []
    in_asan = False
    for line in lines:
        if any(marker in line for marker in [
            "ERROR: AddressSanitizer", "ERROR: MemorySanitizer",
            "ERROR: UndefinedBehaviorSanitizer", "SUMMARY:"
        ]):
            in_asan = True
        if in_asan:
            asan_lines.append(line)
        if in_asan and line.startswith("SUMMARY:"):
            break

    if asan_lines:
        return "\n".join(asan_lines)

    # No ASAN block found — return only the first sentence (crash type, not explanation)
    first_sentence_end = crash_desc.find(". ")
    if first_sentence_end > 0:
        return crash_desc[:first_sentence_end + 1].strip()

    return crash_desc[:200]  # last resort


def sanitize_entry(cve_entry: dict) -> dict:
    """
    Return a sanitised copy of *cve_entry* with leakage fields removed.

    The original dict is NOT modified.
    """
    cleaned = copy.deepcopy(cve_entry)

    # ── Load real crash log if available ──────────────────────────────────
    crash_log_path = cleaned.get("crash_log_path")
    if crash_log_path and os.path.exists(crash_log_path):
        try:
            with open(crash_log_path, "r", encoding="utf-8") as f:
                cleaned["crash_description"] = f.read()
            logger.info("Sanitizer: Loaded real crash log from %s", crash_log_path)
        except Exception as e:
            logger.warning("Sanitizer: Failed to read crash_log_path %s: %s", crash_log_path, e)

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

    # Sanitize crash_description — strip narrative prose, keep only ASAN output
    if "crash_description" in cleaned:
        cleaned["crash_description"] = sanitize_crash_description(
            cleaned["crash_description"]
        )

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



# Fields that are explicitly allowed to reach the agent.
# Any field not in this set and not in _LEAKAGE_FIELDS will trigger a warning.
_ALLOWED_FIELDS: set[str] = {
    "cve_id", "id", "task_id",
    "docker_image_vul", "docker_image",
    "crash_description",
    "sanitizer_type",
    "vuln_class",
    "poc_bucket",
    "target_source",
    "fuzz_target",
}


def audit_unknown_fields(cve_entry: dict) -> list[str]:
    """
    Return a list of field names that are neither in the allowed set nor in the
    leakage set.  These are unknown fields that may or may not constitute leakage
    and should be reviewed manually before adding to the dataset.
    """
    known = _LEAKAGE_FIELDS | _ALLOWED_FIELDS
    return [k for k in cve_entry if k not in known]

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