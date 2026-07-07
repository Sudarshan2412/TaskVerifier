"""
agent/fact_accumulator.py — Confirmed-facts accumulator for iterative PoC refinement.

Problem
-------
The critic LLM discovers concrete facts during its ReAct loop (e.g. a constant
value from a #define, the correct byte offset of a structure field, which code
path is actually reached).  These facts appear in the verifier feedback text,
but the next retry prompt only injects the *last* feedback verbatim.

Over multiple attempts the feedback text rotates: old confirmed facts fall off
the context window or are contradicted by new (sometimes wrong) analyses.  The
generator LLM re-derives the same facts from scratch, or worse, adopts a
contradictory theory from a later critic turn.

Solution
--------
FactAccumulator maintains a session-scoped set of structured "confirmed facts".
After each verifier pass, extract_facts() is called on the feedback text.  The
accumulator stores new findings and deduplicates by key.  On every retry,
render() produces a compact, deterministic "CONFIRMED FACTS" block that is
injected at the TOP of the feedback prompt — before the verifier output.

Design rules
------------
* Format-agnostic: facts are plain key/value pairs.  The extractor uses
  lightweight regex heuristics that work across any language/format domain.
* Non-invasive: FactAccumulator is opt-in.  If it finds nothing, it returns
  an empty string and the pipeline is unaffected.
* Deterministic: facts are stored in insertion order; re-rendering always
  produces the same text for the same fact set.
* Conservative: only patterns that the critic explicitly marks as "confirmed"
  or "verified" are accepted.  Hedged statements ("maybe", "might", "likely")
  are ignored.

Public API
----------
    acc = FactAccumulator()
    acc.update(feedback_text: str) -> None
    acc.render() -> str          # "" if no facts yet
    acc.reset() -> None          # call between CVEs
"""

from __future__ import annotations

import re
from collections import OrderedDict


# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------
# Each pattern is a compiled regex.  Every match contributes a (key, value)
# pair to the fact store.  Patterns must be conservative — only accept
# explicit confirmation language.

_NUM = r"(-?(?:0x[0-9a-fA-F]+|\d+))"
_IDENT = r"([A-Za-z_][A-Za-z0-9_]{2,})"  # single-word C-style identifier

_PATTERNS: list[tuple[str, re.Pattern]] = [
    # ── Named constant, explicit confirmation words ─────────────────────────
    # Matches:
    #   MaxTextExtent is 2053
    #   MaxTextExtent = 4096
    #   MaxRGB confirmed as 65535
    #   DICOM_tag equals 0x0028
    (
        "constant",
        re.compile(
            _IDENT +
            r"\s+(?:confirmed(?:\s+as)?|verified(?:\s+as)?|defined(?:\s+as)?)\s*" +
            _NUM,
            re.IGNORECASE,
        ),
    ),

    # ── C preprocessor #define ─────────────────────────────────────────────
    # Matches:
    #   #define MaxTextExtent 2053
    #   # define BufSize 4096
    (
        "constant",
        re.compile(
            r"#\s*define\s+" + _IDENT + r"\s+" + _NUM,
            re.IGNORECASE,
        ),
    ),

    # ── Multi-word name with "is" / "confirmed as" ─────────────────────────
    # Matches:
    #   DICOM tag is 0x0028
    #   Private DICT offset is 25
    # (up to 4 words before the verb, each word \S+, not a number)
    (
        "constant",
        re.compile(
            r"([A-Za-z][A-Za-z0-9_]*(?:\s+[A-Za-z][A-Za-z0-9_]*){1,3})"
            r"\s+(?:confirmed(?:\s+as)?|verified(?:\s+as)?|defined(?:\s+as)?)\s*" +
            _NUM,
            re.IGNORECASE,
        ),
    ),

    # ── Byte offset confirmation ────────────────────────────────────────────
    # Matches:
    #   Private DICT offset confirmed as 25
    #   offset of Name INDEX is 10
    (
        "offset",
        re.compile(
            r"(?:offset|at byte|at position)\s+(?:of\s+)?"
            r"([A-Za-z0-9_\s]{3,30}?)\s+"
            r"(?:confirmed(?:\s+as)?|verified(?:\s+as)?)\s*" + _NUM,
            re.IGNORECASE,
        ),
    ),

    # ── Operator / opcode confirmation ─────────────────────────────────────
    # Matches:
    #   blend operator is 0x10
    #   opcode for sort confirmed as 0x17
    (
        "opcode",
        re.compile(
            r"(?:operator|opcode)\s+(?:for\s+)?"
            r"([A-Za-z_][A-Za-z0-9_\s]{1,30}?)\s+"
            r"(?:confirmed(?:\s+as)?|verified(?:\s+as)?)\s*" + _NUM,
            re.IGNORECASE,
        ),
    ),

    # ── Source file path ────────────────────────────────────────────────────
    # Matches:
    #   defined in /src/graphicsmagick/magick/common.h:91
    (
        "source_file",
        re.compile(
            r"(?:defined in|found at|located at|in file)\s+(/src/[^\s,)]+)",
            re.IGNORECASE,
        ),
    ),

    # ── P10: Format Theory Detection Patterns ────────────────────────────────
    # Matches claims about delimiters to detect contradiction.
    (
        "delimiter",
        re.compile(
            r"(?:delimiter|terminator|separator)\s+(?:is\s+|confirmed\s+as\s+|uses\s+)?(null[- ]?byte|\\0|backslash[- ]newline|0x5C 0x0A|length prefix|length-prefixed|4-byte length)"
            r"|uses\s+(null[- ]?byte|\\0|backslash[- ]newline|0x5C 0x0A|length prefix|length-prefixed|4-byte length)\s+as\s+(?:the\s+)?(?:string\s+)?(?:delimiter|terminator|separator)",
            re.IGNORECASE,
        ),
    ),

    (
        "endianness",
        re.compile(
            r"(?:is\s+|uses\s+|confirmed\s+as\s+)?"
            r"(big-endian|little-endian|BE|LE)",
            re.IGNORECASE,
        ),
    ),

    (
        "field_count",
        re.compile(
            r"(?:has\s+|requires\s+|confirmed\s+as\s+)?"
            r"(two fields|three fields|two strings|three strings)",
            re.IGNORECASE,
        ),
    ),

    # ── "reads until X" — harness termination condition ────────────────────
    # Matches:
    #   "reads until it encounters backslash-newline"
    #   "reads until null byte"
    # Captures what the fuzz harness uses to delimit input fields.
    (
        "reads_until",
        re.compile(
            r"reads\s+until\s+(?:it\s+encounters\s+|finding\s+)?"
            r"(backslash[- ]newline|null[- ]?byte|0x[0-9a-fA-F]{2}"
            r"|[a-zA-Z][a-zA-Z0-9_ -]{3,40})",
            re.IGNORECASE,
        ),
    ),

    # NOTE: crash_function pattern intentionally REMOVED.
    # After dataset_sanitizer.redact_stacktrace_frames() runs, the critic
    # cannot independently verify any function name against the stacktrace.
    # Locking in a hallucinated function name is more harmful than no fact.
]


# ---------------------------------------------------------------------------
# FactAccumulator class
# ---------------------------------------------------------------------------

_STOPWORDS = frozenset({
    "the", "a", "an", "is", "it", "which", "that", "this", "to", "of",
    "in", "for", "and", "or", "but", "if", "at", "by", "from", "with",
    "on", "as", "so", "no", "not", "be", "was", "were", "been", "are",
    "has", "have", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "must", "shall", "can", "need", "each",
    "every", "all", "any", "both", "few", "more", "most", "other",
    "some", "such", "than", "too", "very", "just", "because", "about",
    "into", "through", "during", "before", "after", "above", "below",
    "between", "out", "off", "over", "under", "again", "further", "then",
    "once", "here", "there", "when", "where", "why", "how", "what",
})

class FactAccumulator:
    """
    Maintains a deduplicated, ordered store of confirmed facts extracted from
    critic feedback strings.

    Usage::

        acc = FactAccumulator()
        # after each verifier pass:
        acc.update(result.feedback)
        # when building the next retry prompt:
        confirmed_block = acc.render()  # inject this at prompt top
    """

    def __init__(self) -> None:
        # key → (category, value_string)
        # Using OrderedDict so render() is deterministic and insertion-ordered.
        self._facts: OrderedDict[str, tuple[str, str]] = OrderedDict()
        # category → (existing_value, conflicting_value)
        # Populated when a new confirmed fact contradicts an existing one.
        self._contradictions: dict[str, tuple[str, str]] = {}

    # ── public ──────────────────────────────────────────────────────────────

    def update(self, feedback_text: str) -> None:
        """
        Parse *feedback_text* and add any newly confirmed facts to the store.

        Duplicate keys (same name, different value) are NOT overwritten —
        the first confirmed value wins.  This prevents a later wrong critic
        turn from silently overwriting a correct earlier finding.
        """
        if not feedback_text:
            return

        for category, pattern in _PATTERNS:
            for match in pattern.finditer(feedback_text):
                if category == "source_file":
                    key = f"source_file:{match.group(1)}"
                    value = match.group(1)
                else:
                    key_name = _normalise(match.group(1))
                    
                    # Skip garbage extractions: stopwords, short words, or hex strings (which are usually values, not keys)
                    if len(key_name) < 3 or key_name in _STOPWORDS or re.match(r'^0x[0-9a-f]+$', key_name):
                        continue
                        
                    key = f"{category}:{key_name}"
                    value = match.group(2) if len(match.groups()) >= 2 else match.group(1)

                # Contradiction detection:
                # 1. Exact same key exists (e.g. constant:maxtextextent) with different value
                if key in self._facts:
                    _, existing_val = self._facts[key]
                    if existing_val != value.strip():
                        if category in ("delimiter", "reads_until", "constant", "endianness", "field_count"):
                            self._contradictions[category] = (existing_val, value.strip())
                            # Last-wins: Overwrite with the newly confirmed finding
                            self._facts[key] = (category, value.strip())
                    continue

                # 2. Same category, different key (e.g. delimiter:\0 vs delimiter:backslash-newline)
                # Only some categories are mutually exclusive globally.
                if category in ("delimiter", "endianness", "field_count", "reads_until"):
                    existing_in_category = [
                        (k, v) for k, v in self._facts.items()
                        if k.startswith(f"{category}:")
                    ]
                    if existing_in_category:
                        old_key, (_, existing_val) = existing_in_category[0]
                        self._contradictions[category] = (existing_val, value.strip())
                        # Delete the old contradictory fact so we don't force the LLM to use it
                        del self._facts[old_key]
                        self._facts[key] = (category, value.strip())
                        continue

                self._facts[key] = (category, value.strip())

    def render(self) -> str:
        """
        Return a formatted "CONFIRMED FACTS" block for injection into the
        retry prompt, or an empty string if no facts have been accumulated yet.

        The block is intentionally compact — it should not dominate the prompt.
        """
        if not self._facts:
            return ""

        lines = ["CONFIRMED FACTS (verified from container — do not contradict):"]
        for key, (category, value) in self._facts.items():
            label = key.split(":", 1)[1] if ":" in key else key
            lines.append(f"  • {label} = {value}  [{category}]")

        if self._contradictions:
            lines.append("")
            lines.append("FACT CONFLICTS — resolve by reading the source before writing code:")
            for category, (old_val, new_val) in self._contradictions.items():
                lines.append(
                    f"  ⚠ [{category}] Prior confirmed: '{old_val}' vs new claim: '{new_val}'. "
                    f"READ the relevant source file to determine which is correct."
                )

        lines.append(
            "If your analysis contradicts any of the above, "
            "trust these values — they were extracted from the actual container.\n"
        )
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Clear all accumulated facts (call between CVE tasks)."""
        self._facts.clear()
        self._contradictions.clear()

    def __len__(self) -> int:
        return len(self._facts)

    def __repr__(self) -> str:
        return f"FactAccumulator({len(self._facts)} facts)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(s: str) -> str:
    """Collapse whitespace and lowercase a match group used as a dict key."""
    return re.sub(r"\s+", "_", s.strip().lower())