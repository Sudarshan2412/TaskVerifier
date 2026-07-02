"""
agent/retry_memory.py — Negative-example memory for iterative PoC refinement.

Problem
-------
The agent frequently re-attempts strategies that already failed.  For example,
in the arvo:368 run, the agent tried CFF2 headers three times even after the
verifier proved CFF2 is rejected.  Without explicit negative-example memory,
the LLM has no concise record of what NOT to try.

Solution
--------
RetryMemory maintains a list of (approach_summary, failure_reason) pairs.
After each failed attempt, the agent loop calls ``record()`` with a short
description of what was tried and why it failed.  On every retry,
``render()`` produces a compact "FAILED APPROACHES" block that is injected
into the retry prompt alongside the FactAccumulator's confirmed facts.

Design rules
------------
* Each entry is ≤ 120 chars to keep total injection compact.
* Maximum 8 entries stored (oldest evicted on overflow via FIFO).
* Format-agnostic: works for any CVE, any file format.
* Non-invasive: if empty, render() returns "" and the pipeline is unaffected.

Public API
----------
    mem = RetryMemory()
    mem.record(approach: str, reason: str) -> None
    mem.render() -> str          # "" if no entries yet
    mem.reset() -> None          # call between CVEs
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass


_MAX_ENTRIES = 8
_MAX_APPROACH_LEN = 80
_MAX_REASON_LEN = 80
_MAX_STRUCTURE_NOTE_LEN = 120


@dataclass(frozen=True)
class _FailedApproach:
    attempt: int
    approach: str
    reason: str
    structure_notes: str = ""  # e.g. 'CFF2 table tag, blend op=0x17'


class RetryMemory:
    """
    Maintains a bounded FIFO of failed approaches for the current CVE task.

    Usage::

        mem = RetryMemory()
        # after each failed attempt:
        mem.record(attempt=1, approach="CFF2 header with blend ops",
                   reason="major=2 rejected by CFF1 code path")
        # when building the next retry prompt:
        block = mem.render()  # inject into prompt
    """

    def __init__(self, max_entries: int = _MAX_ENTRIES) -> None:
        self._entries: deque[_FailedApproach] = deque(maxlen=max_entries)

    def record(self, attempt: int, approach: str, reason: str) -> None:
        """
        Record a failed attempt.

        Parameters
        ----------
        attempt : int
            The attempt number (1-indexed).
        approach : str
            Short description of the strategy tried (truncated to 80 chars).
        reason : str
            Short description of why it failed (truncated to 80 chars).
        """
        self._entries.append(
            _FailedApproach(
                attempt=attempt,
                approach=approach[:_MAX_APPROACH_LEN],
                reason=reason[:_MAX_REASON_LEN],
            )
        )

    def record_with_notes(
        self,
        attempt: int,
        approach: str,
        reason: str,
        structure_notes: str = "",
    ) -> None:
        """
        Record a failed attempt with optional structured notes.

        structure_notes should be a one-line description of the key structural
        choices made in this attempt — not the verifier output, but what the
        PoC actually tried (e.g. "CFF2 table tag, blend op=0x17").
        This helps distinguish attempts that differ only in internal structure.

        Format-agnostic: any format-specific detail can go in structure_notes.
        """
        self._entries.append(
            _FailedApproach(
                attempt=attempt,
                approach=approach[:_MAX_APPROACH_LEN],
                reason=reason[:_MAX_REASON_LEN],
                structure_notes=structure_notes[:_MAX_STRUCTURE_NOTE_LEN],
            )
        )

    def render(self) -> str:
        """
        Return a formatted "FAILED APPROACHES" block for injection into the
        retry prompt, or an empty string if nothing has been recorded yet.
        """
        if not self._entries:
            return ""

        lines = [
            "FAILED APPROACHES — do NOT repeat these strategies:",
        ]
        for entry in self._entries:
            detail = (
                f"  ✗ Attempt {entry.attempt}: {entry.approach} "
                f"→ FAILED because: {entry.reason}"
            )
            if entry.structure_notes:
                detail += f" [structural choices: {entry.structure_notes}]"
            lines.append(detail)
        lines.append(
            "You MUST try a fundamentally different approach from all of the above.\n"
        )
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Clear all entries (call between CVE tasks)."""
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"RetryMemory({len(self._entries)} entries)"