"""
agent/failure_tracker.py — Detects repeated failure categories across iterations and triggers escalation.
"""

import re
from typing import List, Dict
from agent.iteration_models import FailurePattern

def categorize_failure(verifier_status: str, feedback_text: str) -> str:
    """
    Maps verifier output to generic categories.
    Absolutely no format-specific (HEIC, PNG) or CVE-specific knowledge.
    """
    status = (verifier_status or "").lower()
    feedback = (feedback_text or "").lower()

    if status == "compile_fail":
        return "compile_error"
    elif status == "infra_fail":
        return "infrastructure_error"
    elif status == "skip_duplicate":
        return "duplicate_poc"
    elif "did not contain extractable c code" in feedback or status == "skip":
        return "extraction_failed"
    elif "timed out" in feedback or "timeout" in feedback:
        return "timeout"
    elif "did not create /tmp/poc" in feedback or "generator program itself crashed" in feedback:
        return "generator_failure"
    elif status == "no_crash":
        return "parser_rejection"
    else:
        return "other_failure"


class FailurePatternTracker:
    """
    Tracks failure categories across attempts to detect patterns.
    """

    def __init__(self) -> None:
        # category -> list of attempt numbers
        self.history: Dict[str, List[int]] = {}

    def record_failure(self, category: str, attempt: int) -> None:
        """Record a failure occurrence under a category."""
        if not category:
            category = "other_failure"
        if category not in self.history:
            self.history[category] = []
        self.history[category].append(attempt)

    def get_repeated_patterns(self, threshold: int = 2) -> List[FailurePattern]:
        """
        Returns list of categories that occurred >= threshold times.
        """
        patterns = []
        for cat, attempts in self.history.items():
            if len(attempts) >= threshold:
                patterns.append(
                    FailurePattern(
                        category=cat,
                        count=len(attempts),
                        first_attempt=attempts[0],
                        last_attempt=attempts[-1]
                    )
                )
        # Sort by count desc
        patterns.sort(key=lambda p: p.count, reverse=True)
        return patterns

    def should_force_strategy_change(self) -> bool:
        """
        True if any failure category has occurred >= 3 times.
        """
        return any(len(attempts) >= 3 for attempts in self.history.values())

    def get_escalation_prompt(self) -> str:
        """
        Generates a generic prompt encouraging the LLM to rethink its approach.
        """
        repeated = self.get_repeated_patterns(threshold=2)
        if not repeated:
            return ""

        lines = [
            "\n⚠️ WARNING: REPEATED FAILURE PATTERNS DETECTED ⚠️"
        ]
        for p in repeated:
            lines.append(
                f"  • Category '{p.category}' has failed {p.count} times (since attempt {p.first_attempt})."
            )
        
        lines.append(
            "\nYour incremental edits are not triggering the vulnerability. "
            "You MUST fundamentally rethink your strategy:\n"
            "1. Do NOT just make minor modifications to the same payload or structure.\n"
            "2. Consider a completely different structure or logic flow.\n"
            "3. Re-read the target source signatures to see if you missed a parameter, constraint, or alternative code path.\n"
            "4. Verify that you aren't repeating assumptions that previously failed."
        )
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Reset the failure history."""
        self.history.clear()
