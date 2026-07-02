"""
agent/iteration_memory.py — Tracks rich history of attempts across iterations and provides summaries.
"""

from typing import List
from agent.iteration_models import IterationRecord

class IterationMemory:
    """
    Maintains a list of IterationRecord objects representing attempts.
    """

    def __init__(self) -> None:
        self.records: List[IterationRecord] = []

    def add_record(self, record: IterationRecord) -> None:
        """Add a rich IterationRecord to memory."""
        self.records.append(record)

    def get_compact_summary(self) -> str:
        """
        Produces a concise, growing summary of all previous attempts.
        Focuses on reasoning, strategy, and outcome.
        """
        if not self.records:
            return ""

        lines = [f"=== ITERATION HISTORY ({len(self.records)} attempt(s)) ==="]
        for record in self.records:
            lines.append(
                f"Attempt {record.attempt} | Status: {record.verifier_status} | Category: {record.failure_category}"
            )
            if record.root_cause:
                lines.append(f"  Root cause: {record.root_cause}")
            if record.strategy_description:
                lines.append(f"  Strategy: {record.strategy_description}")
            if record.fixes_attempted:
                fixes_str = ", ".join(record.fixes_attempted)
                lines.append(f"  Fixes attempted: {fixes_str}")
            if record.outcome:
                lines.append(f"  Outcome: {record.outcome}")
            lines.append("  ⛔ Do not repeat this strategy.")
            lines.append("")

        return "\n".join(lines).strip() + "\n"

    def get_failed_strategies(self) -> List[str]:
        """Returns strategy descriptions of failed attempts."""
        return [r.strategy_description for r in self.records if r.strategy_description]

    def get_attempt_count(self) -> int:
        """Returns the number of recorded attempts."""
        return len(self.records)

    def render(self) -> str:
        """
        Backward-compatible method matching RetryMemory.render() signature.
        """
        if not self.records:
            return ""

        lines = ["FAILED APPROACHES — do NOT repeat these strategies:"]
        for record in self.records:
            fixes = f" [{', '.join(record.fixes_attempted)}]" if record.fixes_attempted else ""
            lines.append(
                f"  ✗ Attempt {record.attempt}: {record.strategy_description} "
                f"→ FAILED because: {record.outcome or record.verifier_status}{fixes}"
            )
        lines.append("You MUST try a fundamentally different approach from all of the above.\n")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        """Clear all records."""
        self.records.clear()
