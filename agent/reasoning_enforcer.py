"""
agent/reasoning_enforcer.py — Enforces, extracts, and validates structured reasoning before code generation.
"""

import re
from typing import List, Optional
from agent.iteration_models import StructuredReasoning
from agent.iteration_memory import IterationMemory

# Stop words to filter out during semantic keyword check
STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "for", "with",
    "about", "against", "between", "into", "through", "during", "before",
    "after", "above", "below", "to", "from", "up", "down", "in", "out", "on",
    "off", "over", "under", "again", "further", "then", "once", "here", "there",
    "when", "where", "why", "how", "all", "any", "both", "each", "few", "more",
    "most", "other", "some", "such", "no", "nor", "not", "only", "own", "same",
    "so", "than", "too", "very", "s", "t", "can", "will", "just", "don", "should",
    "now", "failed", "attempt", "failure", "error", "compile", "run", "crash",
    "because", "was", "were", "been", "have", "has", "had", "does", "did", "doing"
}

class ReasoningEnforcer:
    """
    Enforces structured reasoning section before code is generated.
    """

    def build_reasoning_instructions(self) -> str:
        """
        Builds the prompt section that details structured reasoning requirements.
        """
        return (
            "=== MANDATORY STRUCTURED REASONING (ANALYSIS REQUIRED) ===\n"
            "Before writing the corrected C code, you MUST answer the following questions. "
            "Structure your response exactly with these markdown headings:\n\n"
            "## 1. ROOT CAUSE\n"
            "Explain exactly why the previous payload failed to trigger the crash. "
            "Be detailed and refer to the diagnostics.\n\n"
            "## 2. CHANGES\n"
            "List the specific changes you are going to make to the generator program. "
            "Include numeric list items (e.g. 1. change this, 2. change that).\n\n"
            "## 3. VERIFICATION\n"
            "Explain how the changes will address the previous failure. "
            "What criteria must the new payload meet?\n\n"
            "## 4. PREVIOUS FAILURES\n"
            "List the specific failure strategies or logic issues you are avoiding "
            "based on the history of previous attempts.\n\n"
            "## CODE\n"
            "Only after the above sections, provide the corrected C code inside a single C code block "
            "(triple backticks and the letter 'c').\n"
            "======================================\n"
        )

    def extract_reasoning(self, raw_response: str) -> Optional[StructuredReasoning]:
        """
        Parses assistant response to extract structured reasoning.
        Uses regex to grab contents under headers.
        """
        if not raw_response:
            return None

        # Clean raw response
        text = raw_response.strip()

        # Find content between headers
        root_cause_match = re.search(
            r'##\s*1\.\s*ROOT\s*CAUSE\s*(.*?)(?=##\s*2\.\s*CHANGES|##\s*3\.|##\s*4\.|##\s*CODE|$)', 
            text, re.DOTALL | re.IGNORECASE
        )
        changes_match = re.search(
            r'##\s*2\.\s*CHANGES\s*(.*?)(?=##\s*3\.\s*VERIFICATION|##\s*4\.|##\s*CODE|$)', 
            text, re.DOTALL | re.IGNORECASE
        )
        verification_match = re.search(
            r'##\s*3\.\s*VERIFICATION\s*(.*?)(?=##\s*4\.\s*PREVIOUS\s*FAILURES|##\s*CODE|$)', 
            text, re.DOTALL | re.IGNORECASE
        )
        failures_match = re.search(
            r'##\s*4\.\s*PREVIOUS\s*FAILURES\s*(.*?)(?=##\s*CODE|```|$)', 
            text, re.DOTALL | re.IGNORECASE
        )

        if not (root_cause_match or changes_match or verification_match or failures_match):
            # Try a looser heading matching (without numbers)
            root_cause_match = re.search(
                r'ROOT\s*CAUSE\s*(.*?)(?=CHANGES|VERIFICATION|PREVIOUS\s*FAILURES|CODE|$)', 
                text, re.DOTALL | re.IGNORECASE
            )
            changes_match = re.search(
                r'CHANGES\s*(.*?)(?=VERIFICATION|PREVIOUS\s*FAILURES|CODE|$)', 
                text, re.DOTALL | re.IGNORECASE
            )
            verification_match = re.search(
                r'VERIFICATION\s*(.*?)(?=PREVIOUS\s*FAILURES|CODE|$)', 
                text, re.DOTALL | re.IGNORECASE
            )
            failures_match = re.search(
                r'PREVIOUS\s*FAILURES\s*(.*?)(?=CODE|```|$)', 
                text, re.DOTALL | re.IGNORECASE
            )

        root_cause = root_cause_match.group(1).strip() if root_cause_match else ""
        changes_raw = changes_match.group(1).strip() if changes_match else ""
        verification = verification_match.group(1).strip() if verification_match else ""
        failures_raw = failures_match.group(1).strip() if failures_match else ""

        # Extract changes as list
        planned_changes = []
        for line in changes_raw.splitlines():
            line = line.strip()
            # Match numbered lines or bullet points
            if line and (re.match(r'^\d+\.', line) or line.startswith('-') or line.startswith('*')):
                planned_changes.append(re.sub(r'^\d+\.\s*|^[-*]\s*', '', line).strip())
            elif line:
                planned_changes.append(line)

        # Extract previous failures list
        previous_failures = []
        for line in failures_raw.splitlines():
            line = line.strip()
            if line and (re.match(r'^\d+\.', line) or line.startswith('-') or line.startswith('*')):
                previous_failures.append(re.sub(r'^\d+\.\s*|^[-*]\s*', '', line).strip())
            elif line:
                previous_failures.append(line)

        # If we failed to find any structured sections, return None
        if not root_cause and not planned_changes and not verification and not previous_failures:
            return None

        # Build raw text block for record
        raw_reasoning_parts = []
        if root_cause:
            raw_reasoning_parts.append(f"Root Cause: {root_cause}")
        if planned_changes:
            raw_reasoning_parts.append(f"Planned Changes: {'; '.join(planned_changes)}")
        raw_text = "\n".join(raw_reasoning_parts)

        return StructuredReasoning(
            root_cause=root_cause,
            planned_changes=planned_changes,
            validation_strategy=verification,
            previous_failures_acknowledged=previous_failures,
            raw_text=raw_text
        )

    def validate_reasoning(
        self, 
        reasoning: StructuredReasoning, 
        iteration_memory: IterationMemory, 
        feedback_text: str
    ) -> List[str]:
        """
        Checks if reasoning is valid. Returns a list of issues found.
        Empty list means reasoning is valid.
        """
        issues = []

        if not reasoning:
            issues.append("Response did not contain the required structured reasoning headings.")
            return issues

        if len(reasoning.root_cause) < 15:
            issues.append("Root Cause section is missing or too short (must explain why previous attempt failed).")

        if not reasoning.planned_changes:
            issues.append("Changes section is empty (must list concrete changes you will make).")

        if len(reasoning.validation_strategy) < 10:
            issues.append("Verification section is missing or too short.")

        # Check semantic consistency with previous failed strategies/reasons
        # Collect keywords from prior failed strategies / verifier feedback
        prior_texts = []
        for record in iteration_memory.records:
            if record.strategy_description:
                prior_texts.append(record.strategy_description)
            if record.root_cause:
                prior_texts.append(record.root_cause)
        
        if feedback_text:
            prior_texts.append(feedback_text)

        if prior_texts:
            prior_words = self._extract_keywords(" ".join(prior_texts))
            # Keywords mentioned in LLM's acknowledgement / root cause sections
            llm_texts = [
                reasoning.root_cause, 
                reasoning.validation_strategy, 
                " ".join(reasoning.previous_failures_acknowledged)
            ]
            llm_words = self._extract_keywords(" ".join(llm_texts))

            # Find overlap
            overlap = prior_words.intersection(llm_words)
            if not overlap:
                issues.append(
                    "The Previous Failures or Root Cause section does not seem to address "
                    "the actual failed attempts or raw verifier feedback from memory. "
                    "You must demonstrate acknowledgement of the specific issues reported."
                )

        return issues

    def extract_code_after_reasoning(self, raw_response: str) -> str:
        """
        Extracts C code from the response. Ensures it targets code after the reasoning block.
        """
        # Find where CODE header or last reasoning header occurs
        split_markers = [r'##\s*CODE', r'##\s*4\.\s*PREVIOUS\s*FAILURES', r'PREVIOUS\s*FAILURES']
        split_idx = 0
        for marker in split_markers:
            match = re.search(marker, raw_response, re.IGNORECASE)
            if match:
                split_idx = max(split_idx, match.end())

        search_text = raw_response[split_idx:] if split_idx > 0 else raw_response

        # Find code blocks
        code_match = re.search(r'```c(?:\s*\n)?(.*?)\n```', search_text, re.DOTALL | re.IGNORECASE)
        if not code_match:
            # Try generic code block fallback
            code_match = re.search(r'```(?:.*?)(?:\s*\n)?(.*?)\n```', search_text, re.DOTALL)

        if code_match:
            return code_match.group(1).strip()
        
        return ""

    def _extract_keywords(self, text: str) -> set:
        """Helper to tokenize text into a set of clean keywords."""
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())
        return {w for w in words if w not in STOPWORDS}
