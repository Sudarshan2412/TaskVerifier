"""
agent/validator_interface.py — Pluggable validation framework with base interface and registry.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Set
from agent.iteration_models import ValidationResult, ValidationDiagnostic

class Validator(ABC):
    """
    Abstract Base Class for all pluggable validators.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def can_validate(self, task_context: dict) -> bool:
        """Determines if this validator is applicable to the current task/format."""
        pass

    @abstractmethod
    def validate(self, poc_code: str, task_context: dict) -> ValidationResult:
        """Runs validation checks on the code and returns a ValidationResult."""
        pass


class ValidatorRegistry:
    """
    Registry to manage and execute applicable validators.
    """

    def __init__(self) -> None:
        self._validators: List[Validator] = []

    def register(self, validator: Validator) -> None:
        """Register a new validator plugin."""
        self._validators.append(validator)

    def get_applicable(self, task_context: dict) -> List[Validator]:
        """Returns list of registered validators that can run for this context."""
        return [v for v in self._validators if v.can_validate(task_context)]

    def run_all(self, poc_code: str, task_context: dict) -> List[ValidationResult]:
        """Runs all applicable validators on the given code."""
        results = []
        for v in self.get_applicable(task_context):
            try:
                results.append(v.validate(poc_code, task_context))
            except Exception as e:
                # Shield registry from individual validator failures
                diagnostics = [
                    ValidationDiagnostic(
                        passed=False,
                        severity="error",
                        location="validator_infrastructure",
                        reason=f"Validator {v.name} raised exception: {str(e)}",
                        possible_fix="Check validator plugin implementation"
                    )
                ]
                results.append(
                    ValidationResult(
                        validator_name=v.name,
                        passed=False,
                        diagnostics=diagnostics
                    )
                )
        return results


class StructuralValidator(Validator):
    """
    Built-in generic validator that performs structural checks on the generated C code.
    Works for any CVE/format.
    """

    @property
    def name(self) -> str:
        return "structural_validator"

    def can_validate(self, task_context: dict) -> bool:
        return True  # Applicable to all C-based tasks

    def validate(self, poc_code: str, task_context: dict) -> ValidationResult:
        diagnostics = []
        code = poc_code or ""

        # Check 1: Code is non-empty
        if not code.strip():
            diagnostics.append(
                ValidationDiagnostic(
                    passed=False,
                    severity="error",
                    location="code_integrity",
                    reason="The generated PoC code is completely empty.",
                    possible_fix="Ensure C program code is generated and wrapped in triple backticks."
                )
            )

        # Check 2: Contains main function
        if code.strip() and "main" not in code:
            diagnostics.append(
                ValidationDiagnostic(
                    passed=False,
                    severity="error",
                    location="c_structure",
                    reason="The PoC code is missing a 'main' function definition.",
                    possible_fix="Implement 'int main(int argc, char **argv)' or 'int main(void)' to run the PoC."
                )
            )

        # Check 3: Writes to /tmp/poc
        if code.strip() and "/tmp/poc" not in code:
            diagnostics.append(
                ValidationDiagnostic(
                    passed=False,
                    severity="warning",
                    location="poc_output",
                    reason="The code does not mention writing to '/tmp/poc'.",
                    possible_fix="Verify that your program opens '/tmp/poc' (e.g. fopen(\"/tmp/poc\", \"wb\")) to write the payload."
                )
            )

        # Check 4: Check if duplicate code has been generated
        seen_hashes: Set[str] = task_context.get("seen_poc_hashes", set())
        import hashlib
        poc_hash = hashlib.md5(code.encode("utf-8", errors="ignore")).hexdigest()
        if code.strip() and poc_hash in seen_hashes:
            diagnostics.append(
                ValidationDiagnostic(
                    passed=False,
                    severity="error",
                    location="iteration_loop",
                    reason="The generated code is identical to a previous attempt.",
                    possible_fix="You must try a fundamentally different approach. Do not generate duplicate code."
                )
            )

        passed = all(d.passed for d in diagnostics)
        return ValidationResult(
            validator_name=self.name,
            passed=passed,
            diagnostics=diagnostics
        )
