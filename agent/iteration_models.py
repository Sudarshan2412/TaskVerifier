"""
agent/iteration_models.py — Core dataclasses for generic iteration and reasoning tracking.
"""

from dataclasses import dataclass, field
from typing import Optional, List

@dataclass
class IterationRecord:
    attempt: int
    verifier_status: str
    failure_category: str
    root_cause: str
    strategy_description: str
    fixes_attempted: List[str] = field(default_factory=list)
    outcome: str = ""

@dataclass
class StructuredReasoning:
    root_cause: str
    planned_changes: List[str] = field(default_factory=list)
    validation_strategy: str = ""
    previous_failures_acknowledged: List[str] = field(default_factory=list)
    raw_text: str = ""

@dataclass
class ValidationDiagnostic:
    passed: bool
    severity: str  # "error", "warning", "info"
    location: str  # e.g., "compilation", "execution", "structure"
    reason: str
    possible_fix: str

@dataclass
class ValidationResult:
    validator_name: str
    passed: bool
    diagnostics: List[ValidationDiagnostic] = field(default_factory=list)

@dataclass
class FailurePattern:
    category: str
    count: int
    first_attempt: int
    last_attempt: int
