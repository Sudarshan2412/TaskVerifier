"""
tests/test_iteration.py — Comprehensive unit tests for the generic iterative improvement architecture.
"""

import pytest
from agent.iteration_models import IterationRecord, StructuredReasoning
from agent.iteration_memory import IterationMemory
from agent.failure_tracker import FailurePatternTracker, categorize_failure
from agent.reasoning_enforcer import ReasoningEnforcer
from agent.validator_interface import ValidatorRegistry, StructuralValidator
from agent.feedback_normalizer import normalize_feedback, format_diagnostics_for_prompt
from verifier import VerifierResult

# ──────────────────────────────────────────────────────────────────────────────
# 1. IterationMemory Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestIterationMemory:
    def test_empty_memory_summary_and_render(self):
        mem = IterationMemory()
        assert mem.get_compact_summary() == ""
        assert mem.render() == ""
        assert mem.get_attempt_count() == 0

    def test_adds_records_and_generates_summary(self):
        mem = IterationMemory()
        mem.add_record(IterationRecord(
            attempt=1,
            verifier_status="compile_fail",
            failure_category="compile_error",
            root_cause="forgot syntax header",
            strategy_description="add stdio.h header",
            fixes_attempted=["#include <stdio.h>"],
            outcome="compilation failed"
        ))
        
        summary = mem.get_compact_summary()
        assert "Attempt 1" in summary
        assert "compile_error" in summary
        assert "forgot syntax header" in summary
        assert "add stdio.h header" in summary
        assert "Do not repeat this strategy" in summary

    def test_failed_strategies(self):
        mem = IterationMemory()
        mem.add_record(IterationRecord(
            attempt=1,
            verifier_status="no_crash",
            failure_category="parser_rejection",
            root_cause="wrong offset",
            strategy_description="try offset 16",
            outcome="rejected"
        ))
        mem.add_record(IterationRecord(
            attempt=2,
            verifier_status="no_crash",
            failure_category="parser_rejection",
            root_cause="wrong offset again",
            strategy_description="try offset 32",
            outcome="rejected"
        ))
        
        strategies = mem.get_failed_strategies()
        assert strategies == ["try offset 16", "try offset 32"]

    def test_legacy_render_backward_compat(self):
        mem = IterationMemory()
        mem.add_record(IterationRecord(
            attempt=1,
            verifier_status="compile_fail",
            failure_category="compile_error",
            root_cause="syntax issue",
            strategy_description="fixed macro syntax",
            fixes_attempted=["fix define"],
            outcome="still failed compilation"
        ))
        
        legacy_rendered = mem.render()
        assert "FAILED APPROACHES" in legacy_rendered
        assert "Attempt 1: fixed macro syntax" in legacy_rendered
        assert "still failed compilation" in legacy_rendered
        assert "[fix define]" in legacy_rendered


# ──────────────────────────────────────────────────────────────────────────────
# 2. FailurePatternTracker & Categorize Failure Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFailurePatternTracker:
    def test_categorize_failure(self):
        assert categorize_failure("compile_fail", "syntax error") == "compile_error"
        assert categorize_failure("no_crash", "target exited normally") == "parser_rejection"
        assert categorize_failure("infra_fail", "docker issue") == "infrastructure_error"
        assert categorize_failure("skip_duplicate", "duplicate code") == "duplicate_poc"
        assert categorize_failure("skip", "no extractable code") == "extraction_failed"
        assert categorize_failure("no_crash", "timed out during run") == "timeout"
        assert categorize_failure("no_crash", "did not create /tmp/poc") == "generator_failure"

    def test_tracks_patterns_and_triggers_escalation(self):
        tracker = FailurePatternTracker()
        tracker.record_failure("parser_rejection", 1)
        tracker.record_failure("parser_rejection", 2)
        
        patterns = tracker.get_repeated_patterns(threshold=2)
        assert len(patterns) == 1
        assert patterns[0].category == "parser_rejection"
        assert patterns[0].count == 2
        assert tracker.should_force_strategy_change() is False

        # Add 3rd failure to trigger force strategy change
        tracker.record_failure("parser_rejection", 3)
        assert tracker.should_force_strategy_change() is True
        
        escalation = tracker.get_escalation_prompt()
        assert "WARNING: REPEATED FAILURE PATTERNS DETECTED" in escalation
        assert "parser_rejection" in escalation
        assert "fundamentally rethink your strategy" in escalation


# ──────────────────────────────────────────────────────────────────────────────
# 3. ReasoningEnforcer Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestReasoningEnforcer:
    def test_builds_instructions(self):
        enforcer = ReasoningEnforcer()
        instructions = enforcer.build_reasoning_instructions()
        assert "## 1. ROOT CAUSE" in instructions
        assert "## 2. CHANGES" in instructions
        assert "## CODE" in instructions

    def test_extract_reasoning_sections(self):
        response = (
            "Hello, here is my reasoning:\n"
            "## 1. ROOT CAUSE\n"
            "The magic offset was incorrect in the header.\n"
            "## 2. CHANGES\n"
            "1. Change offset to 42\n"
            "2. Set length to 100\n"
            "## 3. VERIFICATION\n"
            "Ensure the parser handles offset 42 without rejection.\n"
            "## 4. PREVIOUS FAILURES\n"
            "- Attempted offset 16\n\n"
            "## CODE\n"
            "```c\n"
            "int main() { return 0; }\n"
            "```"
        )
        enforcer = ReasoningEnforcer()
        reasoning = enforcer.extract_reasoning(response)
        
        assert reasoning is not None
        assert reasoning.root_cause == "The magic offset was incorrect in the header."
        assert reasoning.planned_changes == ["Change offset to 42", "Set length to 100"]
        assert reasoning.validation_strategy == "Ensure the parser handles offset 42 without rejection."
        assert reasoning.previous_failures_acknowledged == ["Attempted offset 16"]

    def test_validate_reasoning_semantic_checks(self):
        enforcer = ReasoningEnforcer()
        mem = IterationMemory()
        mem.add_record(IterationRecord(
            attempt=1,
            verifier_status="no_crash",
            failure_category="parser_rejection",
            root_cause="wrong offset",
            strategy_description="used offset sixteen",
            outcome="rejected"
        ))

        # 1. Valid reasoning (mentions similar concepts/words)
        valid = StructuredReasoning(
            root_cause="The parser rejected the offset sixteen parameter",
            planned_changes=["use offset thirty two instead"],
            validation_strategy="verify with compiler and run check",
            previous_failures_acknowledged=["offset sixteen did not crash target"],
            raw_text=""
        )
        issues = enforcer.validate_reasoning(valid, mem, "Verifier says offset sixteen is bad")
        assert len(issues) == 0

        # 2. Invalid reasoning (does not mention anything related to failed attempts / feedback)
        invalid = StructuredReasoning(
            root_cause="Some generic message",
            planned_changes=["do something totally unrelated"],
            validation_strategy="run it",
            previous_failures_acknowledged=["none"],
            raw_text=""
        )
        issues = enforcer.validate_reasoning(invalid, mem, "Verifier says offset sixteen is bad")
        assert any("does not seem to address" in issue for issue in issues)

    def test_extract_code_after_reasoning(self):
        response = (
            "## 1. ROOT CAUSE\n"
            "Some reason\n"
            "## 2. CHANGES\n"
            "Change code\n"
            "## CODE\n"
            "```c\n"
            "int main() { return 42; }\n"
            "```"
        )
        enforcer = ReasoningEnforcer()
        code = enforcer.extract_code_after_reasoning(response)
        assert code == "int main() { return 42; }"


# ──────────────────────────────────────────────────────────────────────────────
# 4. StructuralValidator Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestStructuralValidator:
    def test_structural_validation_rules(self):
        validator = StructuralValidator()
        
        # 1. Empty code
        res = validator.validate("", {})
        assert res.passed is False
        assert any("completely empty" in d.reason for d in res.diagnostics)

        # 2. Missing main
        res = validator.validate("int foo() { return 0; }", {})
        assert res.passed is False
        assert any("missing a 'main' function" in d.reason for d in res.diagnostics)

        # 3. Duplicate code check
        import hashlib
        code = "int main() {}"
        h = hashlib.md5(code.encode("utf-8")).hexdigest()
        context = {"seen_poc_hashes": {h}}
        res = validator.validate(code, context)
        assert any("identical to a previous attempt" in d.reason for d in res.diagnostics)


# ──────────────────────────────────────────────────────────────────────────────
# 5. FeedbackNormalizer Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFeedbackNormalizer:
    def test_normalize_compiler_failure(self):
        res = VerifierResult("compile_fail", "error: syntax error", {"compiler": {"stderr": "error: syntax error"}})
        norm = normalize_feedback(res, [])
        
        assert norm["failure_category"] == "compile_error"
        assert "syntax error" in norm["diagnostics"][0]["reason"]

    def test_normalize_with_validator_diagnostics(self):
        res = VerifierResult("no_crash", "Target did not crash", {})
        from agent.iteration_models import ValidationResult, ValidationDiagnostic
        
        val_res = ValidationResult(
            validator_name="custom_validator",
            passed=False,
            diagnostics=[
                ValidationDiagnostic(
                    passed=False,
                    severity="warning",
                    location="header",
                    reason="Header length is too small",
                    possible_fix="Increase header length"
                )
            ]
        )
        
        norm = normalize_feedback(res, [val_res])
        assert norm["failure_category"] == "parser_rejection"
        assert len(norm["diagnostics"]) == 2  # verifier no_crash diagnostic + validator diagnostic
        assert norm["diagnostics"][1]["location"] == "validator:custom_validator:header"
        assert norm["diagnostics"][1]["reason"] == "Header length is too small"
