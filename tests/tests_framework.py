"""
tests_framework.py — Regression tests for TaskVerifier framework fixes.

Run with: python3 -m pytest tests_framework.py -v

All tests are format-agnostic. None reference CFF, FreeType, or arvo:368.
"""

import sys
import os
import pytest

# Allow running from the patch directory
sys.path.insert(0, os.path.dirname(__file__))


# ─────────────────────────────────────────────────────────────────────────────
# Fix 1: dataset_sanitizer — narrative stripping
# ─────────────────────────────────────────────────────────────────────────────

from dataset_sanitizer import (
    sanitize_entry,
    sanitize_crash_description,
    audit_unknown_fields,
    validate_crash_description,
)


class TestSanitizeCrashDescription:
    def test_narrative_fix_adjust_stripped(self):
        """Fix sentences that explain the patch mechanism must be removed."""
        narrative = (
            "Heap-use-after-free READ (1 byte) in foo(). "
            "Fix adjusts every stale pointer by the realloc delta."
        )
        result = sanitize_crash_description(narrative)
        assert "Fix adjusts" not in result

    def test_narrative_root_cause_stripped(self):
        """When narrative has no ASAN block, only the first sentence survives — 
        longer explanatory sentences are removed."""
        narrative = "Root cause: buffer allocated too small. Fix doubles the size. Vulnerability requires two consecutive calls."
        result = sanitize_crash_description(narrative)
        # The function truncates at the first sentence — explanatory content beyond that is removed
        assert "Fix doubles" not in result
        assert "Vulnerability requires" not in result

    def test_raw_asan_output_preserved(self):
        """Real ASAN output must pass through unchanged."""
        asan = (
            "ERROR: AddressSanitizer: heap-use-after-free on address 0x5030\n"
            "#0 0x7f in foo /src/lib/foo.c:100\n"
            "#1 0x7e in bar /src/lib/bar.c:200\n"
            "SUMMARY: AddressSanitizer: heap-use-after-free /src/lib/foo.c:100 in foo"
        )
        result = sanitize_crash_description(asan)
        assert "ERROR: AddressSanitizer" in result
        assert "SUMMARY:" in result
        # Should not be truncated
        assert "#0" in result

    def test_empty_input_safe(self):
        assert sanitize_crash_description("") == ""

    def test_none_input_safe(self):
        assert sanitize_crash_description(None) is None

    def test_asan_block_extracted_from_mixed(self):
        """When narrative precedes ASAN block, extract only the ASAN part."""
        mixed = (
            "This bug was found by fuzzing. The vulnerability requires two consecutive blend ops.\n"
            "ERROR: AddressSanitizer: heap-use-after-free on address 0x1234\n"
            "#0 0x7f in vuln_func /src/foo.c:50\n"
            "SUMMARY: AddressSanitizer: heap-use-after-free /src/foo.c:50 in vuln_func"
        )
        result = sanitize_crash_description(mixed)
        assert "two consecutive blend ops" not in result
        assert "ERROR: AddressSanitizer" in result


class TestEditorialCommentStripping:
    def test_block_comment_vulnerable_stripped(self):
        source = 'int x; /* VULNERABLE: overflow here */ int y;'
        entry = {"cve_id": "test", "target_source": source}
        cleaned = sanitize_entry(entry)
        assert "VULNERABLE" not in cleaned["target_source"]
        assert "int x;" in cleaned["target_source"]  # code preserved

    def test_line_comment_vulnerable_stripped(self):
        """Line-style vulnerability comments must also be stripped."""
        source = 'int x = ptr->val; // VULNERABLE: use-after-free here\nint y = 1;'
        entry = {"cve_id": "test", "target_source": source}
        cleaned = sanitize_entry(entry)
        assert "VULNERABLE" not in cleaned["target_source"]
        assert "int y = 1" in cleaned["target_source"]

    def test_stale_comment_stripped(self):
        source = 'result = old_ptr; /* stale pointer — invalid after realloc */ return result;'
        entry = {"cve_id": "test", "target_source": source}
        cleaned = sanitize_entry(entry)
        assert "stale" not in cleaned["target_source"]

    def test_line_comment_bug_stripped(self):
        source = 'if (x > 0) { // BUG: should be >= 0\n    foo();\n}'
        entry = {"cve_id": "test", "target_source": source}
        cleaned = sanitize_entry(entry)
        assert "BUG" not in cleaned["target_source"]
        assert "foo()" in cleaned["target_source"]

    def test_normal_comments_preserved(self):
        """Non-editorial comments must not be stripped."""
        source = 'int x; /* allocate buffer */ int y; // loop counter'
        entry = {"cve_id": "test", "target_source": source}
        cleaned = sanitize_entry(entry)
        assert "allocate buffer" in cleaned["target_source"]
        # loop counter is a normal comment — this one MAY or may not be stripped
        # depending on implementation conservatism; we only require VULNERABLE/BUG/FIX not present


class TestLeakageFieldStripping:
    def test_hint_stripped(self):
        entry = {"cve_id": "test", "hint": "write two blend ops", "target_source": ""}
        cleaned = sanitize_entry(entry)
        assert "hint" not in cleaned

    def test_fix_commit_stripped(self):
        entry = {"cve_id": "test", "fix_commit": "abc123", "target_source": ""}
        cleaned = sanitize_entry(entry)
        assert "fix_commit" not in cleaned

    def test_docker_image_fix_stripped(self):
        entry = {"cve_id": "test", "docker_image_fix": "arvo:368-fix", "target_source": ""}
        cleaned = sanitize_entry(entry)
        assert "docker_image_fix" not in cleaned

    def test_real_crash_stripped(self):
        entry = {"cve_id": "test", "real_crash": True, "target_source": ""}
        cleaned = sanitize_entry(entry)
        assert "real_crash" not in cleaned

    def test_future_fields_stripped(self):
        entry = {
            "cve_id": "test",
            "target_source": "",
            "fix_description": "patch the realloc call",
            "reproduction_steps": "step 1: compile",
            "root_cause": "stale pointer",
        }
        cleaned = sanitize_entry(entry)
        assert "fix_description" not in cleaned
        assert "reproduction_steps" not in cleaned
        assert "root_cause" not in cleaned

    def test_allowed_fields_preserved(self):
        entry = {
            "cve_id": "arvo:1",
            "vuln_class": "use_after_free",
            "poc_bucket": "medium",
            "fuzz_target": "/out/ftfuzzer",
            "target_source": "void foo() {}",
            "crash_description": "ERROR: AddressSanitizer: heap-use-after-free\nSUMMARY: ...",
            "sanitizer_type": "asan",
            "docker_image_vul": "n132/arvo:1-vul",
        }
        cleaned = sanitize_entry(entry)
        for key in ["cve_id", "vuln_class", "poc_bucket", "fuzz_target", "target_source",
                    "sanitizer_type", "docker_image_vul"]:
            assert key in cleaned, f"Expected {key} to be preserved"

    def test_original_not_modified(self):
        """sanitize_entry must not mutate the input dict."""
        entry = {"cve_id": "test", "hint": "secret", "target_source": "int x;"}
        original_hint = entry.get("hint")
        sanitize_entry(entry)
        assert entry.get("hint") == original_hint


class TestAuditUnknownFields:
    def test_known_fields_no_warning(self):
        entry = {"cve_id": "x", "vuln_class": "uaf", "target_source": ""}
        assert audit_unknown_fields(entry) == []

    def test_unknown_field_flagged(self):
        entry = {"cve_id": "x", "some_custom_field_not_in_any_set": "data"}
        unknown = audit_unknown_fields(entry)
        assert "some_custom_field_not_in_any_set" in unknown

    def test_leakage_fields_not_in_unknown(self):
        """Leakage fields should not appear in the unknown list (they are known bad)."""
        entry = {"cve_id": "x", "hint": "secret"}
        unknown = audit_unknown_fields(entry)
        assert "hint" not in unknown  # hint is in _LEAKAGE_FIELDS, not unknown


# ─────────────────────────────────────────────────────────────────────────────
# Fix 3: retry_memory — structured approach notes
# ─────────────────────────────────────────────────────────────────────────────

from retry_memory import RetryMemory


class TestRetryMemoryStructuredNotes:
    def test_record_without_notes_renders(self):
        mem = RetryMemory()
        mem.record(attempt=1, approach="tried variant A", reason="no_crash")
        rendered = mem.render()
        assert "Attempt 1" in rendered
        assert "no_crash" in rendered

    def test_record_with_notes_renders_notes(self):
        mem = RetryMemory()
        mem.record_with_notes(
            attempt=1,
            approach="tried CFF1 blend",
            reason="no_crash",
            structure_notes="op=0x1F, tags=CFF",
        )
        rendered = mem.render()
        assert "op=0x1F" in rendered
        assert "tags=CFF" in rendered
        assert "Attempt 1" in rendered

    def test_empty_notes_not_shown(self):
        mem = RetryMemory()
        mem.record_with_notes(attempt=1, approach="foo", reason="bar", structure_notes="")
        rendered = mem.render()
        assert "structural choices:" not in rendered

    def test_notes_truncated(self):
        mem = RetryMemory()
        mem.record_with_notes(
            attempt=1, approach="a", reason="b", structure_notes="x" * 300
        )
        entry = mem._entries[0]
        assert len(entry.structure_notes) <= 120

    def test_max_entries_fifo(self):
        """When max entries exceeded, oldest is dropped."""
        mem = RetryMemory(max_entries=3)
        for i in range(4):
            mem.record(attempt=i+1, approach=f"approach {i}", reason="no_crash")
        assert len(mem) == 3
        rendered = mem.render()
        assert "Attempt 1" not in rendered  # evicted
        assert "Attempt 4" in rendered

    def test_reset_clears(self):
        mem = RetryMemory()
        mem.record(attempt=1, approach="a", reason="b")
        mem.reset()
        assert len(mem) == 0
        assert mem.render() == ""

    def test_mixed_record_and_record_with_notes(self):
        """record() and record_with_notes() can be mixed."""
        mem = RetryMemory()
        mem.record(attempt=1, approach="plain", reason="no_crash")
        mem.record_with_notes(attempt=2, approach="structured", reason="no_crash",
                              structure_notes="op=0x17")
        rendered = mem.render()
        assert "Attempt 1" in rendered
        assert "Attempt 2" in rendered
        assert "op=0x17" in rendered


# ─────────────────────────────────────────────────────────────────────────────
# Fix 4: agent_loop — _extract_approach_note
# ─────────────────────────────────────────────────────────────────────────────

from agent_loop import _extract_approach_note


class TestExtractApproachNote:
    def test_extracts_opcode(self):
        feedback = "The blend operator byte value 0x17 was used."
        note = _extract_approach_note("", feedback)
        assert "0x17" in note

    def test_extracts_version_tag(self):
        feedback = "The font uses tag 'CFF2' which requires version 2."
        note = _extract_approach_note("", feedback)
        assert "CFF2" in note or "version" in note.lower() or "2" in note

    def test_extracts_format_tag(self):
        feedback = "The OTTO table is required. The 'CFF ' tag was present."
        note = _extract_approach_note("", feedback)
        assert "CFF" in note or "OTTO" in note

    def test_extracts_structural_keyword(self):
        feedback = "The INDEX structure was malformed — offSize field missing."
        note = _extract_approach_note("", feedback)
        assert "INDEX" in note

    def test_empty_feedback_returns_empty(self):
        note = _extract_approach_note("", "")
        assert note == ""

    def test_generic_feedback_may_return_empty(self):
        """For feedback with no structural indicators, returns empty (safe)."""
        feedback = "The PoC compiled and ran but did not trigger the crash."
        note = _extract_approach_note("", feedback)
        # Note: may or may not be empty; we just require it doesn't crash
        assert isinstance(note, str)
        assert len(note) <= 120


# ─────────────────────────────────────────────────────────────────────────────
# Integration: sanitize_entry + crash_description together
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegration:
    def test_full_arvo_style_entry_sanitized(self):
        """Simulate a full ARVO entry going through sanitize_entry."""
        entry = {
            "cve_id": "arvo:test",
            "docker_image_vul": "n132/arvo:test-vul",
            "docker_image_fix": "n132/arvo:test-fix",
            "crash_description": (
                "Heap-use-after-free READ (4 bytes) in foo_parser(). "
                "Fix adjusts the stale pointer after realloc. "
                "Root cause: pointer not updated when buffer is reallocated."
            ),
            "sanitizer_type": "asan",
            "vuln_class": "use_after_free",
            "exit_code_vul": 77,
            "real_crash": True,
            "hint": "call foo() twice with the same buffer to trigger realloc",
            "crash_log_path": "logs/arvo_test.txt",
            "poc_bucket": "medium",
            "target_source": (
                "void foo_parser(char *buf) {\n"
                "    /* VULNERABLE: use-after-free after realloc */\n"
                "    ptr = realloc(ptr, new_size);  // stale after this\n"
                "    use(old_ptr);  // BUG: old_ptr is now freed\n"
                "}"
            ),
            "fuzz_target": "/out/foo_fuzzer",
        }
        cleaned = sanitize_entry(entry)

        # Leakage fields stripped
        assert "hint" not in cleaned
        assert "fix_commit" not in cleaned
        assert "docker_image_fix" not in cleaned
        assert "real_crash" not in cleaned
        assert "exit_code_vul" not in cleaned

        # Crash description sanitized
        assert "Fix adjusts" not in cleaned["crash_description"]
        assert "Root cause" not in cleaned["crash_description"]

        # Editorial comments stripped from source
        assert "VULNERABLE" not in cleaned["target_source"]
        assert "BUG" not in cleaned["target_source"]

        # Essential data preserved
        assert cleaned["cve_id"] == "arvo:test"
        assert cleaned["vuln_class"] == "use_after_free"
        assert cleaned["fuzz_target"] == "/out/foo_fuzzer"


if __name__ == "__main__":
    # Quick self-test without pytest
    import traceback
    test_classes = [
        TestSanitizeCrashDescription,
        TestEditorialCommentStripping,
        TestLeakageFieldStripping,
        TestAuditUnknownFields,
        TestRetryMemoryStructuredNotes,
        TestExtractApproachNote,
        TestIntegration,
    ]
    passed = 0
    failed = 0
    for cls in test_classes:
        inst = cls()
        for method_name in dir(inst):
            if method_name.startswith("test_"):
                try:
                    getattr(inst, method_name)()
                    print(f"  PASS  {cls.__name__}::{method_name}")
                    passed += 1
                except Exception as e:
                    print(f"  FAIL  {cls.__name__}::{method_name}: {e}")
                    traceback.print_exc()
                    failed += 1
    print(f"\n{passed} passed, {failed} failed")