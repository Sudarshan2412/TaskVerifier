import os
import tempfile
import pytest
 
 
# ─────────────────────────────────────────────
# SECTION 1 — compiler.py  (3 tests)
# ─────────────────────────────────────────────
 
from verifier.compiler import compile_poc
 
 
def test_T1_valid_c_code_compiles():
    """Valid C code with no bugs should compile and run successfully."""
    code = '#include <stdio.h>\nint main(){ printf("hi"); return 0; }'
    result = compile_poc(code)

    assert result["success"] is True, (
        f"compile_poc returned success=False for valid C code.\n"
        f"Errors: {result['errors']}\n"
        f"Stderr: {result['stderr'][:300]}\n"
        "Make sure clang is on your PATH: run 'clang --version' in terminal."
    )
 
 
def test_T2_invalid_c_code_returns_errors():
    """Garbage input should fail to compile and return at least one error."""
    result = compile_poc("this is not C code at all!!")
 
    assert result["success"] is False, "compile_poc should return success=False for invalid code."
    assert len(result["errors"]) > 0, "errors list should not be empty when compilation fails."
 
 
def test_T3_errors_have_correct_fields():
    """Each error dict must contain 'line' (int), 'type', and 'message' fields."""
    result = compile_poc("int main(){ undeclared_var = 5; return 0; }")
 
    assert result["success"] is False
    assert len(result["errors"]) > 0, "Expected at least one error for undeclared variable."
 
    error = result["errors"][0]
    assert "line" in error,    "Error dict is missing the 'line' field."
    assert "type" in error,    "Error dict is missing the 'type' field."
    assert "message" in error, "Error dict is missing the 'message' field."
    assert isinstance(error["line"], int), "'line' field must be an integer, not a string."
 
 
# ─────────────────────────────────────────────
# SECTION 2 — sanitizer.py  (3 tests)
# ─────────────────────────────────────────────
 
from verifier.sanitizer import parse_asan_output
 
 
SAMPLE_HEAP_OVERFLOW = """
=================================================================
==999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x401234 in vulnerable_func /src/vuln.c:42:3
    #1 0x401300 in main /src/vuln.c:80:5
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/vuln.c:42 in vulnerable_func
"""
 
SAMPLE_USE_AFTER_FREE = """
=================================================================
==1234==ERROR: AddressSanitizer: use-after-free on address 0xcafebabe
    #0 0x402000 in do_free /src/target.c:15:1
    #1 0x402100 in main /src/target.c:30:5
"""
 
SAMPLE_MANY_FRAMES = """
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x100 in func_a /a.c:1
    #1 0x101 in func_b /b.c:2
    #2 0x102 in func_c /c.c:3
    #3 0x103 in func_d /d.c:4
    #4 0x104 in func_e /e.c:5
"""
 
 
def test_T4_parses_heap_overflow_correctly():
    """Should extract crash type, address, and top 2 frames from ASan output."""
    result = parse_asan_output(SAMPLE_HEAP_OVERFLOW)
 
    assert result["crash_type"] == "heap-buffer-overflow", (
        f"Expected 'heap-buffer-overflow', got '{result['crash_type']}'"
    )
    assert result["crash_address"] == "0xdeadbeef", (
        f"Expected '0xdeadbeef', got '{result['crash_address']}'"
    )
    assert len(result["stack_frames"]) == 2, (
        f"Expected 2 stack frames, got {len(result['stack_frames'])}"
    )
    assert result["stack_frames"][0]["function"] == "vulnerable_func", (
        f"Expected first frame function to be 'vulnerable_func', got '{result['stack_frames'][0]['function']}'"
    )
 
 
def test_T5_parses_use_after_free_correctly():
    """Should handle use-after-free crash type."""
    result = parse_asan_output(SAMPLE_USE_AFTER_FREE)
 
    assert result["crash_type"] == "use-after-free", (
        f"Expected 'use-after-free', got '{result['crash_type']}'"
    )
    assert result["crash_address"] != "unknown", (
        "crash_address should not be 'unknown' — check your address regex in sanitizer.py"
    )
 
 
def test_T6_only_keeps_top_2_frames():
    """Even with 5 stack frames in output, only the top 2 should be kept."""
    result = parse_asan_output(SAMPLE_MANY_FRAMES)
 
    assert len(result["stack_frames"]) == 2, (
        f"Expected exactly 2 frames, got {len(result['stack_frames'])}. "
        "Check your frame_num < 2 condition in sanitizer.py"
    )
    frame_indices = [f["frame"] for f in result["stack_frames"]]
    assert max(frame_indices) == 1, (
        f"Highest frame index kept should be 1, got {max(frame_indices)}"
    )
 
 
# ─────────────────────────────────────────────
# SECTION 3 — hallucination_detector.py  (3 tests)
# ─────────────────────────────────────────────
 
from verifier.hallucination_detector import detect_hallucinations
 
 
def _write_temp_source(code: str) -> str:
    """Helper — writes code to a temp .c file and returns the path."""
    f = tempfile.NamedTemporaryFile(suffix=".c", mode="w", delete=False)
    f.write(code)
    f.close()
    return f.name
 
 
def test_T7_flags_invented_symbols():
    """A PoC that calls a made-up function should have it flagged."""
    target_source = "void real_function(int x){ return; }"
    poc_code      = "void exploit(){ totally_made_up_function(1, 2, 3); }"
 
    path = _write_temp_source(target_source)
    try:
        result = detect_hallucinations(path, poc_code)
        assert "totally_made_up_function" in result, (
            f"Expected 'totally_made_up_function' in hallucinated list, got: {result}"
        )
    finally:
        os.unlink(path)
 
 
def test_T8_does_not_flag_real_symbols():
    """Functions that exist in the target source must NOT be flagged."""
    target_source = "void real_function(int x){ return; }\nvoid another_real(char* s){ return; }"
    poc_code      = "void exploit(){ real_function(42); another_real(\"test\"); }"
 
    path = _write_temp_source(target_source)
    try:
        result = detect_hallucinations(path, poc_code)
        assert "real_function" not in result, (
            "'real_function' exists in target source — it should NOT be flagged as hallucinated."
        )
        assert "another_real" not in result, (
            "'another_real' exists in target source — it should NOT be flagged as hallucinated."
        )
    finally:
        os.unlink(path)
 
 
def test_T9_does_not_flag_stdlib_names():
    """Standard C library names like malloc, printf, free must never be flagged."""
    target_source = "void real_func(){ return; }"
    poc_code      = "#include <stdio.h>\nvoid exploit(){ char* p = malloc(100); printf(\"%s\", p); free(p); }"
 
    path = _write_temp_source(target_source)
    try:
        result = detect_hallucinations(path, poc_code)
        stdlib_names = {"malloc", "printf", "free", "memcpy", "strlen", "strcmp",
                        "fprintf", "exit", "abort", "calloc", "realloc", "NULL"}
        incorrectly_flagged = [s for s in result if s in stdlib_names]
        assert incorrectly_flagged == [], (
            f"Standard library names were incorrectly flagged: {incorrectly_flagged}. "
            "Add these to STDLIB_NAMES in hallucination_detector.py"
        )
    finally:
        os.unlink(path)
 
 
# ─────────────────────────────────────────────
# SECTION 4 — feedback_builder.py + verify()  (3 tests)
# ─────────────────────────────────────────────
 
from verifier.feedback_builder import build_feedback
from verifier import verify
 
 
def test_T10_feedback_mentions_line_number():
    """Feedback for a compile failure should include the line number."""
    compiler_result = {
        "success": False,
        "errors": [{"file": "poc.c", "line": 7, "type": "error", "message": "undeclared identifier x"}]
    }
    feedback = build_feedback(compiler_result)
 
    assert len(feedback) > 0, "feedback string should not be empty."
    assert "7" in feedback, (
        "Feedback should mention line 7 so the AI knows where the error is."
    )
    assert any(word in feedback.lower() for word in ["compilation", "compile", "failed"]), (
        "Feedback should mention that compilation failed."
    )
    assert any(word in feedback.lower() for word in ["fix", "try", "retry"]), (
        "Feedback should end with a prompt telling the AI to try again."
    )
 
 
def test_T11_feedback_includes_hallucinated_symbol_names():
    """When symbols are flagged, their names must appear in the feedback text."""
    compiler_result = {
        "success": False,
        "errors": [{"file": "poc.c", "line": 1, "type": "error", "message": "unknown function"}]
    }
    feedback = build_feedback(
        compiler_result,
        hallucinated_symbols=["fake_func", "made_up_var"]
    )
 
    assert "fake_func" in feedback, (
        "'fake_func' was hallucinated but does not appear in the feedback text. "
        "Check build_feedback() handles the hallucinated_symbols argument."
    )
    assert "made_up_var" in feedback, (
        "'made_up_var' was hallucinated but does not appear in the feedback text."
    )
 
 
def test_T12_verify_end_to_end():
    """The exact call Prarthana will make from agent_loop.py."""
    # Part A: garbage code should return compile_fail
    result_a = verify("this is not C code", os.devnull)

    assert result_a.status == "compile_fail", (
        f"Expected 'compile_fail' for garbage code, got '{result_a.status}'"
    )
    assert len(result_a.feedback) > 0, "feedback string must not be empty."
    assert isinstance(result_a.details, dict), "details must be a dict."

    # Part B: valid code that exits cleanly should return no_crash
    valid_c = '#include <stdio.h>\nint main(){ printf("hello"); return 0; }'
    src_path = _write_temp_source("void placeholder(){}")
    try:
        result_b = verify(valid_c, src_path)
        assert result_b.status in ("no_crash", "crash"), (
            f"Expected 'no_crash' or 'crash', got '{result_b.status}'"
        )
        assert len(result_b.feedback) > 0, "feedback must not be empty."
    finally:
        os.unlink(src_path)