import pytest
import tempfile
import os
from verifier.compiler import compile_poc
from verifier.sanitizer import parse_asan_output
from verifier.execution import check_execution
from verifier.hallucination_detector import detect_hallucinations
from verifier.feedback_builder import build_feedback
from verifier import verify


# ─── compiler.py tests ───

def test_compiler_valid_code():
    """Valid C code should compile successfully."""
    valid_c = "#include \nint main(){ printf(\"hi\"); return 0; }"
    result = compile_poc(valid_c)
    assert result['success'] == True
    assert result['binary_path'] is not None
    # Clean up the binary
    if result['binary_path'] and os.path.exists(result['binary_path']):
        os.unlink(result['binary_path'])


def test_compiler_invalid_code():
    """Garbage code should fail to compile and return errors."""
    bad_c = "this is not C code at all!!!"
    result = compile_poc(bad_c)
    assert result['success'] == False
    assert len(result['errors']) > 0


# ─── sanitizer.py tests ───

def test_parse_asan_heap_overflow():
    """Should correctly extract crash type and address from ASan output."""
    sample = """
=================================================================
==999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
READ of size 4 at 0xdeadbeef thread T0
    #0 0x401234 in vulnerable_func /src/vuln.c:42:3
    #1 0x401300 in main /src/vuln.c:80:5
"""
    result = parse_asan_output(sample)
    assert result['crash_type'] == 'heap-buffer-overflow'
    assert result['crash_address'] == '0xdeadbeef'
    assert len(result['stack_frames']) == 2
    assert result['stack_frames'][0]['function'] == 'vulnerable_func'

# ─── hallucination_detector.py tests ───

def test_hallucination_detector_catches_invented_symbols():
    """Should flag symbols in PoC that don't exist in target source."""
    target_source = "void real_function(int x){ return; }"
    poc_with_hallucination = "void exploit(){ totally_made_up_function(); }"

    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(target_source)
        path = f.name

    try:
        hallucinated = detect_hallucinations(path, poc_with_hallucination)
        assert 'totally_made_up_function' in hallucinated
    finally:
        os.unlink(path)


def test_hallucination_detector_allows_real_symbols():
    """Should NOT flag symbols that actually exist in the target source."""
    target_source = "void real_function(int x){ return; }"
    poc_using_real = "void exploit(){ real_function(42); }"

    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
        f.write(target_source)
        path = f.name

    try:
        hallucinated = detect_hallucinations(path, poc_using_real)
        assert 'real_function' not in hallucinated
    finally:
        os.unlink(path)


# ─── feedback_builder.py tests ───

def test_feedback_compile_fail():
    """Feedback for a compile failure should mention the error."""
    compiler_result = {
        'success': False,
        'errors': [{'file': 'poc.c', 'line': 5, 'type': 'error', 'message': 'undeclared variable x'}]
    }
    feedback = build_feedback(compiler_result)
    assert 'Compilation failed' in feedback
    assert '5' in feedback


# ─── full pipeline test ───

def test_full_pipeline_compile_failure():
    """End-to-end: garbage code should produce a compile_fail VerifierResult."""
    result = verify("not C code", "/dev/null")
    assert result.status == 'compile_fail'
    assert len(result.feedback) > 0
