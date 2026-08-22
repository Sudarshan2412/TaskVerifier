from verifier.compiler import compile_poc
from verifier.sanitizer import parse_asan_output
from verifier.execution import check_execution
from verifier.feedback_builder import build_feedback
from verifier.hallucination_detector import detect_hallucinations
import re
import os


# ── P1: Crash-Site Validation ────────────────────────────────────────────────
# Compare the actual crash location against the expected crash from the
# public crash description.  This is format-agnostic: it extracts file
# basenames and line numbers from any ASAN/UBSAN/MSAN output format.

def _extract_crash_site(output: str) -> tuple[str, int]:
    """Extract the first non-infrastructure crash file and line from output.

    Returns (basename, line_number) or ("", 0) if nothing is found.
    Format-agnostic: matches standard sanitizer output patterns.
    """
    _INFRA_DIRS = (
        'libfuzzer', 'compiler-rt', 'sanitizer_common',
        'asan', 'ubsan', 'msan'
    )
    
    # 1. Try to find a SUMMARY line first (most reliable for the fatal crash)
    summary_pattern = re.compile(r'SUMMARY:.*?(/[^\s:]+\.(?:c|cc|cpp|h|hpp|inc)):(\d+)')
    for match in summary_pattern.finditer(output):
        filepath = match.group(1)
        if not any(inf in filepath.lower() for inf in _INFRA_DIRS):
            return (os.path.basename(filepath), int(match.group(2)))
            
    # 2. Try to find the actual error line (runtime error: or ERROR:)
    error_pattern = re.compile(r'(/[^\s:]+\.(?:c|cc|cpp|h|hpp|inc)):(\d+)(?::\d+)?:\s*(?:runtime error|ERROR):')
    for match in error_pattern.finditer(output):
        filepath = match.group(1)
        if not any(inf in filepath.lower() for inf in _INFRA_DIRS):
            return (os.path.basename(filepath), int(match.group(2)))

    # 3. Fallback: scan all file paths, but try to skip libFuzzer stack traces
    file_line_pattern = re.compile(r'(/[^\s:]+\.(?:c|cc|cpp|h|hpp|inc)):(\d+)')
    for match in file_line_pattern.finditer(output):
        filepath = match.group(1)
        if not any(inf in filepath.lower() for inf in _INFRA_DIRS):
            # Skip fuzzer harness files (fuzz_*.c) in favour of library source files.
            # Harness files often appear in infra stack traces and are rarely the
            # actual crash site.  We'll still accept them in fallback stage 4.
            if "fuzz_" not in filepath.lower():
                return (os.path.basename(filepath), int(match.group(2)))
                
    # 4. Absolute fallback
    for match in file_line_pattern.finditer(output):
        filepath = match.group(1)
        if not any(inf in filepath.lower() for inf in _INFRA_DIRS):
            return (os.path.basename(filepath), int(match.group(2)))
            
    return ("", 0)


def _validate_crash_site(
    actual_output: str, crash_description: str
) -> tuple[bool, str, str]:
    """Compare actual crash location against expected.

    Returns:
        (is_correct_site, actual_location_str, expected_location_str)

    If either location cannot be extracted, returns (True, ?, ?) to avoid
    false-negative blocking (benefit of the doubt).
    """
    actual_file, actual_line = _extract_crash_site(actual_output)
    expected_file, expected_line = _extract_crash_site(crash_description)

    actual_str = f"{actual_file}:{actual_line}" if actual_file else "unknown"
    expected_str = f"{expected_file}:{expected_line}" if expected_file else "unknown"

    # If we can't extract either, give benefit of the doubt
    if not actual_file or not expected_file:
        return (True, actual_str, expected_str)

    # File basename must match
    if actual_file.lower() != expected_file.lower():
        return (False, actual_str, expected_str)

    # Line number: allow ±50 lines of tolerance for inlining / code shifts
    if abs(actual_line - expected_line) > 50:
        return (False, actual_str, expected_str)

    return (True, actual_str, expected_str)

class VerifierResult:
    def __init__(self, status: str, feedback: str, details: dict):
        self.status = status
        self.feedback = feedback
        self.details = details

    def __repr__(self):
        return f"VerifierResult(status={self.status!r}, feedback={self.feedback[:60]!r}...)"

def _extract_real_asan(stderr: str, exit_code: int = 0) -> dict:
    import re
    match = re.search(r'(AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer):\s*([^\n\r]+)', stderr)
    
    if match:
        return {
            'crashed': True, 
            'crash_type': f"{match.group(1)}: {match.group(2)}", 
            'crash_address': 'See terminal log', 
            'stack_frames': []
        }
    
    # Signal-based crash with no sanitizer output (e.g. non-instrumented binary)
    signal_num = exit_code - 128 if exit_code > 128 else 0
    signal_names = {11: 'SIGSEGV (Segmentation fault)', 6: 'SIGABRT (Abort)', 
                    8: 'SIGFPE (Floating point)', 4: 'SIGILL (Illegal instruction)'}
    signal_desc = signal_names.get(signal_num, f'Signal {signal_num}')
    
    return {
        'crashed': True, 
        'crash_type': f'Raw Signal Crash: {signal_desc}', 
        'crash_address': 'Unknown (no sanitizer instrumentation)', 
        'stack_frames': stderr[-1000:] if stderr else "NO STDERR OUTPUT"
    }
    
def verify(poc_code: str, cve_entry: dict, previous_feedback: str = "", failed_approaches: str = "", confirmed_facts: str = "") -> VerifierResult:
    details = {}
    target_src = cve_entry.get("target_source", "")
    image_name = cve_entry.get("docker_image") or cve_entry.get("docker_image_vul") or "cybergym-sandbox:latest"

    # 1. Hallucination check
    hallucinated = detect_hallucinations(target_source_code=target_src, poc_code=poc_code)
    details['hallucinated_symbols'] = hallucinated

    # 2. Compilation
    compiler_result = compile_poc(poc_code=poc_code, cve_entry=cve_entry)
    details['compiler'] = compiler_result

    if not compiler_result['success']:
        feedback = build_feedback(compiler_result, hallucinated_symbols=hallucinated, 
                                  target_source=target_src, image_name=image_name, poc_code=poc_code, cve_entry=cve_entry) # <--- ADDED HERE
        if any(error.get('type') == 'infrastructure_error' for error in compiler_result.get('errors', [])):
            return VerifierResult('infra_fail', feedback, details)
        return VerifierResult('compile_fail', feedback, details)

    # 3. Execution check
    exec_result = check_execution(compiler_result['binary_path'], cve_entry)
    details['execution'] = exec_result

    # Fast-path: skip the expensive critic for trivial failures
    def _trivial_failure_feedback(execution_result: dict, poc_code: str) -> str | None:
        """Returns a short feedback string if the failure is trivially diagnosable, else None."""
        stderr = execution_result.get("stderr", "")
        stdout = execution_result.get("stdout", "")
        message = execution_result.get("message", "")

        # Generator didn't write the file at all
        if "did not create /tmp/poc" in message or "empty" in message.lower():
            return (
                "Your generator compiled and ran but did not write anything to /tmp/poc. "
                "Make sure your C program calls fopen(\"/tmp/poc\", \"wb\") and fwrite/fputc, "
                "then fclose before returning."
            )

        # Generator crashed before writing the file
        if "generator timed out" in message or "Failed to run" in message:
            return (
                "Your generator program itself crashed or timed out before writing /tmp/poc. "
                "Simplify the generator — it only needs to write a payload file, not perform complex logic."
            )

        # Infrastructure error — no point invoking critic
        if "INFRASTRUCTURE ERROR" in message:
            return message  # pass through as-is

        # Payload structurally looks empty (0 bytes or only null bytes)
        if poc_code and len(poc_code.strip()) < 50:
            return (
                "Your generator is too short to produce a meaningful payload. "
                "Write a complete C program that constructs and writes a crafted input."
            )

        return None  # Not trivial — invoke the full critic

    if not exec_result['triggered']:
        base_feedback = build_feedback(compiler_result, execution_result=exec_result, 
                                  hallucinated_symbols=hallucinated, target_source=target_src, image_name=image_name, poc_code=poc_code, previous_feedback=previous_feedback, failed_approaches=failed_approaches, confirmed_facts=confirmed_facts, cve_entry=cve_entry) # <--- ADDED HERE
        
        # --- NEW: SELF-CRITIQUE INJECTION ---
        # Force the LLM to act as its own critic on the next iteration
        self_reflection_prompt = (
            f"{base_feedback}\n\n"
            f"=== CRITIQUE REQUIRED ===\n"
            f"Before writing the updated C code, you MUST write a short paragraph of analysis. "
            f"Read the fuzzer output provided above and explain EXACTLY why the previous payload "
            f"was rejected or failed to reach the vulnerable code. "
            f"State your new strategy clearly, and THEN output the C code."
        )
        
        return VerifierResult('no_crash', self_reflection_prompt, details)

    # 4. Crash parsing (REAL output)
    stderr_output = exec_result.get('stderr', '')
    
    print("\n" + "="*60)
    print("🎯 CRASH TRIGGERED! RAW STDERR:")
    print("="*60)
    print(stderr_output[:1500]) # Print first 1500 chars to avoid terminal spam
    print("="*60 + "\n")

    sanitizer_result = _extract_real_asan(stderr_output, exit_code=exec_result.get('exit_code', 0))
    details['sanitizer'] = sanitizer_result

    # ── P1: Crash-Site Validation ─────────────────────────────────────────
    # Compare actual crash location against the expected crash from
    # crash_description.  If the crash is in a different file/line range,
    # report 'wrong_crash' so the agent knows it hit the wrong code path.
    crash_desc = cve_entry.get("crash_description", "")
    combined_crash_output = stderr_output + "\n" + exec_result.get('stdout', '')
    is_correct_site, actual_loc, expected_loc = _validate_crash_site(
        combined_crash_output, crash_desc
    )

    if not is_correct_site:
        print(f"[VERIFY] ⚠ Wrong crash site: actual={actual_loc}, expected={expected_loc}")
        feedback = build_feedback(compiler_result, sanitizer_result, exec_result,
                                  hallucinated, target_source=target_src, image_name=image_name, poc_code=poc_code, cve_entry=cve_entry,
                                  is_wrong_crash=True, actual_loc=actual_loc, expected_loc=expected_loc, combined_crash_output=combined_crash_output)
        return VerifierResult('wrong_crash', feedback, details)

    feedback = build_feedback(compiler_result, sanitizer_result, exec_result, 
                              hallucinated, target_source=target_src, image_name=image_name, poc_code=poc_code, cve_entry=cve_entry) # <--- ADDED HERE
    
    # ── P11: Feedback Quality Gate ───────────────────────────────────────────
    # We must inline a simplified quality check here because we don't have
    # access to _is_low_quality_feedback from feedback_builder directly.
    stripped_fb = feedback.strip()
    if not stripped_fb or len(stripped_fb) < 100:
        feedback = (
            "The verifier crashed but did not produce a valid diagnostic report. "
            "Please analyze the provided fuzzer output and try a different approach."
        )

    return VerifierResult('crash', feedback, details)

class VerifierPipeline:
    def __init__(self): pass
    def verify(self, poc_code: str, cve_entry: dict, previous_feedback: str = "", failed_approaches: str = "", confirmed_facts: str = "") -> VerifierResult:
        return verify(poc_code=poc_code, cve_entry=cve_entry, previous_feedback=previous_feedback, failed_approaches=failed_approaches, confirmed_facts=confirmed_facts)