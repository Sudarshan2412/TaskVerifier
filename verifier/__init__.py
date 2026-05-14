from verifier.compiler import compile_poc
from verifier.sanitizer import run_and_parse
from verifier.execution import check_execution
from verifier.feedback_builder import build_feedback
from verifier.hallucination_detector import detect_hallucinations
import re

class VerifierResult:
    def __init__(self, status: str, feedback: str, details: dict):
        self.status = status
        self.feedback = feedback
        self.details = details

    def __repr__(self):
        return f"VerifierResult(status={self.status!r}, feedback={self.feedback[:60]!r}...)"

def _extract_real_asan(stderr: str) -> dict:
    """Parses actual AddressSanitizer output from Docker's stderr stream."""
    match = re.search(r'ERROR: (AddressSanitizer: [^\n]+)', stderr)
    if match:
        return {'crashed': True, 'crash_type': match.group(1), 'crash_address': 'See logs', 'stack_frames': []}
    return {'crashed': True, 'crash_type': 'Unknown Crash or Fatal Docker Error', 'crash_address': 'Unknown', 'stack_frames': []}

def verify(poc_code: str, cve_entry: dict) -> VerifierResult:
    details = {}
    target_src = cve_entry.get("target_source", "")
    image_name = cve_entry.get("docker_image") or "cybergym-sandbox:latest"

    # 1. Hallucination check
    hallucinated = detect_hallucinations(target_source_code=target_src, poc_code=poc_code)
    details['hallucinated_symbols'] = hallucinated

    # 2. Compilation
    compiler_result = compile_poc(poc_code=poc_code, cve_entry=cve_entry)
    details['compiler'] = compiler_result

    if not compiler_result['success']:
        feedback = build_feedback(compiler_result, hallucinated_symbols=hallucinated, 
                                  target_source=target_src, image_name=image_name)
        if any(error.get('type') == 'infrastructure_error' for error in compiler_result.get('errors', [])):
            return VerifierResult('infra_fail', feedback, details)
        return VerifierResult('compile_fail', feedback, details)

    # 3. Execution check
    exec_result = check_execution(compiler_result['binary_path'], cve_entry)
    details['execution'] = exec_result

    if not exec_result['triggered']:
        feedback = build_feedback(compiler_result, execution_result=exec_result, 
                                  hallucinated_symbols=hallucinated, target_source=target_src, image_name=image_name)
        return VerifierResult('no_crash', feedback, details)

    # 4. Crash parsing (REAL output)
    stderr_output = exec_result.get('stderr', '')
    
    print("\n" + "="*60)
    print("🎯 CRASH TRIGGERED! RAW STDERR:")
    print("="*60)
    print(stderr_output[:1500]) # Print first 1500 chars to avoid terminal spam
    print("="*60 + "\n")

    sanitizer_result = _extract_real_asan(stderr_output)
    details['sanitizer'] = sanitizer_result

    feedback = build_feedback(compiler_result, sanitizer_result, exec_result, 
                              hallucinated, target_source=target_src, image_name=image_name)
    
    return VerifierResult('crash', feedback, details)

class VerifierPipeline:
    def __init__(self): pass
    def verify(self, poc_code: str, cve_entry: dict) -> VerifierResult:
        return verify(poc_code=poc_code, cve_entry=cve_entry)