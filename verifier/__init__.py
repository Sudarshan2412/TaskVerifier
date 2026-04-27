from verifier.compiler import compile_poc
from verifier.sanitizer import run_and_parse
from verifier.execution import check_execution
from verifier.feedback_builder import build_feedback
from verifier.hallucination_detector import detect_hallucinations


class VerifierResult:
    def __init__(self, status: str, feedback: str, details: dict):
        self.status = status          # 'pass', 'hallucination', 'compile_fail', 'no_crash', 'crash'
        self.feedback = feedback      # The text to send back to the AI
        self.details = details        # Raw data from each stage

    def __repr__(self):
        return f"VerifierResult(status={self.status!r}, feedback={self.feedback[:60]!r}...)"


def verify(poc_code: str, target_source_path: str) -> VerifierResult:
    """
    Main entry point Prarthana calls from agent_loop.py.
    Runs the full pipeline: hallucination → compile → run → parse.
    Stops at the first failure stage.
    
    poc_code: string of C code the AI generated
    target_source_path: path to the real vulnerable C file (from cybergym_subset.json)

    Returns a VerifierResult with status, feedback text, and raw details.
    """
    details = {}

    # ── Stage 1: Hallucination detection (runs FIRST, before compiling) ──
    hallucinated = detect_hallucinations(target_source_path, poc_code)
    details['hallucinated_symbols'] = hallucinated

    # ── Stage 2: Compilation ──
    compiler_result = compile_poc(poc_code)
    details['compiler'] = compiler_result

    if not compiler_result['success']:
        feedback = build_feedback(compiler_result, hallucinated_symbols=hallucinated)
        return VerifierResult('compile_fail', feedback, details)

    binary_path = compiler_result['binary_path']

    # ── Stage 3: Execution check (did it crash?) ──
    exec_result = check_execution(binary_path)
    details['execution'] = exec_result

    if not exec_result['triggered']:
        feedback = build_feedback(compiler_result, execution_result=exec_result, hallucinated_symbols=hallucinated)
        return VerifierResult('no_crash', feedback, details)

           # ── Stage 4: Parse the crash output ──
    sanitizer_result = run_and_parse(binary_path)
    details['sanitizer'] = sanitizer_result

    feedback = build_feedback(compiler_result, sanitizer_result, exec_result, hallucinated)
    return VerifierResult('crash', feedback, details)


class VerifierPipeline:
    """
    Wraps the verify() function to provide a class-based interface.
    Expected by agent_loop.py per the spec.
    """
    
    def __init__(self):
        """Initialize the verifier pipeline."""
        pass
    
    def verify(self, poc_code: str, cve_entry: dict) -> VerifierResult:
        """
        Verify a PoC against a CVE entry.
        
        Args:
            poc_code: String of C code the AI generated
            cve_entry: Dict with 'target_source' field (path to the vulnerable C file)
            
        Returns:
            VerifierResult with status, feedback, and details
        """
        target_source_path = cve_entry["target_source"]
        return verify(poc_code=poc_code, target_source_path=target_source_path)