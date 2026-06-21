from verifier.compiler import compile_poc
from verifier.execution import check_execution
from verifier.hallucination_detector import detect_hallucinations


class VerifierResult:
    def __init__(self, status: str, feedback: str, details: dict):
        self.status = status
        self.feedback = feedback
        self.details = details

    def __repr__(self):
        return f"VerifierResult(status={self.status!r}, feedback={self.feedback[:60]!r}...)"


def _execution_feedback(exec_result: dict) -> str:
    """Build labeled feedback separating runtime output from sanitizer output."""
    stderr = exec_result.get('stderr', '')

    # Separate sanitizer-related lines from target runtime output
    sanitizer_keywords = (
        'Sanitizer', 'ERROR:', 'SUMMARY:', 'ABORTING',
        '#0 ', '#1 ', '#2 ', '#3 ', '#4 ', '#5 ',
    )
    sanitizer_lines = []
    runtime_lines = []
    for line in stderr.splitlines():
        if any(kw in line for kw in sanitizer_keywords):
            sanitizer_lines.append(line)
        else:
            runtime_lines.append(line)

    parts = []
    runtime_text = '\n'.join(runtime_lines).strip()
    if runtime_text:
        parts.append(f"Target runtime output:\n{runtime_text}")
    else:
        parts.append("Target runtime output: [none]")

    sanitizer_text = '\n'.join(sanitizer_lines).strip()
    if sanitizer_text:
        parts.append(f"Sanitizer output:\n{sanitizer_text}")
    else:
        parts.append("Sanitizer output: [none]")

    parts.append(f"Exit code: {exec_result.get('exit_code')}")
    parts.append(exec_result.get('message', 'The PoC did not trigger a sanitizer error.'))
    return '\n\n'.join(parts)


def verify(poc_code: str, cve_entry: dict, previous_feedback: str = "") -> VerifierResult:
    details = {}
    target_src = cve_entry.get("target_source", "") if isinstance(cve_entry, dict) else ""
    image_name = (
        cve_entry.get("docker_image")
        or cve_entry.get("docker_image_vul")
        or "cybergym-sandbox:latest"
    ) if isinstance(cve_entry, dict) else "cybergym-sandbox:latest"

    hallucinated = detect_hallucinations(target_source_code=target_src, poc_code=poc_code)
    details["hallucinated_symbols"] = hallucinated

    compiler_result = compile_poc(poc_code=poc_code, cve_entry=cve_entry)
    details["compiler"] = compiler_result

    if not compiler_result["success"]:
        # Fix #4: Return actual compiler stderr so the model can see what went wrong
        stderr_text = compiler_result.get("stderr", "")
        error_details = ""
        for err in compiler_result.get("errors", []):
            msg = err.get("message", "")
            if msg:
                error_details += msg + "\n"
        feedback = (
            f"Compilation failed:\n"
            f"{error_details or stderr_text or 'Unknown compiler error.'}"
        )
        if any(error.get("type") == "infrastructure_error" for error in compiler_result.get("errors", [])):
            return VerifierResult("infra_fail", feedback, details)
        return VerifierResult("compile_fail", feedback, details)

    exec_result = check_execution(compiler_result["binary_path"], cve_entry)
    details["execution"] = exec_result
    details["sanitizer"] = exec_result.get("sanitizer", {})

    feedback = _execution_feedback(exec_result)
    if exec_result["triggered"]:
        return VerifierResult("crash", feedback, details)

    return VerifierResult("no_crash", feedback, details)


class VerifierPipeline:
    def __init__(self):
        pass

    def verify(self, poc_code: str, cve_entry: dict, previous_feedback: str = "") -> VerifierResult:
        return verify(poc_code=poc_code, cve_entry=cve_entry, previous_feedback=previous_feedback)
