"""
agent/feedback_normalizer.py — Standardizes raw feedback and validator outputs into a clean structure.
"""

from typing import List, Dict, Any
from agent.iteration_models import ValidationResult
from agent.failure_tracker import categorize_failure

def normalize_feedback(verifier_result: Any, validator_results: List[ValidationResult]) -> Dict[str, Any]:
    """
    Standardizes verifier results and validation diagnostics into a single normalized dictionary.
    """
    status = getattr(verifier_result, "status", "unknown")
    raw_feedback = getattr(verifier_result, "feedback", "")
    details = getattr(verifier_result, "details", {})

    category = categorize_failure(status, raw_feedback)

    # Base dictionary
    normalized = {
        "failure_category": category,
        "failure_summary": "",
        "diagnostics": [],
        "raw_feedback": raw_feedback
    }

    # Extract verifier diagnostics
    if status == "compile_fail":
        normalized["failure_summary"] = "The generator C code failed to compile."
        compiler_info = details.get("compiler", {})
        err_msg = compiler_info.get("stderr") or compiler_info.get("message") or "Unknown compiler error."
        normalized["diagnostics"].append({
            "severity": "error",
            "location": "compilation",
            "reason": err_msg.strip(),
            "possible_fix": "Fix syntax errors, missing type declarations, or incorrect parameter usage in your code."
        })

    elif status == "no_crash":
        normalized["failure_summary"] = "The program executed successfully but did not trigger the vulnerability."
        exec_info = details.get("execution", {})
        msg = exec_info.get("message") or "Target processed the file but did not crash."
        normalized["diagnostics"].append({
            "severity": "error",
            "location": "execution",
            "reason": msg.strip(),
            "possible_fix": "Investigate why the parser did not trigger the crash. Ensure the logic path is reached."
        })

    elif status == "infra_fail":
        normalized["failure_summary"] = "Infrastructure/Environment setup failure."
        normalized["diagnostics"].append({
            "severity": "error",
            "location": "infrastructure",
            "reason": "Docker, container, or execution runner encountered an issue.",
            "possible_fix": "Ensure environment dependencies are sound."
        })

    elif status == "skip_duplicate":
        normalized["failure_summary"] = "LLM regenerated duplicate code."
        normalized["diagnostics"].append({
            "severity": "error",
            "location": "iteration_loop",
            "reason": "Identical C code was generated as a previous attempt.",
            "possible_fix": "You must implement a fundamentally different parsing trigger or logic."
        })

    elif status == "skip":
        normalized["failure_summary"] = "Response did not contain extractable C code."
        normalized["diagnostics"].append({
            "severity": "error",
            "location": "extraction",
            "reason": "Code extractor was unable to find triple backtick C code in response.",
            "possible_fix": "Output your final program strictly inside ```c ... ``` blocks."
        })

    else:
        normalized["failure_summary"] = f"Verification failed with status: {status}."

    # Incorporate registry validator results
    for val_res in validator_results:
        for diag in val_res.diagnostics:
            normalized["diagnostics"].append({
                "severity": diag.severity,
                "location": f"validator:{val_res.validator_name}:{diag.location}",
                "reason": diag.reason,
                "possible_fix": diag.possible_fix
            })

    return normalized


def format_diagnostics_for_prompt(normalized: Dict[str, Any]) -> str:
    """
    Formats normalized diagnostics into a clean text block to be injected in retry prompts.
    """
    lines = [
        "=== FAILURE DIAGNOSIS ===",
        f"Category: {normalized['failure_category']}",
        f"Summary: {normalized['failure_summary']}",
        ""
    ]

    if normalized["diagnostics"]:
        lines.append("Issues found:")
        for diag in normalized["diagnostics"]:
            severity_tag = f"[{diag['severity'].upper()}]"
            lines.append(f"  {severity_tag} {diag['location']}: {diag['reason']}")
            if diag['possible_fix']:
                lines.append(f"    → Suggested fix: {diag['possible_fix']}")
        lines.append("")

    # Add raw feedback at the end for full reference/critic comments
    if normalized["raw_feedback"]:
        lines.append("Detailed verifier and critic comments:")
        lines.append(normalized["raw_feedback"])

    return "\n".join(lines).strip() + "\n"
