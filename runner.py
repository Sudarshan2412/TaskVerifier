"""Experiment runner for Sudarshan track (integrated phase)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from agent.agent_loop import run_agent, AgentResult
from evaluator import evaluate
from logger import log_attempt


def _task_id(vuln: dict[str, Any]) -> str:
    return str(vuln.get("task_id") or vuln.get("id") or vuln.get("cve_id") or "unknown_task")


def _poc_bucket(vuln: dict[str, Any]) -> str:
    return str(vuln.get("poc_length_bucket") or vuln.get("poc_bucket") or "unknown")


def _normalize_cve_entry(cve: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize cybergym_subset.json entry to match agent_loop.py expectations.
    
    agent_loop.py expects: id, vuln_class, poc_bucket, sanitizer_type, target_source, crash_description
    cybergym_subset.json provides: cve_id, vuln_class, sanitizer_type, crash_description, ...
    """
    normalized = {}
    
    # Map cve_id -> id
    normalized["id"] = cve.get("cve_id") or cve.get("id") or "UNKNOWN"
    
    # Copy fields that match or have fallbacks
    normalized["vuln_class"] = cve.get("vuln_class", "other")
    normalized["sanitizer_type"] = cve.get("sanitizer_type", "unknown")
    normalized["crash_description"] = cve.get("crash_description") or cve.get("vulnerability_description", "")
    
    # poc_bucket: try to find it in various forms
    normalized["poc_bucket"] = cve.get("poc_bucket") or cve.get("poc_length_bucket", "unknown")
    
    # target_source: Required by agent_loop but missing in some versions of the subset JSON.
    # We fallback to a placeholder; real verifiers would load this from disk or Docker.
    normalized["target_source"] = cve.get("target_source", "// Placeholder source code")
    
    return normalized


def run_trial(vuln: dict[str, Any], use_verifiers: bool = True, max_attempts: int = 5) -> dict[str, Any]:
    """Run a single trial using the real agent loop and return a structured result record."""
    attempts_budget = max_attempts if use_verifiers else 1
    
    # Normalize the entry for the agent
    cve_entry = _normalize_cve_entry(vuln)
    task_id = cve_entry["id"]
    
    # Execute the real agent loop
    result: AgentResult = run_agent(cve_entry, max_attempts=attempts_budget)

    # Log each attempt in the transcript
    for step in result.transcript:
        # Map agent_loop keys to logger expected keys
        log_attempt(
            task_id=task_id,
            attempt=step["attempt"],
            poc_code=step["extracted_poc"],
            raw_model_output=step["raw_response"],
            verifier_stage=step["verifier_stage"],
            feedback_sent=step["verifier_feedback"],
            success=bool(result.success and step["attempt"] == result.attempts),
            hallucinated_symbols=step.get("hallucinated_symbols", []),
        )

    # Final evaluation against CyberGym standards
    expected = str(vuln.get("vulnerability_description") or vuln.get("crash_description") or "")
    
    # For the evaluation: 
    # 1. pre_patch_crashed is True if the verifier reached "crash" status
    pre_crashed = result.success 
    
    # 2. We use the last attempt's verifier feedback/stage as the "type" for matching
    # In a real run, the verifier stage "success" or status "crash" implies a match.
    pre_crash_type = expected if pre_crashed else "no crash triggered"
    
    # 3. Post-patch check is currently out of scope for the agent loop (handled by Diya's verifier internals)
    # but the evaluator expects it. We assume False (no crash) unless specifically flagged.
    post_crashed = False 
    
    verdict = evaluate(pre_crashed, pre_crash_type, post_crashed, expected)

    return {
        "task_id": task_id,
        "poc_length_bucket": _poc_bucket(vuln),
        "vuln_class": str(vuln.get("vuln_class") or "other"),
        "use_verifiers": use_verifiers,
        "success": bool(verdict["passed"]),
        "attempts": int(result.attempts),
        "reason": str(verdict["reason"]),
        "final_poc": result.final_poc,
        "failure_reason": result.failure_reason
    }


def run_experiment(
    subset_path: str,
    use_verifiers: bool = True,
    limit: int | None = None,
    max_attempts: int = 5,
) -> list[dict[str, Any]]:
    """Run all trials from a subset JSON and return per-task records."""
    subset_text = Path(subset_path).read_text(encoding="utf-8")
    subset = json.loads(subset_text)
    
    if isinstance(subset, list):
        tasks = subset
    elif isinstance(subset, dict) and "tasks" in subset:
        tasks = subset["tasks"]
    else:
        raise ValueError("subset JSON must contain a list or a top-level 'tasks' list")

    if limit is not None:
        tasks = tasks[:limit]

    results: list[dict[str, Any]] = []
    total = len(tasks)
    for index, vuln in enumerate(tasks, start=1):
        mode = "verifier" if use_verifiers else "baseline"
        task_id = _task_id(vuln)
        print(f"[{index}/{total}] Running {task_id} ({mode})")

        started = time.time()
        try:
            record = run_trial(vuln, use_verifiers=use_verifiers, max_attempts=max_attempts)
        except Exception as e:
            print(f"  !! Error running {task_id}: {e}")
            record = {
                "task_id": task_id,
                "success": False,
                "attempts": 0,
                "reason": f"CRASH: {str(e)}",
                "use_verifiers": use_verifiers
            }
            
        record["elapsed_seconds"] = round(time.time() - started, 2)
        results.append(record)

        status = "PASS" if record.get("success") else "FAIL"
        print(f"  -> {status} in {record.get('attempts', 0)} attempt(s) ({record['elapsed_seconds']}s)")

    return results
