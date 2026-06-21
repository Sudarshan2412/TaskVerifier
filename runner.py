"""Experiment runner for Sudarshan track (integrated phase)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from agent.agent_loop import run_agent, AgentResult
from evaluator import evaluate
from logger import StepLogger, ReportWriter


def _task_id(vuln: dict[str, Any]) -> str:
    return str(vuln.get("task_id") or vuln.get("id") or vuln.get("cve_id") or "unknown_task")


def _poc_bucket(vuln: dict[str, Any]) -> str:
    return str(vuln.get("poc_length_bucket") or vuln.get("poc_bucket") or "unknown")


def _normalize_cve_entry(cve: dict[str, Any]) -> dict[str, Any]:
    normalized = {}
    normalized["id"] = cve.get("cve_id") or cve.get("id") or "UNKNOWN"
    normalized["vuln_class"] = cve.get("vuln_class", "other")
    normalized["sanitizer_type"] = cve.get("sanitizer_type", "asan")
    normalized["crash_description"] = cve.get("crash_description") or cve.get("vulnerability_description", "")
    normalized["poc_bucket"] = cve.get("poc_bucket") or cve.get("poc_length_bucket", "unknown")
    normalized["docker_image"] = cve.get("docker_image_vul") or "cybergym-sandbox:latest"
    normalized["target_source"] = cve.get("target_source", "// Placeholder source code")
    normalized["fuzz_target"] = cve.get("fuzz_target", "/usr/bin/fuzz_target")
    # Fix #10: carry per-task max_attempts override
    if cve.get("max_attempts") is not None:
        normalized["max_attempts"] = int(cve["max_attempts"])
    return normalized


def run_trial(
    vuln: dict[str, Any], 
    use_verifiers: bool = True, 
    max_attempts: int = 5,
    step_logger: StepLogger = None
) -> tuple[dict[str, Any], AgentResult]:
    
    # Fix #10: per-task max_attempts override
    task_max = cve_entry.get("max_attempts")
    if task_max is not None:
        max_attempts = max(max_attempts, int(task_max))
    attempts_budget = max_attempts if use_verifiers else 1
    cve_entry = _normalize_cve_entry(vuln)
    task_id = cve_entry["id"]
    
    # Execute the real agent loop
    result: AgentResult = run_agent(cve_entry, max_attempts=attempts_budget, step_logger=step_logger)

    expected = str(vuln.get("vulnerability_description") or vuln.get("crash_description") or "")
    pre_crashed = result.success 
    pre_crash_type = expected if pre_crashed else "no crash triggered"
    post_crashed = False 
    
    verdict = evaluate(pre_crashed, pre_crash_type, post_crashed, expected)

    record = {
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
    
    return record, result


def run_experiment(
    subset_path: str,
    use_verifiers: bool = True,
    limit: int | None = None,
    max_attempts: int = 5,
) -> list[dict[str, Any]]:
    
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
    
    step_logger = StepLogger()
    report_writer = ReportWriter(max_attempts=max_attempts)
    step_logger.log_run_header(total, max_attempts)
    
    for index, vuln in enumerate(tasks, start=1):
        task_id = _task_id(vuln)
        bucket = _poc_bucket(vuln)
        vuln_class = vuln.get("vuln_class", "unknown")
        
        step_logger.log_cve_header(index, total, task_id, bucket, vuln_class)

        started = time.time()
        try:
            record, agent_result = run_trial(
                vuln, 
                use_verifiers=use_verifiers, 
                max_attempts=max_attempts,
                step_logger=step_logger
            )
            
            report_writer.add_cve_result(
                cve_id=task_id,
                bucket=bucket,
                vuln_class=vuln_class,
                success=record["success"],
                attempts=record["attempts"],
                failure_reason=record["failure_reason"] or record["reason"],
                final_poc=record["final_poc"],
                transcript=agent_result.transcript,
                hallucinated_symbols_per_attempt=agent_result.hallucinated_symbols_per_attempt
            )
            
        except Exception as e:
            step_logger.log_cve_error(task_id, str(e))
            record = {
                "task_id": task_id,
                "success": False,
                "attempts": 0,
                "reason": f"CRASH: {str(e)}",
                "use_verifiers": use_verifiers
            }
            report_writer.add_cve_result(
                cve_id=task_id, bucket=bucket, vuln_class=vuln_class,
                success=False, attempts=0, failure_reason="exception",
                final_poc="", transcript=[], hallucinated_symbols_per_attempt=[],
                error=str(e)
            )
            
        record["elapsed_seconds"] = round(time.time() - started, 2)
        results.append(record)
        
        if index < total:
            step_logger.log_sleep(2)
            time.sleep(2)

    report_path = report_writer.write_report("logs")
    print(f"\n[INFO] Markdown report written to {report_path}")

    return results
