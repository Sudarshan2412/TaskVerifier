"""Experiment runner for Sudarshan track (mock-agent phase)."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from evaluator import evaluate
from logger import log_attempt


def _task_id(vuln: dict[str, Any]) -> str:
    return str(vuln.get("task_id") or vuln.get("id") or "unknown_task")


def _poc_bucket(vuln: dict[str, Any]) -> str:
    return str(vuln.get("poc_length_bucket") or vuln.get("poc_bucket") or "unknown")


def _mock_run_agent(vuln: dict[str, Any], max_attempts: int) -> dict[str, Any]:
    """Temporary local mock until Prarthana's run_agent() is available in Week 7+."""
    bucket = _poc_bucket(vuln)
    expected_attempt = {"short": 1, "medium": 2, "long": 3}.get(bucket, 2)
    success = expected_attempt <= max_attempts
    attempts_used = expected_attempt if success else max_attempts

    transcript: list[dict[str, Any]] = []
    for attempt in range(1, attempts_used + 1):
        is_final_success = success and attempt == attempts_used
        transcript.append(
            {
                "attempt": attempt,
                "poc_code": f"// mock poc for {_task_id(vuln)} attempt {attempt}",
                "raw_model_output": f"```c\\n// mock output attempt {attempt}\\n```",
                "verifier_feedback": "PASS" if is_final_success else "mock feedback: adjust input size",
                "verifier_stage": "success" if is_final_success else "sanitizer",
            }
        )

    return {
        "success": success,
        "attempts": attempts_used,
        "transcript": transcript,
    }


def run_trial(vuln: dict[str, Any], use_verifiers: bool = True, max_attempts: int = 5) -> dict[str, Any]:
    """Run a single trial and return a structured result record."""
    attempts_budget = max_attempts if use_verifiers else 1
    task_id = _task_id(vuln)
    result = _mock_run_agent(vuln, attempts_budget)

    for step in result["transcript"]:
        log_attempt(
            task_id=task_id,
            attempt=step["attempt"],
            poc_code=step["poc_code"],
            raw_model_output=step["raw_model_output"],
            verifier_stage=step["verifier_stage"],
            feedback_sent=step["verifier_feedback"],
            success=bool(result["success"] and step["attempt"] == result["attempts"]),
        )

    expected = str(vuln.get("vulnerability_description") or vuln.get("crash_description") or "")
    pre_crashed = bool(result["success"])
    pre_crash_type = expected if pre_crashed else ""
    post_crashed = False
    verdict = evaluate(pre_crashed, pre_crash_type, post_crashed, expected)

    return {
        "task_id": task_id,
        "poc_length_bucket": _poc_bucket(vuln),
        "vuln_class": str(vuln.get("vuln_class") or "other"),
        "use_verifiers": use_verifiers,
        "success": bool(verdict["passed"]),
        "attempts": int(result["attempts"]),
        "reason": str(verdict["reason"]),
    }


def run_experiment(
    subset_path: str,
    use_verifiers: bool = True,
    limit: int | None = None,
    max_attempts: int = 5,
) -> list[dict[str, Any]]:
    """Run all trials from a subset JSON and return per-task records."""
    subset = json.loads(Path(subset_path).read_text(encoding="utf-8"))
    tasks = subset.get("tasks", subset)

    if not isinstance(tasks, list):
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
        record = run_trial(vuln, use_verifiers=use_verifiers, max_attempts=max_attempts)
        record["elapsed_seconds"] = round(time.time() - started, 2)
        results.append(record)

        status = "PASS" if record["success"] else "FAIL"
        print(f"  -> {status} in {record['attempts']} attempt(s)")

    return results
