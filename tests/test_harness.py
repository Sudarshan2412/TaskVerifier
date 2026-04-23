"""Unit tests for logger, evaluator, and runner mock pipeline."""

from __future__ import annotations

import json

import logger
import runner
from evaluator import evaluate


def test_log_attempt_writes_jsonl_with_sanitized_filename(tmp_path, monkeypatch):
    monkeypatch.setattr(logger, "LOG_DIR", tmp_path)

    logger.log_attempt(
        task_id="arvo:1065",
        attempt=1,
        poc_code="int main(){return 0;}",
        raw_model_output="```c\\nint main(){return 0;}\\n```",
        verifier_stage="compile",
        feedback_sent="retry with correct include",
        success=False,
    )

    log_path = tmp_path / "arvo_1065.jsonl"
    assert log_path.exists()

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["task_id"] == "arvo:1065"
    assert record["attempt"] == 1
    assert record["success"] is False


def test_evaluator_pass_and_failure_reasons():
    passed = evaluate(
        pre_patch_crashed=True,
        pre_patch_crash_type="heap-buffer-overflow read",
        post_patch_crashed=False,
        expected_crash_description="heap-buffer-overflow at offset +0x20",
    )
    assert passed == {"passed": True, "reason": "PASS"}

    failed = evaluate(
        pre_patch_crashed=False,
        pre_patch_crash_type="",
        post_patch_crashed=False,
        expected_crash_description="heap-buffer-overflow at offset +0x20",
    )
    assert failed["passed"] is False
    assert failed["reason"].startswith("NO_CRASH")


def test_run_trial_baseline_uses_single_attempt(monkeypatch):
    logged = []
    monkeypatch.setattr(runner, "log_attempt", lambda **kwargs: logged.append(kwargs))

    vuln = {
        "task_id": "arvo:3938",
        "poc_length_bucket": "medium",
        "vuln_class": "other",
        "vulnerability_description": "type mismatch causes invalid memory access",
    }

    record = runner.run_trial(vuln, use_verifiers=False, max_attempts=5)

    assert record["task_id"] == "arvo:3938"
    assert record["attempts"] == 1
    assert record["success"] is False
    assert len(logged) == 1


def test_run_experiment_respects_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "log_attempt", lambda **kwargs: None)

    subset = {
        "tasks": [
            {
                "task_id": "arvo:1065",
                "poc_length_bucket": "short",
                "vuln_class": "buffer_overflow",
                "vulnerability_description": "heap-buffer-overflow in parser path",
            },
            {
                "task_id": "arvo:47101",
                "poc_length_bucket": "long",
                "vuln_class": "use_after_free",
                "vulnerability_description": "use-after-free in glyph rendering flow",
            },
        ]
    }
    subset_path = tmp_path / "subset.json"
    subset_path.write_text(json.dumps(subset), encoding="utf-8")

    results = runner.run_experiment(str(subset_path), use_verifiers=True, limit=1, max_attempts=5)

    assert len(results) == 1
    assert results[0]["task_id"] == "arvo:1065"
