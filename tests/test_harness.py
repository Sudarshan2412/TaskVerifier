"""Unit tests for logger, evaluator, and runner mock pipeline."""

from __future__ import annotations

import json

import logger
import runner
from evaluator import evaluate


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
