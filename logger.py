"""Trial and attempt logging utilities for Sudarshan track."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

LOG_DIR = Path("data/results/logs")


class AttemptLogRecord(BaseModel):
    """Validated schema for one attempt-level log entry."""

    model_config = ConfigDict(extra="allow")

    timestamp: str
    task_id: str
    attempt: int = Field(ge=1)
    raw_model_output: str
    poc_code_extracted: str
    verifier_stage_reached: str
    feedback_sent_to_model: str
    success: bool


def _task_key(record: Mapping[str, Any]) -> str:
    """Resolve per-task log filename key with backward-compatible fallbacks."""
    raw_key = str(record.get("task_id") or record.get("vuln_id") or "unknown_task")
    return re.sub(r"[^A-Za-z0-9._-]+", "_", raw_key)


def _normalize_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize common fields before writing to disk."""
    normalized = dict(record)

    if "task_id" not in normalized:
        if "vuln_id" in normalized:
            normalized["task_id"] = str(normalized["vuln_id"])
        else:
            raise ValueError("record must include either 'task_id' or 'vuln_id'")

    normalized.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    return normalized


def log_trial(record: Mapping[str, Any]) -> None:
    """Append one normalized record to the task-specific JSONL log."""
    normalized = _normalize_record(record)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    path = LOG_DIR / f"{_task_key(normalized)}.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(normalized, ensure_ascii=True) + "\n")


def log_attempt(
    task_id: str,
    attempt: int,
    poc_code: str,
    raw_model_output: str,
    verifier_stage: str,
    feedback_sent: str,
    success: bool,
) -> None:
    """Write one attempt-level log record."""
    record = AttemptLogRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        task_id=task_id,
        attempt=attempt,
        raw_model_output=raw_model_output,
        poc_code_extracted=poc_code,
        verifier_stage_reached=verifier_stage,
        feedback_sent_to_model=feedback_sent,
        success=success,
    )
    log_trial(record.model_dump())
