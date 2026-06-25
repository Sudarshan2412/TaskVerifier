"""
run_pipeline.py — Run the agent loop on CVEs with step-by-step logging.
"""

from __future__ import annotations

import json
import os
import time
import logging
from pathlib import Path

from agent.agent_loop import run_agent
from logger import StepLogger, ReportWriter
from dataset_sanitizer import sanitize_entry

MAX_ATTEMPTS = int(os.environ.get("WEEK8_MAX_ATTEMPTS", "2"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

TARGET_CVE_IDS = [c.strip() for c in os.environ.get("WEEK8_CVE_IDS", "").split(",") if c.strip()]


# ──────────────────────────────────────────────────────────────────────────────
# CVE selection
# ──────────────────────────────────────────────────────────────────────────────

def pick_test_cves(subset, n=2):
    if not subset or len(subset) < n:
        return subset[:n]

    bucket_field = None
    for candidate in ["poc_length_bucket", "bucket", "poc_bucket", "length_bucket"]:
        if candidate in subset[0]:
            bucket_field = candidate
            break

    if bucket_field:
        short  = [c for c in subset if c.get(bucket_field) == "short"][:1]
        medium = [c for c in subset if c.get(bucket_field) == "medium"][:2]
        long_  = [c for c in subset if c.get(bucket_field) == "long"][:1]
        rest   = [c for c in subset if c not in short + medium + long_][:1]
        selected = (short + medium + long_ + rest)[:n]
        if len(selected) == n:
            return selected

    return [subset[i] for i in range(len(subset)) if i % 2 == 0][:n]


def select_test_cves(subset, n=2, explicit_ids=None):
    if explicit_ids:
        explicit_set = set(explicit_ids)
        return [cve for cve in subset if cve.get("cve_id") in explicit_set]
    return pick_test_cves(subset, n=n)


def _normalize_cve_entry(cve: dict) -> dict:
    normalized = {}
    normalized["id"]               = cve.get("cve_id", "UNKNOWN")
    normalized["vuln_class"]       = cve.get("vuln_class", "other")
    normalized["sanitizer_type"]   = cve.get("sanitizer_type", "asan")
    normalized["crash_description"]= cve.get("crash_description") or cve.get("vulnerability_description", "")
    normalized["poc_bucket"]       = cve.get("poc_bucket") or cve.get("poc_length_bucket", "unknown")
    normalized["target_source"]    = cve.get("target_source", "// Placeholder")
    normalized["docker_image"]     = cve.get("docker_image_vul") or "cybergym-sandbox:latest"
    # BUG FIX: don't fall back to a non-existent default path.
    # Leave empty so execution.py can emit a clear error instead of a silent infra failure.
    normalized["fuzz_target"]      = cve.get("fuzz_target", "")
    # BUG FIX: carry exit_code_vul so execution.py knows what a crash looks like
    # for this specific CVE (some targets exit 0 even on crash).
    normalized["exit_code_vul"]    = cve.get("exit_code_vul", 1)
    return normalized


# ──────────────────────────────────────────────────────────────────────────────
# Load and select CVEs
# ──────────────────────────────────────────────────────────────────────────────

with open("cybergym_subset.json") as f:
    subset = json.load(f)

test_cves_raw = select_test_cves(subset, n=2, explicit_ids=TARGET_CVE_IDS)
test_cves = [_normalize_cve_entry(sanitize_entry(cve)) for cve in test_cves_raw]


# ──────────────────────────────────────────────────────────────────────────────
# Run
# ──────────────────────────────────────────────────────────────────────────────

step_logger   = StepLogger()
report_writer = ReportWriter(max_attempts=MAX_ATTEMPTS)

step_logger.log_run_header(total_cves=len(test_cves), max_attempts=MAX_ATTEMPTS)

for i, cve in enumerate(test_cves, start=1):
    cve_id     = cve.get("id", "UNKNOWN")
    bucket     = cve.get("poc_bucket", "unknown")
    vuln_class = cve.get("vuln_class", "unknown")

    step_logger.log_cve_header(i, len(test_cves), cve_id, bucket, vuln_class)

    # Warn early if fuzz_target is missing — saves wasted attempts
    if not cve.get("fuzz_target"):
        step_logger._safe_print(
            f"  ⚠  WARNING: no fuzz_target for {cve_id}. "
            f"Add it to cybergym_subset.json or all attempts will fail at execution."
        )

    try:
        result = run_agent(cve_entry=cve, max_attempts=MAX_ATTEMPTS, step_logger=step_logger)

        result_dict = {
            "cve_id":     cve_id,
            "success":    result.success,
            "attempts":   result.attempts,
            "final_poc":  result.final_poc,
            "failure_reason": result.failure_reason,
            "transcript": result.transcript,
            "hallucinated_symbols_per_attempt": result.hallucinated_symbols_per_attempt,
        }

        os.makedirs("logs", exist_ok=True)
        safe_id = cve_id.replace("/", "_").replace(":", "_").replace("-", "_")
        with open(f"logs/week8_manual_{safe_id}.json", "w") as f:
            json.dump(result_dict, f, indent=2)

        report_writer.add_cve_result(
            cve_id=cve_id, bucket=bucket, vuln_class=vuln_class,
            success=result.success, attempts=result.attempts,
            failure_reason=result.failure_reason, final_poc=result.final_poc,
            transcript=result.transcript,
            hallucinated_symbols_per_attempt=result.hallucinated_symbols_per_attempt
        )

    except Exception as e:
        step_logger.log_cve_error(cve_id, str(e))
        report_writer.add_cve_result(
            cve_id=cve_id, bucket=bucket, vuln_class=vuln_class,
            success=False, attempts=0, failure_reason="exception",
            final_poc="", transcript=[], hallucinated_symbols_per_attempt=[],
            error=str(e)
        )

    if i < len(test_cves):
        step_logger.log_sleep(5)
        time.sleep(5)


# ──────────────────────────────────────────────────────────────────────────────
# Final report
# ──────────────────────────────────────────────────────────────────────────────

report_path = report_writer.write_report("logs")
print(f"\n✅ All done! Markdown report saved to: {report_path}")