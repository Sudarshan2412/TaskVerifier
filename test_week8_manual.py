"""
test_week8_manual.py — Week 8 Task 1: Manual testing of agent_loop.py on 5 CVEs.

Runs agent_loop.py on 5 CVEs from cybergym_subset.json with different PoC size buckets.
Saves transcripts to logs/ and prints a summary table.
"""

import json
import os
import time
import logging
from pathlib import Path

from agent.agent_loop import run_agent

MAX_ATTEMPTS = int(os.environ.get("WEEK8_MAX_ATTEMPTS", "2"))

# Configure logging to see debug output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
TARGET_CVE_IDS = [c.strip() for c in os.environ.get("WEEK8_CVE_IDS", "").split(",") if c.strip()]

# ──────────────────────────────────────────────────────────────────────────────
# Step 1 — Load 5 CVEs from the subset
# ──────────────────────────────────────────────────────────────────────────────

def pick_test_cves(subset, n=2):
    """
    Pick n CVEs from subset, trying to get a mix of PoC sizes if bucket field exists.
    
    If no bucket field exists, just pick by index (0, 2, 4, 6, 8).
    """
    if not subset or len(subset) < n:
        return subset[:n]
    
    # Try to find bucket field name
    bucket_field = None
    for candidate in ["poc_length_bucket", "bucket", "poc_bucket", "length_bucket"]:
        if candidate in subset[0]:
            bucket_field = candidate
            logger.info(f"Found bucket field: {bucket_field}")
            break
    
    if bucket_field:
        # Try to pick: 1 short, 2 medium, 1 long, 1 any
        short = [c for c in subset if c.get(bucket_field) == "short"][:1]
        medium = [c for c in subset if c.get(bucket_field) == "medium"][:2]
        long_ = [c for c in subset if c.get(bucket_field) == "long"][:1]
        rest = [c for c in subset if c not in short + medium + long_][:1]
        selected = (short + medium + long_ + rest)[:n]
        
        if len(selected) == n:
            logger.info(
                f"Picked by bucket: {len(short)} short, {len(medium)} medium, {len(long_)} long, {len(rest)} other"
            )
            return selected
    
    # Fallback: pick by index
    logger.info("Bucket field not found or filtering didn't yield enough CVEs. Using index-based selection.")
    return [subset[i] for i in range(len(subset)) if i % 2 == 0][:n]


def select_test_cves(subset, n=2, explicit_ids=None):
    """
    Select CVEs either by explicit ID list or by the default picker.
    """
    if explicit_ids:
        explicit_set = set(explicit_ids)
        selected = [cve for cve in subset if cve.get("cve_id") in explicit_set]
        missing = [cve_id for cve_id in explicit_ids if cve_id not in {c.get("cve_id") for c in selected}]
        if missing:
            logger.warning(f"Requested CVEs not found in subset: {missing}")
        logger.info(f"Selected {len(selected)} CVEs by explicit ID list: {explicit_ids}")
        return selected

    return pick_test_cves(subset, n=n)


def _normalize_cve_entry(cve: dict) -> dict:
    """
    Normalize cybergym_subset.json entry to match agent_loop.py expectations.
    
    agent_loop.py expects: id, vuln_class, poc_bucket, sanitizer_type, target_source, crash_description
    cybergym_subset.json provides: cve_id, vuln_class, sanitizer_type, crash_description, ...
    
    This function creates a normalized entry by mapping fields and adding defaults where needed.
    """
    normalized = {}
    
    # Map cve_id -> id
    normalized["id"] = cve.get("cve_id", "UNKNOWN")
    
    # Copy fields that match
    normalized["vuln_class"] = cve.get("vuln_class", "other")
    normalized["sanitizer_type"] = cve.get("sanitizer_type", "unknown")
    normalized["crash_description"] = cve.get("crash_description", "")
    
    # poc_bucket: try to find it in various forms
    normalized["poc_bucket"] = cve.get("poc_bucket") or cve.get("poc_length_bucket", "unknown")
    
    # target_source: This field doesn't exist in cybergym_subset.json
    # For now, use a placeholder — the verifier will need the actual source code
    # In a real scenario, this would be loaded from the docker image or source path
    normalized["target_source"] = cve.get("target_source", "// Placeholder source code")
    
    return normalized


# Load subset
logger.info("Loading cybergym_subset.json...")
with open("cybergym_subset.json") as f:
    subset = json.load(f)

test_cves_raw = select_test_cves(subset, n=2, explicit_ids=TARGET_CVE_IDS)
logger.info(f"Selected {len(test_cves_raw)} CVEs for testing")

# Normalize entries to match agent_loop.py expectations
test_cves = [_normalize_cve_entry(cve) for cve in test_cves_raw]

# ──────────────────────────────────────────────────────────────────────────────
# Step 2 — Run the agent loop on each CVE
# ──────────────────────────────────────────────────────────────────────────────

results = []

for i, cve in enumerate(test_cves, start=1):
    cve_id = cve.get("id", "UNKNOWN")
    print(f"\n{'='*70}")
    print(f"CVE {i}/{len(test_cves)}: {cve_id}")
    print(f"Bucket: {cve.get('poc_bucket', 'unknown')}")
    print(f"Vuln class: {cve.get('vuln_class', 'unknown')}")
    print(f"{'='*70}")
    
    try:
        logger.info(f"Running agent for {cve_id}...")
        result = run_agent(cve_entry=cve, max_attempts=MAX_ATTEMPTS)
        
        # Convert AgentResult dataclass to dict for JSON serialization
        result_dict = {
            "cve_id": result.cve_id,
            "success": result.success,
            "attempts": result.attempts,
            "final_poc": result.final_poc,
            "failure_reason": result.failure_reason,
            "transcript": result.transcript,
            "hallucinated_symbols_per_attempt": result.hallucinated_symbols_per_attempt,
        }
        result_dict["cve_id"] = cve_id
        results.append(result_dict)
        
        status = "✓ SUCCESS" if result.success else "✗ FAILED"
        print(f"  {status} in {result.attempts} attempt(s)")
        
    except Exception as e:
        logger.exception(f"ERROR running agent for {cve_id}: {e}")
        results.append({
            "cve_id": cve_id,
            "success": False,
            "attempts": 0,
            "transcript": [],
            "error": str(e),
            "hallucinated_symbols_per_attempt": []
        })
        print(f"  ✗ ERROR: {e}")
    
    # Sleep between runs to avoid rate limiting
    if i < len(test_cves):
        logger.info(f"Sleeping 5s before next CVE...")
        time.sleep(5)

# ──────────────────────────────────────────────────────────────────────────────
# Step 3 — Save transcripts to logs/
# ──────────────────────────────────────────────────────────────────────────────

os.makedirs("logs", exist_ok=True)

for r in results:
    safe_id = r["cve_id"].replace("/", "_").replace(":", "_").replace("-", "_")
    fname = f"logs/week8_manual_{safe_id}.json"
    with open(fname, "w") as f:
        json.dump(r, f, indent=2)
    print(f"  Saved: {fname}")

# ──────────────────────────────────────────────────────────────────────────────
# Step 4 — Print summary table
# ──────────────────────────────────────────────────────────────────────────────

print("\n" + "="*90)
print("WEEK 8 MANUAL TEST SUMMARY")
print("="*90)
print(f"{'CVE ID':<30} {'Result':<10} {'Attempts':<12} {'Halluc':<10} {'Fail Mode'}")
print("-"*90)

for r in results:
    success_str = "PASS" if r.get("success") else "FAIL"
    attempts = r.get("attempts", 0)
    transcript = r.get("transcript", [])
    error = r.get("error", "")
    
    # Check if hallucination was flagged in any attempt
    halluc_flagged = any(
        len(turn.get("hallucinated_symbols", [])) > 0
        for turn in transcript
        if isinstance(turn, dict)
    )
    
    # Guess failure mode from last transcript entry
    fail_mode = "—"
    if not r.get("success"):
        if transcript and isinstance(transcript[-1], dict):
            last = transcript[-1]
            vr = last.get("verifier_status", "")
            
            if "infra" in vr.lower():
                fail_mode = "verifier_infra_error"
            elif "compile" in vr.lower():
                fail_mode = "compile_error_loop"
            elif "no_crash" in vr.lower():
                fail_mode = "no_crash"
            elif "crash" not in vr.lower() and vr:
                fail_mode = vr
            
            if halluc_flagged and not fail_mode.startswith("compile"):
                fail_mode = "hallucination_loop"
        
        if error:
            fail_mode = "agent_error"
    
    halluc_str = "Yes" if halluc_flagged else "—"
    print(f"{r['cve_id']:<30} {success_str:<10} {attempts:<12} {halluc_str:<10} {fail_mode}")

print("="*90)
passed = sum(1 for r in results if r.get("success"))
total = len(results)
print(f"Result: {passed}/{total} passed")
print("="*90)

# ──────────────────────────────────────────────────────────────────────────────
# Save summary to file
# ──────────────────────────────────────────────────────────────────────────────

summary_lines = []
summary_lines.append("WEEK 8 MANUAL TEST SUMMARY")
summary_lines.append("="*90)
summary_lines.append(f"{'CVE ID':<30} {'Result':<10} {'Attempts':<12} {'Halluc':<10} {'Fail Mode'}")
summary_lines.append("-"*90)

for r in results:
    success_str = "PASS" if r.get("success") else "FAIL"
    attempts = r.get("attempts", 0)
    transcript = r.get("transcript", [])
    halluc_flagged = any(
        len(turn.get("hallucinated_symbols", [])) > 0
        for turn in transcript if isinstance(turn, dict)
    )
    
    fail_mode = "—"
    if not r.get("success"):
        if transcript and isinstance(transcript[-1], dict):
            last = transcript[-1]
            vr = last.get("verifier_status", "")
            if "infra" in vr.lower():
                fail_mode = "verifier_infra_error"
            elif "compile" in vr.lower():
                fail_mode = "compile_error_loop"
            elif "no_crash" in vr.lower():
                fail_mode = "no_crash"
            elif vr:
                fail_mode = vr
            if halluc_flagged:
                fail_mode = "hallucination_loop"
        if r.get("error"):
            fail_mode = "agent_error"
    
    halluc_str = "Yes" if halluc_flagged else "—"
    summary_lines.append(f"{r['cve_id']:<30} {success_str:<10} {attempts:<12} {halluc_str:<10} {fail_mode}")

summary_lines.append("="*90)
summary_lines.append(f"Result: {passed}/{total} passed")

with open("logs/week8_summary.txt", "w") as f:
    f.write("\n".join(summary_lines))

print(f"\nSummary saved to logs/week8_summary.txt")
print("\nDone! Check logs/ directory for detailed transcripts.")
