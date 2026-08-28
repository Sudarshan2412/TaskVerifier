#!/usr/bin/env python3
"""
audit_extraction.py
Summarizes a batch extract_target_source.py run so you know what needs a
human look before it goes anywhere near the dataset.

Usage:
  python3 extract_target_source.py $(cat all_ids.txt) > results.json
  python3 audit_extraction.py results.json
"""
import json, sys

# Rough plausibility bounds -- not a correctness check, just a "this is
# probably too short/long to be a real single-function extraction, look
# at it" flag.
MIN_PLAUSIBLE_CHARS = 40
MAX_PLAUSIBLE_CHARS = 6000

GOOD = "patch_line_lookup"
NEEDS_REVIEW = {"crash_state_function_match", "patch_hunk_context_fallback", "failed"}

def main(path):
    with open(path) as f:
        results = json.load(f)

    by_method = {}
    flagged = []

    for r in results:
        if "error" in r:
            flagged.append((r["cve_id"], "SCRIPT_ERROR", r["error"]))
            continue
        method = r.get("extraction_method", "unknown")
        by_method.setdefault(method, []).append(r["cve_id"])

        ts = r.get("target_source", "")
        ts_len = len(ts)

        reasons = []
        if method in NEEDS_REVIEW:
            reasons.append(f"method={method}")
        if ts_len < MIN_PLAUSIBLE_CHARS:
            reasons.append(f"too short ({ts_len} chars)")
        if ts_len > MAX_PLAUSIBLE_CHARS:
            reasons.append(f"unusually long ({ts_len} chars) -- confirm it's one coherent function")
        if "EXTRACTION_FAILED" in ts:
            reasons.append("hard failure")

        if reasons:
            flagged.append((r["cve_id"], method, "; ".join(reasons)))

    print(f"Total entries: {len(results)}\n")
    print("By extraction_method:")
    for method, ids in sorted(by_method.items(), key=lambda kv: -len(kv[1])):
        print(f"  {method:32s} {len(ids):3d}  {ids if len(ids) <= 6 else ids[:6] + ['...']}")

    print(f"\nFlagged for manual review ({len(flagged)}):")
    for cve_id, method, reason in flagged:
        print(f"  {cve_id:20s} [{method}] {reason}")

    if not flagged:
        print("  (none)")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 audit_extraction.py results.json", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])