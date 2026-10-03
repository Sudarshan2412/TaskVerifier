#!/usr/bin/env python3
"""
validate_fuzz_targets.py — Stage 0 metadata pre-flight validator.

Cheap, deterministic, no LLM calls: for each CVE in your dataset, compares
the stored `fuzz_target` field against the `Fuzz Target: X` line in the raw
OSS-Fuzz report already embedded in ARVO-Meta's meta.json
(report.comments[0].content) -- ground truth from the original bug report.

This is the automated version of what caught arvo:64574's fuzz_target bug
by hand: the stored value was /out/jq_fuzz_parse, but the raw report said
"Fuzz Target: jq_fuzz_parse_extended" -- and no correct PoC will ever
reproduce a crash if the configured binary structurally can't reach the
vulnerable code path, no matter how good the extraction or the agent is.

Usage:
  python3 validate_fuzz_targets.py cybergym_subset.json
  python3 validate_fuzz_targets.py solved_cves_metadata.json

Requires ARVO-Meta cloned (same convention as extract_target_source.py --
self-heals via the same ensure_arvo_meta() if missing).
"""
import json
import os
import re
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ARVO_META = os.environ.get("ARVO_META", os.path.join(_SCRIPT_DIR, ".cache", "arvo-meta"))

_FUZZ_TARGET_RE = re.compile(r'Fuzz Target:\s*(\S+)')


def ensure_arvo_meta():
    meta_dir = os.path.join(ARVO_META, "archive_data", "meta")
    if os.path.isdir(meta_dir):
        return
    print(f"[setup] ARVO-Meta not found at {ARVO_META} -- cloning (one-time)...", file=sys.stderr)
    os.makedirs(os.path.dirname(ARVO_META.rstrip('/')) or ".", exist_ok=True)
    import subprocess
    subprocess.run(
        ["git", "clone", "--depth", "1", "https://github.com/n132/ARVO-Meta.git", ARVO_META],
        check=True, capture_output=True
    )


def load_meta(arvo_id):
    path = os.path.join(ARVO_META, "archive_data", "meta", f"{arvo_id}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def extract_real_fuzz_target(meta):
    """Pull the ground-truth fuzz target name straight from the raw OSS-Fuzz
    report text, if present. Returns None if the report doesn't have this
    field (some entries won't -- not every CVE's raw report includes it,
    and that's fine, it just means this check can't say anything either way)."""
    comments = meta.get("report", {}).get("comments", [])
    if not comments:
        return None
    content = comments[0].get("content", "")
    m = _FUZZ_TARGET_RE.search(content)
    return m.group(1) if m else None


def normalize(name):
    """Strip path prefix and compare bare binary names -- stored fuzz_target
    is usually '/out/foo', the raw report usually just says 'foo'."""
    return name.rstrip('/').split('/')[-1] if name else name


def main(dataset_path):
    ensure_arvo_meta()
    with open(dataset_path) as f:
        dataset = json.load(f)

    checked = 0
    mismatches = []
    no_report_data = []

    for entry in dataset:
        cve_id = entry.get("cve_id", "")
        if not cve_id.startswith("arvo:"):
            continue  # this check only applies to ARVO entries (oss-fuzz: ids have no matching meta.json here)
        arvo_id = cve_id.split(":", 1)[1]
        stored_target = entry.get("fuzz_target", "")
        if not stored_target:
            continue

        meta = load_meta(arvo_id)
        if meta is None:
            continue
        real_target = extract_real_fuzz_target(meta)
        if real_target is None:
            no_report_data.append(cve_id)
            continue

        checked += 1
        if normalize(stored_target) != normalize(real_target):
            mismatches.append({
                "cve_id": cve_id,
                "stored_fuzz_target": stored_target,
                "report_fuzz_target": real_target,
            })

    print(f"\nChecked {checked} entries with usable report data "
          f"({len(no_report_data)} skipped -- no 'Fuzz Target:' line in their raw report).\n")

    if mismatches:
        print(f"MISMATCHES FOUND ({len(mismatches)}):")
        for m in mismatches:
            print(f"  {m['cve_id']:20s} stored={m['stored_fuzz_target']!r:35s} report says={m['report_fuzz_target']!r}")
        print(
            "\nEach of these needs a fix: correct the fuzz_target field, "
            "and if target_source was extracted against the wrong assumption, re-check it "
            "with the arvo-source-extraction skill."
        )
    else:
        print("No mismatches found in the checked entries.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 validate_fuzz_targets.py <dataset.json>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])