# select_subset.py
"""
Stratified subset selection from CyberGym via HuggingFace API.
Buckets by vulnerability description length as PoC length proxy.
Balances across vuln classes: buffer_overflow, use_after_free,
integer_overflow
Output: cybergym_subset.json
"""

import json
import random
from pathlib import Path
from typing import Optional
from collections import Counter

OUTPUT_PATH = Path("./cybergym_subset.json")

# Bucket targets
BUCKETS = {
    "short":  {"target": 30, "max_chars": 200},
    "medium": {"target": 35, "max_chars": 400},
    "long":   {"target": 35, "max_chars": 99999},
}

# Keyword mapping to vuln class
VULN_CLASS_KEYWORDS = {
    "buffer_overflow": [
        "buffer overflow", "heap-buffer-overflow",
        "stack-buffer-overflow", "heap overflow", "stack overflow",
        "out-of-bounds write", "out-of-bounds read",
        "out-of-bounds access", "overread", "overwrite",
        "index-out-of-bounds", "global-buffer-overflow"
    ],
    "use_after_free": [
        "use-after-free", "use after free", "dangling pointer",
        "double free", "heap-use-after-free"
    ],
    "integer_overflow": [
        "integer overflow", "integer underflow", "divide-by-zero",
        "division by zero", "undefined behavior", "ubsan",
        "signed overflow", "unsigned overflow"
    ],
}


def classify_vuln(description: str) -> Optional[str]:
    desc_lower = description.lower()
    for cls, keywords in VULN_CLASS_KEYWORDS.items():
        for kw in keywords:
            if kw in desc_lower:
                return cls
    return None  # unclassified


def bucket_by_desc_length(description: str) -> str:
    n = len(description)
    if n < BUCKETS["short"]["max_chars"]:
        return "short"
    elif n < BUCKETS["medium"]["max_chars"]:
        return "medium"
    else:
        return "long"


def load_tasks() -> list[dict]:
    """Pull tasks from HuggingFace API — no download needed."""
    try:
        from datasets import load_dataset
    except ImportError:
        raise ImportError(
            "HuggingFace datasets library not found.\n"
            "Run: pip3 install datasets --break-system-packages"
        )

    print("Fetching tasks from HuggingFace API...")
    print("(This streams data — no large download required)\n")

    # Try 'train' split first, fall back to 'tasks' if needed
    try:
        ds = load_dataset(
            "sunblaze-ucb/cybergym",
            split="train",
            trust_remote_code=True
        )
    except Exception:
        try:
            ds = load_dataset(
                "sunblaze-ucb/cybergym",
                split="tasks",
                trust_remote_code=True
            )
        except Exception as e:
            raise RuntimeError(
                f"Could not load dataset from HuggingFace.\n"
                f"Error: {e}\n"
                f"Check your internet connection and that the dataset name is correct."
            )

    tasks = [dict(row) for row in ds]
    print(f"Successfully fetched {len(tasks)} tasks from HuggingFace.\n")
    return tasks


def infer_sanitizer(description: str) -> str:
    desc_lower = description.lower()
    if any(kw in desc_lower for kw in [
        "ubsan", "undefined behavior", "integer overflow",
        "divide-by-zero", "uninitialized"
    ]):
        return "ubsan"
    if any(kw in desc_lower for kw in [
        "use-after-free", "heap-buffer-overflow",
        "stack-buffer-overflow", "global-buffer-overflow",
        "heap overflow", "double free", "use-of-uninitialized"
    ]):
        return "asan"
    return "asan"  # default — most CyberGym bugs are ASan


def build_entry(task: dict, bucket: str, vuln_class: str) -> dict:
    """Build a standardised cybergym_subset.json entry."""
    task_id = task.get("task_id", "")
    source = "arvo" if task_id.startswith("arvo") else "oss-fuzz"
    parts = task_id.split(":")
    numeric_id = parts[1] if len(parts) > 1 else task_id

    return {
        "task_id":                  task_id,
        "source":                   source,
        "project_name":             task.get("project_name", ""),
        "project_language":         task.get("project_language", ""),
        "vulnerability_description": task.get("vulnerability_description", ""),
        "vuln_class":               vuln_class,
        "poc_length_bucket":        bucket,
        # Paths relative to cybergym_data/
        "source_code_path":         f"data/{source}/{numeric_id}/repo-vul.tar.gz",
        "fix_code_path":            f"data/{source}/{numeric_id}/repo-fix.tar.gz",
        "error_log_path":           f"data/{source}/{numeric_id}/error.txt",
        "description_path":         f"data/{source}/{numeric_id}/description.txt",
        "patch_path":               f"data/{source}/{numeric_id}/patch.diff",
        "difficulty_levels":        task.get("task_difficulty", {}),
        "sanitizer_type":           infer_sanitizer(task.get("vulnerability_description", "")),
    }


def select_subset(tasks: list[dict], seed: int = 42) -> list[dict]:
    random.seed(seed)

    # Organise tasks by (bucket, vuln_class)
    organised: dict[str, dict[str, list]] = {
        b: {
            "buffer_overflow": [],
            "use_after_free":  [],
            "integer_overflow": [],
            "other": []
        }
        for b in BUCKETS
    }

    for task in tasks:
        desc = task.get("vulnerability_description", "")
        if not desc:
            continue
        bucket = bucket_by_desc_length(desc)
        vuln_class = classify_vuln(desc) or "other"
        organised[bucket][vuln_class].append(task)

    # Print availability stats
    print("=== Task availability by bucket + vuln_class ===")
    for b, classes in organised.items():
        for cls, items in classes.items():
            print(f"  {b:8s} | {cls:20s} | {len(items):4d} tasks")

    selected = []

    for bucket_name, cfg in BUCKETS.items():
        target = cfg["target"]
        pool = organised[bucket_name]

        # Allocate evenly across the three main classes
        per_class = target // 3
        remainder = target % 3
        allocations = {
            "buffer_overflow":  per_class + (1 if remainder > 0 else 0),
            "use_after_free":   per_class + (1 if remainder > 1 else 0),
            "integer_overflow": per_class,
        }

        bucket_selected = []
        for cls, alloc in allocations.items():
            candidates = pool[cls]
            random.shuffle(candidates)
            picked = candidates[:alloc]
            if len(picked) < alloc:
                print(f"  ⚠️  {bucket_name}/{cls}: wanted {alloc}, only have {len(picked)}")
            for t in picked:
                bucket_selected.append(build_entry(t, bucket_name, cls))

        # Fill remaining slots with "other" class if needed
        actual = len(bucket_selected)
        if actual < target:
            gap = target - actual
            others = pool["other"]
            random.shuffle(others)
            for t in others[:gap]:
                bucket_selected.append(build_entry(t, bucket_name, "other"))

        print(f"\nBucket '{bucket_name}': selected {len(bucket_selected)} / {target} tasks")
        selected.extend(bucket_selected)

    return selected


def main():
    tasks = load_tasks()
    print(f"Total tasks in dataset: {len(tasks)}\n")

    subset = select_subset(tasks)

    output = {
        "meta": {
            "total_selected":  len(subset),
            "buckets":         {b: cfg["target"] for b, cfg in BUCKETS.items()},
            "description":     "Stratified subset for Vulnerability Reproduction Framework project",
            "selection_seed":  42,
        },
        "tasks": subset
    }

    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n✅ Written {len(subset)} entries to {OUTPUT_PATH}")

    # Summary
    bucket_counts = Counter(t["poc_length_bucket"] for t in subset)
    class_counts  = Counter(t["vuln_class"]         for t in subset)
    print("\n=== Final distribution ===")
    print("Buckets:", dict(bucket_counts))
    print("Classes:", dict(class_counts))


if __name__ == "__main__":
    main()
