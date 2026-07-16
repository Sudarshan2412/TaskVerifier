"""Compute aggregate experiment metrics for baseline vs verifier runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

REQUIRED_COLUMNS = [
    "task_id",
    "poc_length_bucket",
    "vuln_class",
    "success",
    "attempts",
]


def load_results(path: str) -> pd.DataFrame:
    """Load JSON results into a validated DataFrame."""
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError(f"Expected a list of result records in {path}")

    frame = pd.DataFrame(records)
    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing required columns in {path}: {missing}")

    frame["success"] = frame["success"].astype(bool)
    frame["attempts"] = frame["attempts"].astype(int)
    return frame


def _bucket_rows(baseline: pd.DataFrame, verifier: pd.DataFrame) -> list[dict[str, Any]]:
    bucket_order = ["short", "medium", "long"]
    discovered = sorted(set(baseline["poc_length_bucket"]).union(set(verifier["poc_length_bucket"])))
    ordered = [bucket for bucket in bucket_order if bucket in discovered] + [bucket for bucket in discovered if bucket not in bucket_order]

    rows: list[dict[str, Any]] = []
    for bucket in ordered:
        b_rate = baseline[baseline["poc_length_bucket"] == bucket]["success"].mean()
        v_rate = verifier[verifier["poc_length_bucket"] == bucket]["success"].mean()
        rows.append(
            {
                "bucket": bucket,
                "baseline": float(b_rate) if pd.notna(b_rate) else 0.0,
                "verifier": float(v_rate) if pd.notna(v_rate) else 0.0,
                "delta": float(v_rate - b_rate) if pd.notna(v_rate) and pd.notna(b_rate) else 0.0,
            }
        )
    return rows


def _class_rows(baseline: pd.DataFrame, verifier: pd.DataFrame) -> list[dict[str, Any]]:
    classes = sorted(set(baseline["vuln_class"]).union(set(verifier["vuln_class"])))
    rows: list[dict[str, Any]] = []
    for vuln_class in classes:
        b_rate = baseline[baseline["vuln_class"] == vuln_class]["success"].mean()
        v_rate = verifier[verifier["vuln_class"] == vuln_class]["success"].mean()
        rows.append(
            {
                "vuln_class": vuln_class,
                "baseline": float(b_rate) if pd.notna(b_rate) else 0.0,
                "verifier": float(v_rate) if pd.notna(v_rate) else 0.0,
                "delta": float(v_rate - b_rate) if pd.notna(v_rate) and pd.notna(b_rate) else 0.0,
            }
        )
    return rows


def compute_all(baseline_path: str, verifier_path: str) -> dict[str, Any]:
    """Compute overall, bucket, class, and attempts-to-success metrics."""
    baseline = load_results(baseline_path)
    verifier = load_results(verifier_path)

    baseline_rate = float(baseline["success"].mean())
    verifier_rate = float(verifier["success"].mean())

    successful = verifier[verifier["success"] == True]
    attempts_distribution = (
        successful["attempts"].value_counts().sort_index().to_dict() if not successful.empty else {}
    )

    return {
        "overall": {
            "baseline": baseline_rate,
            "verifier": verifier_rate,
            "delta": verifier_rate - baseline_rate,
        },
        "by_bucket": _bucket_rows(baseline, verifier),
        "by_vuln_class": _class_rows(baseline, verifier),
        "verifier_attempts_to_success": {
            "mean_attempts": float(successful["attempts"].mean()) if not successful.empty else 0.0,
            "distribution": {str(key): int(value) for key, value in attempts_distribution.items()},
        },
    }


def print_report(summary: dict[str, Any]) -> None:
    """Print a concise human-readable metrics report."""
    overall = summary["overall"]
    print("=== OVERALL SUCCESS RATES ===")
    print(f"Baseline: {overall['baseline']:.1%}")
    print(f"Verifier: {overall['verifier']:.1%}")
    print(f"Delta:    {overall['delta']:+.1%}")

    print("\n=== BY POC BUCKET ===")
    for row in summary["by_bucket"]:
        print(
            f"{row['bucket']:8s} baseline={row['baseline']:.1%} "
            f"verifier={row['verifier']:.1%} delta={row['delta']:+.1%}"
        )

    print("\n=== BY VULNERABILITY CLASS ===")
    for row in summary["by_vuln_class"]:
        print(
            f"{row['vuln_class']:20s} baseline={row['baseline']:.1%} "
            f"verifier={row['verifier']:.1%} delta={row['delta']:+.1%}"
        )

    print("\n=== ITERATIONS TO SUCCESS (VERIFIER) ===")
    attempts = summary["verifier_attempts_to_success"]
    print(f"Mean attempts: {attempts['mean_attempts']:.2f}")
    print(f"Distribution: {attempts['distribution']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute experiment metrics")
    parser.add_argument("--baseline", required=True, help="Path to baseline result JSON")
    parser.add_argument("--verifier", required=True, help="Path to verifier result JSON")
    parser.add_argument("--out", help="Optional path to save JSON summary")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = compute_all(args.baseline, args.verifier)
    print_report(summary)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\nSaved summary to {out_path}")


if __name__ == "__main__":
    main()
