"""Generate result plots for baseline vs verifier experiments."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


BUCKET_ORDER = ["short", "medium", "long"]


def _load_results(path: str) -> pd.DataFrame:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError(f"Expected list in {path}")
    frame = pd.DataFrame(records)
    if "success" not in frame.columns:
        raise ValueError(f"Missing 'success' column in {path}")
    return frame


def plot_success_by_bucket(baseline_path: str, verifier_path: str, out_dir: str) -> Path:
    baseline = _load_results(baseline_path)
    verifier = _load_results(verifier_path)

    buckets = [bucket for bucket in BUCKET_ORDER if bucket in set(baseline["poc_length_bucket"]).union(set(verifier["poc_length_bucket"]))]
    x = list(range(len(buckets)))

    b_rates = [baseline[baseline["poc_length_bucket"] == bucket]["success"].mean() for bucket in buckets]
    v_rates = [verifier[verifier["poc_length_bucket"] == bucket]["success"].mean() for bucket in buckets]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar([index - 0.2 for index in x], b_rates, 0.4, label="Baseline", color="#2E6F95")
    ax.bar([index + 0.2 for index in x], v_rates, 0.4, label="With verifier", color="#5B8E7D")
    ax.set_xticks(x)
    ax.set_xticklabels([bucket.title() for bucket in buckets])
    ax.set_ylabel("Success rate")
    ax.set_ylim(0, 1)
    ax.set_title("PoC Success Rate by Bucket")
    ax.legend()

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    figure_path = out_path / "success_by_bucket.png"
    fig.tight_layout()
    fig.savefig(figure_path, dpi=150)
    plt.close(fig)
    return figure_path


def plot_attempt_distribution(verifier_path: str, out_dir: str) -> Path:
    verifier = _load_results(verifier_path)
    successful = verifier[verifier["success"] == True]

    fig, ax = plt.subplots(figsize=(7, 4))
    if successful.empty:
        ax.text(0.5, 0.5, "No successful trials", ha="center", va="center")
        ax.set_axis_off()
    else:
        counts = successful["attempts"].value_counts().sort_index()
        ax.bar(counts.index.astype(str), counts.values, color="#B35C44")
        ax.set_xlabel("Attempts")
        ax.set_ylabel("Count")
        ax.set_title("Verifier: Attempts Needed for Successful Trials")

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    figure_path = out_path / "verifier_attempt_distribution.png"
    fig.tight_layout()
    fig.savefig(figure_path, dpi=150)
    plt.close(fig)
    return figure_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot experiment results")
    parser.add_argument("--baseline", required=True, help="Path to baseline result JSON")
    parser.add_argument("--verifier", required=True, help="Path to verifier result JSON")
    parser.add_argument("--out-dir", default="data/results/figures", help="Output directory for figures")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bucket_plot = plot_success_by_bucket(args.baseline, args.verifier, args.out_dir)
    attempts_plot = plot_attempt_distribution(args.verifier, args.out_dir)
    print(f"Saved {bucket_plot}")
    print(f"Saved {attempts_plot}")


if __name__ == "__main__":
    main()
