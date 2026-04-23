"""Run a small baseline or verifier pilot using the local mock harness."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runner import run_experiment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pilot experiment with mock agent")
    parser.add_argument("--subset", required=True, help="Path to subset JSON file")
    parser.add_argument("--mode", choices=["baseline", "verifier"], default="baseline")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    use_verifiers = args.mode == "verifier"
    max_attempts = args.max_attempts if use_verifiers else 1

    results = run_experiment(
        subset_path=args.subset,
        use_verifiers=use_verifiers,
        limit=args.limit,
        max_attempts=max_attempts,
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Saved {len(results)} records to {out_path}")


if __name__ == "__main__":
    main()
