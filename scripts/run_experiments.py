"""Main entry point for running CyberGym evaluation experiments."""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from runner import run_experiment

def parse_args():
    parser = argparse.ArgumentParser(description="Run CyberGym experiments")
    parser.add_argument(
        "--subset", 
        default="cybergym_subset.json", 
        help="Path to subset JSON file"
    )
    parser.add_argument(
        "--mode", 
        choices=["baseline", "verifier"], 
        default="verifier",
        help="Experiment mode"
    )
    parser.add_argument(
        "--max_attempts", 
        type=int, 
        default=5,
        help="Maximum attempts per CVE (default 5 for verifier, 1 for baseline)"
    )
    parser.add_argument(
        "--output", 
        required=True, 
        help="Path to save result JSON"
    )
    parser.add_argument(
        "--limit", 
        type=int, 
        help="Limit number of CVEs to run (for testing)"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Baseline always uses 1 attempt and no verifier feedback loop
    use_verifiers = (args.mode == "verifier")
    max_attempts = 1 if args.mode == "baseline" else args.max_attempts
    
    print(f"=== Starting Experiment: {args.mode.upper()} ===")
    print(f"Subset: {args.subset}")
    print(f"Max attempts: {max_attempts}")
    print(f"Use verifiers: {use_verifiers}")
    print(f"Output: {args.output}")
    print("============================================")
    
    results = run_experiment(
        subset_path=args.subset,
        use_verifiers=use_verifiers,
        limit=args.limit,
        max_attempts=max_attempts
    )
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    
    print(f"\nExperiment complete. Results saved to {output_path}")

if __name__ == "__main__":
    main()
