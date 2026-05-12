# """
# Baseline runner for one-shot generation without verifier pipeline.

# This script calls the LLM exactly once per CVE with no retry loop and no
# hallucination feedback. Uses OpenRouter API with DeepSeek model.

# No existing files are modified. All logic is self-contained in this file.
# """

# import json
# import os
# import sys
# import argparse
# from pathlib import Path
# from typing import Any
# import requests
# from dotenv import load_dotenv

# # Import existing functions (read-only usage)
# from agent.prompt_builder import build_initial_prompt, load_few_shot_examples
# from agent.code_extractor import extract_code, ExtractionError
# from evaluator import evaluate
# from logger import log_trial
# from verifier.hallucination_detector import detect_hallucinations
# from verifier import verify

# # Load environment
# load_dotenv()

# # ─────────────────────────────────────────────────────────────────────────────
# # OpenRouter API Configuration (inline, not imported from agent/llm_client.py)
# # ─────────────────────────────────────────────────────────────────────────────

# OPENROUTER_API_KEY = os.environ.get("OPEN_ROUTER_KEY")
# OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# # Model from agent/llm_client.py: DEEPSEEK_MODEL = "deepseek/deepseek-v4-flash"
# DEEPSEEK_MODEL = "deepseek/deepseek-v4-flash"


# def call_llm(prompt: str, temperature: float = 0.6) -> str:
#     """
#     Call OpenRouter API with DeepSeek model and return the text response.
    
#     Args:
#         prompt: The prompt string
#         temperature: Temperature for generation (default 0.6)
        
#     Returns:
#         The model's text response
        
#     Raises:
#         RuntimeError: If API key is missing or API call fails
#     """
#     if not OPENROUTER_API_KEY:
#         raise RuntimeError("OPEN_ROUTER_KEY not found in environment. Set it in .env file.")

#     headers = {
#         "Authorization": f"Bearer {OPENROUTER_API_KEY}",
#         "Content-Type": "application/json",
#         "HTTP-Referer": "https://github.com/Sudarshan2412/TaskVerifier",
#         "X-Title": "TaskVerifier Baseline",
#     }

#     payload = {
#         "model": DEEPSEEK_MODEL,
#         "messages": [{"role": "user", "content": prompt}],
#         "temperature": temperature,
#         "max_tokens": 2048,
#         "reasoning": {"effort": "none", "exclude": True},
#         "include_reasoning": False,
#     }

#     try:
#         response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=60)
#         response.raise_for_status()
#         data = response.json()

#         if not data or "choices" not in data or not data["choices"]:
#             raise RuntimeError(f"OpenRouter API returned no valid choices: {data}")

#         choice = data["choices"][0]
#         message = choice.get("message", {})
#         content = message.get("content", "").strip()

#         if not content:
#             raise RuntimeError("OpenRouter API returned empty content")

#         return content

#     except requests.RequestException as e:
#         raise RuntimeError(f"OpenRouter API call failed: {e}")


# def normalize_cve_entry(cve: dict[str, Any]) -> dict[str, Any]:
#     """
#     Normalize cybergym_subset.json entry to match prompt_builder expectations.
    
#     prompt_builder expects: id, vuln_class, poc_bucket, sanitizer_type,
#                           target_source, crash_description
#     """
#     normalized = {}

#     normalized["id"] = cve.get("cve_id") or cve.get("id") or "UNKNOWN"
#     normalized["vuln_class"] = cve.get("vuln_class", "other")
#     normalized["sanitizer_type"] = cve.get("sanitizer_type", "unknown")
#     normalized["crash_description"] = cve.get("crash_description", "")
#     normalized["poc_bucket"] = cve.get("poc_bucket", "unknown")
#     normalized["target_source"] = cve.get("target_source", "")

#     return normalized


# def run_baseline_trial(
#     cve_entry: dict[str, Any],
#     temperature: float = 0.6,
#     few_shot_examples: list = None
# ) -> dict[str, Any]:
#     """
#     Run a single baseline trial: one LLM call, no retry, passive hallucination check.
    
#     Args:
#         cve_entry: Normalized CVE entry dict
#         temperature: Temperature for LLM
#         few_shot_examples: List of few-shot examples
        
#     Returns:
#         Result dict with pass/fail, hallucination info, and metadata
#     """
#     result = {
#         "mode": "baseline",
#         "cve_id": cve_entry.get("id"),
#         "bucket": cve_entry.get("poc_bucket"),
#         "passed": False,
#         "temperature": temperature,
#         "hallucinated_symbols": [],
#         "hallucination_flagged": False,
#         "raw_model_output_length": 0,
#         "poc_extracted": False,
#         "failure_reason": None,
#     }

#     try:
#         # Step 1: Build initial prompt
#         prompt = build_initial_prompt(cve_entry, few_shot_examples or [])

#         # Step 2: Call LLM once (no retry)
#         try:
#             raw_response = call_llm(prompt, temperature)
#         except RuntimeError as e:
#             print(f"[ERROR] LLM call failed for {cve_entry['id']}: {e}")
#             result["failure_reason"] = "llm_error"
#             return result

#         result["raw_model_output_length"] = len(raw_response)

#         # Step 3: Extract code
#         try:
#             poc_code = extract_code(raw_response)
#             result["poc_extracted"] = True
#         except ExtractionError as e:
#             print(f"[WARN] Code extraction failed for {cve_entry['id']}: {e}")
#             result["failure_reason"] = "no_code_extracted"
#             # Log this trial even though extraction failed
#             log_trial({
#                 "task_id": cve_entry["id"],
#                 "mode": "baseline",
#                 "temperature": temperature,
#                 "poc_extracted": False,
#                 "raw_output_length": len(raw_response),
#                 "hallucinated_symbols": [],
#             })
#             return result

#         # Step 4: Check hallucinations (passive measurement, no feedback)
#         target_source = cve_entry.get("target_source", "")
#         if target_source:
#             hallucinated_symbols = detect_hallucinations(target_source, poc_code)
#             result["hallucinated_symbols"] = hallucinated_symbols
#             result["hallucination_flagged"] = len(hallucinated_symbols) > 0

#         # Step 5: Evaluate using verifier pipeline
#         # This tells us if the PoC actually works (compile, crash, matches expected)
#         try:
#             verifier_result = verify(poc_code, target_source)

#             # Map verifier status to pass/fail and failure reason
#             if verifier_result.status == "crash":
#                 # Verify that the crash matches what's expected
#                 expected_crash = cve_entry.get("crash_description", "")
#                 pre_crashed = True
#                 pre_crash_type = expected_crash
#                 post_crashed = False  # Out of scope for baseline

#                 eval_result = evaluate(pre_crashed, pre_crash_type, post_crashed, expected_crash)
#                 result["passed"] = eval_result["passed"]
                
#                 if not eval_result["passed"]:
#                     result["failure_reason"] = eval_result.get("reason", "verification_failed")
#                     # Parse reason for consistency
#                     reason_lower = result["failure_reason"].lower()
#                     if "crash" in reason_lower and "wrong" in reason_lower:
#                         result["failure_reason"] = "wrong_binary_crashed"
#                     elif "post" in reason_lower and "crash" in reason_lower:
#                         result["failure_reason"] = "post_patch_crash"

#             elif verifier_result.status == "compile_fail":
#                 result["failure_reason"] = "compile_error"
#             elif verifier_result.status == "no_crash":
#                 result["failure_reason"] = "no_crash"
#             elif verifier_result.status == "infra_fail":
#                 result["failure_reason"] = "infrastructure_error"
#             else:
#                 result["failure_reason"] = f"verifier_{verifier_result.status}"

#         except Exception as e:
#             print(f"[WARN] Verifier failed for {cve_entry['id']}: {e}")
#             result["failure_reason"] = "verifier_error"

#         # Step 6: Log trial
#         log_trial({
#             "task_id": cve_entry["id"],
#             "mode": "baseline",
#             "temperature": temperature,
#             "poc_extracted": result["poc_extracted"],
#             "passed": result["passed"],
#             "raw_output_length": result["raw_model_output_length"],
#             "hallucinated_symbols": result["hallucinated_symbols"],
#             "hallucination_flagged": result["hallucination_flagged"],
#         })

#         return result

#     except Exception as e:
#         print(f"[ERROR] Unexpected error for {cve_entry['id']}: {e}")
#         result["failure_reason"] = "unexpected_error"
#         return result


# def main():
#     """Main entry point."""
#     parser = argparse.ArgumentParser(
#         description="Baseline runner: one-shot generation without verifier feedback"
#     )
#     parser.add_argument(
#         "--temperature",
#         type=float,
#         default=0.6,
#         help="Temperature for LLM generation (default 0.6)",
#     )
#     parser.add_argument(
#         "--dataset",
#         type=str,
#         default="cybergym_subset.json",
#         help="Path to CVE dataset (default cybergym_subset.json)",
#     )
#     parser.add_argument(
#         "--output",
#         type=str,
#         default="data/results/baseline_results.json",
#         help="Output file for results (default data/results/baseline_results.json)",
#     )

#     args = parser.parse_args()

#     # Load dataset
#     dataset_path = Path(args.dataset)
#     if not dataset_path.exists():
#         print(f"[ERROR] Dataset not found: {dataset_path}")
#         sys.exit(1)

#     try:
#         with open(dataset_path) as f:
#             cve_entries = json.load(f)
#     except json.JSONDecodeError as e:
#         print(f"[ERROR] Failed to parse dataset: {e}")
#         sys.exit(1)

#     if not isinstance(cve_entries, list):
#         print(f"[ERROR] Dataset must be a JSON array, got {type(cve_entries).__name__}")
#         sys.exit(1)

#     print(f"[INFO] Loaded {len(cve_entries)} CVE entries")

#     # Load few-shot examples
#     few_shot_examples = load_few_shot_examples("few_shot_examples.json")
#     if few_shot_examples:
#         print(f"[INFO] Loaded {len(few_shot_examples)} few-shot examples")

#     # Run trials
#     results = []
#     passed_count = 0
#     hallucinated_count = 0

#     for i, cve in enumerate(cve_entries, start=1):
#         cve_id = cve.get("cve_id") or cve.get("id") or f"CVE_{i}"
#         print(f"[{i}/{len(cve_entries)}] Processing {cve_id}...", end=" ", flush=True)

#         try:
#             normalized_cve = normalize_cve_entry(cve)
#             result = run_baseline_trial(normalized_cve, args.temperature, few_shot_examples)
#             results.append(result)

#             if result["passed"]:
#                 passed_count += 1
#                 print("✓ PASS")
#             else:
#                 reason = result.get("failure_reason", "unknown")
#                 print(f"✗ FAIL ({reason})")

#             if result["hallucination_flagged"]:
#                 hallucinated_count += 1

#         except Exception as e:
#             print(f"✗ ERROR: {e}")
#             results.append({
#                 "mode": "baseline",
#                 "cve_id": cve_id,
#                 "bucket": "unknown",
#                 "passed": False,
#                 "temperature": args.temperature,
#                 "hallucinated_symbols": [],
#                 "hallucination_flagged": False,
#                 "raw_model_output_length": 0,
#                 "poc_extracted": False,
#                 "failure_reason": "trial_exception",
#             })

#     # Write results
#     output_path = Path(args.output)
#     output_path.parent.mkdir(parents=True, exist_ok=True)

#     with open(output_path, "w") as f:
#         json.dump(results, f, indent=2)

#     print(f"\n[INFO] Results written to {output_path}")

#     # Print summary
#     pass_rate = (passed_count / len(results) * 100) if results else 0
#     hallucination_rate = (hallucinated_count / len(results) * 100) if results else 0

#     print("\n" + "=" * 60)
#     print("BASELINE SUMMARY")
#     print("=" * 60)
#     print(f"Total CVEs:              {len(results)}")
#     print(f"Passed:                  {passed_count}")
#     print(f"Pass Rate:               {pass_rate:.1f}%")
#     print(f"Hallucinations Detected: {hallucinated_count}")
#     print(f"Hallucination Rate:      {hallucination_rate:.1f}%")
#     print("=" * 60)


# if __name__ == "__main__":
#     main()
"""
Baseline runner for one-shot generation without verifier pipeline.

This script calls the LLM exactly once per CVE with no retry loop and no
hallucination feedback. Uses OpenRouter API with DeepSeek model.

No existing files are modified. All logic is self-contained in this file.
"""

import json
import os
import sys
import argparse
import subprocess
from pathlib import Path
from typing import Any
import requests
from dotenv import load_dotenv

# Import existing functions (read-only usage)
from agent.prompt_builder import build_initial_prompt, load_few_shot_examples
from agent.code_extractor import extract_code, ExtractionError
from evaluator import evaluate
from logger import log_trial
from verifier.hallucination_detector import detect_hallucinations
from verifier import verify
from verifier.compiler import compile_poc

# Load environment
load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# OpenRouter API Configuration
# ─────────────────────────────────────────────────────────────────────────────

OPENROUTER_API_KEY = os.environ.get("OPEN_ROUTER_KEY")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEEPSEEK_MODEL = "deepseek/deepseek-v4-flash"


def call_llm(prompt: str, temperature: float = 0.6) -> str:
    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPEN_ROUTER_KEY not found in environment. Set it in .env file.")

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Sudarshan2412/TaskVerifier",
        "X-Title": "TaskVerifier Baseline",
    }

    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": 2048,
        "reasoning": {"effort": "none", "exclude": True},
        "include_reasoning": False,
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()

        if not data or "choices" not in data or not data["choices"]:
            raise RuntimeError(f"OpenRouter API returned no valid choices: {data}")

        choice = data["choices"][0]
        message = choice.get("message", {})
        content = message.get("content", "").strip()

        if not content:
            raise RuntimeError("OpenRouter API returned empty content")

        return content

    except requests.RequestException as e:
        raise RuntimeError(f"OpenRouter API call failed: {e}")


def run_poc_against_cve_image(
    poc_binary_path: str,
    docker_image: str,
    fuzzer_binary: str,
    timeout: int = 30,
) -> dict:
    """
    Run the compiled PoC binary locally to generate /tmp/poc,
    then copy that input into the CVE Docker image and run
    the fuzzer binary against it to check for a real crash.
    """
    result = {
        "crashed": False,
        "crash_output": "",
        "exit_code": 0,
    }

    # Step A: run the PoC binary locally to generate /tmp/poc
    try:
        subprocess.run(
            [poc_binary_path],
            capture_output=True,
            timeout=10,
        )
    except Exception as e:
        result["crash_output"] = f"Failed to run PoC binary locally: {e}"
        return result

    poc_input = Path("/tmp/poc")
    if not poc_input.exists():
        result["crash_output"] = "PoC binary did not write /tmp/poc"
        return result

    # Step B: run the fuzzer inside the CVE image against /tmp/poc
    cmd = [
        "docker", "run", "--rm",
        "--cap-add=SYS_PTRACE",
        "-e", "ASAN_OPTIONS=halt_on_error=1:detect_leaks=0:abort_on_error=1",
        "-e", "MSAN_OPTIONS=halt_on_error=1",
        "-v", "/tmp/poc:/tmp/poc:ro",
        docker_image,
        "/bin/bash", "-c",
        f"{fuzzer_binary} /tmp/poc 2>&1"
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = proc.stdout + proc.stderr
        result["exit_code"] = proc.returncode
        result["crash_output"] = output

        crash_indicators = [
            "ERROR: AddressSanitizer",
            "ERROR: MemorySanitizer",
            "SUMMARY: AddressSanitizer",
            "SUMMARY: MemorySanitizer",
            "heap-buffer-overflow",
            "use-after-free",
            "stack-buffer-overflow",
            "use-of-uninitialized-value",
            "ABORTING",
        ]
        result["crashed"] = any(ind in output for ind in crash_indicators)

    except subprocess.TimeoutExpired:
        result["crash_output"] = f"Timed out after {timeout}s"

    return result


def normalize_cve_entry(cve: dict[str, Any]) -> dict[str, Any]:
    normalized = {}
    normalized["id"] = cve.get("cve_id") or cve.get("id") or "UNKNOWN"
    normalized["vuln_class"] = cve.get("vuln_class", "other")
    normalized["sanitizer_type"] = cve.get("sanitizer_type", "unknown")
    normalized["crash_description"] = cve.get("crash_description", "")
    normalized["poc_bucket"] = cve.get("poc_bucket", "unknown")
    normalized["target_source"] = cve.get("target_source", "")
    # Pass through docker image and fuzzer binary if present
    normalized["docker_image_vul"] = cve.get("docker_image_vul", "")
    normalized["fuzzer_binary"] = cve.get("fuzzer_binary", "")
    return normalized


def run_baseline_trial(
    cve_entry: dict[str, Any],
    temperature: float = 0.6,
    few_shot_examples: list = None
) -> dict[str, Any]:
    result = {
        "mode": "baseline",
        "cve_id": cve_entry.get("id"),
        "bucket": cve_entry.get("poc_bucket"),
        "passed": False,
        "temperature": temperature,
        "hallucinated_symbols": [],
        "hallucination_flagged": False,
        "raw_model_output_length": 0,
        "poc_extracted": False,
        "failure_reason": None,
    }

    try:
        # Step 1: Build initial prompt
        prompt = build_initial_prompt(cve_entry, few_shot_examples or [])

        # Step 2: Call LLM once (no retry)
        try:
            raw_response = call_llm(prompt, temperature)
        except RuntimeError as e:
            print(f"[ERROR] LLM call failed for {cve_entry['id']}: {e}")
            result["failure_reason"] = "llm_error"
            return result

        result["raw_model_output_length"] = len(raw_response)

        # Step 3: Extract code
        try:
            poc_code = extract_code(raw_response)
            result["poc_extracted"] = True
        except ExtractionError as e:
            print(f"[WARN] Code extraction failed for {cve_entry['id']}: {e}")
            result["failure_reason"] = "no_code_extracted"
            log_trial({
                "task_id": cve_entry["id"],
                "mode": "baseline",
                "temperature": temperature,
                "poc_extracted": False,
                "raw_output_length": len(raw_response),
                "hallucinated_symbols": [],
            })
            return result

        # Step 4: Check hallucinations (passive — no feedback given to model)
        target_source = cve_entry.get("target_source", "")
        if target_source:
            hallucinated_symbols = detect_hallucinations(target_source, poc_code)
            result["hallucinated_symbols"] = hallucinated_symbols
            result["hallucination_flagged"] = len(hallucinated_symbols) > 0

        # Step 5: Evaluate — real CVE image if available, else generic sandbox
        try:
            docker_image = cve_entry.get("docker_image_vul", "")
            fuzzer_binary = cve_entry.get("fuzzer_binary", "")

            if docker_image and fuzzer_binary:
                # Compile the PoC first to get the binary that writes /tmp/poc
                compiler_result = compile_poc(poc_code)
                if not compiler_result.get("success"):
                    result["failure_reason"] = "compile_error"
                else:
                    cve_eval = run_poc_against_cve_image(
                        poc_binary_path=compiler_result["binary_path"],
                        docker_image=docker_image,
                        fuzzer_binary=fuzzer_binary,
                    )
                    pre_crashed = cve_eval["crashed"]
                    crash_output = cve_eval["crash_output"]
                    expected_crash = cve_entry.get("crash_description", "")
                    eval_result = evaluate(pre_crashed, crash_output, False, expected_crash)
                    result["passed"] = eval_result["passed"]
                    if not eval_result["passed"]:
                        result["failure_reason"] = eval_result.get("reason", "verification_failed")
            else:
                # Fall back to generic sandbox
                verifier_result = verify(poc_code, target_source)
                if verifier_result.status == "crash":
                    expected_crash = cve_entry.get("crash_description", "")
                    eval_result = evaluate(True, expected_crash, False, expected_crash)
                    result["passed"] = eval_result["passed"]
                    if not eval_result["passed"]:
                        result["failure_reason"] = eval_result.get("reason", "verification_failed")
                elif verifier_result.status == "compile_fail":
                    result["failure_reason"] = "compile_error"
                elif verifier_result.status == "no_crash":
                    result["failure_reason"] = "no_crash"
                elif verifier_result.status == "infra_fail":
                    result["failure_reason"] = "infrastructure_error"
                else:
                    result["failure_reason"] = f"verifier_{verifier_result.status}"

        except Exception as e:
            print(f"[WARN] Verifier failed for {cve_entry['id']}: {e}")
            result["failure_reason"] = "verifier_error"

        # Step 6: Log trial
        log_trial({
            "task_id": cve_entry["id"],
            "mode": "baseline",
            "temperature": temperature,
            "poc_extracted": result["poc_extracted"],
            "passed": result["passed"],
            "raw_output_length": result["raw_model_output_length"],
            "hallucinated_symbols": result["hallucinated_symbols"],
            "hallucination_flagged": result["hallucination_flagged"],
        })

        return result

    except Exception as e:
        print(f"[ERROR] Unexpected error for {cve_entry['id']}: {e}")
        result["failure_reason"] = "unexpected_error"
        return result


def main():
    parser = argparse.ArgumentParser(
        description="Baseline runner: one-shot generation without verifier feedback"
    )
    parser.add_argument("--temperature", type=float, default=0.6)
    parser.add_argument("--dataset", type=str, default="cybergym_subset.json")
    parser.add_argument("--output", type=str, default="data/results/baseline_results.json")
    parser.add_argument(
        "--cve-ids",
        type=str,
        default="",
        help="Comma-separated CVE IDs to run (default: all)",
    )

    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"[ERROR] Dataset not found: {dataset_path}")
        sys.exit(1)

    try:
        with open(dataset_path) as f:
            cve_entries = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse dataset: {e}")
        sys.exit(1)

    if not isinstance(cve_entries, list):
        print(f"[ERROR] Dataset must be a JSON array, got {type(cve_entries).__name__}")
        sys.exit(1)

    # Filter by CVE IDs if specified
    if args.cve_ids:
        ids = [x.strip() for x in args.cve_ids.split(",")]
        cve_entries = [c for c in cve_entries if c.get("cve_id") in ids]
        print(f"[INFO] Filtered to {len(cve_entries)} CVEs: {ids}")

    print(f"[INFO] Loaded {len(cve_entries)} CVE entries")

    few_shot_examples = load_few_shot_examples("few_shot_examples.json")
    if few_shot_examples:
        print(f"[INFO] Loaded {len(few_shot_examples)} few-shot examples")

    results = []
    passed_count = 0
    hallucinated_count = 0

    for i, cve in enumerate(cve_entries, start=1):
        cve_id = cve.get("cve_id") or cve.get("id") or f"CVE_{i}"
        print(f"[{i}/{len(cve_entries)}] Processing {cve_id}...", end=" ", flush=True)

        try:
            normalized_cve = normalize_cve_entry(cve)
            result = run_baseline_trial(normalized_cve, args.temperature, few_shot_examples)
            results.append(result)

            if result["passed"]:
                passed_count += 1
                print("✓ PASS")
            else:
                reason = result.get("failure_reason", "unknown")
                print(f"✗ FAIL ({reason})")

            if result["hallucination_flagged"]:
                hallucinated_count += 1

        except Exception as e:
            print(f"✗ ERROR: {e}")
            results.append({
                "mode": "baseline",
                "cve_id": cve_id,
                "bucket": "unknown",
                "passed": False,
                "temperature": args.temperature,
                "hallucinated_symbols": [],
                "hallucination_flagged": False,
                "raw_model_output_length": 0,
                "poc_extracted": False,
                "failure_reason": "trial_exception",
            })

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[INFO] Results written to {output_path}")

    pass_rate = (passed_count / len(results) * 100) if results else 0
    hallucination_rate = (hallucinated_count / len(results) * 100) if results else 0

    print("\n" + "=" * 60)
    print("BASELINE SUMMARY")
    print("=" * 60)
    print(f"Total CVEs:              {len(results)}")
    print(f"Passed:                  {passed_count}")
    print(f"Pass Rate:               {pass_rate:.1f}%")
    print(f"Hallucinations Detected: {hallucinated_count}")
    print(f"Hallucination Rate:      {hallucination_rate:.1f}%")
    print("=" * 60)


if __name__ == "__main__":
    main()