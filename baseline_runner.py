"""
Baseline runner for one-shot generation without verifier feedback.

This script calls the LLM exactly once per CVE with no retry loop and no
hallucination feedback. Uses OpenRouter API with DeepSeek model.
Generates a ReportWriter log format.
"""

import json
import os
import sys
import argparse
from pathlib import Path
from typing import Any
import requests
from dotenv import load_dotenv

from agent.prompt_builder import build_initial_prompt, load_few_shot_examples
from agent.code_extractor import extract_code, ExtractionError
from evaluator import evaluate
from logger import StepLogger, ReportWriter
from verifier.hallucination_detector import detect_hallucinations
from verifier import verify

# Load environment
load_dotenv()

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

        return data["choices"][0].get("message", {}).get("content", "").strip()

    except requests.RequestException as e:
        raise RuntimeError(f"OpenRouter API call failed: {e}")


def normalize_cve_entry(cve: dict[str, Any]) -> dict[str, Any]:
    normalized = {}
    normalized["id"] = cve.get("cve_id") or cve.get("id") or "UNKNOWN"
    normalized["vuln_class"] = cve.get("vuln_class", "other")
    normalized["sanitizer_type"] = cve.get("sanitizer_type", "unknown")
    normalized["crash_description"] = cve.get("crash_description", "")
    normalized["poc_bucket"] = cve.get("poc_bucket", "unknown")
    normalized["target_source"] = cve.get("target_source", "")
    return normalized


def run_baseline_trial(
    cve_entry: dict[str, Any],
    temperature: float = 0.6,
    few_shot_examples: list = None,
    step_logger: StepLogger = None
) -> dict[str, Any]:
    
    result = {
        "cve_id": cve_entry.get("id"),
        "bucket": cve_entry.get("poc_bucket"),
        "vuln_class": cve_entry.get("vuln_class", "unknown"),
        "passed": False,
        "temperature": temperature,
        "failure_reason": None,
        "final_poc": "",
        "transcript": [],
        "hallucinated_symbols_per_attempt": [[]]
    }

    transcript_entry = {
        "attempt": 1,
        "prompt": "",
        "raw_response": "",
        "extracted_poc": "",
        "hallucinated_symbols": [],
        "verifier_status": "",
        "verifier_stage": "",
        "verifier_feedback": ""
    }

    try:
        # 1. Prompt
        prompt = build_initial_prompt(cve_entry, few_shot_examples or [])
        transcript_entry["prompt"] = prompt
        if step_logger: step_logger.log_prompt_built("initial", len(prompt))

        # 2. LLM
        try:
            raw_response = call_llm(prompt, temperature)
            transcript_entry["raw_response"] = raw_response
            if step_logger: step_logger.log_llm_response(0, len(raw_response))
        except RuntimeError as e:
            result["failure_reason"] = "llm_error"
            transcript_entry["verifier_feedback"] = str(e)
            result["transcript"].append(transcript_entry)
            if step_logger: step_logger.log_outcome(False, 1, "llm_error")
            return result

        # 3. Extraction
        try:
            poc_code = extract_code(raw_response)
            transcript_entry["extracted_poc"] = poc_code
            result["final_poc"] = poc_code
            if step_logger: step_logger.log_extraction(True, len(poc_code))
        except ExtractionError as e:
            result["failure_reason"] = "no_code_extracted"
            transcript_entry["verifier_feedback"] = str(e)
            result["transcript"].append(transcript_entry)
            if step_logger: 
                step_logger.log_extraction(False, 0, str(e))
                step_logger.log_outcome(False, 1, "no_code_extracted")
            return result

        # 4. Hallucination Check
        target_source = cve_entry.get("target_source", "")
        if target_source:
            hallucs = detect_hallucinations(target_source, poc_code)
            transcript_entry["hallucinated_symbols"] = hallucs
            result["hallucinated_symbols_per_attempt"] = [hallucs]
            if step_logger: step_logger.log_hallucination(hallucs)
        else:
            if step_logger: step_logger.log_hallucination([])

        # 5. Verify
        try:
            verifier_result = verify(poc_code, target_source)
            transcript_entry["verifier_status"] = verifier_result.status
            transcript_entry["verifier_feedback"] = verifier_result.feedback
            
            # Map verify output for step logger
            compile_ok = verifier_result.status != "compile_fail"
            exec_ok = True if verifier_result.status == "crash" else False if verifier_result.status == "no_crash" else None
            crash_type = cve_entry.get("crash_description", "") if verifier_result.status == "crash" else ""
            if step_logger:
                step_logger.log_verifier(compile_ok, exec_ok, crash_type, 
                                         compile_error=verifier_result.feedback if not compile_ok else "",
                                         exec_message=verifier_result.feedback if exec_ok is False else "")

            if verifier_result.status == "crash":
                expected_crash = cve_entry.get("crash_description", "")
                eval_result = evaluate(True, expected_crash, False, expected_crash)
                result["passed"] = eval_result["passed"]
                if not eval_result["passed"]:
                    result["failure_reason"] = "wrong_binary_crashed"
            elif verifier_result.status == "compile_fail":
                result["failure_reason"] = "compile_error"
            elif verifier_result.status == "no_crash":
                result["failure_reason"] = "no_crash"
            elif verifier_result.status == "infra_fail":
                result["failure_reason"] = "infrastructure_error"
            else:
                result["failure_reason"] = f"verifier_{verifier_result.status}"

        except Exception as e:
            result["failure_reason"] = "verifier_error"
            transcript_entry["verifier_feedback"] = str(e)
            if step_logger: step_logger.log_verifier(False, compile_error=str(e))

        result["transcript"].append(transcript_entry)
        if step_logger: step_logger.log_outcome(result["passed"], 1, result["failure_reason"] or "")
        return result

    except Exception as e:
        result["failure_reason"] = "unexpected_error"
        transcript_entry["verifier_feedback"] = str(e)
        result["transcript"].append(transcript_entry)
        if step_logger: step_logger.log_outcome(False, 1, "unexpected_error")
        return result


def main():
    parser = argparse.ArgumentParser(description="Baseline runner (one-shot)")
    parser.add_argument("--temperature", type=float, default=0.6)
    parser.add_argument("--dataset", type=str, default="cybergym_subset.json")
    parser.add_argument("--output", type=str, default="logs/baseline_results.json")
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"[ERROR] Dataset not found: {dataset_path}")
        sys.exit(1)

    with open(dataset_path) as f:
        cve_entries = json.load(f)

    few_shot_examples = load_few_shot_examples("few_shot_examples.json")
    
    # Initialize Loggers
    step_logger = StepLogger()
    report_writer = ReportWriter(max_attempts=1)
    
    step_logger.log_run_header(len(cve_entries), 1)

    results = []
    
    for i, cve in enumerate(cve_entries, start=1):
        cve_id = cve.get("cve_id") or cve.get("id") or f"CVE_{i}"
        normalized_cve = normalize_cve_entry(cve)
        
        step_logger.log_cve_header(i, len(cve_entries), cve_id, normalized_cve["poc_bucket"], normalized_cve["vuln_class"])
        step_logger.log_attempt_header(1, 1)
        
        result = run_baseline_trial(normalized_cve, args.temperature, few_shot_examples, step_logger=step_logger)
        results.append(result)

        report_writer.add_cve_result(
            cve_id=result["cve_id"],
            bucket=result["bucket"],
            vuln_class=result["vuln_class"],
            success=result["passed"],
            attempts=1,
            failure_reason=result["failure_reason"] or "",
            final_poc=result["final_poc"],
            transcript=result["transcript"],
            hallucinated_symbols_per_attempt=result["hallucinated_symbols_per_attempt"]
        )

    # Write old summary json
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    # Write new report
    report_path = report_writer.write_report("logs")
    print(f"\n[INFO] Baseline results written to {output_path}")
    print(f"[INFO] Markdown report written to {report_path}")

if __name__ == "__main__":
    main()
