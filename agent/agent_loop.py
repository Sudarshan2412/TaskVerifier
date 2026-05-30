"""
agent_loop.py — Central retry loop for single-CVE vulnerability reproduction.
"""

import logging
import os
import time
import hashlib
from dataclasses import dataclass, field

from logger import NullStepLogger

from agent import llm_client
from agent.prompt_builder import (
    build_initial_prompt,
    build_feedback_prompt,
    load_few_shot_examples,
)
from agent.code_extractor import extract_code, ExtractionError
from agent.context_manager import ContextManager
from verifier import VerifierPipeline
from verifier.hallucination_detector import detect_hallucinations

logger = logging.getLogger(__name__)

INTER_ATTEMPT_SLEEP_SECONDS = float(os.environ.get("INTER_ATTEMPT_SLEEP_SECONDS", "0"))
FEW_SHOT_PATH = "few_shot_examples.json"


def _check_llm_client_has_history_support() -> None:
    try:
        if not hasattr(llm_client, "call_llm_with_history"):
            raise ImportError(
                "llm_client.py is missing call_llm_with_history(messages: list[dict]) -> str. "
                "Add it before running agent_loop.py."
            )
    except ImportError:
        raise


_check_llm_client_has_history_support()


@dataclass
class AgentResult:
    cve_id: str
    success: bool
    attempts: int
    final_poc: str
    failure_reason: str
    transcript: list[dict] = field(default_factory=list)
    hallucinated_symbols_per_attempt: list[list[str]] = field(default_factory=list)


def run_agent(
    cve_entry: dict,
    max_attempts: int = 5,
    few_shot_examples: list = None,
    step_logger=None,
) -> AgentResult:
    if few_shot_examples is None:
        few_shot_examples = load_few_shot_examples(FEW_SHOT_PATH)

    sl = step_logger or NullStepLogger()

    ctx = ContextManager()
    ctx.reset()
    verifier = VerifierPipeline()

    transcript = []
    hallucinated_per_attempt = []
    last_poc = ""
    last_feedback_text = ""
    last_hallucinated_symbols = []
    seen_poc_hashes: set[str] = set()

    cve_id = cve_entry.get("id") or cve_entry.get("cve_id", "unknown")
    logger.info(f"Starting agent loop for CVE {cve_id} with max_attempts={max_attempts}")

    for attempt in range(1, max_attempts + 1):
        logger.debug(f"CVE {cve_id}: Attempt {attempt}/{max_attempts}")
        sl.log_attempt_header(attempt, max_attempts)

        # ── PROMPT ───────────────────────────────────────────────────────────
        try:
            if attempt == 1:
                prompt = build_initial_prompt(cve_entry, few_shot_examples)
                sl.log_prompt_built("initial", len(prompt))
            else:
                prompt = build_feedback_prompt(
                    cve_entry=cve_entry,
                    feedback_text=last_feedback_text,
                    hallucinated_symbols=last_hallucinated_symbols,
                    previous_poc=last_poc,
                    attempt_number=attempt - 1
                )
                sl.log_prompt_built("feedback", len(prompt))
                # NEW: log what feedback is being sent so you can follow the loop
                sl.log_feedback_sent(last_feedback_text, len(last_feedback_text))
        except Exception as e:
            logger.error(f"CVE {cve_id}: Failed to build prompt: {e}")
            return AgentResult(
                cve_id=cve_id, success=False, attempts=attempt - 1,
                final_poc=last_poc, failure_reason="prompt_build_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )

        ctx.add_user_message(prompt)

        # ── LLM CALL ─────────────────────────────────────────────────────────
        llm_start = time.time()
        try:
            raw_response = llm_client.call_llm_with_history(ctx.get_history())
            llm_elapsed = time.time() - llm_start
            sl.log_llm_response(llm_elapsed, len(raw_response))
        except Exception as e:
            logger.error(f"CVE {cve_id}: Attempt {attempt} LLM call failed: {e}")
            transcript.append({
                "attempt": attempt, "prompt": prompt, "raw_response": "",
                "extracted_poc": "", "hallucinated_symbols": [],
                "verifier_status": "skip", "verifier_stage": "",
                "verifier_feedback": "", "fuzzer_output": "", "fuzzer_cmd": ""
            })
            return AgentResult(
                cve_id=cve_id, success=False, attempts=attempt,
                final_poc=last_poc, failure_reason="llm_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )

        ctx.add_assistant_message(raw_response)

        # ── CODE EXTRACTION ──────────────────────────────────────────────────
        try:
            poc_code = extract_code(raw_response)
            last_poc = poc_code
            sl.log_extraction(True, len(poc_code))
            
            poc_hash = hashlib.md5(poc_code.encode()).hexdigest()
            if poc_hash in seen_poc_hashes:
                # Model is spinning — force a different temperature on the next call
                logger.warning(f"CVE {cve_id}: Attempt {attempt}: LLM regenerated identical PoC. Forcing deviation.")
                last_feedback_text = (
                    "CRITICAL: You generated the exact same code as a previous attempt. "
                    "This is not acceptable. You MUST try a completely different approach — "
                    "different payload structure, different vulnerability trigger path, different format. "
                    "Do not repeat any previously tried approach."
                )
                transcript.append({
                    "attempt": attempt, "prompt": prompt, "raw_response": raw_response,
                    "extracted_poc": poc_code, "hallucinated_symbols": [],
                    "verifier_status": "skip_duplicate", "verifier_stage": "",
                    "verifier_feedback": last_feedback_text, "fuzzer_output": "", "fuzzer_cmd": ""
                })
                hallucinated_per_attempt.append([])
                continue
            seen_poc_hashes.add(poc_hash)
            
        except ExtractionError as e:
            sl.log_extraction(False, error=str(e))
            transcript.append({
                "attempt": attempt, "prompt": prompt, "raw_response": raw_response,
                "extracted_poc": "", "hallucinated_symbols": [],
                "verifier_status": "skip", "verifier_stage": "",
                "verifier_feedback": "", "fuzzer_output": "", "fuzzer_cmd": ""
            })
            hallucinated_per_attempt.append([])
            last_hallucinated_symbols = []
            last_feedback_text = (
                "Your response did not contain extractable C code. "
                "Output ONLY a single C program inside triple backticks (```c ... ```)."
            )
            if attempt < max_attempts:
                time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)
            continue

        # ── HALLUCINATION DETECTION ──────────────────────────────────────────
        try:
            hallucinated_symbols = detect_hallucinations(
                target_source_code=cve_entry.get("target_source", ""), poc_code=poc_code
            )
            last_hallucinated_symbols = hallucinated_symbols
            hallucinated_per_attempt.append(hallucinated_symbols)
            sl.log_hallucination(hallucinated_symbols)
        except Exception as e:
            logger.error(f"CVE {cve_id}: Hallucination detection error: {e}")
            hallucinated_symbols = []
            last_hallucinated_symbols = []
            hallucinated_per_attempt.append([])

        # ── VERIFIER ─────────────────────────────────────────────────────────
        try:
            result = verifier.verify(
                poc_code=poc_code,
                cve_entry=cve_entry,
                previous_feedback=last_feedback_text
            )
            logger.debug(f"CVE {cve_id}: Attempt {attempt} verifier status: {result.status}")

            v_details = result.details if hasattr(result, "details") else {}
            compile_ok  = v_details.get("compiler",  {}).get("success", True)
            compile_err = v_details.get("compiler",  {}).get("stderr",  "")
            exec_info   = v_details.get("execution", {})
            exec_ok     = exec_info.get("triggered", None)
            exec_msg    = exec_info.get("message",   "")
            san_info    = v_details.get("sanitizer", {})
            crash_type  = san_info.get("crash_type", "") if san_info else ""

            sl.log_verifier(
                compile_ok=compile_ok, exec_ok=exec_ok,
                crash_type=crash_type, compile_error=compile_err,
                exec_message=exec_msg,
            )

            # NEW: log docker execution detail if we got that far
            if exec_info:
                fuzzer_cmd = exec_info.get("fuzzer_cmd", "")
                fuzzer_out = exec_info.get("stderr", "") or exec_info.get("stdout", "")
                if fuzzer_cmd:
                    sl.log_docker_exec(
                        image=cve_entry.get("docker_image", ""),
                        fuzz_target=cve_entry.get("fuzz_target", ""),
                        exit_code=exec_info.get("exit_code", -1)
                    )
                if fuzzer_out:
                    sl.log_fuzzer_output(
                        stdout=exec_info.get("stdout", ""),
                        stderr=exec_info.get("stderr", "")
                    )

        except Exception as e:
            logger.error(f"CVE {cve_id}: Verifier raised exception: {e}")
            transcript.append({
                "attempt": attempt, "prompt": prompt, "raw_response": raw_response,
                "extracted_poc": poc_code, "hallucinated_symbols": hallucinated_symbols,
                "verifier_status": "error", "verifier_stage": "unknown",
                "verifier_feedback": str(e)[:500], "fuzzer_output": "", "fuzzer_cmd": ""
            })
            return AgentResult(
                cve_id=cve_id, success=False, attempts=attempt,
                final_poc=poc_code, failure_reason="verifier_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )

        last_feedback_text = result.feedback

        # ── TRANSCRIPT ENTRY ─────────────────────────────────────────────────
        exec_details = result.details.get("execution", {}) if hasattr(result, "details") else {}
        transcript.append({
            "attempt": attempt,
            "prompt": prompt,
            "raw_response": raw_response,
            "extracted_poc": poc_code,
            "hallucinated_symbols": hallucinated_symbols,
            "verifier_status": result.status,
            # BUG FIX: was result.details.get("stage","") which is always ""
            # now correctly inferred from which sub-stage was reached
            "verifier_stage": (
                "sanitizer"  if result.status == "crash"     else
                "execution"  if exec_details                 else
                "compiler"
            ),
            "verifier_feedback": result.feedback,
            # NEW: capture fuzzer output and command for the Markdown report
            "fuzzer_output": (
                exec_details.get("stderr", "") or exec_details.get("stdout", "")
            )[:800],
            "fuzzer_cmd": exec_details.get("fuzzer_cmd", ""),
        })

        # ── SUCCESS / INFRA ABORT ────────────────────────────────────────────
        if result.status == "crash":
            logger.info(f"CVE {cve_id}: SUCCESS on attempt {attempt}")
            sl.log_outcome(True, attempt)
            return AgentResult(
                cve_id=cve_id, success=True, attempts=attempt,
                final_poc=poc_code, failure_reason="",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )

        if result.status == "infra_fail":
            logger.error(f"CVE {cve_id}: Infrastructure failure on attempt {attempt}")
            sl.log_outcome(False, attempt, "verifier_infrastructure_failed")
            return AgentResult(
                cve_id=cve_id, success=False, attempts=attempt,
                final_poc=poc_code, failure_reason="verifier_infrastructure_failed",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )

        if attempt < max_attempts:
            time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)

    # ── ALL ATTEMPTS EXHAUSTED ────────────────────────────────────────────────
    logger.warning(f"CVE {cve_id}: FAILURE after {max_attempts} attempts")
    extraction_failed_all = all(e["extracted_poc"] == "" for e in transcript)
    failure_reason = (
        "extraction_failed_all_attempts" if extraction_failed_all
        else "max_attempts_reached"
    )
    sl.log_outcome(False, max_attempts, failure_reason)
    return AgentResult(
        cve_id=cve_id, success=False, attempts=max_attempts,
        final_poc=last_poc, failure_reason=failure_reason,
        transcript=transcript,
        hallucinated_symbols_per_attempt=hallucinated_per_attempt
    )