"""
agent_loop.py — Central retry loop for single-CVE vulnerability reproduction.
"""

import logging
import re
import os
import time
import hashlib
from dataclasses import dataclass, field

from logger import NullStepLogger

from agent import llm_client
from agent.prompt_builder import build_initial_prompt, build_feedback_prompt, build_iteration_prompt, load_few_shot_examples

from agent.code_extractor import extract_code, ExtractionError
from agent.context_manager import ContextManager
from agent.fact_accumulator import FactAccumulator
from agent.retry_memory import RetryMemory
from agent.iteration_models import IterationRecord
from agent.iteration_memory import IterationMemory
from agent.failure_tracker import FailurePatternTracker, categorize_failure
from agent.reasoning_enforcer import ReasoningEnforcer
from agent.validator_interface import ValidatorRegistry, StructuralValidator
from agent.feedback_normalizer import normalize_feedback

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



def _extract_approach_note(poc_code: str, feedback_text: str) -> str:
    """
    Extract a one-line structural note about what the PoC attempted.

    Used to populate RetryMemory with enough detail to distinguish attempts
    that all resulted in "no_crash" but tried different internal structures.

    Format-agnostic: uses generic patterns for operator values, version numbers,
    and format magic strings.  Does not contain any CVE-specific logic.

    Returns a string of up to 120 chars, or "" if nothing useful is found.
    """
    notes = []

    # Operator or opcode value mentioned in feedback
    # Match "operator ... 0x17" or "opcode ... 0x17" with up to 3 words between
    op_match = re.search(
        r'\bop(?:code|erator)?(?:\s+\S+){0,3}?\s+(0x[0-9a-fA-F]{1,4})\b',
        feedback_text, re.IGNORECASE
    )
    if not op_match:
        # Also match simple "op=0x17" or "operator 0x17"
        op_match = re.search(
            r'\bop(?:code|erator)?\s*=?\s*(0x[0-9a-fA-F]{1,4})\b',
            feedback_text, re.IGNORECASE
        )
    if op_match:
        notes.append(f"op={op_match.group(1)}")

    # Version number (CFF1/CFF2, table tag, format version integer)
    ver_match = re.search(
        r'\b(?:version|major|minor|tag)\s*([12]|0x[0-9a-fA-F]{4,8}|\'[\w ]{1,8}\')\b',
        feedback_text, re.IGNORECASE
    )
    if ver_match:
        notes.append(f"ver={ver_match.group(1)}")

    # 4-char format tags in single quotes (e.g. 'CFF ', 'OTTO', 'CFF2')
    tag_matches = re.findall(r"'([A-Z][A-Z0-9 ]{0,3})'", feedback_text)
    if tag_matches:
        notes.append(f"tags={'|'.join(tag_matches[:3])}")

    # Key structural keywords that distinguish approaches
    for kw in ("INDEX", "vstore", "FDSelect", "CharStrings", "PrivateDict", "GlyphTable",
               "endchar", "vsindex", "blend", "FDArray", "Charstring"):
        if re.search(r'\b' + kw + r'\b', feedback_text, re.IGNORECASE):
            notes.append(kw)
            break  # one keyword is enough for disambiguation

    if not notes:
        return ""
    return (", ".join(notes))[:120]


def run_agent(
    cve_entry: dict,
    max_attempts: int = 5,
    few_shot_examples: list = None,
    step_logger=None,
) -> AgentResult:
    if few_shot_examples is None:
        few_shot_examples = load_few_shot_examples(FEW_SHOT_PATH)

    sl = step_logger or NullStepLogger()

    CONTEXT_BUDGET = int(os.environ.get("CONTEXT_BUDGET_TOKENS", "800000"))
    ctx = ContextManager(max_tokens=CONTEXT_BUDGET)
    ctx.reset()
    SYSTEM_PROMPT = (
        "You are an expert vulnerability researcher specializing in PoC exploit generation. "
        "You are working in an iterative loop where you generate C code, receive compilation "
        "and execution feedback, and refine your approach. "
        "RULES:\n"
        "1. Output ONLY valid C code inside triple backticks. No prose outside the code block.\n"
        "2. The generator program MUST write its output to exactly '/tmp/poc'.\n"
        "3. Do NOT use hex byte arrays — use loops, fprintf, or fputc.\n"
        "4. Learn from ALL previous feedback in this conversation. Do not repeat mistakes.\n"
        "5. If the verifier says a symbol doesn't exist, DO NOT use it again.\n"
    )
    ctx.add_system_message(SYSTEM_PROMPT)
    verifier = VerifierPipeline()

    transcript = []
    hallucinated_per_attempt = []
    last_poc = ""
    last_feedback_text = ""
    last_hallucinated_symbols = []
    seen_poc_hashes: set[str] = set()
    fact_acc = FactAccumulator()  # accumulates confirmed facts across all retry attempts
    retry_mem = RetryMemory()  # legacy retry memory (retained for backward compatibility)
    
    # New architecture components
    iteration_mem = IterationMemory()
    failure_tracker = FailurePatternTracker()
    reasoning_enforcer = ReasoningEnforcer()
    validator_registry = ValidatorRegistry()
    validator_registry.register(StructuralValidator())
    
    last_normalized_feedback = None

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
                prompt = build_iteration_prompt(
                    cve_entry=cve_entry,
                    feedback_text=last_feedback_text,
                    hallucinated_symbols=last_hallucinated_symbols,
                    previous_poc=last_poc,
                    attempt_number=attempt - 1,
                    confirmed_facts=fact_acc.render(),
                    failed_approaches=retry_mem.render(),
                    normalized_feedback=last_normalized_feedback,
                    iteration_memory=iteration_mem,
                    failure_tracker=failure_tracker
                )
                sl.log_prompt_built("feedback", len(prompt))
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
        ctx.log_context_usage()

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
        ctx.log_context_usage()

        # ── REASONING ENFORCEMENT & EXTRACTION ────────────────────────────────
        structured_reasoning = None
        poc_code = ""
        
        if attempt > 1:
            structured_reasoning = reasoning_enforcer.extract_reasoning(raw_response)
            if not structured_reasoning:
                logger.warning(f"CVE {cve_id}: Attempt {attempt}: LLM response missing structured reasoning.")
                reasoning_issues = ["Response did not contain the required structured reasoning headings."]
            else:
                reasoning_issues = reasoning_enforcer.validate_reasoning(
                    structured_reasoning, iteration_mem, last_feedback_text
                )
            
            if reasoning_issues:
                # Wasted attempt! LLM failed structured reasoning validation.
                last_feedback_text = (
                    "CRITICAL REASONING VALIDATION FAILED:\n" + 
                    "\n".join(f"- {issue}" for issue in reasoning_issues) +
                    "\nYou MUST provide structured reasoning before code generation. Please try again."
                )
                
                last_normalized_feedback = {
                    "failure_category": "reasoning_validation_failed",
                    "failure_summary": "LLM failed structured reasoning validation.",
                    "diagnostics": [
                        {
                            "severity": "error",
                            "location": "reasoning",
                            "reason": last_feedback_text,
                            "possible_fix": "Follow the requested markdown heading structure and explicitly address prior errors."
                        }
                    ],
                    "raw_feedback": last_feedback_text
                }
                
                failure_tracker.record_failure("reasoning_validation_failed", attempt)
                iteration_mem.add_record(IterationRecord(
                    attempt=attempt,
                    verifier_status="reasoning_validation_failed",
                    failure_category="reasoning_validation_failed",
                    root_cause="",
                    strategy_description="Failed to provide valid structured reasoning",
                    fixes_attempted=[],
                    outcome="reasoning validation failed"
                ))
                
                transcript.append({
                    "attempt": attempt, "prompt": prompt, "raw_response": raw_response,
                    "extracted_poc": "", "hallucinated_symbols": [],
                    "verifier_status": "reasoning_validation_failed", "verifier_stage": "reasoning",
                    "verifier_feedback": last_feedback_text, "fuzzer_output": "", "fuzzer_cmd": ""
                })
                hallucinated_per_attempt.append([])
                
                if attempt < max_attempts:
                    time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)
                continue
                
            poc_code = reasoning_enforcer.extract_code_after_reasoning(raw_response)
        else:
            try:
                poc_code = extract_code(raw_response)
            except ExtractionError as e:
                poc_code = ""

        # ── STATIC VALIDATION ────────────────────────────────────────────────
        validation_results = []
        if poc_code:
            task_context = {"seen_poc_hashes": seen_poc_hashes}
            validation_results = validator_registry.run_all(poc_code, task_context)
            validation_failed = any(not vr.passed for vr in validation_results)
            
            if validation_failed:
                diags = []
                for vr in validation_results:
                    for diag in vr.diagnostics:
                        if not diag.passed:
                            diags.append(f"- [{diag.severity.upper()}] {diag.location}: {diag.reason}")
                
                last_feedback_text = (
                    "CRITICAL STATIC VALIDATION FAILED:\n" +
                    "\n".join(diags) +
                    "\nPlease fix your code structure."
                )
                
                last_normalized_feedback = {
                    "failure_category": "static_validation_failed",
                    "failure_summary": "Extracted code failed pluggable static validators.",
                    "diagnostics": [],
                    "raw_feedback": last_feedback_text
                }
                for vr in validation_results:
                    for diag in vr.diagnostics:
                        if not diag.passed:
                            last_normalized_feedback["diagnostics"].append({
                                "severity": diag.severity,
                                "location": diag.location,
                                "reason": diag.reason,
                                "possible_fix": diag.possible_fix
                            })
                
                failure_tracker.record_failure("static_validation_failed", attempt)
                iteration_mem.add_record(IterationRecord(
                    attempt=attempt,
                    verifier_status="static_validation_failed",
                    failure_category="static_validation_failed",
                    root_cause=structured_reasoning.root_cause if structured_reasoning else "",
                    strategy_description=structured_reasoning.validation_strategy if structured_reasoning else "First attempt",
                    fixes_attempted=structured_reasoning.planned_changes if structured_reasoning else [],
                    outcome="static validation failed"
                ))
                
                transcript.append({
                    "attempt": attempt, "prompt": prompt, "raw_response": raw_response,
                    "extracted_poc": poc_code, "hallucinated_symbols": [],
                    "verifier_status": "static_validation_failed", "verifier_stage": "validation",
                    "verifier_feedback": last_feedback_text, "fuzzer_output": "", "fuzzer_cmd": ""
                })
                hallucinated_per_attempt.append([])
                
                if attempt < max_attempts:
                    time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)
                continue

        # If code extraction failed completely
        if not poc_code:
            sl.log_extraction(False, error="Code block missing or malformed")
            
            last_feedback_text = (
                "Your response did not contain extractable C code. "
                "Output ONLY a single C program inside triple backticks (```c ... ```)."
            )
            
            last_normalized_feedback = {
                "failure_category": "extraction_failed",
                "failure_summary": "Did not contain extractable C code.",
                "diagnostics": [
                    {
                        "severity": "error",
                        "location": "extraction",
                        "reason": last_feedback_text,
                        "possible_fix": "Enclose C code block in triple backticks starting with ```c."
                    }
                ],
                "raw_feedback": last_feedback_text
            }
            
            failure_tracker.record_failure("extraction_failed", attempt)
            iteration_mem.add_record(IterationRecord(
                attempt=attempt,
                verifier_status="extraction_failed",
                failure_category="extraction_failed",
                root_cause="",
                strategy_description="No code block generated",
                fixes_attempted=[],
                outcome="code extraction failed"
            ))
            
            transcript.append({
                "attempt": attempt, "prompt": prompt, "raw_response": raw_response,
                "extracted_poc": "", "hallucinated_symbols": [],
                "verifier_status": "extraction_failed", "verifier_stage": "extraction",
                "verifier_feedback": last_feedback_text, "fuzzer_output": "", "fuzzer_cmd": ""
            })
            hallucinated_per_attempt.append([])
            
            if attempt < max_attempts:
                time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)
            continue

        # Register hash to seen
        poc_hash = hashlib.md5(poc_code.encode("utf-8", errors="ignore")).hexdigest()
        seen_poc_hashes.add(poc_hash)
        last_poc = poc_code
        sl.log_extraction(True, len(poc_code))

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
                previous_feedback=last_feedback_text,
                failed_approaches=retry_mem.render()
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
                "verifier_feedback": str(e)[:5000], "fuzzer_output": "", "fuzzer_cmd": ""
            })
            return AgentResult(
                cve_id=cve_id, success=False, attempts=attempt,
                final_poc=poc_code, failure_reason="verifier_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )

        # ── FEEDBACK NORMALIZATION & TRACKING ─────────────────────────────────
        last_normalized_feedback = normalize_feedback(result, validation_results)
        last_feedback_text = result.feedback
        
        fail_category = last_normalized_feedback["failure_category"]
        failure_tracker.record_failure(fail_category, attempt)

        # ── FACT ACCUMULATION ─────────────────────────────────────────────────
        fact_acc.update(last_feedback_text)

        # ── ITERATION / RETRY MEMORY ──────────────────────────────────────────
        if result.status != "crash":
            iteration_mem.add_record(IterationRecord(
                attempt=attempt,
                verifier_status=result.status,
                failure_category=fail_category,
                root_cause=structured_reasoning.root_cause if structured_reasoning else "Initial attempt analysis",
                strategy_description=structured_reasoning.validation_strategy if structured_reasoning else "First attempt",
                fixes_attempted=structured_reasoning.planned_changes if structured_reasoning else [],
                outcome=last_normalized_feedback["failure_summary"]
            ))

            first_line = last_feedback_text.split("\n")[0].strip()
            approach_summary = (first_line[:80] if first_line else last_feedback_text[:80])
            retry_mem.record(
                attempt=attempt,
                approach=approach_summary,
                reason=result.status,
            )

        # ── TRANSCRIPT ENTRY ─────────────────────────────────────────────────
        exec_details = result.details.get("execution", {}) if hasattr(result, "details") else {}
        transcript.append({
            "attempt": attempt,
            "prompt": prompt,
            "raw_response": raw_response,
            "extracted_poc": poc_code,
            "hallucinated_symbols": hallucinated_symbols,
            "verifier_status": result.status,
            "verifier_stage": (
                "sanitizer"  if result.status == "crash"     else
                "execution"  if exec_details                 else
                "compiler"
            ),
            "verifier_feedback": result.feedback,
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