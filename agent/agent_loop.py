"""
agent_loop.py — Central retry loop for single-CVE vulnerability reproduction.

For a single CVE entry, orchestrates:
1. Initial LLM prompt generation
2. Code extraction
3. Hallucination detection
4. Verification pipeline
5. Feedback-driven retry (up to max_attempts)

Returns structured AgentResult with full transcript for logging and evaluation.
"""

import logging
import time
from dataclasses import dataclass, field

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

# Configure logging
logger = logging.getLogger(__name__)

# Module-level constants — tunable for rate limiting and resource control
INTER_ATTEMPT_SLEEP_SECONDS = 5  # proactive sleep between retry attempts
FEW_SHOT_PATH = "few_shot_examples.json"  # default path; runner.py may override


# ──────────────────────────────────────────────────────────────────────────────
# Startup validation — called at module import time
# ──────────────────────────────────────────────────────────────────────────────

def _check_llm_client_has_history_support() -> None:
    """
    Validate that llm_client.py exposes call_llm_with_history().
    
    Fails loudly at import time rather than silently at runtime.
    """
    try:
        if not hasattr(llm_client, "call_llm_with_history"):
            raise ImportError(
                "llm_client.py is missing call_llm_with_history(messages: list[dict]) -> str. "
                "Add it before running agent_loop.py."
            )
    except ImportError:
        raise


_check_llm_client_has_history_support()


# ──────────────────────────────────────────────────────────────────────────────
# Return type: AgentResult
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    """
    Result of running the agent loop for a single CVE.
    
    Contains success/failure status, all attempts, final PoC code,
    and full transcript for logging and evaluation.
    """
    cve_id: str                                         # CVE identifier
    success: bool                                       # True if verifier passed
    attempts: int                                       # How many LLM calls were made
    final_poc: str                                      # Last extracted PoC code (empty if all failed)
    failure_reason: str                                 # "" if success; one of the failure codes if not
    transcript: list[dict] = field(default_factory=list)  # Full record of all attempts
    hallucinated_symbols_per_attempt: list[list[str]] = field(default_factory=list)  # Hallucinations per attempt


# ──────────────────────────────────────────────────────────────────────────────
# Main agent loop
# ──────────────────────────────────────────────────────────────────────────────

def run_agent(
    cve_entry: dict,
    max_attempts: int = 5,
    few_shot_examples: list = None
) -> AgentResult:
    """
    Main public function. Called by runner.py for each CVE.
    
    Implements the full retry loop:
    1. Build initial or feedback prompt
    2. Call LLM with conversation history
    3. Extract PoC code
    4. Run hallucination detection
    5. Verify PoC against target vulnerability
    6. If pass → return success
    7. If fail → build feedback prompt and retry
    8. Repeat up to max_attempts times
    
    Args:
        cve_entry: One dict from cybergym_subset.json with keys:
                   id, target_source, crash_description, sanitizer_type, poc_bucket, vuln_class
        max_attempts: Maximum retry attempts (default 5)
        few_shot_examples: List of few-shot example dicts (loaded from JSON if not provided)
    
    Returns:
        AgentResult with success status, attempts count, final PoC, and full transcript
    """
    
    # Load few-shot examples if not provided
    if few_shot_examples is None:
        few_shot_examples = load_few_shot_examples(FEW_SHOT_PATH)
    
    # Initialize state
    ctx = ContextManager()
    ctx.reset()
    verifier = VerifierPipeline()
    
    transcript = []
    hallucinated_per_attempt = []
    last_poc = ""
    last_feedback_text = ""
    last_hallucinated_symbols = []
    
    cve_id = cve_entry["id"]
    
    logger.info(f"Starting agent loop for CVE {cve_id} with max_attempts={max_attempts}")
    
    # ──────────────────────────────────────────────────────────────────────────
    # Main retry loop
    # ──────────────────────────────────────────────────────────────────────────
    
    for attempt in range(1, max_attempts + 1):
        logger.debug(f"CVE {cve_id}: Attempt {attempt}/{max_attempts}")
        
        # ── PROMPT CONSTRUCTION ──────────────────────────────────────
        try:
            if attempt == 1:
                prompt = build_initial_prompt(cve_entry, few_shot_examples)
            else:
                prompt = build_feedback_prompt(
                    cve_entry=cve_entry,
                    feedback_text=last_feedback_text,
                    hallucinated_symbols=last_hallucinated_symbols,
                    previous_poc=last_poc,
                    attempt_number=attempt - 1
                )
        except Exception as e:
            logger.error(f"CVE {cve_id}: Failed to build prompt: {e}")
            return AgentResult(
                cve_id=cve_id,
                success=False,
                attempts=attempt - 1,
                final_poc=last_poc,
                failure_reason="llm_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )
        
        ctx.add_user_message(prompt)
        
        # ── LLM CALL ─────────────────────────────────────────────────────────
        try:
            raw_response = llm_client.call_llm_with_history(ctx.get_history())
            logger.debug(f"CVE {cve_id}: Attempt {attempt} LLM response received ({len(raw_response)} chars)")
        except Exception as e:
            logger.error(f"CVE {cve_id}: Attempt {attempt} LLM call failed (unrecoverable): {e}")
            transcript_entry = {
                "attempt": attempt,
                "prompt": prompt,
                "raw_response": "",
                "extracted_poc": "",
                "hallucinated_symbols": [],
                "verifier_status": "skip",
                "verifier_stage": "",
                "verifier_feedback": ""
            }
            transcript.append(transcript_entry)
            return AgentResult(
                cve_id=cve_id,
                success=False,
                attempts=attempt,
                final_poc=last_poc,
                failure_reason="llm_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )
        
        ctx.add_assistant_message(raw_response)
        
        # ── CODE EXTRACTION ──────────────────────────────────────────────────
        try:
            poc_code = extract_code(raw_response)
            last_poc = poc_code
            logger.debug(f"CVE {cve_id}: Attempt {attempt} code extracted ({len(poc_code)} chars)")
        except ExtractionError as e:
            logger.warning(f"CVE {cve_id}: Attempt {attempt} extraction failed: {e}")
            transcript_entry = {
                "attempt": attempt,
                "prompt": prompt,
                "raw_response": raw_response,
                "extracted_poc": "",
                "hallucinated_symbols": [],
                "verifier_status": "skip",
                "verifier_stage": "",
                "verifier_feedback": ""
            }
            transcript.append(transcript_entry)
            hallucinated_per_attempt.append([])
            last_hallucinated_symbols = []
            last_feedback_text = "Your response did not contain extractable C code. Output ONLY C code in triple backticks."
            
            # Sleep before next attempt (if not the last one)
            if attempt < max_attempts:
                logger.debug(f"CVE {cve_id}: Sleeping {INTER_ATTEMPT_SLEEP_SECONDS}s before next attempt")
                time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)
            
            continue
        
        # ── HALLUCINATION DETECTION ──────────────────────────────────────────
        try:
            hallucinated_symbols = detect_hallucinations(
                target_source_path=cve_entry["target_source"],
                poc_code=poc_code
            )
            last_hallucinated_symbols = hallucinated_symbols
            hallucinated_per_attempt.append(hallucinated_symbols)
            
            if hallucinated_symbols:
                logger.warning(f"CVE {cve_id}: Attempt {attempt} hallucinated symbols: {hallucinated_symbols}")
        except Exception as e:
            logger.error(f"CVE {cve_id}: Attempt {attempt} hallucination detection error: {e}")
            hallucinated_symbols = []
            last_hallucinated_symbols = []
            hallucinated_per_attempt.append([])
        
        # ── VERIFIER ─────────────────────────────────────────────────────────
        try:
            result = verifier.verify(poc_code=poc_code, cve_entry=cve_entry)
            logger.debug(f"CVE {cve_id}: Attempt {attempt} verifier status: {result.status}")
        except Exception as e:
            logger.error(f"CVE {cve_id}: Attempt {attempt} verifier raised exception: {e}")
            transcript_entry = {
                "attempt": attempt,
                "prompt": prompt,
                "raw_response": raw_response,
                "extracted_poc": poc_code,
                "hallucinated_symbols": hallucinated_symbols,
                "verifier_status": "error",
                "verifier_stage": "unknown",
                "verifier_feedback": str(e)[:500]
            }
            transcript.append(transcript_entry)
            return AgentResult(
                cve_id=cve_id,
                success=False,
                attempts=attempt,
                final_poc=poc_code,
                failure_reason="verifier_error",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )
        
        last_feedback_text = result.feedback
        
        # ── RECORD TRANSCRIPT ENTRY ──────────────────────────────────────────
        transcript_entry = {
            "attempt": attempt,
            "prompt": prompt,
            "raw_response": raw_response,
            "extracted_poc": poc_code,
            "hallucinated_symbols": hallucinated_symbols,
            "verifier_status": result.status,
            "verifier_stage": result.details.get("stage", "") if hasattr(result, "details") else "",
            "verifier_feedback": result.feedback
        }
        transcript.append(transcript_entry)
        
        # ── SUCCESS CHECK ────────────────────────────────────────────────────
        # Map verifier status: "crash" indicates successful PoC (vulnerability triggered)
        if result.status == "crash":
            logger.info(f"CVE {cve_id}: SUCCESS on attempt {attempt}")
            return AgentResult(
                cve_id=cve_id,
                success=True,
                attempts=attempt,
                final_poc=poc_code,
                failure_reason="",
                transcript=transcript,
                hallucinated_symbols_per_attempt=hallucinated_per_attempt
            )
        
        # ── SLEEP BEFORE NEXT ATTEMPT ────────────────────────────────────────
        if attempt < max_attempts:
            logger.debug(f"CVE {cve_id}: Attempt {attempt} failed (status={result.status}) — sleeping {INTER_ATTEMPT_SLEEP_SECONDS}s before next attempt")
            time.sleep(INTER_ATTEMPT_SLEEP_SECONDS)
    
    # ── ALL ATTEMPTS EXHAUSTED ───────────────────────────────────────────────
    logger.warning(f"CVE {cve_id}: FAILURE after {max_attempts} attempts")
    
    # Check if extraction failed on all attempts
    extraction_failed_all = all(
        entry["extracted_poc"] == "" for entry in transcript
    )
    failure_reason = (
        "extraction_failed_all_attempts" if extraction_failed_all
        else "max_attempts_reached"
    )
    
    return AgentResult(
        cve_id=cve_id,
        success=False,
        attempts=max_attempts,
        final_poc=last_poc,
        failure_reason=failure_reason,
        transcript=transcript,
        hallucinated_symbols_per_attempt=hallucinated_per_attempt
    )


# ──────────────────────────────────────────────────────────────────────────────
# Test block
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import unittest.mock as mock

    # Mock CVE entry
    mock_entry = {
        "id": "CVE-2021-9999",
        "poc_bytes": 60,
        "poc_bucket": "medium",
        "vuln_class": "buffer_overflow",
        "target_source": "void vuln(char *input) { char buf[8]; strcpy(buf, input); }",
        "crash_description": "heap-buffer-overflow on strcpy",
        "sanitizer_type": "asan"
    }

    # Mock LLM response with valid C code
    mock_response = (
        "```c\n"
        "#include <string.h>\n"
        "void vuln(char *i){char b[8];strcpy(b,i);}\n"
        "int main(){vuln(\"AAAAAAAAAA\");}\n"
        "```"
    )

    # Mock verifier result for successful PoC
    class MockVerifierResult:
        def __init__(self):
            self.status = "crash"
            self.feedback = "PoC successfully triggered the vulnerability."
            self.details = {"stage": "execution"}

    with mock.patch("agent.llm_client.call_llm_with_history", return_value=mock_response), \
         mock.patch("verifier.VerifierPipeline.verify") as mock_verify, \
         mock.patch("verifier.hallucination_detector.detect_hallucinations", return_value=[]):

        mock_verify.return_value = MockVerifierResult()

        result = run_agent(mock_entry, max_attempts=2)
        print(f"\n=== Mock Test Results ===")
        print(f"Success: {result.success}")
        print(f"Attempts: {result.attempts}")
        print(f"Failure reason: '{result.failure_reason}'")
        print(f"Transcript entries: {len(result.transcript)}")
        print(f"Final PoC length: {len(result.final_poc)}")
        
        assert result.success is True, "Expected success=True in mock test"
        assert result.attempts == 1, "Expected attempts=1 (passed on first try)"
        assert result.failure_reason == "", "Expected empty failure_reason on success"
        print("\n✓ All mock assertions passed!")
