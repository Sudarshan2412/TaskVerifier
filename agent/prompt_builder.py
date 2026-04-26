"""
prompt_builder.py — Constructs text prompts for the Groq API.

Handles two cases:
1. Initial prompt — first attempt at generating a PoC for a CVE, with few-shot examples
2. Feedback prompt — retry attempts, injecting verifier feedback and hallucinated symbols
"""

import json
import logging
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

# Path to few-shot examples file (available after Aparna's Week 3 handoff)
FEW_SHOT_EXAMPLES_PATH = "few_shot_examples.json"


def load_few_shot_examples(path: str = "few_shot_examples.json") -> list:
    """
    Load few-shot examples from a JSON file.
    
    If the file does not exist or is malformed, log a warning and return an empty list.
    
    Args:
        path: Path to the few_shot_examples.json file
        
    Returns:
        List of dicts with keys 'prompt_input' and 'ideal_poc_output', or empty list
    """
    try:
        with open(path, "r") as f:
            data = json.load(f)
        
        # Validate that loaded data matches the expected schema
        if not isinstance(data, list):
            logger.warning(
                "few_shot_examples.json: expected a JSON array at top level, got %s. "
                "Falling back to zero examples.",
                type(data).__name__
            )
            return []
        
        validated = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                logger.warning("few_shot_examples.json: entry %d is not a dict — skipping.", i)
                continue
            if "prompt_input" not in item or "ideal_poc_output" not in item:
                logger.warning(
                    "few_shot_examples.json: entry %d missing required keys "
                    "('prompt_input', 'ideal_poc_output') — skipping.",
                    i
                )
                continue
            validated.append(item)
        
        if not validated:
            logger.warning(
                "few_shot_examples.json: no valid entries found after validation. "
                "Continuing with zero examples."
            )
        
        return validated
    except FileNotFoundError:
        logger.warning(f"few_shot_examples.json not found at '{path}'. Continuing without examples.")
        return []
    except json.JSONDecodeError:
        logger.warning(f"few_shot_examples.json at '{path}' is malformed JSON. Continuing without examples.")
        return []
    except Exception as e:
        logger.warning(f"Error loading few_shot_examples.json: {e}. Continuing without examples.")
        return []


def format_few_shot_block(examples: list) -> str:
    """
    Format few-shot examples into a readable prompt block.
    
    Args:
        examples: List of example dicts with 'prompt_input' and 'ideal_poc_output' keys
        
    Returns:
        Formatted string block, or empty string if list is empty
    """
    if not examples:
        return ""
    
    formatted_parts = []
    for i, example in enumerate(examples, start=1):
        # Extract fields from example
        prompt_input = example.get("prompt_input", "")
        ideal_poc = example.get("ideal_poc_output", "")
        
        # Format this example
        example_block = (
            f"### Example {i}\n"
            f"Input context:\n"
            f"{prompt_input}\n\n"
            f"Correct PoC output:\n"
            f"```c\n"
            f"{ideal_poc}\n"
            f"```"
        )
        formatted_parts.append(example_block)
    
    # Join all examples with blank lines between them
    return "\n\n".join(formatted_parts)


def build_initial_prompt(cve_entry: dict, few_shot_examples: list) -> str:
    """
    Build the initial prompt for the first attempt at generating a PoC.
    
    Args:
        cve_entry: Dict with keys: id, vuln_class, poc_bucket, sanitizer_type, 
                   target_source, crash_description
        few_shot_examples: List of example dicts
        
    Returns:
        Formatted prompt string
        
    Raises:
        KeyError: If required fields are missing from cve_entry
    """
    # Validate required fields
    required_fields = ["id", "vuln_class", "poc_bucket", "sanitizer_type", "target_source", "crash_description"]
    missing_fields = [field for field in required_fields if field not in cve_entry]
    if missing_fields:
        raise KeyError(f"cve_entry missing required fields: {missing_fields}")
    
    # Extract fields
    cve_id = cve_entry["id"]
    vuln_class = cve_entry["vuln_class"]
    poc_bucket = cve_entry["poc_bucket"]
    sanitizer_type = cve_entry["sanitizer_type"]
    target_source = cve_entry["target_source"]
    crash_description = cve_entry["crash_description"]
    
    # Format few-shot block
    few_shot_block = format_few_shot_block(few_shot_examples)
    
    # Build the prompt
    prompt = (
        f"You are a security researcher. Your task is to write a Proof-of-Concept (PoC) C program\n"
        f"that triggers the following known vulnerability.\n\n"
        f"CVE ID: {cve_id}\n"
        f"Vulnerability class: {vuln_class}\n"
        f"Sanitizer: {sanitizer_type.upper()}\n"
        f"Expected PoC size: {poc_bucket} (< 50 bytes / 50–100 bytes / > 100 bytes)\n\n"
        f"--- Vulnerable Source ---\n"
        f"```c\n"
        f"{target_source}\n"
        f"```\n\n"
        f"Expected crash: {crash_description}\n"
    )
    
    # Add few-shot examples if available
    if few_shot_block:
        prompt += f"\n{few_shot_block}\n"
    
    # Add final instruction
    prompt += (
        f"\nWrite a PoC C program that, when compiled with -fsanitize=address and executed,\n"
        f"triggers the crash described above on the vulnerable source.\n"
        f"Output ONLY the C code inside triple backticks. No explanation."
    )
    
    return prompt


def build_feedback_prompt(
    cve_entry: dict,
    feedback_text: str,
    hallucinated_symbols: list,
    previous_poc: str,
    attempt_number: int
) -> str:
    """
    Build a retry prompt after a previous attempt failed.
    
    Args:
        cve_entry: Dict with keys: id, crash_description (at minimum)
        feedback_text: Verifier feedback string (3-5 lines)
        hallucinated_symbols: List of symbol names that don't exist in the source
        previous_poc: The C code from the previous attempt
        attempt_number: Which attempt this is (1-indexed)
        
    Returns:
        Formatted retry prompt string
        
    Raises:
        KeyError: If required fields are missing from cve_entry
    """
    # Validate required fields
    required_fields = ["id", "crash_description"]
    missing_fields = [field for field in required_fields if field not in cve_entry]
    if missing_fields:
        raise KeyError(f"cve_entry missing required fields: {missing_fields}")
    
    # Handle None hallucinated_symbols
    if hallucinated_symbols is None:
        hallucinated_symbols = []
    
    # Extract fields
    cve_id = cve_entry["id"]
    crash_description = cve_entry["crash_description"]
    
    # Build the prompt
    prompt = (
        f"You are continuing to work on CVE {cve_id}.\n"
        f"Target crash: {crash_description}\n\n"
        f"Your previous attempt (Attempt {attempt_number}) failed:\n"
        f"```c\n"
        f"{previous_poc}\n"
        f"```\n\n"
        f"Verifier feedback:\n"
        f"{feedback_text}\n"
    )
    
    # Add hallucination section if hallucinated_symbols is non-empty
    if hallucinated_symbols:
        hallucination_section = (
            f"\nWARNING — Hallucinated symbols detected:\n"
            f"{', '.join(hallucinated_symbols)}\n"
            f"These symbols do not exist in the target source. Do NOT use them.\n"
            f"Only use functions, variables, and headers that appear in the provided source code.\n"
        )
        prompt += hallucination_section
    
    # Add final instruction
    prompt += (
        f"\nFix the PoC. Output ONLY the corrected C code inside triple backticks. No explanation."
    )
    
    return prompt


if __name__ == "__main__":
    """Test block with mock data."""
    # Set logging to INFO level for test output
    logging.basicConfig(level=logging.INFO, force=True)
    
    mock_entry = {
        "id": "CVE-2021-9999",
        "poc_bytes": 60,
        "poc_bucket": "medium",
        "vuln_class": "buffer_overflow",
        "target_source": 'void vuln(char *input) { char buf[8]; strcpy(buf, input); }',
        "crash_description": "heap-buffer-overflow on strcpy",
        "sanitizer_type": "asan"
    }

    examples = load_few_shot_examples(FEW_SHOT_EXAMPLES_PATH)
    if examples:
        logging.info(
            "Loaded %d few-shot example(s) from '%s'.",
            len(examples),
            FEW_SHOT_EXAMPLES_PATH
        )
    else:
        logging.info(
            "No few-shot examples loaded — prompts will use zero examples."
        )

    initial = build_initial_prompt(mock_entry, examples)
    print("=== INITIAL PROMPT ===")
    print(initial)

    feedback = build_feedback_prompt(
        cve_entry=mock_entry,
        feedback_text="Compiler error: implicit declaration of function 'vuln' at line 3.",
        hallucinated_symbols=["trigger_bug", "exploit_func"],
        previous_poc='int main() { trigger_bug(); }',
        attempt_number=1
    )
    print("\n=== FEEDBACK PROMPT ===")
    print(feedback)
