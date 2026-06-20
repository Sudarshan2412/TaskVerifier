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
from agent.source_extractor import extract_source_from_container   # ADD THIS

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
    cve_id = cve_entry.get("id") or cve_entry.get("cve_id", "unknown")
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
    
    # Pull additional source context from the container image.
    # General-purpose: parses the crash stacktrace, greps the container for those functions.
    container_source = extract_source_from_container(cve_entry)
    if container_source:
        prompt += f"\n{container_source}\n"

    # Add few-shot examples if available
    if few_shot_block:
        prompt += f"\n{few_shot_block}\n"
    
    hint = cve_entry.get("hint", "")
    if hint:
        hint += (
            "\nIMPORTANT: In MVG, text strings must use single quotes: text 0,0 '%[...]' "
            "NOT double quotes. Double-quoted strings are parsed differently."
        )
        prompt += f"\n\nIMPORTANT HINT:\n{hint}"
    
    fuzz_target = cve_entry.get("fuzz_target", "")
    hint = cve_entry.get("hint", "")
    target_name = fuzz_target.split("/")[-1].lower() if fuzz_target else ""

    if fuzz_target and any(fmt in fuzz_target.upper() for fmt in ["MVG", "SVG", "PS", "PDF", "JPEG", "PNG"]):
        prompt += (
            f"\n\nThe fuzz target binary is: {fuzz_target}\n"
            f"The input file must be a valid {fuzz_target.split('/')[-1].replace('coder_','').replace('_fuzzer','')} format file.\n"
            f"\nCRITICAL C WRITING RULE — to write a literal '%' character to a file:\n"
            f"  CORRECT:   fputc('%', f);\n"
            f"  WRONG:     fprintf(f, \"%%\");   // TranslateTextEx sees %% as escaped percent,\n"
            f"             // so escape sequences like %[ are NEVER triggered.\n"
            f"\nFor MVG format specifically, use this exact C pattern:\n"
            f"```c\n"
            f"fprintf(f, \"push graphic-context\\n\");\n"
            f"fprintf(f, \"text 0,0 '\");\n"
            f"fputc('%', f);   // literal percent\n"
            f"fputc('[', f);\n"
            f"for (int i = 0; i < N; i++) fputc('A', f);  // N >= MaxTextExtent\n"
            f"fprintf(f, \"]'\\n\");\n"
            f"fprintf(f, \"pop graphic-context\\n\");\n"
            f"```\n"
        )
    elif not hint:
        # General-purpose format hints derived from the fuzz target name.
        # Add new branches here as you encounter new target types.
        if any(x in target_name for x in ["fuzz_as", "assembl"]):
            prompt += (
                f"\n\nThe fuzz target is a GNU assembler (as). "
                f"Your PoC must write a plain text assembly file to /tmp/poc. "
                f"The vulnerability is triggered by specific directive values — "
                f"study the source for integer bounds and craft the directive accordingly. "
                f"Example structure: .file <number> \"name.c\" or .loc <number> <line> <col>\n"
            )
        elif any(x in target_name for x in ["heif", "libheif", "file-fuzzer"]):
            prompt += (
                f"\n\nThe fuzz target processes HEIF/ISO Base Media files. "
                f"Your PoC must write a valid binary HEIF container to /tmp/poc. "
                f"Focus on image dimension fields (width, height, stride) — "
                f"the overflow is triggered when computed buffer sizes exceed allocated memory.\n"
            )
        elif any(x in target_name for x in ["mng", "png"]):
            prompt += (
                f"\n\nThe fuzz target processes MNG/PNG files. "
                f"Your PoC must write a valid binary MNG/PNG file to /tmp/poc. "
                f"CRC values in chunk headers are typically ignored by the parser — "
                f"you can use dummy zeros. Focus on chunk type and data layout.\n"
            )

    # Add final instruction
    prompt += (
        f"\nWrite a PoC C program that, when compiled with -fsanitize=address and executed,\n"
        "\n\nCRITICAL OUTPUT CONSTRAINTS:\n"
        "- Do NOT write the payload as a hex byte array literal (unsigned char poc[] = {0x41, ...}).\n"
        "  These arrays are too long and will be truncated. You will run out of tokens.\n"
        "- Instead, write the payload using a loop or fprintf/fputc calls.\n"
        "- The generator MUST write its output to exactly '/tmp/poc' (no extension).\n"
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
    cve_id = cve_entry.get("id") or cve_entry.get("cve_id", "unknown")
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
    fuzz_target = cve_entry.get("fuzz_target", "")
    if fuzz_target and any(fmt in fuzz_target.upper() for fmt in ["MVG", "SVG", "PS", "PDF", "JPEG", "PNG"]):
        prompt += (
            f"\nREMINDER: Use fputc('%', f) not fprintf(f, \"%%[\") to write a literal "
            f"percent sign. The %% escape prevents the vulnerable code path from being reached.\n"
        )
    # Add final instruction
    prompt += (
        f"\nFix the PoC. Output ONLY the corrected C code inside triple backticks. No explanation."
        "\n\nCRITICAL OUTPUT CONSTRAINTS:\n"
        "- Do NOT write the payload as a hex byte array literal (unsigned char poc[] = {0x41, ...}).\n"
        "  These arrays are too long and will be truncated. You will run out of tokens.\n"
        "- Instead, write the payload using a loop or fprintf/fputc calls.\n"
        "- The generator MUST write its output to exactly '/tmp/poc' (no extension).\n"
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
