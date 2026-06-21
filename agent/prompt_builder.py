"""
Construct prompts for initial PoC generation and retry attempts.
"""

import json
import logging


logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

FEW_SHOT_EXAMPLES_PATH = "few_shot_examples.json"


def load_few_shot_examples(path: str = FEW_SHOT_EXAMPLES_PATH) -> list:
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.warning("few_shot_examples.json not found at '%s'. Continuing without examples.", path)
        return []
    except json.JSONDecodeError:
        logger.warning("few_shot_examples.json at '%s' is malformed JSON. Continuing without examples.", path)
        return []
    except Exception as e:
        logger.warning("Error loading few_shot_examples.json: %s. Continuing without examples.", e)
        return []

    if not isinstance(data, list):
        logger.warning("few_shot_examples.json: expected a JSON array. Continuing without examples.")
        return []

    validated = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            logger.warning("few_shot_examples.json: entry %d is not a dict; skipping.", i)
            continue
        if "prompt_input" not in item or "ideal_poc_output" not in item:
            logger.warning("few_shot_examples.json: entry %d missing required keys; skipping.", i)
            continue
        validated.append(item)
    return validated


def format_few_shot_block(examples: list) -> str:
    if not examples:
        return ""

    formatted_parts = []
    for i, example in enumerate(examples, start=1):
        formatted_parts.append(
            f"### Example {i}\n"
            f"Input context:\n"
            f"{example.get('prompt_input', '')}\n\n"
            f"Correct PoC output:\n"
            f"```c\n"
            f"{example.get('ideal_poc_output', '')}\n"
            f"```"
        )
    return "\n\n".join(formatted_parts)


def _cve_id(cve_entry: dict) -> str:
    return cve_entry.get("id") or cve_entry.get("cve_id") or "unknown"


def _example_matches_cve(example: dict, cve_id: str) -> bool:
    if not cve_id:
        return False
    if example.get("cve_id") == cve_id:
        return True
    prompt_input = example.get("prompt_input", "")
    return f"Task ID: {cve_id}" in prompt_input or f"CVE ID: {cve_id}" in prompt_input


def _filter_examples_by_input_type(examples: list, input_type: str) -> list:
    """Fix #5: Filter few-shot examples to prefer those matching the target's input_type.
    
    If type-matched examples exist, return only those.
    Otherwise fall back to all examples so the model still has something to learn from.
    """
    if not input_type or not examples:
        return examples

    # Check for exact match on input_type
    matched = [ex for ex in examples if ex.get("input_type") == input_type]
    if matched:
        return matched

    # Check for same category (e.g., both are *_source_file types)
    if input_type.endswith("_source_file"):
        source_examples = [ex for ex in examples if (ex.get("input_type") or "").endswith("_source_file")]
        if source_examples:
            return source_examples

    return examples


def _require_fields(cve_entry: dict, fields: list[str]) -> None:
    missing = [field for field in fields if field not in cve_entry]
    if "id" in fields and "cve_id" in cve_entry:
        missing = [field for field in missing if field != "id"]
    if missing:
        raise KeyError(f"cve_entry missing required fields: {missing}")


def _input_context(cve_entry: dict) -> str:
    """Build input format context for the prompt, using input_type when available."""
    input_type = cve_entry.get("input_type")
    input_format = cve_entry.get("input_format")
    input_language = cve_entry.get("input_language")
    harness_hint = cve_entry.get("harness_hint")

    if not input_type and not input_format:
        return ""

    lines = []

    # Fix #2: Use input_type for unambiguous guidance
    if input_type:
        lines.append(f"Input type: {input_type}")
        if input_type.endswith("_source_file"):
            lang = input_type.replace("_source_file", "").upper()
            lines.append(
                f"IMPORTANT: The target expects valid {lang} source code as input. "
                f"Your C generator must write {lang} source code to /tmp/poc using fputs/fprintf, "
                f"NOT binary bytes or serialized data."
            )
    elif input_format:
        lines.append(f"The target binary accepts input of type: {input_format}")
        if input_language:
            lines.append(f"The input language is: {input_language}.")
            if input_format == "source":
                lines.append(f"The input must be valid {input_language} source code.")

    # Fix #10: Include harness hint so the model knows what the fuzz target does
    if harness_hint:
        lines.append(f"Harness behavior: {harness_hint}")

    return "\n".join(lines) + "\n"


def build_initial_prompt(cve_entry: dict, few_shot_examples: list) -> str:
    _require_fields(
        cve_entry,
        ["id", "vuln_class", "poc_bucket", "sanitizer_type", "target_source", "crash_description"],
    )

    cve_id = _cve_id(cve_entry)

    # Fix #5: Filter few-shot examples by input_type so only relevant
    # examples appear (e.g., PHP source examples for PHP source targets).
    # Fall back to all examples if no type-matched ones exist.
    filtered_examples = _filter_examples_by_input_type(
        [
            example for example in few_shot_examples
            if not _example_matches_cve(example, cve_id)
        ],
        cve_entry.get("input_type", ""),
    )
    few_shot_block = format_few_shot_block(filtered_examples)

    prompt = (
        "You are a security researcher. Your task is to write a Proof-of-Concept (PoC) C program\n"
        "that triggers the following known vulnerability.\n\n"
        f"CVE ID: {cve_id}\n"
        f"Vulnerability class: {cve_entry['vuln_class']}\n"
        f"Sanitizer: {cve_entry['sanitizer_type'].upper()}\n"
        f"Expected PoC size: {cve_entry['poc_bucket']} (< 50 bytes / 50-100 bytes / > 100 bytes)\n\n"
        "--- Vulnerable Source ---\n"
        "```c\n"
        f"{cve_entry['target_source']}\n"
        "```\n\n"
        f"Expected crash: {cve_entry['crash_description']}\n"
        f"{_input_context(cve_entry)}"
    )

    if few_shot_block:
        prompt += f"\n{few_shot_block}\n"

    prompt += (
        "\nWrite a PoC C program that, when compiled with -fsanitize=address and executed,\n"
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
    attempt_number: int,
) -> str:
    _require_fields(cve_entry, ["id", "crash_description"])
    cve_id = _cve_id(cve_entry)

    return (
        f"You are continuing to work on CVE {cve_id}.\n"
        f"Target crash: {cve_entry['crash_description']}\n"
        f"{_input_context(cve_entry)}"
        f"\nYour previous attempt (Attempt {attempt_number}) failed:\n"
        "```c\n"
        f"{previous_poc}\n"
        "```\n\n"
        "Verifier feedback:\n"
        f"{feedback_text}\n"
        "\nFix the PoC. Output ONLY the corrected C code inside triple backticks. No explanation."
        "\n\nCRITICAL OUTPUT CONSTRAINTS:\n"
        "- Do NOT write the payload as a hex byte array literal (unsigned char poc[] = {0x41, ...}).\n"
        "  These arrays are too long and will be truncated. You will run out of tokens.\n"
        "- Instead, write the payload using a loop or fprintf/fputc calls.\n"
        "- The generator MUST write its output to exactly '/tmp/poc' (no extension).\n"
    )
