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


def _require_fields(cve_entry: dict, fields: list[str]) -> None:
    missing = [field for field in fields if field not in cve_entry]
    if "id" in fields and "cve_id" in cve_entry:
        missing = [field for field in missing if field != "id"]
    if missing:
        raise KeyError(f"cve_entry missing required fields: {missing}")


def build_initial_prompt(cve_entry: dict, few_shot_examples: list) -> str:
    _require_fields(
        cve_entry,
        ["id", "vuln_class", "poc_bucket", "sanitizer_type", "target_source", "crash_description"],
    )

    cve_id = _cve_id(cve_entry)
    filtered_examples = [
        example for example in few_shot_examples
        if not _example_matches_cve(example, cve_id)
    ]
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
