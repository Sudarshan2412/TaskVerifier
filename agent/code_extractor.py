"""
code_extractor.py — Extracts clean C code from raw LLM responses.

Takes the raw text response from the Groq API and returns only the clean C code string,
ready to be written to a .c file and passed to the verifier pipeline.
"""

import re
import logging

logger = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Raised when code cannot be extracted from the model's response."""
    pass


def extract_code(raw_response: str) -> str:
    """
    Extract clean C code from raw LLM response.
    
    Orchestrates the extraction process:
    1. Strip leading/trailing whitespace
    2. Check if empty
    3. Try fenced block extraction
    4. Fall back to heuristic extraction
    5. Raise ExtractionError if both fail
    
    Args:
        raw_response: The exact string returned by llm_client.call_llm()
        
    Returns:
        Clean C code string (without backticks or language tags)
        
    Raises:
        ExtractionError: If code cannot be extracted
    """
    # Step 1: Strip whitespace
    raw_response = raw_response.strip()
    
    # Step 2: Check if empty
    if not raw_response:
        raise ExtractionError("Model returned empty response")
    
    # Step 3: Try fenced block extraction
    fenced_code = _extract_from_fenced_block(raw_response)
    if fenced_code:
        return fenced_code
    
    # Step 4: Fall back to heuristic
    heuristic_code = _extract_heuristic(raw_response)
    if heuristic_code:
        return heuristic_code
    
    # Step 5: Raise error if both fail
    raise ExtractionError("Could not extract C code from model response")


def _extract_from_fenced_block(text: str) -> str:
    """
    Extract code from triple-backtick fenced blocks.
    
    Finds all fenced code blocks and returns the last one (in case of multiple blocks).
    Strips backticks and language tags, returning only the code content.
    
    Args:
        text: Raw response text
        
    Returns:
        Extracted code string, or empty string if no fenced blocks found
    """
    # Regex pattern: ``` + optional language identifier + newline + code + ```
    # Non-greedy to avoid eating multiple blocks at once
    pattern = re.compile(r'```(?:\w+)?\n(.*?)```', re.DOTALL)
    
    # Find all matches
    matches = pattern.findall(text)
    
    if not matches:
        return ""
    
    # Return the last match, stripped of whitespace
    return matches[-1].strip()


def _extract_heuristic(text: str) -> str:
    """
    Fallback heuristic extraction for raw C code without fences.
    
    Checks for C code indicators to distinguish code from prose.
    If any indicators are found, returns the full text.
    
    C indicators checked:
    - #include
    - int main(
    - void 
    - return 0;
    
    Args:
        text: Raw response text
        
    Returns:
        Full text if C indicators found, empty string otherwise
    """
    # C code indicators
    c_indicators = ["#include", "int main(", "void ", "return 0;"]
    
    # Check if any indicator is present
    for indicator in c_indicators:
        if indicator in text:
            return text.strip()
    
    # No indicators found — this is likely prose, not code
    return ""


if __name__ == "__main__":
    """Test with various model output patterns."""
    cases = [
        # Case 1: clean fenced block with tag
        ("Clean fenced with tag",
         "```c\n#include <stdio.h>\nint main() { return 0; }\n```"),

        # Case 2: fenced block without tag
        ("Fenced without tag",
         "```\n#include <stdio.h>\nint main() { return 0; }\n```"),

        # Case 3: prose before and after
        ("Prose before and after",
         "Here is the PoC:\n```c\n#include <string.h>\nint main() { char buf[8]; strcpy(buf, \"AAAAAAAAAA\"); }\n```\nThis triggers the overflow."),

        # Case 4: multiple fenced blocks — should return the LAST one
        ("Multiple blocks",
         "Explanation:\n```\nsome notes\n```\nPoC:\n```c\nint main() { return 0; }\n```"),

        # Case 5: raw C, no fences
        ("Raw C no fences",
         "#include <stdlib.h>\nint main() { char *p = malloc(10); p[20] = 1; }"),

        # Case 6: pure prose — should raise ExtractionError
        ("Pure prose",
         "I cannot write exploit code for this vulnerability."),

        # Case 7: empty string — should raise ExtractionError
        ("Empty string", ""),
    ]

    for name, raw in cases:
        print(f"\n--- {name} ---")
        try:
            result = extract_code(raw)
            print(f"OK:\n{result}")
        except ExtractionError as e:
            print(f"ExtractionError (expected for some cases): {e}")
