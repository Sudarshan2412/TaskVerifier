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


# ---------------------------------------------------------------------------
# Shared "does this look like real C code" signal
# ---------------------------------------------------------------------------

# Same indicator set _extract_heuristic() already used for its raw-text
# fallback -- kept as one constant so the fenced-block validator below and
# the heuristic fallback can never quietly drift apart from each other.
_C_CODE_INDICATORS = ("#include", "int main(", "void ", "return 0;")


def _looks_like_generator(candidate: str) -> bool:
    """
    Heuristic check that `candidate` is plausibly a real PoC generator
    program, not a stray fragment, a quoted stack trace, or leftover prose
    that happened to land inside a fenced code block.

    FIX (found from a real tool-use run, arvo:3848): a lone fenced code
    block used to be trusted unconditionally by _extract_from_fenced_block()
    -- confirmed on two consecutive attempts of that run, each of which
    wrapped something that wasn't a generator in triple backticks (a 3-line
    orphaned function call with no body, then a raw ASan stack-trace dump)
    and had it accepted as "the PoC," guaranteeing compile_fail and burning
    two of five attempts on a parsing bug rather than a reasoning miss.

    Two independent positive signals, either is sufficient:
      - References the exact output path (or the call used to write it)
        every valid generator must use, per the system prompt's own
        mandatory rule (`build_initial_prompt` / `build_tool_mode_prompt`:
        "The generator MUST write its output to exactly '/tmp/poc'").
      - Has basic C-program shape (same indicator set _extract_heuristic()
        already checks for its own raw-text fallback).

    Both of the real bad extractions above fail this check: neither
    contains '/tmp/poc'/'fopen', and neither contains any of
    _C_CODE_INDICATORS (the orphaned call has no `#include`/`int main(`/
    `void `/`return 0;`, and stack-trace frame lines don't either).
    """
    if '/tmp/poc' in candidate or 'fopen' in candidate:
        return True
    return any(indicator in candidate for indicator in _C_CODE_INDICATORS)


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

    Finds all fenced code blocks and returns the best candidate -- see
    _looks_like_generator() for what "best" means. Returns "" (not the raw
    text of a bad candidate) when nothing found looks like real code, so
    extract_code() falls through to _extract_heuristic() on the full
    response instead of silently accepting a fragment or a stack trace as
    "the PoC."

    Args:
        text: Raw response text

    Returns:
        Extracted code string, or empty string if no valid fenced block found
    """
    # Regex pattern: ``` + optional language identifier + newline + code + ```
    # Non-greedy to avoid eating multiple blocks at once
    pattern = re.compile(r'```(?:\w+)?\n(.*?)```', re.DOTALL)

    # Find all matches
    matches = [m.strip() for m in pattern.findall(text)]

    if not matches:
        return ""

    if len(matches) == 1:
        # FIX (arvo:3848, see _looks_like_generator docstring): a single
        # fenced block is no longer trusted unconditionally. If it doesn't
        # look like real generator code, return "" and let extract_code()
        # fall through to _extract_heuristic() on the full response instead
        # of handing back a fragment or a stack trace as a "final" answer.
        candidate = matches[0]
        return candidate if _looks_like_generator(candidate) else ""

    # FIX (found from a real tool-use run, arvo:1972): a single long tool-use
    # response can contain many small inline code fragments -- the model
    # quoting a line or two of source while reasoning about it -- in addition
    # to its actual final generator. Blindly taking the LAST fenced block
    # (matches[-1], unconditionally, below this comment previously) is a safe
    # assumption for single-shot mode's typical "one block of analysis, one
    # final code block" shape, where it's effectively the only candidate --
    # but it broke down here: the final response was 65,835 chars containing
    # many small quoted snippets, and the actual last one was a 69-character
    # fragment, not the intended generator, because the model appended a
    # small trailing reference after its real answer.
    #
    # Score candidates instead of blindly trusting position: prefer a block
    # that looks like a complete generator and, among those, the longest.
    # Falls back to effectively the same "last wins" tiebreak when nothing
    # scores differently, so single-shot's existing single-block behavior
    # above is completely unchanged, and even its rare multi-block case only
    # changes outcome when one candidate is clearly a more complete
    # generator than another.
    best_index = max(
        range(len(matches)),
        key=lambda i: (_looks_like_generator(matches[i]), len(matches[i]), i)
    )
    best = matches[best_index]

    # FIX (arvo:3848, extended to the multi-block path for consistency): if
    # NONE of the candidates look like real code -- e.g. every block is a
    # quoted snippet or trace, not a generator -- don't fall back to
    # "longest wins" anyway. Return "" so the caller tries the heuristic
    # path on the full response instead of promoting the least-bad fragment
    # to "the PoC."
    return best if _looks_like_generator(best) else ""


def _extract_heuristic(text: str) -> str:
    """
    Fallback heuristic extraction for raw C code without fences.
    
    Checks for C code indicators to distinguish code from prose.
    If any indicators are found, returns the full text.
    
    Args:
        text: Raw response text
        
    Returns:
        Full text if C indicators found, empty string otherwise
    """
    # Check if any indicator is present (shared with _looks_like_generator()
    # above, so the two never drift apart from each other)
    for indicator in _C_CODE_INDICATORS:
        if indicator in text:
            # Strip any leftover markdown fences that would cause compiler errors
            text = re.sub(r'^```\w*\n?', '', text.strip())
            text = re.sub(r'\n?```\s*$', '', text)
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

        # Case 8 (regression test for the arvo:3848 bug): a single fenced
        # block that is NOT a generator -- an orphaned function call with no
        # body, no #include, no /tmp/poc. Must NOT be accepted as-is; must
        # raise ExtractionError since there's no other code anywhere in the
        # surrounding text either.
        ("Single non-generator fenced block (arvo:3848 case 1)",
         "Let me trace through this.\n```c\npe_iterate_resources(\n"
         "    pe,\n    (RESOURCE_CALLBACK_FUNC) pe_collect_resources,\n"
         "    (void*) pe);\n```"),

        # Case 9 (regression test, arvo:3848 attempt 2 shape): a single
        # fenced block containing a stack trace, not code. Must also be
        # rejected.
        ("Single fenced stack trace (arvo:3848 case 2)",
         "```\n#0 0x54cc88 in foo bar.c:1\n#1 0x54e901 in baz qux.c:2\n```"),
    ]

    for name, raw in cases:
        print(f"\n--- {name} ---")
        try:
            result = extract_code(raw)
            print(f"OK:\n{result}")
        except ExtractionError as e:
            print(f"ExtractionError (expected for some cases): {e}")