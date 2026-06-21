import os
import re


# Standard C library names and keywords — we don't flag these even if not in target source
STDLIB_NAMES = {
    # C keywords that the symbol regex matches as "function calls"
    'if', 'for', 'while', 'do', 'switch', 'return', 'sizeof', 'typeof',
    'else', 'case', 'break', 'continue', 'goto', 'default',
    # Standard library functions
    'main', 'printf', 'malloc', 'free', 'memcpy', 'memset',
    'strlen', 'strcmp', 'strcpy', 'fopen', 'fclose', 'fprintf',
    'exit', 'abort', 'puts', 'sprintf', 'snprintf', 'atoi',
    'calloc', 'realloc', 'memmove', 'NULL', 'stderr', 'stdout', 'stdin',
    'perror', 'fwrite', 'fread', 'fputc', 'fgetc', 'sizeof',
    'stdio.h', 'stdlib.h', 'string.h', 'stdint.h', 'stddef.h',
}


def extract_symbols_from_source(source_code: str) -> set:
    """
    Parses a C source file and collects all:
    - function names (defined in the file)
    - #include header names
    - global variable names
    """
    symbols = set()

    # Extract function definitions: return_type function_name(
    func_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
    symbols.update(func_pattern.findall(source_code))
    # Extract #include headers: #include "header.h" or #include <header.h>
    include_pattern = re.compile(r'#include\s*[<"]([\w./]+)[>"]')
    symbols.update(include_pattern.findall(source_code))

    return symbols


def _load_source(target_source_or_path: str) -> str | None:
    """
    Accept either a path to source code or inline source code.

    Week 8 cybergym entries store the vulnerable source directly in
    ``target_source``. Older verifier code expected that field to be a path.
    """
    if not target_source_or_path:
        return None

    # Inline source should never be treated as a filesystem path. This avoids
    # OSError: [Errno 36] File name too long for multi-line snippets.
    if "\n" in target_source_or_path or "{" in target_source_or_path:
        return target_source_or_path

    try:
        if os.path.isfile(target_source_or_path):
            with open(target_source_or_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
    except OSError:
        return None

    return None

def _strip_comments(code: str) -> str:
    """Remove // line comments and /* block comments */ from C code."""
    # Block comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    # Line comments
    code = re.sub(r'//[^\n]*', '', code)
    return code


def _strip_string_literals(code: str) -> str:
    """Remove contents of string literals so symbols inside them aren't flagged.
    
    Fix #7: The PoC generator often writes target-language source (PHP, Ruby,
    Python) via fputs/fprintf string arguments.  Those strings contain valid
    identifiers in the *target* language that are not C symbols and should not
    be checked against the target source's C symbol table.
    """
    # Remove escaped quotes first so they don't confuse the regex
    code = code.replace('\\"', '').replace("\\'", '')
    # Replace string literal contents with empty strings
    code = re.sub(r'"[^"]*"', '""', code)
    code = re.sub(r"'[^']*'", "''", code)
    return code


def detect_hallucinations(target_source_code: str, poc_code: str) -> list:
    """
    Standardize the argument name to match the call in __init__.py
    """
    source_code = _load_source(target_source_code)
    if not source_code:
        return []

    real_symbols = extract_symbols_from_source(source_code)
    clean_poc = _strip_comments(poc_code)
    # Fix #7: Strip string literal contents so that target-language identifiers
    # (e.g., PHP's getMessage, ReflectionClass) inside fputs/fprintf calls
    # are not flagged as hallucinated C symbols.
    clean_poc = _strip_string_literals(clean_poc)
    locally_defined = set(re.findall(
        r'(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{', poc_code
    ))
    
    poc_symbols = extract_symbols_from_source(clean_poc)
    hallucinated = [
        sym for sym in poc_symbols
        if sym not in real_symbols
        and sym not in STDLIB_NAMES
        and sym not in locally_defined  # ← add this
    ]
    return hallucinated