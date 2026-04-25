import re


# Standard C library names — we don't flag these even if not in target source
STDLIB_NAMES = {
    'main', 'printf', 'malloc', 'free', 'memcpy', 'memset',
    'strlen', 'strcmp', 'strcpy', 'fopen', 'fclose', 'fprintf',
    'exit', 'abort', 'puts', 'sprintf', 'snprintf', 'atoi',
    'calloc', 'realloc', 'memmove', 'NULL', 'stderr', 'stdout', 'stdin'
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

    # Extract global variable names (simple heuristic: type name; at start of line)
    global_var_pattern = re.compile(r'^(?:static\s+)?(?:int|char|float|double|long|unsigned|void\s*\*?)\s+([a-zA-Z_]\w*)', re.MULTILINE)
    symbols.update(global_var_pattern.findall(source_code))

    return symbols


def detect_hallucinations(target_source_path: str, poc_code: str) -> list:
    """
    Main function. 
    - target_source_path: path to the real vulnerable C file
    - poc_code: the string of C code the AI generated
    Returns: list of symbol names the AI used that don't exist in the target source.
    """
    # Read the real source file
    try:
        with open(target_source_path, 'r') as f:
            source_code = f.read()
    except FileNotFoundError:
        # If we can't read the source, skip hallucination check
         return []

    # What symbols exist in the real source?
    real_symbols = extract_symbols_from_source(source_code)

    # What symbols does the AI's PoC use?
    poc_symbols = extract_symbols_from_source(poc_code)

    # Hallucinated = in PoC but NOT in real source AND not a standard lib name
    hallucinated = [
        sym for sym in poc_symbols
        if sym not in real_symbols and sym not in STDLIB_NAMES
    ]

    return hallucinated