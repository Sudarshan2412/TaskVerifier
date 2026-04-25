def build_feedback(
    compiler_result: dict,
    sanitizer_result: dict = None,
    execution_result: dict = None,
    hallucinated_symbols: list = None
) -> str:
    """
    Takes results from the verifier stages and builds a short, clear
    feedback string to inject into the AI's next prompt.
    """
    lines = []

    # Case 1: Code didn't compile
    if not compiler_result.get('success'):
        errors = compiler_result.get('errors', [])
        if errors:
            first = errors[0]
            # handle both key names — 'line' or no line at all
            line_info = f" at line {first['line']}" if 'line' in first and first['line'] else ""
            lines.append(
                f"Compilation failed{line_info}: {first.get('message', 'unknown error')}."
            )
            if len(errors) > 1:
                lines.append(f"There are {len(errors)} total errors.")
        else:
            lines.append("Compilation failed with unknown errors.")

    # Case 2: Code compiled but ran cleanly (no crash)
    elif execution_result and not execution_result.get('triggered'):
        lines.append(execution_result['message'])

    # Case 3: Code crashed — tell the AI what type of crash happened
    elif sanitizer_result and sanitizer_result.get('crashed'):
        ct = sanitizer_result.get('crash_type', 'unknown')
        addr = sanitizer_result.get('crash_address', 'unknown')
        frames = sanitizer_result.get('stack_frames', [])
        lines.append(f"The program crashed with a {ct} at address {addr}.")
        if frames:
            f0 = frames[0]
            lines.append(f"Crash occurred in function '{f0['function']}' at {f0['location']}.")

    # Add hallucination warning if any invented symbols were detected
    if hallucinated_symbols:
        syms = ', '.join(hallucinated_symbols[:5])
        lines.append(
            f"Warning: your code used symbols not found in the target source: {syms}. "
            f"These do not exist — only use functions and variables from the target file."
        )
    lines.append("Please fix the PoC and try again.")
    return ' '.join(lines)