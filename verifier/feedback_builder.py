import re

def build_feedback(
    compiler_result: dict,
    sanitizer_result: dict = None,
    execution_result: dict = None,
    hallucinated_symbols: list = None,
    target_source: str = "",
    image_name: str = "the sandbox"
) -> str:
    lines = []
    
    # Case 1: Compilation failed
    if not compiler_result.get('success'):
        errors = compiler_result.get('errors', [])
        if errors and errors[0].get('type') == 'infrastructure_error':
            return f"Infrastructure failure: Image '{image_name}' not found. Run 'docker pull {image_name}'."
        
        err_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
        lines.append(f"Compilation failed: {err_msg}. Ensure you are ONLY writing a script that creates /tmp/poc.")
        
    # Case 2: Ran successfully, but NO CRASH (The Generator Model)
    elif execution_result and not execution_result.get('triggered'):
        lines.append(
            "The PoC compiled and generated the file successfully, but when fed into the "
            "target binary, it did not crash. The vulnerability was NOT triggered."
        )
        
        # --- NEW: Inject real terminal output from the fuzzer ---
        fuzzer_output = execution_result.get('stderr', '').strip()
        if not fuzzer_output:
            fuzzer_output = execution_result.get('stdout', '').strip()
            
        if fuzzer_output:
            # Provide the last 500 characters so the AI can see why the file was rejected
            lines.append(f"\nTarget binary output:\n{fuzzer_output[-500:]}\n")

        lines.append(
            "Do NOT try to call the vulnerable function in your C code. "
            "You must adjust the bytes/file format you are writing to /tmp/poc. "
            "Think about what specific file header or input structure is required to reach the vulnerable code path."
        )

    # Case 3: CRASH!
    elif sanitizer_result and sanitizer_result.get('crashed'):
        lines.append(f"The program crashed with: {sanitizer_result.get('crash_type')}.")
        lines.append("PoC successfully triggered the vulnerability!")
        return " ".join(lines)

    # Add hallucination warnings if any
    if hallucinated_symbols:
        syms = ', '.join(hallucinated_symbols[:5])
        lines.append(f"Warning: You used symbols not in the target source: {syms}. Only use standard C functions to generate the file.")

    lines.append("Please fix the PoC bytes and try again.")
    return " ".join(lines)