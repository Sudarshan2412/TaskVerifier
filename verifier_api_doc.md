# Verifier API — for Prarthana

## How to import
from verifier import verify
from verifier.hallucination_detector import detect_hallucinations

## Main function: verify()

result = verify(poc_code, target_source_path)

### Parameters
- poc_code (str): The raw C code string the LLM generated
- target_source_path (str): Path to the real vulnerable C file
  (this is the 'target_source' field in cybergym_subset.json)

### Returns: VerifierResult object with these fields
- result.status (str): one of:
    'compile_fail'  — code did not compile
    'no_crash'      — code compiled and ran fine, no vulnerability triggered
    'crash'         — code crashed (vulnerability triggered!)
    
- result.feedback (str): 3-5 sentence string ready to inject into next prompt

- result.feedback (str): 3-5 sentence string ready to inject into next prompt

- result.details (dict): raw data from each stage if you need it

### Example usage in agent_loop.py
result = verify(generated_code, cve_entry['target_source'])
if result.status == 'crash':
    print("SUCCESS — vulnerability triggered!")
else:
    # inject result.feedback into the next prompt
    next_prompt = build_retry_prompt(feedback=result.feedback)

## Hallucination detector (called inside verify() automatically)
## But you can also call it standalone:
hallucinated = detect_hallucinations(target_source_path, poc_code)
# returns a list like: ['fake_function', 'made_up_var']