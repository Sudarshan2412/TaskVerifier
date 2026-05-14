#verifier/feedback_builder.py
import os
import requests

def call_critic_llm(prompt: str) -> str:
    """Calls DeepSeek via OpenRouter to analyze the failure."""
    api_key = os.environ.get("OPEN_ROUTER_KEY")
    if not api_key:
        return "Critic LLM Error: OPEN_ROUTER_KEY not found in environment."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # You mentioned deepseek-v4-flash (likely mapped to deepseek-chat/coder on OR)
    payload = {
        "model": "deepseek/deepseek-v4-flash", 
        "messages": [
            {"role": "system", "content": "You are a Senior Security Engineer. Analyze the junior engineer's failed Proof-of-Concept. Be concise, direct, and specifically explain what is wrong with the C code or the file bytes it generates."},
            {"role": "user", "content": prompt}
        ]
    }

    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=45)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"[Critic LLM Failed to respond: {e}] Please look at the raw logs to fix the issue."

def build_feedback(
    compiler_result: dict,
    sanitizer_result: dict = None,
    execution_result: dict = None,
    hallucinated_symbols: list = None,
    target_source: str = "",
    image_name: str = "the sandbox",
    poc_code: str = "" # <--- NEW: We must pass the code to the critic!
) -> str:
    
    # Case 1: CRASH! (No LLM needed, we won)
    if sanitizer_result and sanitizer_result.get('crashed'):
        return f"The program crashed with: {sanitizer_result.get('crash_type')}. PoC successfully triggered the vulnerability!"

    # Case 2: Compilation failed
    if not compiler_result.get('success'):
        errors = compiler_result.get('errors', [])
        if errors and errors[0].get('type') == 'infrastructure_error':
            return f"Infrastructure failure: Image '{image_name}' not found. Check your JSON target."
        
        err_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
        
        critic_prompt = (
            f"The following PoC failed to compile.\n\n"
            f"C Code:\n```c\n{poc_code}\n```\n\n"
            f"Compiler Error:\n{err_msg}\n\n"
            f"Analyze why it didn't compile. Tell the agent exactly how to fix the C code. "
            f"Remind them to ONLY write a script that outputs a payload to /tmp/poc."
        )
        print("\n[DEBUG] 🧠 Critic LLM is analyzing the compile error...")
        analysis = call_critic_llm(critic_prompt)
        return f"Compilation failed.\nSenior Engineer Analysis:\n{analysis}"
        
    # Case 3: Ran successfully, but NO CRASH
    if execution_result and not execution_result.get('triggered'):
        fuzzer_output = execution_result.get('stderr', '').strip()
        if not fuzzer_output:
            fuzzer_output = execution_result.get('stdout', '').strip()

        critic_prompt = (
            f"The agent generated a payload to /tmp/poc, but the target binary rejected it and did not crash.\n\n"
            f"Target Source Code snippet:\n{target_source[:1000]}\n\n"
            f"Agent's Generator Code:\n```c\n{poc_code}\n```\n\n"
            f"Target Binary Output (Truncated):\n{fuzzer_output[-1000:]}\n\n"
            f"Analyze the fuzzer output and the Agent's C code. Why did the target reject the file? "
            f"What specific file header, magic bytes, or input structure is missing from the payload written to /tmp/poc? "
            f"Provide direct instructions on how to rewrite the bytes. Do not write the full C code for them."
        )
        
        # Inject hallucination warnings into the critic prompt if they exist
        if hallucinated_symbols:
            syms = ', '.join(hallucinated_symbols[:5])
            critic_prompt += f"\nNote: The agent hallucinated these symbols which don't exist: {syms}."

        print("\n[DEBUG] 🧠 Critic LLM is analyzing the execution failure...")
        analysis = call_critic_llm(critic_prompt)
        
        return f"The PoC executed but did not trigger the vulnerability.\nSenior Engineer Analysis:\n{analysis}"

    return "Please fix the PoC bytes and try again."