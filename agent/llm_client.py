# agent/llm_client.py

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

# OpenRouter Configuration
API_KEY = os.environ.get("OPEN_ROUTER_KEY")
BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

# Model Selection
DEEPSEEK_MODEL = "deepseek/deepseek-v4-flash"
DEEPSEEK_PRO_MODEL = "deepseek/deepseek-v4-pro"
NEMOTRON_MODEL = "nvidia/nemotron-3-super-120b-a12b"
NEMOTRON_ULTRA_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
MINIMAX_M3_MODEL = "minimax/minimax-m3"
MINIMAX_M25_MODEL = "minimax/minimax-m2.5"
QWEN_37_PLUS_MODEL = "qwen/qwen-3.7-plus"
KIMI_K26_MODEL = "moonshotai/kimi-k2.6"

DEFAULT_MODEL = DEEPSEEK_MODEL

# FIX (token-budget audit, Sept 2026): this used to default to 16384 and was
# applied identically to every turn -- a `TOOL_CALL: list_dir` turn that
# should cost a few dozen tokens got the same ceiling as a final PoC
# submission. Confirmed in logs/medium_cves_failures/arvo_3848: the model
# was actually hitting the old ceiling, producing a 55,023-char
# (~15.7k-token) response on attempt 1 alone. A real generator program is
# rarely more than a few hundred lines; a real tool call is a handful of
# lines. 4000 gives real submissions plenty of room while cutting off the
# "think out loud indefinitely" failure mode that was both the main token
# cost driver and (via code_extractor.py picking the wrong fragment out of
# a wall of text) a contributor to wasted attempts on medium/long CVEs.
# Still fully overridable via MAX_RESPONSE_TOKENS for anyone who needs more.
DEFAULT_MAX_RESPONSE_TOKENS = int(os.environ.get("MAX_RESPONSE_TOKENS", "4000"))


# ---------------------------------------------------------------------------
# Cumulative token usage tracking (process-lifetime -- i.e. one
# `python run_pipeline.py` invocation, since each run is a fresh process)
# ---------------------------------------------------------------------------
_cumulative_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}


def get_cumulative_usage() -> dict:
    """
    Return a copy of the running token-usage total for this process so far.

    Updated after every successful response from both call_llm() and
    call_llm_with_history() that includes a `usage` field -- OpenRouter
    always includes one for a real completion. Callers (e.g. agent_loop.py's
    per-turn logging) can read this after each call to show a live running
    total instead of only being able to reconstruct token spend after the
    fact from a saved report.
    """
    return dict(_cumulative_usage)


def reset_cumulative_usage() -> None:
    """Zero the running total. Not called anywhere in the pipeline itself --
    available for tests or tools that want a clean count without starting a
    new process."""
    for key in _cumulative_usage:
        _cumulative_usage[key] = 0


def _record_usage(usage: dict | None) -> None:
    """
    Add one response's token usage to the running total and print it, so
    token consumption is visible in the terminal as a run progresses,
    rather than only reconstructable afterward from a saved report.

    FIX (token-budget audit follow-up, Sept 2026): added alongside the
    DEFAULT_MAX_RESPONSE_TOKENS / MAX_TOOL_TURNS / context-budget reductions
    made earlier in that audit, so their effect on real token spend is
    visible live on a run instead of only inferable after the fact.

    `usage` is OpenRouter's standard OpenAI-compatible field
    (prompt_tokens / completion_tokens / total_tokens). Missing or
    malformed usage data is treated as "nothing to record," never as an
    error -- this must never be the reason a real, usable LLM response
    fails.
    """
    if not isinstance(usage, dict) or not any(
        usage.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens")
    ):
        return

    prompt = usage.get("prompt_tokens") or 0
    completion = usage.get("completion_tokens") or 0
    total = usage.get("total_tokens") or (prompt + completion)

    _cumulative_usage["prompt_tokens"] += prompt
    _cumulative_usage["completion_tokens"] += completion
    _cumulative_usage["total_tokens"] += total

    print(
        f"[USAGE] this call: {prompt:,} prompt + {completion:,} completion = {total:,} tokens"
        f"  |  running total this run: {_cumulative_usage['total_tokens']:,} tokens"
        f" ({_cumulative_usage['prompt_tokens']:,} prompt + {_cumulative_usage['completion_tokens']:,} completion)"
    )


def _extract_openrouter_error_reason(error_detail) -> str | None:
    """
    Pull OpenRouter's machine-readable error reason (e.g.
    'in_flight_budget_exhausted') out of a parsed error body, if present.

    error_detail is either the parsed JSON error body (dict) or raw
    response text (str, when the body wasn't valid JSON) -- see the
    `except: error_detail = e.response.text` fallback below. Only the dict
    case has a reason to extract.
    """
    if not isinstance(error_detail, dict):
        return None
    return error_detail.get("error", {}).get("metadata", {}).get("reason")


def _extract_message_content(choice: dict) -> str | None:
    """
    Normalize OpenRouter/OpenAI-compatible message content.

    Reasoning models may return a ``reasoning`` field while leaving
    ``content`` as None. That is not usable by the code extractor, so callers
    should retry instead of treating the reasoning text as the final PoC.
    """
    message = choice.get("message")
    if not isinstance(message, dict):
        print(f"[DEBUG] Choice missing message: {choice}")
        return None

    content = message.get("content")
    if isinstance(content, str):
        content = content.strip()
        return content or None

    if isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(part.get("text", ""))
        content = "".join(text_parts).strip()
        return content or None

    print(f"[DEBUG] Message missing content: {message}")
    return None


def call_llm(
    prompt: str, 
    model: str = DEFAULT_MODEL,
    temperature: float = 0.6, 
    max_retries: int = 2,
    max_response_tokens: int = DEFAULT_MAX_RESPONSE_TOKENS
) -> str:
    """
    Send a single prompt string to the OpenRouter API and return the model's text response.
    """
    if not API_KEY:
        raise RuntimeError("OPEN_ROUTER_KEY not found in environment.")

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Sudarshan2412/TaskVerifier",
        "X-Title": "TaskVerifier Agent",
    }
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_response_tokens,
        # OpenRouter reasoning models can otherwise return only
        # message.reasoning with content=None, which our pipeline cannot use.
        "reasoning": {"effort": "none", "exclude": True},
        "include_reasoning": False,
    }

    for attempt in range(max_retries):
        try:
            print(f"[DEBUG] API call retry {attempt + 1}/{max_retries} (network/rate-limit retries, unrelated to CVE attempt count): Sending request to {BASE_URL}")
            print(f"[DEBUG] Payload model: {payload['model']}")
            response = requests.post(BASE_URL, json=payload, headers=headers, timeout=(10, 120))
            print(f"[DEBUG] Response status: {response.status_code}")
            response.raise_for_status()
            data = response.json()
            
            # Defensive check for NoneType and empty choices
            if not data or "choices" not in data or not data["choices"] or data["choices"][0] is None:
                print(f"[DEBUG] Malformed or empty response: {data}")
                err_msg = data.get("error", {}).get("message", "Unknown error") if isinstance(data, dict) else "Non-dict response"
                raise RuntimeError(f"OpenRouter API returned no valid choices: {err_msg}")

            choice = data["choices"][0]
            result = _extract_message_content(choice)
            if result is None:
                if attempt < max_retries - 1:
                    print("[DEBUG] Empty assistant content; retrying request...")
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError("OpenRouter API returned empty assistant content after all retries.")

            print(f"[DEBUG] Successfully extracted response: {result[:50]}...")
            _record_usage(data.get("usage"))
            return result

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"[DEBUG] Connection error on attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise RuntimeError("OpenRouter API connection failed after all retries.")

        except requests.exceptions.HTTPError as e:
            print(f"[DEBUG] HTTP error on attempt {attempt + 1}: {e.response.status_code}")
            try:
                error_detail = e.response.json()
                print(f"[DEBUG] Error detail: {error_detail}")
            except:
                error_detail = e.response.text
            
            if e.response.status_code == 429:
                if attempt < max_retries - 1:
                    sleep_time = 15 + (2 ** attempt)
                    print(f"[DEBUG] Rate limited. Sleeping {sleep_time}s before retry...")
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError("OpenRouter API rate limit hit after all retries.")
            elif (
                e.response.status_code == 402
                and _extract_openrouter_error_reason(error_detail) == "in_flight_budget_exhausted"
            ):
                # FIX (Sept 2026, arvo:26952 baseline run): OpenRouter's own
                # error body describes this as transient -- a per-account
                # cap on requests reserved-but-not-yet-settled, distinct
                # from actually being out of credits -- and includes a
                # Retry-After header with its own estimate of when it'll
                # clear. Previously this fell into the `else` branch below
                # and raised immediately, wasting the entire attempt on a
                # condition OpenRouter itself expected to resolve on its own.
                if attempt < max_retries - 1:
                    retry_after = e.response.headers.get("Retry-After")
                    try:
                        sleep_time = float(retry_after) if retry_after is not None else 30.0
                    except ValueError:
                        sleep_time = 30.0
                    print(
                        f"[DEBUG] In-flight budget exhausted (transient OpenRouter "
                        f"billing cap, not necessarily low balance). Sleeping "
                        f"{sleep_time:.0f}s before retry..."
                    )
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError(f"OpenRouter API HTTP error: {e.response.status_code} - {error_detail}")
            else:
                raise RuntimeError(f"OpenRouter API HTTP error: {e.response.status_code} - {error_detail}")

        except (KeyError, IndexError, ValueError, TypeError) as e:
            print(f"[DEBUG] Parse error: {e}")
            raise RuntimeError(f"Unexpected response format from OpenRouter API: {e}")

    raise RuntimeError("call_llm failed after all retries.")


def call_llm_with_history(
    conversation: list[dict],
    model: str = DEFAULT_MODEL,
    temperature: float = 0.6,
    max_retries: int = 2,
    max_response_tokens: int = DEFAULT_MAX_RESPONSE_TOKENS
) -> str:
    """
    Send a multi-turn conversation to the OpenRouter API and return the model's reply.
    """
    if not API_KEY:
        raise RuntimeError("OPEN_ROUTER_KEY not found in environment.")

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/Sudarshan2412/TaskVerifier",
        "X-Title": "TaskVerifier Agent",
    }
    
    messages = []
    for turn in conversation:
        role = "assistant" if turn["role"] == "model" else turn["role"]
        messages.append({"role": role, "content": turn["content"]})

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_response_tokens,
        # OpenRouter reasoning models can otherwise return only
        # message.reasoning with content=None, which our pipeline cannot use.
        "reasoning": {"effort": "none", "exclude": True},
        "include_reasoning": False,
    }

    for attempt in range(max_retries):
        try:
            print(f"[DEBUG] API call retry {attempt + 1}/{max_retries} (network/rate-limit retries, unrelated to CVE attempt count): Sending request to {BASE_URL}")
            print(f"[DEBUG] Payload model: {payload['model']}")
            response = requests.post(BASE_URL, json=payload, headers=headers, timeout=(10, 120))
            print(f"[DEBUG] Response status: {response.status_code}")
            response.raise_for_status()
            data = response.json()

            # Defensive check for NoneType and empty choices
            if not data or "choices" not in data or not data["choices"] or data["choices"][0] is None:
                print(f"[DEBUG] Malformed or empty response: {data}")
                err_msg = data.get("error", {}).get("message", "Unknown error") if isinstance(data, dict) else "Non-dict response"
                raise RuntimeError(f"OpenRouter API returned no valid choices: {err_msg}")

            choice = data["choices"][0]
            result = _extract_message_content(choice)
            if result is None:
                if attempt < max_retries - 1:
                    print("[DEBUG] Empty assistant content; retrying request...")
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError("OpenRouter API returned empty assistant content after all retries.")

            print(f"[DEBUG] Successfully extracted response: {result[:50]}...")
            _record_usage(data.get("usage"))
            return result

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"[DEBUG] Connection error on attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise RuntimeError("OpenRouter API connection failed after all retries.")

        except requests.exceptions.HTTPError as e:
            print(f"[DEBUG] HTTP error on attempt {attempt + 1}: {e.response.status_code}")
            try:
                error_detail = e.response.json()
                print(f"[DEBUG] Error detail: {error_detail}")
            except:
                error_detail = e.response.text

            if e.response.status_code == 429:
                if attempt < max_retries - 1:
                    sleep_time = 15 + (2 ** attempt)
                    print(f"[DEBUG] Rate limited. Sleeping {sleep_time}s before retry...")
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError("OpenRouter API rate limit hit after all retries.")
            elif (
                e.response.status_code == 402
                and _extract_openrouter_error_reason(error_detail) == "in_flight_budget_exhausted"
            ):
                # FIX (Sept 2026, arvo:26952 baseline run): see the matching
                # comment in call_llm() above -- this is the function
                # agent_loop.py actually calls every turn, so it's the one
                # that hit the real 402 on arvo:26952's tool-use baseline
                # run. Same fix: OpenRouter's own error body calls this
                # transient and gives a Retry-After estimate, so back off
                # and retry instead of raising and losing the whole attempt.
                if attempt < max_retries - 1:
                    retry_after = e.response.headers.get("Retry-After")
                    try:
                        sleep_time = float(retry_after) if retry_after is not None else 30.0
                    except ValueError:
                        sleep_time = 30.0
                    print(
                        f"[DEBUG] In-flight budget exhausted (transient OpenRouter "
                        f"billing cap, not necessarily low balance). Sleeping "
                        f"{sleep_time:.0f}s before retry..."
                    )
                    time.sleep(sleep_time)
                else:
                    raise RuntimeError(f"OpenRouter API HTTP error: {e.response.status_code} - {error_detail}")
            else:
                raise RuntimeError(f"OpenRouter API HTTP error: {e.response.status_code} - {error_detail}")

        except (KeyError, IndexError, ValueError, TypeError) as e:
            print(f"[DEBUG] Parse error: {e}")
            raise RuntimeError(f"Unexpected response format from OpenRouter API: {e}")

    raise RuntimeError("call_llm_with_history failed after all retries.")


if __name__ == "__main__":
    print("[DEBUG] Starting test with API key configured." if API_KEY else "[DEBUG] API KEY MISSING")
    print(f"[DEBUG] BASE_URL: {BASE_URL}")
    print(f"Testing OpenRouter API connection with {DEFAULT_MODEL}...")
    try:
        reply = call_llm("Say hello.", temperature=0.2)
        print("Response:", reply)
        print("\nAPI connection OK.")
    except Exception as e:
        print(f"\nAPI connection FAILED: {e}")