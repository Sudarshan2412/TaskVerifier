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
NEMOTRON_MODEL = "nvidia/nemotron-3-super-120b-a12b"
DEFAULT_MODEL = DEEPSEEK_MODEL
DEFAULT_MAX_RESPONSE_TOKENS = int(os.environ.get("MAX_RESPONSE_TOKENS", "16384"))


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
            print(f"[DEBUG] Attempt {attempt + 1}/{max_retries}: Sending request to {BASE_URL}")
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
            print(f"[DEBUG] Attempt {attempt + 1}/{max_retries}: Sending request to {BASE_URL}")
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
