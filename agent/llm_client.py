# agent/llm_client.py

import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.environ["GROQ_API_KEY"]
BASE_URL = "https://api.groq.com/openai/v1/chat/completions"


def call_llm(prompt: str, temperature: float = 0.6, max_retries: int = 2) -> str:
    """
    Send a single prompt string to the Groq API and return the model's text response.

    Args:
        prompt: The full prompt string to send.
        temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative).
        max_retries: Number of retry attempts on timeout or server errors.

    Returns:
        The model's response as a plain string.

    Raises:
        RuntimeError: If all retries fail or the response is malformed.
    """
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": 2048
    }

    for attempt in range(max_retries):
        try:
            print(f"[DEBUG] Attempt {attempt + 1}/{max_retries}: Sending request to {BASE_URL}")
            print(f"[DEBUG] Payload model: {payload['model']}")
            response = requests.post(BASE_URL, json=payload, headers=headers, timeout=30)
            print(f"[DEBUG] Response status: {response.status_code}")
            response.raise_for_status()
            data = response.json()
            print(f"[DEBUG] Response data keys: {data.keys()}")
            result = data["choices"][0]["message"]["content"]
            print(f"[DEBUG] Successfully extracted response: {result[:50]}...")
            return result

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"[DEBUG] Connection error on attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise RuntimeError("Groq API connection failed after all retries.")

        except requests.exceptions.HTTPError as e:
            print(f"[DEBUG] HTTP error on attempt {attempt + 1}: {e.response.status_code}")
            if e.response.status_code == 429:
                raise RuntimeError("Groq API rate limit hit. Wait before retrying.")
            else:
                raise RuntimeError(f"Groq API HTTP error: {e}")

        except (KeyError, IndexError, ValueError) as e:
            print(f"[DEBUG] Parse error: {e}")
            raise RuntimeError(f"Unexpected response format from Groq API: {e}")

    raise RuntimeError("call_llm failed after all retries.")


def call_llm_with_history(
    conversation: list[dict],
    temperature: float = 0.6,
    max_retries: int = 2
) -> str:
    """
    Send a multi-turn conversation to the Groq API and return the model's reply.

    Args:
        conversation: List of turn dicts. Each dict must have:
                      - "role": "user" or "assistant"
                      - "text": the message string for that turn
        temperature: Sampling temperature.
        max_retries: Retry attempts on failure.

    Returns:
        The model's latest reply as a plain string.

    Example input:
        [
            {"role": "user", "text": "Write a PoC for CVE-2021-1234."},
            {"role": "assistant", "text": "Here is an attempt: ..."},
            {"role": "user", "text": "That did not compile. Fix the malloc call."}
        ]
    """
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Convert conversation to OpenAI/Groq format (role can be "user" or "assistant", not "model")
    messages = []
    for turn in conversation:
        role = "assistant" if turn["role"] == "model" else turn["role"]
        messages.append({"role": role, "content": turn["text"]})

    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": messages,
        "temperature": temperature,
        "max_tokens": 2048
    }

    for attempt in range(max_retries):
        try:
            print(f"[DEBUG] Attempt {attempt + 1}/{max_retries}: Sending request to {BASE_URL}")
            print(f"[DEBUG] Payload model: {payload['model']}")
            response = requests.post(BASE_URL, json=payload, headers=headers, timeout=30)
            print(f"[DEBUG] Response status: {response.status_code}")
            response.raise_for_status()
            data = response.json()
            print(f"[DEBUG] Response data keys: {data.keys()}")
            result = data["choices"][0]["message"]["content"]
            print(f"[DEBUG] Successfully extracted response: {result[:50]}...")
            return result

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"[DEBUG] Connection error on attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
            else:
                raise RuntimeError("Groq API connection failed after all retries.")

        except requests.exceptions.HTTPError as e:
            print(f"[DEBUG] HTTP error on attempt {attempt + 1}: {e.response.status_code}")
            if e.response.status_code == 429:
                raise RuntimeError("Groq API rate limit hit. Wait before retrying.")
            else:
                raise RuntimeError(f"Groq API HTTP error: {e}")

        except (KeyError, IndexError, ValueError) as e:
            print(f"[DEBUG] Parse error: {e}")
            raise RuntimeError(f"Unexpected response format from Groq API: {e}")

    raise RuntimeError("call_llm_with_history failed after all retries.")


# ---------------------------------------------------------------------------
# Quick sanity-check — run this file directly to verify your key works:
#   python agent/llm_client.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"[DEBUG] Starting test with API key: {API_KEY[:20]}...")
    print(f"[DEBUG] BASE_URL: {BASE_URL}")
    print("Testing Groq API connection...")
    reply = call_llm("Say hello.", temperature=0.2)
    print("Response:", reply)
    print("\nAPI connection OK.")
