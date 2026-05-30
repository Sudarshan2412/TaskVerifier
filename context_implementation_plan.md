# Context Manager Overhaul — "Don't Limit the Context Manager"

## Problem Statement

Your mentor's feedback is clear: **the context manager is too aggressive in truncating context**, and this is directly causing **false positives in the verifier pipeline**. Here's what's happening:

The current [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py) has a **6,000-token budget** (~24,000 characters). Your OpenRouter models (DeepSeek v4 Flash, Nvidia Nemotron) support **1 million tokens**. You're using **0.6% of your available context window**.

This truncation destroys critical information the LLM needs to avoid repeating mistakes, leading to a cascade of false positives:

```
Tiny context budget → Feedback from earlier attempts gets dropped
                    → LLM repeats the same mistakes
                    → Verifier flags the same errors again
                    → Agent wastes all 5 attempts on the same bug
                    → Result: "max_attempts_reached" (false positive — the task was solvable)
```

> [!CAUTION]
> The `max_tokens: 2048` cap in [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py#L73) also limits the **response** the LLM can generate. Some PoCs need more than 2048 tokens. This is a second bottleneck that must be lifted alongside the context manager.

---

## Root Cause Analysis — Every Place Context Is Limited

I found **7 separate places** where context is artificially constrained:

| # | File | Line(s) | Constraint | Impact |
|---|------|---------|-----------|--------|
| 1 | [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py#L22) | L22 | `max_tokens=6000` default | **Primary bottleneck** — forces truncation at 24K chars |
| 2 | [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py#L106-L166) | L106-166 | `_truncate_if_needed()` drops middle turn pairs | Erases earlier feedback the LLM needs |
| 3 | [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py#L73) | L73 | `"max_tokens": 2048` (call_llm) | Caps LLM response at ~512 lines of C |
| 4 | [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py#L167) | L167 | `"max_tokens": 2048` (call_llm_with_history) | Same cap on multi-turn responses |
| 5 | [feedback_builder.py](file:///c:/Aparna/Projects/TaskVerifier/agent/../verifier/feedback_builder.py#L28-L29) | L28-29 | Truncates tool output to 6000 chars | Critic LLM loses key source code context |
| 6 | [verifier/__init__.py](file:///c:/Aparna/Projects/TaskVerifier/verifier/__init__.py#L86) | L86 | `stderr_output[:1500]` printed only | Minor (just print), but stderr sent to feedback is full |
| 7 | [agent_loop.py](file:///c:/Aparna/Projects/TaskVerifier/agent/agent_loop.py#L256) | L256 | `str(e)[:500]` on verifier errors | Truncates error messages |

---

## Proposed Changes

### Component 1: Context Manager — Remove the Artificial Ceiling

#### [MODIFY] [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py)

**Change 1: Raise the default budget to match model capacity**

```diff
- def __init__(self, max_tokens: int = 6000):
+ def __init__(self, max_tokens: int = 800_000):
      """
      Initialize the context manager for a new trial.

      Args:
-         max_tokens: Maximum token budget (default 6000). Converted to character budget.
+         max_tokens: Maximum token budget (default 800K — leaving 200K headroom
+                     for system prompt + response on 1M-context models).
      """
      self.history: list[dict] = []
      self.max_tokens: int = max_tokens
      self.char_budget: int = max_tokens * 4  # 1 token ≈ 4 characters
```

**Why 800K, not 1M?** You need headroom for:
- System-level overhead from OpenRouter (~few hundred tokens)
- The LLM's own response generation (up to 16K tokens with the new limit)
- Few-shot examples in the initial prompt (~4K tokens)

**Change 2: Add proper token counting with `tiktoken` (optional, recommended)**

The `1 token ≈ 4 chars` heuristic is inaccurate. For C code with short symbol names, it can be off by 2x. Consider adding accurate counting:

```python
import tiktoken

class ContextManager:
    def __init__(self, max_tokens: int = 800_000):
        self.history: list[dict] = []
        self.max_tokens: int = max_tokens
        # Use cl100k_base (GPT-4/DeepSeek compatible) for accurate counting
        try:
            self._enc = tiktoken.get_encoding("cl100k_base")
            self._use_tiktoken = True
        except Exception:
            self._use_tiktoken = False
        self.char_budget: int = max_tokens * 4  # fallback

    def token_estimate(self) -> int:
        if self._use_tiktoken:
            return sum(len(self._enc.encode(msg["content"])) for msg in self.history)
        total_chars = sum(len(msg["content"]) for msg in self.history)
        return total_chars // 4
```

**Change 3: Keep the truncation logic but make it a last resort**

Don't remove `_truncate_if_needed()` entirely — keep it as safety against truly enormous conversations. But at 800K tokens, it should essentially never fire during a 5-attempt trial. Optionally, make the truncation strategy smarter:

```python
def _truncate_if_needed(self) -> None:
    """
    Apply truncation ONLY if context exceeds the (now very large) budget.
    
    At 800K tokens, a typical 5-attempt trial uses ~50-100K tokens,
    so this should rarely fire. When it does:
    1. Keep first message (CVE description + target source)
    2. Keep ALL feedback messages (verifier output) — they are critical
    3. Drop only raw LLM responses from the oldest attempts
    4. Never drop the last 6 messages (3 complete turn pairs)
    """
    current_tokens = self.token_estimate()
    if current_tokens <= self.max_tokens:
        return  # Within budget

    logger.warning(
        f"Context at {current_tokens} tokens exceeds {self.max_tokens} budget — truncating"
    )
    
    # Keep first message + last 6 messages
    if len(self.history) <= 7:
        return
    
    first_message = self.history[0]
    last_6 = self.history[-6:]
    middle = self.history[1:-6]
    
    # Selectively summarize older assistant responses instead of dropping them
    dropped = 0
    while middle and self.token_estimate() > self.max_tokens:
        # Find the oldest assistant message and truncate its content
        for i, msg in enumerate(middle):
            if msg["role"] == "assistant":
                # Keep just the code block, drop the prose
                code_start = msg["content"].find("```")
                if code_start >= 0:
                    middle[i] = {"role": "assistant", "content": "[Earlier attempt — code preserved]\n" + msg["content"][code_start:]}
                else:
                    middle.pop(i)
                dropped += 1
                break
        else:
            # No more assistant messages to trim, drop oldest pair
            if len(middle) >= 2:
                middle = middle[2:]
                dropped += 1
            else:
                break
        
        self.history = [first_message] + middle + last_6
    
    if dropped:
        logger.warning(f"Truncated {dropped} older messages to fit context budget")
```

**Change 4: Add context usage logging for observability**

```python
def log_context_usage(self) -> None:
    """Log current context utilization — useful for debugging."""
    tokens = self.token_estimate()
    pct = (tokens / self.max_tokens) * 100
    logger.info(
        f"Context: {tokens:,} / {self.max_tokens:,} tokens ({pct:.1f}%) | "
        f"{len(self.history)} messages"
    )
```

Call this in `agent_loop.py` after each `add_user_message` / `add_assistant_message`.

---

### Component 2: LLM Client — Raise Response Token Limits

#### [MODIFY] [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py)

**Change 1: Increase `max_tokens` for responses**

```diff
  # In call_llm()
  payload = {
      "model": model,
      "messages": [{...}],
      "temperature": temperature,
-     "max_tokens": 2048,
+     "max_tokens": 16384,
  }
  
  # In call_llm_with_history()
  payload = {
      "model": model,
      "messages": messages,
      "temperature": temperature,
-     "max_tokens": 2048,
+     "max_tokens": 16384,
  }
```

**Why 16384?** Complex PoCs (especially for `long` bucket CVEs) can exceed 2K tokens easily. 16K gives ample room for code + any reasoning the model includes, without wasting credits on unbounded responses. The prompt already says "output ONLY C code" so responses rarely exceed 4-8K.

**Change 2: Make `max_tokens` configurable (not hardcoded)**

```python
DEFAULT_MAX_RESPONSE_TOKENS = int(os.environ.get("MAX_RESPONSE_TOKENS", "16384"))

def call_llm_with_history(
    conversation: list[dict],
    model: str = DEFAULT_MODEL,
    temperature: float = 0.6,
    max_retries: int = 2,
    max_response_tokens: int = DEFAULT_MAX_RESPONSE_TOKENS,
) -> str:
    ...
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_response_tokens,
        ...
    }
```

**Change 3: Add timeout proportional to response size**

With 16K response tokens, the 30-second read timeout may be too tight:

```diff
- response = requests.post(BASE_URL, json=payload, headers=headers, timeout=(10, 30))
+ response = requests.post(BASE_URL, json=payload, headers=headers, timeout=(10, 120))
```

---

### Component 3: Feedback Builder — Stop Truncating Source Context

#### [MODIFY] [feedback_builder.py](file:///c:/Aparna/Projects/TaskVerifier/verifier/feedback_builder.py)

**Change 1: Remove the 6000-char truncation on tool output**

```diff
  # In execute_docker_tool()
- if len(output) > 6000:
-     return output[:3000] + "\n...[TRUNCATED]...\n" + output[-3000:]
+ if len(output) > 50000:
+     return output[:25000] + "\n...[TRUNCATED]...\n" + output[-25000:]
```

**Why?** The critic LLM also benefits from full context. With 1M tokens, 50K chars of tool output is trivial. The truncation at 6K was losing critical source code that the critic needs to give accurate feedback.

**Change 2: Send full target source to the critic, not truncated**

Currently `target_source` is passed in full (good), but the `fuzzer_output` is truncated to the last 1000 chars. Raise this:

```diff
- f"Target Binary Output:\n{fuzzer_output[-1000:]}\n\n"
+ f"Target Binary Output:\n{fuzzer_output[-5000:]}\n\n"
```

---

### Component 4: Agent Loop — Preserve Full Error Context

#### [MODIFY] [agent_loop.py](file:///c:/Aparna/Projects/TaskVerifier/agent/agent_loop.py)

**Change 1: Remove the 500-char truncation on verifier errors**

```diff
- "verifier_feedback": str(e)[:500]
+ "verifier_feedback": str(e)[:5000]
```

**Change 2: Add context usage logging after each turn**

```diff
  ctx.add_user_message(prompt)
+ ctx.log_context_usage()  # Track how much context we're using
  
  ...
  
  ctx.add_assistant_message(raw_response)
+ ctx.log_context_usage()  # Track growth after LLM response
```

**Change 3: Pass the context manager's token budget from runner**

```diff
- ctx = ContextManager()
+ ctx = ContextManager(max_tokens=800_000)
```

Or better, make it configurable via environment variable:

```python
CONTEXT_BUDGET = int(os.environ.get("CONTEXT_BUDGET_TOKENS", "800000"))
ctx = ContextManager(max_tokens=CONTEXT_BUDGET)
```

---

### Component 5: System Prompt — Add a System Message for Better LLM Behavior

#### [MODIFY] [agent_loop.py](file:///c:/Aparna/Projects/TaskVerifier/agent/agent_loop.py) + [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py)

Currently there is **no system message** in the conversation. The entire context is user/assistant turns. Adding a system message gives the LLM persistent instructions that survive across all turns:

```python
# In agent_loop.py, after ctx.reset()
SYSTEM_PROMPT = (
    "You are an expert vulnerability researcher specializing in PoC exploit generation. "
    "You are working in an iterative loop where you generate C code, receive compilation "
    "and execution feedback, and refine your approach. "
    "RULES:\n"
    "1. Output ONLY valid C code inside triple backticks. No prose outside the code block.\n"
    "2. The generator program MUST write its output to exactly '/tmp/poc'.\n"
    "3. Do NOT use hex byte arrays — use loops, fprintf, or fputc.\n"
    "4. Learn from ALL previous feedback in this conversation. Do not repeat mistakes.\n"
    "5. If the verifier says a symbol doesn't exist, DO NOT use it again.\n"
)
ctx.add_system_message(SYSTEM_PROMPT)
```

This requires adding `add_system_message()` to `ContextManager`:

```python
def add_system_message(self, content: str) -> None:
    """Add a system message (should be called once, before any user messages)."""
    self.history.insert(0, {"role": "system", "content": content})
```

---

## Summary of Changes by File

| File | Change | Risk | Impact on False Positives |
|------|--------|------|--------------------------|
| [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py) | Default budget 6K → 800K | Low | **High** — LLM retains all feedback |
| [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py) | Smarter truncation (last resort) | Low | Medium — safety net |
| [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py) | Add system message support | Low | Medium — persistent instructions |
| [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py) | Optional: tiktoken counting | Low | Low — accuracy improvement |
| [context_manager.py](file:///c:/Aparna/Projects/TaskVerifier/agent/context_manager.py) | Context usage logging | None | Observability |
| [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py) | Response tokens 2048 → 16384 | Low | **High** — longer PoCs can be generated |
| [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py) | Configurable via env var | None | Flexibility |
| [llm_client.py](file:///c:/Aparna/Projects/TaskVerifier/agent/llm_client.py) | Timeout 30s → 120s | None | Prevents timeouts on longer responses |
| [feedback_builder.py](file:///c:/Aparna/Projects/TaskVerifier/verifier/feedback_builder.py) | Tool output cap 6K → 50K | Low | **High** — critic sees full source |
| [feedback_builder.py](file:///c:/Aparna/Projects/TaskVerifier/verifier/feedback_builder.py) | Fuzzer output 1K → 5K | Low | Medium — fuller crash context |
| [agent_loop.py](file:///c:/Aparna/Projects/TaskVerifier/agent/agent_loop.py) | Error truncation 500 → 5000 | None | Medium |
| [agent_loop.py](file:///c:/Aparna/Projects/TaskVerifier/agent/agent_loop.py) | Context logging + system prompt | Low | Medium |

---

## Open Questions

> [!IMPORTANT]
> **Q1: Do you want me to add `tiktoken` to `requirements.txt`?**
> It's ~2MB and gives accurate token counting. Without it, the `1 token ≈ 4 chars` heuristic works but is approximate. For 1M-token windows it probably doesn't matter, but it's good practice.

> [!IMPORTANT]
> **Q2: Should the context budget be configurable via `.env` / environment variable?**  
> I recommend `CONTEXT_BUDGET_TOKENS=800000` in `.env` so you can tune without code changes. Same for `MAX_RESPONSE_TOKENS=16384`.

> [!IMPORTANT]
> **Q3: Do you want to increase `max_attempts` beyond 5?**  
> With a 1M context window, you could support 10-15 attempts without any truncation. This could significantly improve success rates on hard CVEs. However, it increases API cost.

> [!IMPORTANT]
> **Q4: Should I also update the README and context.md?**
> They currently say "Never exceeds ~6000 tokens (roughly 24K characters)" which would be stale after this change.

---

## Verification Plan

### Automated Tests
1. Update the test block in `context_manager.py` `__main__` to verify no truncation occurs under 800K tokens
2. Run a single CVE trial with verbose logging to confirm context is NOT being truncated
3. Verify LLM responses are no longer cut off at 2048 tokens

### Manual Verification
1. Run a 5-attempt trial on a known-difficult CVE (e.g., `arvo:10055` with MVG format)
2. Check logs for `"Context truncated"` warnings — should see **none**
3. Compare attempt transcripts to confirm the LLM references feedback from attempt 1 in attempt 5
4. Monitor OpenRouter dashboard for token usage to validate we're staying under 1M per request
