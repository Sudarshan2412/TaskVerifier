"""
context_manager.py — Maintains conversation history for multi-turn Groq API interactions.

Manages the history of messages exchanged with the LLM across multiple retry attempts
for a single CVE trial, with token budget constraints and truncation strategy.
"""

import logging
import copy

logger = logging.getLogger(__name__)


class ContextManager:
    """
    Manages conversation history for multi-turn LLM interactions.
    
    Maintains history in Groq's OpenAI-compatible chat format and enforces
    token budget constraints with intelligent truncation.
    """

    def __init__(self, max_tokens: int = 800_000):
        """
        Initialize the context manager for a new trial.
        
        Args:
            max_tokens: Maximum token budget (default 800K).
        """
        self.history: list[dict] = []
        self.max_tokens: int = max_tokens
        try:
            # pyrefly: ignore [missing-import]
            import tiktoken
            self._enc = tiktoken.get_encoding("cl100k_base")
            self._use_tiktoken = True
        except ImportError:
            self._use_tiktoken = False
        self.char_budget: int = max_tokens * 4  # fallback

    def add_system_message(self, content: str) -> None:
        """Add a system message (should be called once, before any user messages)."""
        self.history.insert(0, {"role": "system", "content": content})

    def add_user_message(self, content: str) -> None:
        """
        Add a user message to the history.
        
        Args:
            content: The user message content string
        """
        # Validate: warn if last message was also "user"
        if self.history and self.history[-1]["role"] == "user":
            logger.warning("Two consecutive 'user' messages detected. This may indicate a bug in agent_loop.py")

        # Warn if content is empty
        if not content or not content.strip():
            logger.warning("Empty user message content. Adding anyway.")

        # Append message
        self.history.append({"role": "user", "content": content})

        # Truncate if needed
        self._truncate_if_needed()

    def add_assistant_message(self, content: str) -> None:
        """
        Add an assistant message to the history.
        
        Args:
            content: The assistant message content string
        """
        # Validate: warn if history is empty or last message was also "assistant"
        if not self.history:
            logger.warning("Adding 'assistant' message but history is empty. Expected a 'user' message first.")
        elif self.history[-1]["role"] == "assistant":
            logger.warning("Two consecutive 'assistant' messages detected. This may indicate a bug in agent_loop.py")

        # Append message
        self.history.append({"role": "assistant", "content": content})

        # Truncate if needed
        self._truncate_if_needed()

    def get_history(self) -> list[dict]:
        """
        Get a copy of the current conversation history.
        
        Returns a copy to prevent caller from mutating internal state.
        This list is in the format expected by Groq's chat.completions.create(messages=...).
        
        Returns:
            Copy of the history list
        """
        return copy.deepcopy(self.history)

    def reset(self) -> None:
        """
        Reset the history for a new CVE trial.
        
        Clears all messages and starts fresh.
        """
        self.history = []
        logger.debug("Context reset for new trial")

    def token_estimate(self) -> int:
        """
        Estimate the current token count of the history.
        
        Uses accurate tiktoken count if available, otherwise simple approximation: 1 token ≈ 4 characters.
        
        Returns:
            Estimated token count
        """
        if self._use_tiktoken:
            return sum(len(self._enc.encode(msg["content"])) for msg in self.history)
        total_chars = sum(len(msg["content"]) for msg in self.history)
        return total_chars // 4

    def log_context_usage(self) -> None:
        """Log current context utilization — useful for debugging."""
        tokens = self.token_estimate()
        pct = (tokens / self.max_tokens) * 100
        logger.info(
            f"Context: {tokens:,} / {self.max_tokens:,} tokens ({pct:.1f}%) | "
            f"{len(self.history)} messages"
        )

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


if __name__ == "__main__":
    """Test block with multi-turn conversation simulation."""
    cm = ContextManager(max_tokens=200)  # tiny budget to force truncation easily

    # Simulate a 3-attempt trial
    cm.add_user_message("CVE-2021-9999: Write a PoC that triggers heap-buffer-overflow. " * 10)
    print(f"After initial prompt — estimated tokens: {cm.token_estimate()}")

    cm.add_assistant_message("```c\nint main() { char buf[8]; buf[20] = 1; }\n```")
    cm.add_user_message("Attempt 1 failed. Compiler error at line 1: implicit declaration.")
    cm.add_assistant_message("```c\n#include <string.h>\nint main() { char buf[8]; strcpy(buf, \"AAAAAAAAAAAAAAAA\"); }\n```")
    cm.add_user_message("Attempt 2 failed. ASan: heap-buffer-overflow. Stack frame: main+0x14.")
    cm.add_assistant_message("```c\n#include <string.h>\nint main() { char buf[4]; memcpy(buf, \"AAAAAAAA\", 8); }\n```")

    print(f"After 3 attempts — estimated tokens: {cm.token_estimate()}")
    print(f"History length: {len(cm.get_history())} messages")
    print("History roles:", [m["role"] for m in cm.get_history()])

    # Test reset
    cm.reset()
    print(f"\nAfter reset — history length: {len(cm.get_history())}")

    # Test role validation warning (two user messages in a row)
    print("\n--- Testing role validation ---")
    cm2 = ContextManager()
    cm2.add_user_message("First user message")
    cm2.add_user_message("Second user message — should log a warning")
    print(f"History roles: {[m['role'] for m in cm2.get_history()]}")
