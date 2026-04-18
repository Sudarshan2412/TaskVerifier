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

    def __init__(self, max_tokens: int = 8000):
        """
        Initialize the context manager for a new trial.
        
        Args:
            max_tokens: Maximum token budget (default 8000). Converted to character budget.
        """
        self.history: list[dict] = []
        self.max_tokens: int = max_tokens
        self.char_budget: int = max_tokens * 4  # 1 token ≈ 4 characters

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
        
        Uses simple approximation: 1 token ≈ 4 characters.
        
        Returns:
            Estimated token count
        """
        total_chars = sum(len(msg["content"]) for msg in self.history)
        return total_chars // 4

    def _truncate_if_needed(self) -> None:
        """
        Apply truncation strategy if history exceeds token budget.
        
        Strategy:
        1. Always keep the first message (initial CVE description)
        2. Always keep the last 4 messages (last 2 turn pairs)
        3. Drop middle messages (older attempts) until under budget
        4. Log warnings when truncation occurs
        """
        # Calculate current total characters
        total_chars = sum(len(msg["content"]) for msg in self.history)

        # Check if over budget
        if total_chars <= self.char_budget:
            return  # Within budget, no truncation needed

        # Extract first message (always keep)
        first_message = self.history[0]

        # Extract last 4 messages (keep last 2 turn pairs)
        # If fewer than 5 messages total, keep all for now
        if len(self.history) <= 5:
            # Not enough messages to truncate meaningfully
            logger.warning(
                f"Context exceeds budget ({total_chars} chars) but not enough messages "
                f"to truncate while preserving first + last 4. Keeping as-is."
            )
            return

        last_4 = self.history[-4:]
        middle = self.history[1:-4]

        # Drop middle messages two at a time (one complete turn pair)
        # from the oldest end until under budget
        dropped_pairs = 0
        while middle:
            # Remove oldest pair (first 2 messages from middle)
            if len(middle) >= 2:
                middle = middle[2:]
                dropped_pairs += 1

                # Recalculate total
                total_chars = len(first_message["content"]) + sum(
                    len(msg["content"]) for msg in middle
                ) + sum(len(msg["content"]) for msg in last_4)

                if total_chars <= self.char_budget:
                    break
            else:
                # Only 1 message left in middle, can't drop a full pair
                break

        # Reassemble history
        self.history = [first_message] + middle + last_4

        # Log the truncation
        if dropped_pairs > 0:
            logger.warning(
                f"Context truncated: dropped {dropped_pairs} turn pair(s) to stay under token budget"
            )


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
