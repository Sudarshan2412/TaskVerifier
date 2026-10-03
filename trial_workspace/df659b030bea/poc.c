#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Analysis:
   The previous payload failed because it was not a valid null-terminated Python literal.
   The fuzz target `fuzz_ast_literal_eval` first checks for a null byte using `memchr(data, '\0', size) != NULL`.
   If no null byte is found, the input is rejected before reaching the vulnerable code.
   Even when a null byte was present, the content was not a valid Python literal (e.g., assembly text or malformed strings),
   so `ast.literal_eval` would either raise a SyntaxError or return early without triggering the dict deallocation path.
   The vulnerability is a use-after-free in `dictkeys_decref` during dict destruction.
   To trigger it, we need a valid Python dict literal (e.g., `{"a":1}`) that forces the creation of a dict,
   and then the dict must be deallocated while references to its keys are still alive (or the deallocation order is wrong).
   The previous attempts used simple literals like `1` or `"a"` which do not create a dict.
   Even when a dict was created (e.g., `{"a":1}`), the deallocation order might not expose the bug.
   The key insight is that the bug is in the dict's key deallocation when the dict is destroyed.
   A minimal dict like `{"a":1}` should trigger it if the bug is deterministic.
   However, previous attempts with dict literals did not crash, suggesting either the bug requires a specific key type
   (e.g., a string with a specific refcount) or the deallocation order depends on the insertion order.
   Since we cannot observe the exact CPython version, we must try a dict with a string key that is immortal
   (e.g., a key that is a static string like `"a"` which is immortal in CPython 3.12+).
   But the crash in the target is in `_Py_IsImmortal` which suggests the key is NOT immortal.
   Therefore, we need a key that is NOT immortal (i.e., a dynamically allocated string).
   A simple dict like `{"a":1}` uses a static string `"a"` which IS immortal in CPython 3.12+.
   To force a non-immortal string, we can use a string that is created at runtime, e.g., `{"a"*1:1}` or just `{chr(97):1}`.
   But `ast.literal_eval` only accepts literals, not expressions like `chr(97)`.
   The simplest approach is to use a dict with a non-string key (e.g., an integer) which is always non-immortal.
   But the crash is in `_Py_IsImmortal` which is called on the key, so the key must be a string.
   After re-reading the crash trace: `_Py_IsImmortal` is called from `dictkeys_decref` which is called during dict destruction.
   The use-after-free is on the key's memory. So the key must be freed before the dict is destroyed, or the dict is destroyed twice.
   Given the constraints, the most likely trigger is a dict with a string key that is created and then the dict is destroyed in a way that the key is freed first.
   Since we cannot control the exact memory layout, we will try a dict with a non-immortal string key.
   In CPython, strings created from literals are immortal only if they are compile-time constants.
   But `ast.literal_eval` creates a new string at runtime, so it should NOT be immortal.
   Therefore, `{"a":1}` should work. But previous attempts with `{"a":1}` did not crash.
   Why? Possibly because the fuzz target wraps the input in a way that the dict is not directly destroyed, or the bug requires a specific key count.
   After multiple failures, the verifier suggests trying a simple integer `1` with a null terminator first to ensure format acceptance.
   But that won't trigger the dict bug.
   Given the verifier's note: "If the vulnerability requires a specific dict structure, a more complex literal like `{"a":1}\0` may be needed, but first ensure format acceptance."
   Since we already know the format is accepted (we got past the memchr check), we need to focus on the dict structure.
   The previous attempt 9 used `delim:null, hex:0x31,0x00` which is `"1\0"` and did not crash.
   So we need a dict. Let's try `{"a":1}\0` (bytes: 0x7b 0x22 0x61 0x22 0x3a 0x31 0x7d 0x00).
   But that was tried in attempt 1 (hex:0x7b,0x30,0x78,0x3a) which is not the same.
   Attempt 1 used `0x7b,0x30,0x78,0x3a` which is `{0x:` — invalid.
   Attempt 2 used `0x7b,0x31,0x3a,0x20` — `{1: ` — invalid.
   So we never actually tried a valid dict literal.
   Let's try `{"a":1}\0`. But to be safe, we'll also try `{"a":1, "b":2}\0` and other variants.
   However, the verifier said previous attempts with dict-like structures failed.
   The key difference is that we must include the null terminator.
   The fuzz target requires a null byte. So the payload must be `{"a":1}\0`.
   We'll write a generator that outputs exactly that.

   New strategy: Write a valid Python dict literal with a null terminator. Use `{"a":1}` (8 bytes + null = 9 bytes).
   This should create a dict with one string key. The dict destruction should call `dictkeys_decref` and trigger the bug.
   If it doesn't crash, we'll try a dict with multiple keys or non-string keys.
   But first, let's try the simplest valid dict.
*/

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;
    // Write `{"a":1}` followed by null terminator
    fputs("{\"a\":1}", f);
    fputc(0x00, f);
    fclose(f);
    return 0;
}