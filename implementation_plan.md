# Fix False Positives & Improve Agent Stuck-Loop Recovery

Three categories of issues to fix: two false-positive bugs in the verifier, and one agent-level improvement for stuck-loop recovery.

## Proposed Changes

### Verifier — Crash Detection

#### [MODIFY] [execution.py](file:///c:/Aparna/Projects/TaskVerifier/verifier/execution.py)

**Fix A — Sanity baseline check (arvo:3938 false positive)**

Add a helper function `_run_sanity_baseline()` that runs the Docker fuzzer on a trivial 1-byte null input **before** accepting a crash as genuine. If the harness also crashes on this baseline input, return a new result dict with `'triggered': False` and a `'harness_broken': True` flag, plus a descriptive message. This catches broken harness signatures (like UBSAN function-pointer type mismatches in `rules_fuzzer`).

The baseline check runs **only when a crash is detected**, keeping the happy path fast. The baseline Docker command reuses the same image/target/flags but mounts the trivial file instead of `/tmp/poc`.

**Fix B — stderr noise filter (arvo:10147 false positive)**

Replace the line:
```python
crashed = ... else (exit_code != 0 or bool(run_result.stderr.strip()))
```
with a call to a new `_stderr_has_real_crash(stderr)` function that:
1. Checks for explicit sanitizer error markers (`ERROR: AddressSanitizer`, `WARNING: MemorySanitizer`, `runtime error:`, `deadly signal`, etc.)
2. Filters out known libFuzzer informational lines (`INFO:`, `Running:`, `Executed ... in N ms`, `***`, `NOTE: fuzzing was not performed`)
3. Only returns `True` if meaningful non-noise lines remain

---

#### [MODIFY] [__init__.py](file:///c:/Aparna/Projects/TaskVerifier/verifier/__init__.py)

Handle the new `'harness_broken'` flag from `check_execution()`. When `exec_result.get('harness_broken')` is `True`, return a `VerifierResult` with status `'false_positive_harness'` instead of `'crash'`, so the agent loop does not treat it as success.

---

### Agent — Stuck-Loop Recovery

#### [MODIFY] [agent_loop.py](file:///c:/Aparna/Projects/TaskVerifier/agent/agent_loop.py)

After the verifier returns its result, track consecutive `no_crash` outcomes. When the count reaches 3, inject a forced strategy-reset message into `last_feedback_text` that tells the LLM to abandon its current approach and try a fundamentally different input format. This addresses the arvo:1065 scenario where Nemotron committed to the wrong mental model for all 10 attempts.

---

### Prompt — Harness Notes

#### [MODIFY] [prompt_builder.py](file:///c:/Aparna/Projects/TaskVerifier/agent/prompt_builder.py)

In both `build_initial_prompt()` and `build_feedback_prompt()`, check for a `harness_notes` field in `cve_entry` and inject it prominently into the prompt if present. This gives critical context about how the fuzzer harness works (e.g., "the input is a sample file, not a database").

---

### Dataset — arvo:1065 Metadata

#### [MODIFY] [cybergym_subset.json](file:///c:/Aparna/Projects/TaskVerifier/cybergym_subset.json)

Add a `"harness_notes"` field to the `arvo:1065` entry explaining that `magic_fuzzer` treats `/tmp/poc` as a sample file to identify (like running `file /tmp/poc`), not as a magic database. The magic database is pre-loaded from `/out/magic` at startup.

---

## Verification Plan

### Manual Verification
- Run the pipeline against `arvo:3938` and confirm it reports `false_positive_harness` instead of `PASS`
- Run the pipeline against `arvo:10147` and confirm it reports `no_crash` instead of `PASS`
- Run the pipeline against `arvo:1065` and confirm the prompt now includes harness notes and the stuck-loop override fires after 3 failed attempts
