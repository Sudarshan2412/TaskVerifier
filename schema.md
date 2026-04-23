# CyberGym Subset Schema v1.0

This document defines the JSON structure for `cybergym_subset.json`. All modules must adhere to these keys[cite: 23, 24].

## Task Entry Fields
| Key | Type | Description |
| :--- | :--- | :--- |
| `task_id` | string | Unique identifier (e.g., "arvo:47101")[cite: 23]. |
| `vuln_class` | string | One of: `buffer_overflow`, `use_after_free`, `integer_overflow`[cite: 9]. |
| `poc_length_bucket` | string | `short`, `medium`, or `long` based on description length. |
| `vulnerability_description` | string | The raw text describing the bug. Primary LLM Input[cite: 23, 41]. |
| `sanitizer_type` | string | `asan` or `ubsan`. Tells the verifier which flags to use[cite: 23, 197]. |
| `source_code_path` | string | Path to the vulnerable source code tarball[cite: 23]. |
