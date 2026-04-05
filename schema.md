# cybergym_subset.json — Schema Documentation

This file is the contract all team members code against.
Do NOT change field names without notifying the full team.

## Top-level structure
```json
{
  "meta": { ... },
  "tasks": [ , , ... ]
}
```

## `meta` fields
| Field | Type | Description |
|---|---|---|
| total_selected | int | Number of entries |
| buckets | dict | Target counts per bucket |
| selection_seed | int | Random seed used for reproducibility |

## `tasks[i]` fields — the contract

| Field | Type | Values / Notes |
|---|---|---|
| `task_id` | string | e.g. `"arvo:1065"` or `"oss-fuzz:42535201"` |
| `source` | string | `"arvo"` or `"oss-fuzz"` |
| `project_name` | string | Library name, e.g. `"libxml2"` |
| `project_language` | string | `"c"` or `"c++"` |
| `vulnerability_description` | string | Human-readable crash description |
| `vuln_class` | string | `"buffer_overflow"`, `"use_after_free"`, `"integer_overflow"`, `"other"` |
| `poc_length_bucket` | string | `"short"`, `"medium"`, or `"long"` |
| `source_code_path` | string | Relative path to `repo-vul.tar.gz` under `cybergym_data/` |
| `fix_code_path` | string | Relative path to `repo-fix.tar.gz` |
| `error_log_path` | string | Relative path to `error.txt` (ASan/UBSan crash log) |
| `description_path` | string | Relative path to `description.txt` |
| `patch_path` | string | Relative path to `patch.diff` |
| `difficulty_levels` | dict | CyberGym's level0–level3 file lists |
| `sanitizer_type` | string | `"asan"` or `"ubsan"` — inferred from description |

## Bucket definitions (proxy: vulnerability_description char length)
- **short**: < 200 chars — 30 instances
- **medium**: 200–400 chars — 35 instances  
- **long**: > 400 chars — 35 instances

## Important notes for Diya
- `error_log_path` points to the real ASan/UBSan stderr output captured from a fuzzer run.
- `sanitizer_type` tells you which parser to invoke.

## Important notes for Prarthana
- Use `vulnerability_description`, `vuln_class`, and `source_code_path` for prompt construction.
- `task_id` is the unique key for all logging.

## Important notes for Sudarshan
- `task_id` is your primary key in all result JSONs.
- `poc_length_bucket` and `vuln_class` are your stratification axes for metrics.
