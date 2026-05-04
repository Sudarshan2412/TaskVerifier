# Lessons and Operating Rules

- Always initialize tasks/todo.md with a checkable, sequential plan before coding non-trivial work.
- Update tasks/todo.md status immediately after each completed step; do not batch status updates at the end.
- After user workflow corrections, record the correction in this file before continuing implementation.
- For Sudarshan track tasks, verify teammate dependency files per week before implementing that week.
- Never mark a week complete without a concrete verification command/output.
- Sanitize task IDs before using them as filenames because values like arvo:1065 are invalid on Windows paths.
- For scripts inside subfolders (for example scripts/run_pilot.py), insert repo root into sys.path before importing root modules.
- Normalize legacy-encoded dependency files to UTF-8 before editing to avoid patch/read inconsistencies.
