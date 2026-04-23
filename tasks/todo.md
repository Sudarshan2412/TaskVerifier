# Week 1-6 Execution Plan (Sudarshan Track)

## Dependencies and Blockers by Week

- Week 1: no teammate dependency.
- Week 2-3: needs finalized schema contract from Aparna. Status: available in schema.md.
- Week 4-6: full pilot with real subset needs Aparna's data/cybergym_subset.json. Status: missing in repo.
- Week 7+ (future, not in this run): needs Prarthana's agent/agent_loop.py with run_agent(). Status: missing in repo.

## Sequential Checklist

- [x] Week 1 audit: verify current repo against required skeleton and dependency baseline.
- [x] Week 1 completion: create missing directories/files and placeholder modules.
- [x] Week 1 verification: validate structure and imports.
- [x] Week 1 dependency sync: ensure required packages for Sudarshan track are installed/configured.
- [x] Week 2 implementation: build logger.py with per-attempt JSONL logging.
- [x] Week 2 implementation: build evaluator.py pass/fail logic.
- [x] Week 2 verification: run quick functional checks for logger/evaluator.
- [x] Week 3 implementation: build runner.py using mock agent path.
- [x] Week 3 implementation: add minimal runnable script path for pilot execution.
- [x] Week 3 verification: run small pilot on dummy subset and produce results JSON.
- [x] Week 4 implementation: align runner/logger/evaluator field names to schema.md contract (task_id, poc_length_bucket, vuln_class).
- [x] Week 4 verification: re-run pilot with schema-aligned input.
- [x] Week 5 implementation: add compute_metrics.py and plot_results.py.
- [x] Week 5 verification: compute metrics and generate at least one plot from pilot outputs.
- [x] Week 6 implementation: add tests for core harness modules.
- [x] Week 6 verification: run pytest for harness tests.
- [x] Final review: summarize completed Week 1-6 work and remaining teammate handoff requirements.

## Review Log

- Week 1 complete: scaffold folders and placeholder modules created; import check passed.
- Week 1 dependency sync complete: requirements normalized and core packages import successfully in .venv.
- Week 2 complete: logger writes JSONL safely on Windows and evaluator returns deterministic pass/fail reasons.
- Week 3 complete: mock runner + scripts/run_pilot.py executed baseline and verifier pilots and saved JSON outputs.
- Week 4 complete (schema alignment): outputs/logs now use task_id, poc_length_bucket, and vuln_class from schema contract.
- Week 4 note: real subset file data/cybergym_subset.json from Aparna is still missing; dummy schema-aligned subset used for now.
- Week 5 complete: metrics summary and two plots generated from pilot outputs under data/results/.
- Week 6 complete: pytest run finished with 4 passed, 1 skipped (agent test blocked on Week 7 handoff).
- Final review complete: Week 1-6 local pipeline is ready for teammate integrations.
