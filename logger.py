"""
logger.py — Rich console logging and Markdown report generation.

Two main classes:
  StepLogger   — prints formatted step-by-step output to the console during
                 agent execution so you can watch each pipeline stage.
  ReportWriter — collects structured events and writes a human-readable
                 Markdown report to disk after a run completes.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# StepLogger — rich console output
# ──────────────────────────────────────────────────────────────────────────────

class StepLogger:
    """Prints formatted, step-by-step console output during agent execution.

    Each pipeline stage (prompt, LLM, extraction, hallucination, verifier,
    critic tool loop) gets a numbered line with emoji, status, and timing.
    """

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _safe_print(text: str) -> None:
        """Print with fallback for terminals that can't render Unicode."""
        try:
            print(text, flush=True)
        except UnicodeEncodeError:
            ascii_map = str.maketrans({
                "╔": "+", "╗": "+", "╚": "+", "╝": "+",
                "═": "=", "║": "|", "│": "|",
                "├": "|", "└": "`", "─": "-",
                "📝": "[P]",  "🤖": "[L]",  "🔍": "[E]",
                "🧬": "[H]",  "🔨": "[V]",  "✓": "[/]",
                "✗": "[X]",   "✅": "[OK]", "❌": "[FAIL]",
                "⚠": "[!]",   "💥": "[!!]", "⏳": "[..]",
                "🎯": "[>>]", "📄": "[F]",  "🐳": "[D]",
                "🧠": "[C]",  "📨": "[FB]", "≠": "!=",
            })
            print(text.translate(ascii_map), flush=True)

    # ── Run / CVE level banners ───────────────────────────────────────────────

    def log_run_header(self, total_cves: int, max_attempts: int) -> None:
        """Print a banner at the very start of a test run."""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._safe_print("")
        self._safe_print("╔══════════════════════════════════════════════════════════════════╗")
        self._safe_print(f"║  TaskVerifier Run                                               ║")
        self._safe_print(f"║  {ts}  │  CVEs: {total_cves}  │  Max attempts: {max_attempts:<4}       ║")
        self._safe_print("╚══════════════════════════════════════════════════════════════════╝")
        self._safe_print("")

    def log_cve_header(
        self,
        index: int,
        total: int,
        cve_id: str,
        bucket: str = "unknown",
        vuln_class: str = "unknown",
    ) -> None:
        """Print a boxed banner for a new CVE."""
        label = f"  CVE {index}/{total}: {cve_id}  │  Bucket: {bucket}  │  Class: {vuln_class}"
        width = max(len(label) + 2, 66)
        self._safe_print("")
        self._safe_print("╔" + "═" * width + "╗")
        self._safe_print("║" + label.ljust(width) + "║")
        self._safe_print("╚" + "═" * width + "╝")
        self._safe_print("")

    def log_attempt_header(self, attempt: int, max_attempts: int) -> None:
        """Print a divider for a new attempt."""
        self._safe_print(f"  ── Attempt {attempt}/{max_attempts} " + "─" * 50)

    # ── Pipeline steps 1–5 ───────────────────────────────────────────────────

    def log_prompt_built(self, prompt_type: str, char_count: int) -> None:
        self._safe_print(f"  [1/5] 📝 Prompt built           ({prompt_type}, {char_count:,} chars)")

    def log_llm_response(self, elapsed_sec: float, char_count: int) -> None:
        self._safe_print(f"  [2/5] 🤖 LLM response           {elapsed_sec:.1f}s  ({char_count:,} chars)")

    def log_extraction(self, success: bool, char_count: int = 0, error: str = "") -> None:
        if success:
            self._safe_print(f"  [3/5] 🔍 Code extracted          ✓  ({char_count:,} chars C code)")
        else:
            self._safe_print(f"  [3/5] 🔍 Code extracted          ✗  {error}")

    def log_hallucination(self, symbols: list[str]) -> None:
        if symbols:
            sym_str = ", ".join(symbols[:5])
            extra = f" (+{len(symbols)-5} more)" if len(symbols) > 5 else ""
            self._safe_print(f"  [4/5] 🧬 Hallucination check    ⚠  {sym_str}{extra}")
        else:
            self._safe_print(f"  [4/5] 🧬 Hallucination check    ✓  no hallucinated symbols")

    def log_verifier(
        self,
        compile_ok: bool,
        exec_ok: bool | None = None,
        crash_type: str = "",
        compile_error: str = "",
        exec_message: str = "",
    ) -> None:
        """Print a tree-style verifier breakdown (compile → exec → crash)."""
        self._safe_print(f"  [5/5] 🔨 Verifier pipeline")

        if compile_ok:
            self._safe_print(f"        ├─ Compile:   ✓")
        else:
            err_short = compile_error[:120].replace("\n", " ") if compile_error else "see log"
            self._safe_print(f"        └─ Compile:   ✗  {err_short}")
            return

        if exec_ok is True:
            self._safe_print(f"        ├─ Execute:   ✓  exit_code ≠ 0")
        elif exec_ok is False:
            msg_short = exec_message[:120].replace("\n", " ") if exec_message else "no crash"
            self._safe_print(f"        └─ Execute:   ✗  {msg_short}")
            return
        else:
            self._safe_print(f"        └─ Execute:   —  skipped")
            return

        if crash_type:
            self._safe_print(f"        └─ Crash:     ✓  {crash_type[:100]}")
        else:
            self._safe_print(f"        └─ Crash:     ✗  no sanitizer error detected")

    # ── NEW: Docker execution detail ──────────────────────────────────────────

    def log_poc_written(self, path: str, size_bytes: int) -> None:
        """Log that the PoC generator wrote a file to disk."""
        self._safe_print(f"        ├─ 📄 PoC written:       {path}  ({size_bytes:,} bytes)")

    def log_docker_exec(self, image: str, fuzz_target: str, exit_code: int) -> None:
        """Log the Docker run result for the vulnerable target."""
        status = "✓ crash" if exit_code != 0 else "✗ no crash"
        short_target = fuzz_target.split("/")[-1] if fuzz_target else "unknown"
        self._safe_print(
            f"        ├─ 🐳 Docker exec:       {image}  "
            f"{short_target}  → exit {exit_code}  [{status}]"
        )

    def log_fuzzer_output(self, stdout: str, stderr: str) -> None:
        """Log the first meaningful lines of fuzzer stdout/stderr."""
        combined = (stderr or stdout or "").strip()
        if not combined:
            self._safe_print(f"        │  Fuzzer output:      (empty)")
            return
        lines = [l for l in combined.splitlines() if l.strip()][:3]
        for i, line in enumerate(lines):
            prefix = "        │  " if i < len(lines) - 1 else "        └─ "
            self._safe_print(f"{prefix}Fuzzer: {line[:120]}")

    # ── NEW: Critic LLM tool loop ─────────────────────────────────────────────

    def log_critic_start(self, reason: str) -> None:
        """Log that the Critic LLM has been invoked and why."""
        self._safe_print(f"")
        self._safe_print(f"        🧠 Critic LLM invoked  ({reason})")

    def log_critic_turn(self, turn: int, max_turns: int, action: str) -> None:
        """Log a single ReAct turn inside the critic loop."""
        self._safe_print(f"        ├─ Turn {turn}/{max_turns}:  {action[:100]}")

    def log_docker_tool_call(self, tool_type: str, arg: str, result_len: int) -> None:
        """Log a SEARCH or READ tool call made by the critic."""
        arg_short = arg[:70]
        self._safe_print(
            f"        │   🐳 {tool_type:<7} {arg_short!r}  → {result_len:,} chars"
        )

    def log_critic_result(self, conclusion: str) -> None:
        """Log the critic's final conclusion (first line only)."""
        first_line = conclusion.strip().splitlines()[0] if conclusion.strip() else "(empty)"
        self._safe_print(f"        └─ Critic conclusion: {first_line[:120]}")

    # ── NEW: Feedback ─────────────────────────────────────────────────────────

    def log_feedback_sent(self, feedback_preview: str, char_count: int) -> None:
        """Log the feedback being handed back to the agent for the next attempt."""
        self._safe_print(f"")
        self._safe_print(f"  [FB]  📨 Feedback to LLM       ({char_count:,} chars)")
        first = next(
            (l.strip() for l in feedback_preview.splitlines() if l.strip()), ""
        )
        if first:
            self._safe_print(f"        └─ {first[:120]}{'...' if len(first) > 120 else ''}")

    # ── Outcome / errors ──────────────────────────────────────────────────────

    def log_outcome(self, success: bool, attempt: int, failure_reason: str = "") -> None:
        if success:
            self._safe_print(f"\n  ✅ SUCCESS on attempt {attempt}\n")
        else:
            reason = f"  ({failure_reason})" if failure_reason else ""
            self._safe_print(f"\n  ❌ FAILED after attempt {attempt}{reason}\n")

    def log_cve_error(self, cve_id: str, error: str) -> None:
        self._safe_print(f"\n  💥 ERROR running {cve_id}: {error}\n")

    def log_sleep(self, seconds: float) -> None:
        self._safe_print(f"  ⏳ Sleeping {seconds:.0f}s before next CVE...")


# ──────────────────────────────────────────────────────────────────────────────
# NullStepLogger — silent no-op (default when no logger is supplied)
# ──────────────────────────────────────────────────────────────────────────────

class NullStepLogger(StepLogger):
    """Drop-in replacement that silently discards all log calls."""

    def __getattribute__(self, name: str) -> Any:
        if name.startswith("log_"):
            return lambda *a, **kw: None
        return super().__getattribute__(name)


# ──────────────────────────────────────────────────────────────────────────────
# ReportWriter — Markdown report generation
# ──────────────────────────────────────────────────────────────────────────────

class ReportWriter:
    """Collects structured data during a run and writes a Markdown report."""

    def __init__(self, max_attempts: int = 2) -> None:
        self.run_start = datetime.now(timezone.utc)
        self.max_attempts = max_attempts
        self.cve_reports: list[dict[str, Any]] = []

    # ── Collecting data ───────────────────────────────────────────────────────

    def add_cve_result(
        self,
        cve_id: str,
        bucket: str,
        vuln_class: str,
        success: bool,
        attempts: int,
        failure_reason: str,
        final_poc: str,
        transcript: list[dict],
        hallucinated_symbols_per_attempt: list[list[str]],
        error: str = "",
    ) -> None:
        self.cve_reports.append({
            "cve_id": cve_id,
            "bucket": bucket,
            "vuln_class": vuln_class,
            "success": success,
            "attempts": attempts,
            "failure_reason": failure_reason,
            "final_poc": final_poc,
            "transcript": transcript,
            "hallucinated_symbols_per_attempt": hallucinated_symbols_per_attempt,
            "error": error,
        })

    # ── Report generation ─────────────────────────────────────────────────────

    def write_report(self, output_dir: str | Path = "logs") -> Path:
        """Generate a Markdown report and return the file path."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = out / f"report_{ts}.md"

        lines: list[str] = []
        self._write_header(lines)
        self._write_summary_table(lines)
        self._write_failure_analysis(lines)
        self._write_cve_details(lines)
        self._write_footer(lines)

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    # ── Private helpers ───────────────────────────────────────────────────────

    def _write_header(self, lines: list[str]) -> None:
        ts = self.run_start.strftime("%Y-%m-%d %H:%M:%S UTC")
        passed = sum(1 for r in self.cve_reports if r["success"])
        total = len(self.cve_reports)
        lines.append("# TaskVerifier Run Report")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Run time** | {ts} |")
        lines.append(f"| **CVEs tested** | {total} |")
        lines.append(f"| **Max attempts** | {self.max_attempts} |")
        lines.append(f"| **Pass rate** | {passed}/{total} ({(passed/total*100) if total else 0:.0f}%) |")
        lines.append("")

    def _write_summary_table(self, lines: list[str]) -> None:
        lines.append("## Summary")
        lines.append("")
        lines.append("| CVE ID | Bucket | Vuln Class | Result | Attempts | Hallucinations | Failure Mode |")
        lines.append("|--------|--------|------------|--------|----------|----------------|--------------|")

        for r in self.cve_reports:
            result_str = "✅ PASS" if r["success"] else "❌ FAIL"
            halluc = self._has_hallucinations(r)
            halluc_str = "⚠ Yes" if halluc else "—"
            fail_mode = self._classify_failure(r) if not r["success"] else "—"
            lines.append(
                f"| {r['cve_id']} | {r['bucket']} | {r['vuln_class']} "
                f"| {result_str} | {r['attempts']} | {halluc_str} | {fail_mode} |"
            )
        lines.append("")

    def _write_failure_analysis(self, lines: list[str]) -> None:
        failures = [r for r in self.cve_reports if not r["success"]]
        lines.append("## Failure Analysis")
        lines.append("")
        if not failures:
            lines.append("🎉 All CVEs passed! No failures to analyze.")
            lines.append("")
            return

        by_mode: dict[str, list[str]] = {}
        for r in failures:
            mode = self._classify_failure(r)
            by_mode.setdefault(mode, []).append(r["cve_id"])

        for mode, cves in by_mode.items():
            lines.append(f"- **{mode}** ({len(cves)}): {', '.join(cves)}")
        lines.append("")

    def _write_cve_details(self, lines: list[str]) -> None:
        lines.append("---")
        lines.append("")
        lines.append("## Per-CVE Details")
        lines.append("")

        for i, r in enumerate(self.cve_reports, 1):
            result_emoji = "✅" if r["success"] else "❌"
            lines.append(f"### {i}. {r['cve_id']} {result_emoji}")
            lines.append("")
            lines.append(f"- **Bucket**: {r['bucket']}")
            lines.append(f"- **Vuln class**: {r['vuln_class']}")
            lines.append(f"- **Result**: {'PASS' if r['success'] else 'FAIL'}")
            lines.append(f"- **Attempts used**: {r['attempts']}")
            if r["error"]:
                lines.append(f"- **Error**: `{r['error']}`")
            if r["failure_reason"]:
                lines.append(f"- **Failure reason**: `{r['failure_reason']}`")
            lines.append("")

            for entry in r["transcript"]:
                if not isinstance(entry, dict):
                    continue
                attempt_num = entry.get("attempt", "?")
                v_status = entry.get("verifier_status", "?")
                v_stage = entry.get("verifier_stage", "")

                lines.append("<details>")
                lines.append(
                    f"<summary><strong>Attempt {attempt_num}</strong>"
                    f" — Verifier: <code>{v_status}</code>"
                    + (f" @ <code>{v_stage}</code>" if v_stage else "")
                    + "</summary>"
                )
                lines.append("")

                # ── Prompt ────────────────────────────────────────────────────
                prompt = entry.get("prompt", "")
                if prompt:
                    preview = prompt[:300].replace("\n", " ").strip()
                    lines.append(f"**Prompt** ({len(prompt):,} chars):")
                    lines.append(f"> {preview}{'...' if len(prompt) > 300 else ''}")
                    lines.append("")

                # ── LLM response ──────────────────────────────────────────────
                raw = entry.get("raw_response", "")
                if raw:
                    preview = raw[:400].replace("\n", " ").strip()
                    lines.append(f"**LLM Response** ({len(raw):,} chars):")
                    lines.append(f"> {preview}{'...' if len(raw) > 400 else ''}")
                    lines.append("")

                # ── Extracted PoC ─────────────────────────────────────────────
                poc = entry.get("extracted_poc", "")
                if poc:
                    lines.append("**Extracted PoC:**")
                    lines.append("```c")
                    lines.append(poc)
                    lines.append("```")
                else:
                    lines.append("**Extracted PoC:** _(extraction failed)_")
                lines.append("")

                # ── Hallucinations ────────────────────────────────────────────
                halluc = entry.get("hallucinated_symbols", [])
                if halluc:
                    lines.append(f"**Hallucinated symbols:** `{', '.join(halluc)}`")
                else:
                    lines.append("**Hallucinated symbols:** none")
                lines.append("")

                # ── Verifier result ───────────────────────────────────────────
                lines.append(f"**Verifier status:** `{v_status}`")
                if v_stage:
                    lines.append(f"**Verifier stage:** `{v_stage}`")
                lines.append("")

                # ── NEW: Fuzzer output ────────────────────────────────────────
                fuzzer_out = entry.get("fuzzer_output", "")
                if fuzzer_out:
                    lines.append("**Fuzzer output:**")
                    lines.append("```")
                    lines.append(fuzzer_out[:800])
                    lines.append("```")
                    lines.append("")

                # ── NEW: Docker command ───────────────────────────────────────
                fuzzer_cmd = entry.get("fuzzer_cmd", "")
                if fuzzer_cmd:
                    lines.append(f"**Docker command:** `{fuzzer_cmd}`")
                    lines.append("")

                # ── Feedback sent to next attempt ─────────────────────────────
                feedback = entry.get("verifier_feedback", "")
                if feedback:
                    lines.append("**Feedback to next attempt:**")
                    lines.append("```")
                    lines.append(feedback)
                    lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            lines.append("---")
            lines.append("")

    def _write_footer(self, lines: list[str]) -> None:
        passed = sum(1 for r in self.cve_reports if r["success"])
        total = len(self.cve_reports)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"*Generated by TaskVerifier logger.py at {ts} — {passed}/{total} passed*"
        )

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _has_hallucinations(r: dict) -> bool:
        for entry in r.get("transcript", []):
            if isinstance(entry, dict) and len(entry.get("hallucinated_symbols", [])) > 0:
                return True
        return False

    @staticmethod
    def _classify_failure(r: dict) -> str:
        """Classify a failure into a human-readable mode label."""
        if r.get("error"):
            return "agent_error"

        transcript = r.get("transcript", [])
        if not transcript:
            return "no_transcript"

        last = transcript[-1] if isinstance(transcript[-1], dict) else {}
        vr = last.get("verifier_status", "").lower()

        if "infra" in vr:
            return "verifier_infra_error"
        if "compile" in vr:
            return "compile_error_loop"
        if "no_crash" in vr:
            return "no_crash"

        halluc_flagged = any(
            len(entry.get("hallucinated_symbols", [])) > 0
            for entry in transcript
            if isinstance(entry, dict)
        )
        if halluc_flagged:
            return "hallucination_loop"

        if vr:
            return vr
        return "unknown"