"""
agent/container_runtime.py — Persistent Docker container lifecycle for the
tool-use agent loop (AGENT_MODE=tool_use).

This is INTENTIONALLY separate from verifier/compiler.py and
verifier/execution.py, which spin up their own fresh, ephemeral
`docker run --rm` containers per call for the formal compile+execute
verification step. That separation is deliberate:

  - The PERSISTENT container here is the agent's own exploration space --
    mutable, alive across many tool calls within one CVE's run, used for
    run_bash / read_file / list_dir (agent/tools.py).
  - The EPHEMERAL containers in verifier/ are the clean-room, deterministic
    check used to actually score an attempt (agent/tools.py's
    compile_and_run calls straight through to the existing
    verifier.VerifierPipeline.verify(), unchanged).

Mixing these would risk the agent's own exploration state (files it wrote,
partial builds it left lying around) contaminating the supposedly-clean
verification run. Keep them separate.

SEQUENTIAL-USE ASSUMPTION: every function here assumes one CVE's tool loop
runs at a time -- no concurrent calls into the same ContainerSession, and no
concurrent CVEs sharing this host. This matches the actual operational
pattern already in use (CVEs are processed one at a time, due to Docker
image size / Codespaces disk constraints already discussed for this
project). If this pipeline is ever parallelized, this assumption -- and the
matching one in verifier/compiler.py's per-call workspace namespacing --
needs revisiting.
"""

import logging
import os
import re
import subprocess
import time
import uuid

logger = logging.getLogger(__name__)

# ── Q2 (resolved): every persistent container gets these by default -------
# SYS_PTRACE + disabled seccomp are what ASAN/MSAN need to reliably install
# their own signal handlers and report cleanly instead of raw-crashing --
# derived directly from the exit-code-139-vs-77 mismatch investigation
# earlier in this project. The container is still fully isolated from the
# host regardless of these capabilities.
ELEVATED_CAPS = ["--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined"]

# Resource caps -- same spirit as verifier/execution.py's own hardened
# `docker run` flags for the vulnerable-target execution step, adjusted for
# a container that needs to stay alive and be writable (so NOT --read-only,
# NOT --cap-drop ALL -- SYS_PTRACE above is explicitly required here).
RESOURCE_LIMITS = ["--memory", "1g", "--cpus", "2", "--pids-limit", "256"]

# No network access -- the container only needs the vulnerable image's
# already-baked-in toolchain and source tree, nothing external. Matches
# execution.py's existing security stance for the same reason.
NETWORK_FLAGS = ["--network", "none"]

# Q3 (resolved): 1 hour per-CVE cumulative tool-call time budget.
DEFAULT_TIME_BUDGET_SECONDS = int(os.environ.get("TOOL_TIME_BUDGET_SECONDS", str(60 * 60)))

# Per-call hard timeout -- no single command can hang the loop indefinitely,
# independent of the overall per-CVE budget above.
DEFAULT_EXEC_TIMEOUT_SECONDS = int(os.environ.get("TOOL_EXEC_TIMEOUT_SECONDS", "120"))

CONTAINER_NAME_PREFIX = "taskverifier"

# Cap how much of any single command's output gets fed back to the model as
# an observation -- an unbounded `cat` of a huge file would blow the context
# budget in one turn.
MAX_OBSERVATION_CHARS = 20_000


# ── Command safety filter -----------------------------------------------------
# Defense in depth, not a host-safety mechanism (the container is already
# isolated) -- this exists so a bad/misfiring command can't silently burn the
# CVE's time budget or fill the container's disk with something like a fork
# bomb or an infinite write loop, wasting Codespaces core-hours for nothing.
_DENYLIST_PATTERNS = [
    r'\brm\s+-rf\s+/(?:\s|$)',                    # rm -rf / and variants targeting root
    r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:',  # classic fork bomb
    r'\bmkfs\b',
    r'\bdd\s+.*of=/dev/',
    r'>\s*/dev/sd[a-z]',
]


class CommandRejected(Exception):
    """Raised when a command matches the safety denylist. Never silently
    swallowed -- the caller (agent/tools.py) turns this into an observation
    telling the model why, rather than executing anything."""


class BudgetExceeded(Exception):
    """Raised when a CVE's cumulative tool-call time budget is exhausted.
    The caller should stop granting new tool calls and force a final
    submission turn instead."""


def _check_command_safety(cmd: str) -> None:
    for pattern in _DENYLIST_PATTERNS:
        if re.search(pattern, cmd):
            raise CommandRejected(
                f"Command matched safety denylist pattern {pattern!r}: {cmd[:200]}"
            )


def _resolve_image_name(cve_entry: dict) -> str:
    # Same resolution order used everywhere else in the pipeline
    # (agent_loop.py, verifier/compiler.py, verifier/execution.py) --
    # keeping this consistent matters, since the exploration container must
    # be the SAME image the formal verifier will ultimately check against.
    return (
        cve_entry.get("docker_image")
        or cve_entry.get("docker_image_vul")
        or "cybergym-sandbox:latest"
    )


def _sanitize_for_container_name(s: str) -> str:
    """
    FIX (found running against a real CVE id): Docker container names only
    allow [a-zA-Z0-9][a-zA-Z0-9_.-] -- this project's CVE ids are formatted
    like "arvo:64574", and the colon is illegal in a container name. This
    isn't an edge case, it's every single id in the dataset, so it would
    have failed on 100% of tool_use runs, not just unusual ones. Replaces
    every disallowed character with "_" -- self.cve_id itself (used for
    logging) is left untouched; only the derived container name is sanitized.
    """
    sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '_', s)
    # The pattern also requires the FIRST character to be alnum specifically
    # (not just from the allowed set, which additionally permits _.- after
    # the first character) -- guard against a sanitized id that could start
    # with one of those.
    if sanitized and not sanitized[0].isalnum():
        sanitized = "x" + sanitized
    return sanitized or "unknown"


class ContainerSession:
    """
    One persistent container for the duration of one CVE's tool-use run.
    Create one per CVE (per resolved decision: alive across every attempt
    within that run, not reset per-attempt), use it for every tool call in
    that run, and ALWAYS call cleanup() when done via try/finally -- see
    agent_loop.py's _run_agent_with_tools for the call site.
    """

    def __init__(self, cve_entry: dict, time_budget_seconds: int = None):
        self.cve_entry = cve_entry
        self.cve_id = cve_entry.get("id") or cve_entry.get("cve_id", "unknown")
        self.image_name = _resolve_image_name(cve_entry)
        self.time_budget_seconds = (
            time_budget_seconds if time_budget_seconds is not None
            else DEFAULT_TIME_BUDGET_SECONDS
        )
        self.time_used_seconds = 0.0
        self.container_id = None
        self.container_name = None

    # -- lifecycle ------------------------------------------------------------

    def start(self) -> None:
        if self.container_id is not None:
            raise RuntimeError(
                "ContainerSession.start() called twice -- reuse the existing "
                "session instead of starting a second container for the same CVE run."
            )

        # FIX (lesson from repro_arvo.sh's pull-failure investigation earlier
        # in this project): check the pull result explicitly instead of
        # silently discarding it -- a failed pull falling through to
        # `docker run` against whatever's cached locally is exactly the kind
        # of thing that causes a hard-to-diagnose mismatch later.
        logger.info(f"CVE {self.cve_id}: pulling {self.image_name} for exploration container...")
        pull_result = subprocess.run(
            ["docker", "pull", self.image_name], capture_output=True, text=True
        )
        if pull_result.returncode != 0:
            logger.warning(
                f"CVE {self.cve_id}: docker pull of {self.image_name} failed "
                f"(exit {pull_result.returncode}): {pull_result.stderr.strip()[:300]} -- "
                f"proceeding with whatever is cached locally, if anything."
            )

        run_suffix = uuid.uuid4().hex[:8]
        safe_id = _sanitize_for_container_name(self.cve_id)
        self.container_name = f"{CONTAINER_NAME_PREFIX}_{safe_id}_{run_suffix}"

        cmd = (
            ["docker", "run", "-d", "--name", self.container_name]
            + ELEVATED_CAPS
            + RESOURCE_LIMITS
            + NETWORK_FLAGS
            + [self.image_name, "tail", "-f", "/dev/null"]
        )
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            self.container_name = None
            raise RuntimeError(
                f"Failed to start exploration container for CVE {self.cve_id}: "
                f"{result.stderr.strip()}"
            )
        self.container_id = result.stdout.strip()
        logger.info(
            f"CVE {self.cve_id}: exploration container {self.container_name} "
            f"({self.container_id[:12]}) started"
        )

    def cleanup(self) -> None:
        """
        Always safe to call, even if start() was never called or failed
        partway through -- NEVER raises, since this is meant to run from a
        `finally` block and must not itself introduce a new failure mode
        there. If this somehow fails to remove the container,
        cleanup_orphans.sh is the safety net -- see that script's docstring.
        """
        if self.container_name is None:
            return
        try:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True, timeout=30
            )
            logger.info(f"CVE {self.cve_id}: exploration container {self.container_name} removed")
        except Exception as e:
            logger.error(
                f"CVE {self.cve_id}: cleanup of {self.container_name} failed: {e} "
                f"-- cleanup_orphans.sh will catch this on its next run."
            )
        finally:
            self.container_id = None

    # -- exec -------------------------------------------------------------------

    def exec(self, cmd: str, timeout: int = None) -> dict:
        """
        Run `cmd` (a shell command string) inside the persistent container
        via `docker exec`. Returns
        {"stdout", "stderr", "exit_code", "timed_out"}.

        Raises CommandRejected (safety filter) or BudgetExceeded (time
        budget) BEFORE running anything -- both are checked up front, so a
        rejected/over-budget call never actually executes. Callers (see
        agent/tools.py) should catch these and turn them into an observation
        or a forced-submission signal respectively, not let them propagate
        as an unhandled crash of the whole run.
        """
        if self.container_id is None:
            raise RuntimeError("ContainerSession.exec() called before start()")

        _check_command_safety(cmd)

        if self.time_used_seconds >= self.time_budget_seconds:
            raise BudgetExceeded(
                f"CVE {self.cve_id}: tool-call time budget "
                f"({self.time_budget_seconds}s) exhausted "
                f"({self.time_used_seconds:.0f}s used). No further tool calls "
                f"this run -- submit your best PoC now."
            )

        timeout = timeout if timeout is not None else DEFAULT_EXEC_TIMEOUT_SECONDS
        # Don't let a single call's timeout push past whatever budget remains.
        remaining = self.time_budget_seconds - self.time_used_seconds
        timeout = min(timeout, max(int(remaining), 1))

        start = time.time()
        try:
            result = subprocess.run(
                ["docker", "exec", self.container_name, "sh", "-c", cmd],
                capture_output=True, text=True, timeout=timeout
            )
            elapsed = time.time() - start
            self.time_used_seconds += elapsed
            return {
                "stdout": result.stdout[-MAX_OBSERVATION_CHARS:],
                "stderr": result.stderr[-MAX_OBSERVATION_CHARS:],
                "exit_code": result.returncode,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            self.time_used_seconds += elapsed
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s.",
                "exit_code": -1,
                "timed_out": True,
            }

    def budget_remaining_seconds(self) -> float:
        return max(self.time_budget_seconds - self.time_used_seconds, 0.0)