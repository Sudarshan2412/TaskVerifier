# Making TaskVerifier's agent SOTA-competitive: OpenHands-style architecture + Codespaces constraints

Status: planning document. Not yet implemented. Written so this survives independently of
the extraction-verification pass currently in progress.

## 1. Where we currently stand vs. where CyberGym leaders stand

**Correction (this section was wrong in the first draft):** it previously cited "OpenHands + GPT-5, 22.0% success rate" as the best CyberGym result to date. That number is the *original CyberGym paper's own baseline table entry* for vanilla OpenHands+GPT-5 (high reasoning) from when the benchmark launched -- it was never a current leaderboard result, and citing it that way was a real mistake, not a rounding difference. CyberGym is an actively-competed public leaderboard and the top of it has moved enormously since that baseline. Numbers below are dated because this will go stale again -- re-check https://www.cybergym.io/cybergym/ and the underlying GitHub (sunblaze-ucb/cybergym) before trusting this table more than a few weeks out.

**Current live leaderboard, as of August 2026** (1,507 tasks, ARVO + OSS-Fuzz, hidden differential validation against pre/post-patch builds, 250-min timeout/task):

| Rank/entry | Score | Date | Approach |
|---|---|---|---|
| Sangfor AI | 93.17% | Aug 13 | "Agent Swarm" multi-agent + "Evidence Governance" multi-stage validation |
| NSFOCUS AI | 93.6% Pass@1 | ~Aug | batch orchestration + per-task solving + validation-tooling layers |
| Wiz Atlas | 90.9% | Jul 27 | orchestrates multiple frontier models per task |
| Microsoft MDASH | 88.45% (listed) / 95.95% (self-reported, different counting criterion) | May-Jul | 100+ specialized agents |
| GPT-5.5-Cyber (single model, no agent scaffold) | 85.6% | Jun | -- |
| Claude Mythos 5 | ~83.8% | -- | -- |
| Gemini 3.5 Flash Cyber (in CodeMender) | 83.2% | -- | -- |

Original paper baseline, for contrast with the above (this is what "22%" actually was): OpenHands+GPT-5 at 22.0% with high reasoning / 7.7% with minimal reasoning, on a 300-task subset, evaluated when the benchmark was first published.

**What this changes about the plan below:** the leaderboard entries above aren't single agents with a bash tool -- the tags on the live board itself (`dynamic`, `test-time mem.`) and the vendors' own descriptions (Agent Swarm, orchestrating multiple frontier models, 100+ specialized agents, Evidence Governance) point to multi-model orchestration and multi-stage validation as what's actually separating the top of the board from the rest, not tool access alone. Tool access (Section 3 below) is very likely still a necessary step up from single-shot generation -- CyberGym's task structure (per-task terminal, file ops, prebuilt fuzzer inside an isolated container) is built around exactly that kind of interaction -- but it should be read as a floor to get off of single-shot, not a ceiling that gets us competitive with the current top of the board. Closing more of that gap after Section 3 is done likely means looking at what "Evidence Governance" / multi-stage validation is doing (this maps fairly directly onto what `verify()` / `compile_poc` already do in our own pipeline -- there may be a natural extension there) and whether multi-model ensembling is worth the added Codespaces cost, rather than assuming a single well-tooled agent gets us to parity.

Independent of the leaderboard correction above, the general point about iteration mattering still holds directionally (a fixed executor doing more revision solves more than one-shot), though the specific 23.5%/63%/77% figures cited for that point elsewhere are from a similarly early evaluation window and shouldn't be read as current absolute numbers either -- treat that citation as "iteration compounds a lot," not as a target ceiling.

Three levers, in priority order (highest-confidence / lowest-effort first):
1. **Extraction quality** (in progress) -- CyberGym's own RQ5 shows richer/more accurate
   input info consistently improves success rate. No point tuning anything else against
   corrupted context.
2. **Attempt budget** -- raise `max_attempts` past 5 and measure where the curve actually
   plateaus for our setup.
3. **Agentic tool access** (this document) -- gets us off single-shot generation, which the
   task structure is clearly designed around. Necessary, very likely not sufficient on its
   own to reach current leaderboard territory -- see the note above.

## 2. What OpenHands actually does

Grounded in the OpenHands V1 SDK paper (arXiv 2511.03690) and the CodeActAgent description
used in recent agent-benchmarking papers:

- **Controller-agent-runtime split.** An `AgentController` supervises iteration/budget
  limits and lifecycle (start/stop/pause). The `CodeActAgent` itself only decides what to
  do next; it doesn't own execution.
- **Action/Observation loop, not a fixed pipeline.** Each turn: the agent emits an
  *action* (most commonly `CmdRunAction` -- run an arbitrary bash command), the runtime
  executes it in an isolated sandbox, and the result comes back as an *observation* that
  gets appended to the event stream. The agent decides the next action based on everything
  observed so far. This is the "CodeAct" idea specifically: instead of a large fixed set of
  bespoke JSON tools, give the model bash + a file editor and let it express almost
  anything as code/commands, which is both more flexible and lets execution feedback
  (compiler errors, stack traces, `ls` output) directly steer the next step.
- **Everything is sandboxed.** Actions run inside a container the agent cannot escape;
  this is why OpenHands can be handed a real shell without being handed the host.
- **Event-sourced state, not a single growing prompt.** The full action/observation
  history is an immutable log. As it grows, a summarizing condenser periodically
  compresses older turns instead of truncating or blowing the context window.
- **V1 added an explicit security-analyzer / confirmation policy** (Low/Medium/High risk
  classification per action, configurable auto-approve threshold) -- relevant to us since
  we'd be handing an LLM a live shell inside a container that's compiling and running
  attacker-adjacent C/C++ code.

## 3. Proposed target architecture for TaskVerifier

Don't rebuild the verifier -- `verifier/compiler.py` (`compile_poc`), `verifier/execution.py`
(`check_execution`), and `verifier/__init__.py` (`verify`) already ARE the primitives an
agentic loop needs. The problem isn't that these don't exist, it's that they're only
invoked once *after* the model commits to a full PoC, instead of being callable *during*
the model's reasoning. The fix is exposing them as tools, not replacing them.

**Minimal action set for a CodeAct-style loop, scoped to this task:**
- `run_bash(cmd)` -- executed via `docker exec` into a *persistent* running container for
  that CVE (not a fresh `docker run` per call, which is what `repro_arvo.sh` does today --
  persistence matters here because the agent needs to build up state: write a candidate
  input, run it, inspect the crash, adjust, re-run, without re-pulling/re-starting each time).
- `read_file(path)` / `list_dir(path)` -- scoped to the container's `/src` tree, so the
  model can actually look at the surrounding code instead of only seeing whatever
  `extract_target_source.py` happened to slice out.
- `compile_and_run(poc_bytes)` -- thin wrapper around the existing `compile_poc` +
  `check_execution` + `verify` pipeline, callable mid-attempt, returning the same
  structured result (crash site, sanitizer type, exit code) the current post-hoc verifier
  produces. This is the highest-value single addition: right now the model only finds out
  it was wrong once per *attempt* (5 total); this lets it find out once per *tool call*.
- `submit_poc(poc_bytes)` -- explicit terminal action, replaces "whatever came back from
  the one-shot generation."

**Reuse, don't discard:** `FactAccumulator` and `RetryMemory` are already event-log-shaped
(cross-attempt confirmed-facts store, structured approach notes) -- they map cleanly onto
OpenHands' event-stream model, just currently scoped per-attempt instead of per-tool-call.
`ContextManager` is the natural place to add condensation once transcripts get long from
many tool calls per CVE instead of one prompt per attempt -- without it, a real tool-use
loop will blow past context budgets fast, especially on the long/medium CVEs that are the
whole point of this change.

**Security posture:** we're about to hand an LLM a live shell that's compiling and running
untrusted-ish C/C++ against real memory-corruption PoCs, inside containers that already
need elevated capabilities for ASAN/MSAN to work correctly (see the exit-code-mismatch
discussion above -- `--cap-add=SYS_PTRACE`, `--security-opt seccomp=unconfined`, etc.).
Don't skip a confirmation/risk-classification layer on `run_bash` just because it feels
like overhead -- OpenHands added this in V1 for a reason, and our containers are *more*
permissive than a typical coding-agent sandbox, not less.

## 4. Codespaces-specific constraints

This changes the calculus versus "just copy OpenHands," because Codespaces isn't a
dedicated build farm:

**Compute tier vs. cost.** Machine types: 2-core/4GB, 4-core/8GB, 8-core/16GB, 32-core/64GB.
Billing is per core-hour and scales linearly with core count (an hour on 16-core costs 8x
an hour on 2-core). Compiling C/C++ under ASAN/MSAN repeatedly -- which an iterative
compile-run-inspect loop does *a lot more of* than the current single-shot pipeline -- is
CPU/RAM-heavy, especially for the larger projects in our set (ffmpeg, wireshark, sqlite).
Default/free-tier machines will be slow or OOM under a real agentic loop. Budget for at
least 8-core/16GB for actual agent runs, and treat that as a real recurring cost line, not
a one-time setup choice -- 145 CVEs x N tool calls each x 8-core-hour pricing adds up fast.

**Disk.** Default storage is 32GB regardless of machine tier (higher tiers top out around
128GB but larger allocations reportedly require a support request, not a self-serve
option). Multiple ARVO docker images (each project = its own image) + git clones of
several large C/C++ repos (glibc-family projects especially) + build artifacts will exhaust
32GB fast if run unattended across many CVEs. Need explicit cleanup between CVEs
(`docker system prune`, dropping repo clones once a batch is done) built into whatever
runs the batch, not left as manual housekeeping.

**Idle timeout / session persistence.** Default idle timeout is 30 minutes; the community
consensus is to lower it further to control cost, which is the opposite direction we need
for a long autonomous run. A tool-use agent loop across 145 CVEs at even 10-20 tool calls
each is a multi-hour unattended job. Don't rely on an interactive browser/VS Code session
staying open for that -- run it detached (`tmux`/`screen` inside the codespace, or as a
background process with `nohup`) and raise the idle timeout for the duration of the batch,
or move batch execution off interactive Codespaces entirely once the loop is stable (a
scheduled runner or dedicated VM), keeping Codespaces for interactive dev/debugging only.

**Nested-container capability restrictions.** We already hit one instance of this class of
problem in the exit-code-139-vs-77 investigation -- sanitizer behavior depending on
host kernel/ASLR/seccomp settings. Running Docker *inside* a Codespace (itself a
container) adds another layer where capability restrictions can differ from a bare-metal
or VM Docker host. Before building the agent's `run_bash`/`compile_and_run` tools around
assumptions like "we can toggle ASLR" or "we can attach ptrace," verify those operations
actually work through Codespaces' nested Docker setup (docker-outside-of-docker vs.
docker-in-docker devcontainer feature matters here) rather than assuming parity with a
teammate's local Docker install.

## 5. Phased rollout

1. Finish extraction re-verification (current work).
2. Raise `max_attempts`, re-run `compute_metrics.py` against the current single-shot
   architecture to get a clean before/after baseline before touching the agent loop --
   otherwise we won't know how much of any later improvement came from more attempts vs.
   from tool access.
3. Prototype `compile_and_run` as a mid-attempt tool on a small subset (5-10 CVEs spanning
   short/medium/long buckets) before wiring it into the full loop. Confirm the persistent-
   container-via-`docker exec` approach actually behaves correctly on an 8-core Codespace
   before assuming it will.
4. Add the confirmation/risk-classification layer on `run_bash` before running it
   unattended across the full set.
5. Full agentic loop across the dataset, with disk/cost cleanup automated per the
   constraints above, not manual.

## 6. Open questions to resolve before committing engineering time

- Does `verify()`'s existing crash-site validation logic generalize to being called
  mid-attempt with a partial/exploratory input, or does it assume a "final answer" framing
  that would need rework?
- What's the actual per-CVE tool-call budget we can afford given Codespaces core-hour
  cost, and does that budget realistically compete with Best-of-8/sequential-revision
  numbers from the Mastermind ablation, or are we cost-capped below where the curve starts
  paying off?
- Do we want one persistent container per CVE for the duration of an agent's attempts, or
  reset it per-attempt (safer/cleaner state, but loses the "the agent's earlier
  exploration left useful artifacts in the container" benefit that's part of why tool
  access helps in the first place)?