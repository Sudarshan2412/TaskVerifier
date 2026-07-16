# TaskVerifier

Feedback-guided AI agent for iteratively generating and refining Proof-of-Concept exploit code for known vulnerabilities. The system uses a closed-loop pipeline to compile code, detect failures via sanitizers, parse structured error messages, and feed corrections back to an LLM for multiple refinement attempts.

Benchmarked on the [CyberGym](https://arxiv.org/abs/2506.02548) dataset (1,507 real-world CVEs).

---

## Overview

Typical AI PoC generation fails silently or produces unusable code because the model never sees compilation or execution feedback. **TaskVerifier** addresses this by implementing a feedback loop:

1. LLM generates PoC code
2. Verify pipeline compiles it and captures errors (or executes and detects crashes)
3. Structured feedback extracted from compiler/sanitizer output
4. Feedback appended to LLM context for next attempt
5. Repeat up to 5 times or until success

**Core advantage:** Structured, actionable error messages — extracted from AddressSanitizer, UndefinedBehaviorSanitizer, and compiler output — significantly improve model accuracy on complex, longer exploits (>100 bytes).

**Pass criteria:** PoC crashes the vulnerable binary but not the patched version, matching CyberGym's evaluation standard.

---

## Tech Stack

- **Language:** Python 3.11+
- **LLM:** DeepSeek v4 Flash via OpenRouter API
- **Compilation:** GCC / Clang with ASan + UBSan flags
- **Execution:** Docker (isolated, no network, memory-limited)
- **Analysis:** pandas, matplotlib
- **Validation:** pydantic

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker + Docker Compose
- ~15–20 GB disk space (for CyberGym binary subset)
- OpenRouter API key (get one at https://openrouter.ai)

### Installation

1. **Clone and set up environment:**
   ```bash
   git clone https://github.com/your-org/TaskVerifier.git
   cd TaskVerifier
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   
   # Set API key
   export OPEN_ROUTER_KEY="your-openrouter-api-key"  # or .env file
   ```

2. **Build Docker image:**
   ```bash
   docker build -t cybergym-sandbox:latest .
   ```

3. **Download CyberGym binaries** (optional, for real runs):
   ```bash
   # See instructions.md for setup details
   ```

---

## Usage

### Run Pipeline on a Specific CVE

To run the pipeline on a specific CVE, follow these three steps:

1. **Pull the vulnerable Docker image**:
   ```bash
   docker pull <docker-image-vul>  # Get the image tag from cybergym_subset.json
   ```

2. **Run the pipeline**:
   ```bash
   WEEK8_CVE_IDS="<cve-id>" WEEK8_MAX_ATTEMPTS=<no-of-attempts> python run_pipeline.py
   ```

3. **Remove the Docker image** (optional, to save space):
   ```bash
   docker rmi <docker-image-vul>  # Get the image tag from cybergym_subset.json
   ```

### Single CVE Trial

```python
from agent.agent_loop import run_agent

cve_entry = {
    "id": "arvo_10013",
    "target_source": "// vulnerable C code here",
    "crash_description": "heap-buffer-overflow",
    "vuln_class": "buffer_overflow",
    "sanitizer_type": "asan",
    "poc_bucket": "long",
    "docker_image": "n132/arvo:10013-vul",
}

result = run_agent(cve_entry, max_attempts=5)
print(f"Success: {result.success}")
print(f"Attempts: {result.attempts}")
print(f"Final PoC:\n{result.final_poc}")
```

### Batch Experiment

For verifier-assisted runs (with feedback loop):

```bash
python scripts/run_pilot.py \
  --subset data/cybergym_subset.json \
  --mode verifier \
  --max-attempts 5 \
  --limit 20 \
  --output data/results/with_verifier_sample.json
```

Or use `baseline_runner.py` for one-shot generation:

```bash
python baseline_runner.py \
  --dataset data/cybergym_subset.json \
  --output data/results/baseline.json
```

### Analyze Results

```bash
python compute_metrics.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json \
  --out data/results/metrics.json

python plot_results.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json \
  --out-dir data/results/figures/
```

---

## Project Structure

```
TaskVerifier/
├── agent/                          # LLM client and prompt orchestration
│   ├── agent_loop.py               # Main retry loop with feedback
│   ├── llm_client.py               # OpenRouter API wrapper (DeepSeek v4 Flash)
│   ├── prompt_builder.py           # Prompt templates for initial + feedback phases
│   ├── code_extractor.py           # Parse C code from markdown/prose
│   ├── context_manager.py          # Conversation history with token budget
│   └── __init__.py
│
├── verifier/                       # Compilation, execution, error parsing
│   ├── compiler.py                 # GCC/Clang error extraction
│   ├── sanitizer.py                # ASan/UBSan crash parsing
│   ├── execution.py                # Exit code and crash detection
│   ├── feedback_builder.py         # Compress errors into 3–5 actionable lines
│   ├── hallucination_detector.py   # Flag invalid symbol references
│   └── __init__.py
│
├── harness/                        # Empty (placeholder for future use)
│   └── __init__.py
│
├── scripts/
│   ├── run_experiments.py          # Baseline vs verifier comparison
│   └── run_pilot.py                # Quick 10-task run
│
├── tests/
│   ├── test_agent.py
│   ├── test_harness.py
│   └── test_verifier.py
│
├── data/
│   ├── cybergym_subset.json        # ~100 CVEs (stratified by PoC length)
│   └── results/                    # Trial outputs
│       ├── logs/                   # Per-task attempt logs (JSONL)
│       └── figures/                # Matplotlib plots
│
├── runner.py                       # Trial orchestrator library (imported by scripts)
├── evaluator.py                    # Pass/fail logic (pre-patch crash vs post-patch clean)
├── logger.py                       # JSON transcript writer
├── baseline_runner.py              # Runs experiments without feedback loop
├── compute_metrics.py              # Aggregates results by bucket and class
├── plot_results.py                 # Generates comparison bar charts
├── select_subset.py                # Stratified sampling from CyberGym
│
├── trial_workspace/                # Temporary PoC files (Docker mount point)
├── logs/                           # Manual test logs and transcripts
├── target_sources/                 # C source files of target vulnerabilities
│
├── Dockerfile                      # Container with GCC, ASan, UBSan
├── docker-compose.yml              # Container orchestration
├── requirements.txt
├── few_shot_examples.json          # LLM prompting examples
├── cybergym_subset.json            # CVE dataset
├── schema.md                       # Data structure definitions
├── context.md                      # Project overview
├── instructions.md                 # Detailed environment setup
├── README.md
└── plan.md                         # Development workflow guide
```

---

## How It Works

### Agent Loop

```
CVE Entry
    ↓
┌─ Build initial prompt (target_source + crash_description)
│ ↓
├─ Call LLM (DeepSeek v4 Flash via OpenRouter)
│ ↓
├─ Extract C code from response
│ ↓
├─ Detect hallucinated symbols
│ ↓
├─ Send to Verifier Pipeline
│ ├─ Compiler stage (GCC/Clang)
│ ├─ Sanitizer stage (ASan/UBSan output parsing)
│ ├─ Execution stage (exit code check)
│ └─ Feedback stage (compress to ~3–5 lines)
│ ↓
├─ Feedback received?
│   ├─ YES: Append to context, retry (up to 5 attempts)
│   └─ NO: Return result
│ ↓
Result (success, attempts, final_poc, transcript)
```

### Verifier Pipeline

**Input:** C code (string)
**Output:** Structured feedback (3–5 lines of actionable error info)

| Stage | What it does | Example output |
|-------|-----------|---------|
| **Compiler** | Run GCC with `-fsanitize=address,undefined` | `poc.c:12: undefined reference to 'invalid_func'` |
| **Sanitizer** | Parse ASan/UBSan stderr for crash signature | `ERROR: AddressSanitizer: SEGV on unknown address 0x...` |
| **Execution** | Check exit code and stderr for crashes | `Exit 139 — likely segfault detected` |
| **Feedback Builder** | Compress all stages into concise guidance | `Compilation failed: 'invalid_func' not found at line 12` |

### Evaluation

**Pass:** PoC triggers sanitizer crash on vulnerable binary AND runs cleanly on patched binary.
**Fail:** Any other outcome (no crash, wrong crash type, crashes patched version).

---

## Dependencies

See [requirements.txt](requirements.txt):

```
requests          # HTTP client for OpenRouter API
python-dotenv     # .env file support
pydantic          # Data validation
pandas            # Results analysis
matplotlib        # Plotting
rich              # Terminal formatting
pytest            # Test runner
```

---

## Environment Setup

### OpenRouter API

Get an API key from https://openrouter.ai, then set it in your environment:

```bash
export OPEN_ROUTER_KEY="sk-or-..."
```

Or create a `.env` file:
```
OPEN_ROUTER_KEY=sk-or-...
```

The agent will call `https://openrouter.ai/api/v1/chat/completions` and use the **DeepSeek v4 Flash** model by default.

### CyberGym Binaries (Optional)

For real vulnerability testing, download the binary subset:

```bash
cd ~/cybergym
python3 scripts/server_data/download_subset.py

# Then run the PoC server (see instructions.md for full details)
```

---

## Configuration

### Environment Variables

```bash
# In .env or export in shell:
OPEN_ROUTER_KEY=sk-or-...                        # Required: OpenRouter API key
INTER_ATTEMPT_SLEEP_SECONDS=0                    # Rate limiting between retries
MAX_ATTEMPTS=5                                   # Default retry limit
DOCKER_IMAGE=cybergym-sandbox:latest             # Container to use
```

### Few-Shot Examples

The agent uses few-shot examples from [few_shot_examples.json](few_shot_examples.json) to improve prompt quality. Format:

```json
{
  "examples": [
    {
      "vuln_class": "buffer_overflow",
      "target_code": "...",
      "poc_code": "...",
      "explanation": "..."
    }
  ]
}
```

---

## Scripts

### `select_subset.py`
Stratify CVEs from CyberGym by PoC length (short/medium/long) and vulnerability class. Outputs `cybergym_subset.json`.

```bash
python select_subset.py \
  --input ~/cybergym/cybergym.json \
  --output cybergym_subset.json \
  --short 30 --medium 35 --long 35
```

### `baseline_runner.py`
Generate PoCs without verifier feedback (one attempt per CVE).

```bash
python baseline_runner.py \
  --dataset data/cybergym_subset.json \
  --output data/results/baseline.json \
  --temperature 0.6
```

### `runner.py`
Trial orchestrator library (imported by scripts, not directly executable). Defines `run_trial()` and `run_experiment()` functions used by pilot scripts.

### `scripts/run_pilot.py`
End-to-end pilot runner with CLI. Runs a small batch of trials (baseline or verifier mode).

```bash
python scripts/run_pilot.py \
  --subset data/cybergym_subset.json \
  --mode verifier \
  --limit 20 \
  --max-attempts 5 \
  --output data/results/pilot_results.json
```

### `compute_metrics.py`
Compare baseline vs verifier results by PoC bucket, vulnerability class, and overall.

```bash
python compute_metrics.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json \
  --out data/results/metrics.json
```

### `plot_results.py`
Generate bar charts showing improvement (delta) between baseline and verifier.

```bash
python plot_results.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json \
  --out-dir data/results/figures/
```

---

## Testing

```bash
pytest tests/ -v

# Test specific components:
pytest tests/test_verifier.py -v
pytest tests/test_agent.py -v
```

---

## Project Structure Details

**Data Flow:**
1. `cybergym_subset.json` → stratified CVE sample
2. `runner.py` loads entries, calls `agent_loop.run_agent()`
3. Agent generates PoC, passes to verifier
4. Verifier creates `/trial_workspace/poc.c` and mounts into Docker
5. Docker compiles and executes, returns sanitizer output
6. Feedback extracted and sent back to agent
7. Agent retries with context + feedback
8. Final result logged to `data/results/logs/{task_id}.jsonl`

**Agent Context Management:**
- Uses sliding window to keep conversation history within token budget
- Removes old attempts to make room for new feedback
- Never exceeds ~6000 tokens (roughly 24K characters)

---

## Limitations & Future Work

- **Single-task binary execution:** Currently tests one PoC per binary. Could parallelize across CVEs.
- **No interactive crashes:** Assumes PoCs are fire-and-forget (no stdin interaction).
- **Fixed retry limit:** Currently 5 attempts max. Could adapt based on feedback quality.
- **Limited to C/C++:** Other languages would require additional compiler support.
- **No model fine-tuning:** Uses DeepSeek v4 Flash; could benefit from domain-specific tuning.

Future improvements:
- Multi-attempt parallelization
- Support for other languages (Rust, Go, Java)
- Adaptive retry budgeting
- Fine-tuned models for vulnerability reproduction
- Integration with real CyberGym server for live testing

---

## License

TBD

---

## Contributing

- Follow the workflow documented in [plan.md](plan.md)
- Add tests for new components
- Update [schema.md](schema.md) if data structures change
- Log lessons learned in [tasks/lessons.md](tasks/lessons.md)
```

### 3. Set up the Docker sandbox

```bash
# Build the Docker image
docker build -t cybergym-sandbox:latest .

# Verify sandbox works
docker-compose run --rm sandbox sh -c 'echo "sandbox ok"'

# Verify network is blocked (this should FAIL — that is correct behaviour)
docker-compose run --rm sandbox sh -c 'curl google.com' || echo "Network blocked (expected)"

# Verify ASan is available
docker-compose run --rm sandbox sh -c \
  'echo "#include<stdlib.h>\nint main(){char*p=malloc(10);p[20]=1;}" \
  > t.c && gcc -fsanitize=address t.c -o t && ./t || true'
```

> ⚠️ Never disable `network_mode: none` in docker-compose.yml. Running AI-generated exploit code with network access is a serious security risk.

### 4. Configure OpenRouter API

```bash
# Get an API key from https://openrouter.ai
# Create a .env file in the project root:
echo 'OPEN_ROUTER_KEY=sk-or-...' > .env

# Or export it:
export OPEN_ROUTER_KEY='sk-or-...'
```

### 5. Get the CyberGym dataset

Obtain access to the CyberGym benchmark from the paper authors or their repository. Once you have the data, run the subset selector:

```bash
python select_subset.py \
  --cybergym_dir /path/to/cybergym \
  --output data/cybergym_subset.json \
  --short 30 --medium 35 --long 35
```

This produces `data/cybergym_subset.json` with ~100 CVEs stratified by PoC length and balanced across vulnerability classes (buffer overflow, use-after-free, integer overflow).

Each entry in the JSON has this structure:

```json
{
  "id": "CVE-2021-1234",
  "poc_bytes": 87,
  "poc_bucket": "medium",
  "vuln_class": "buffer_overflow",
  "target_source": "/* C source code of vulnerable function */",
  "crash_description": "heap-buffer-overflow at offset +0x28",
  "sanitizer_type": "asan"
}
```

---

## Running Experiments

### Quick sanity check (baseline only, 5 CVEs)

```bash
python baseline_runner.py \
  --dataset data/cybergym_subset.json \
  --output data/results/baseline_quick.json
```

### Run full baseline experiment (no verifier feedback)

```bash
python baseline_runner.py \
  --dataset data/cybergym_subset.json \
  --output data/results/baseline.json \
  --temperature 0.6
```

### Run verifier experiment (with feedback loop)

For real runs with the verifier loop, use `runner.py`:

```bash
python runner.py \
  --dataset data/cybergym_subset.json \
  --output data/results/with_verifier.json \
  --use-verifiers \
  --max-attempts 5
```

> ⚠️ The full verifier run over ~100 CVEs with 5 attempts each can take 12–24+ hours depending on hardware. Use `tmux` or `screen` to keep the session alive.

### Compute metrics and generate plots

```bash
python compute_metrics.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json \
  --out data/results/metrics.json

python plot_results.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json \
  --out-dir data/results/figures/
```
  --results_dir data/results/ \
  --output_dir data/results/figures/
```

### Run tests

```bash
pytest tests/ -v
```

---

## Results

Results are broken down by PoC length bucket and vulnerability class. Key metrics reported:

| Metric | Description |
|--------|-------------|
| Overall success rate | Baseline vs. verifier-assisted, across all ~100 CVEs |
| Success rate by bucket | Short / medium / long PoC breakdown |
| Mean iterations to success | Average feedback rounds needed on successful verifier trials |
| Failure stage breakdown | Where the pipeline fails most — compile / sanitizer / execution |
| Qualitative failure analysis | Why the agent failed even with structured feedback |

Output figures are saved to `data/results/figures/`.

---

## Ethical Considerations

All experiments use vulnerabilities that were publicly disclosed and patched prior to inclusion in the CyberGym benchmark. No evaluation is conducted on unpatched software. All PoCs are confined to isolated, containerised environments and are never transmitted externally. This project does not attempt to discover new vulnerabilities — it strictly evaluates PoC reproduction for academic research purposes.

---

## References

- Wang et al. (2025). *CyberGym: Evaluating AI Agents' Real-World Cybersecurity Capabilities at Scale.* [arXiv:2506.02548](https://arxiv.org/abs/2506.02548)
- Serebryany et al. (2012). *AddressSanitizer: A Fast Address Sanity Checker.* USENIX ATC.
- Wang et al. (2025). *OpenHands: An Open Platform for AI Software Developers as Generalist Agents.* ICLR 2025.

---

*RV College of Engineering — Experiential Learning 2025–26*
