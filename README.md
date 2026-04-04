# Vulnerability Reproduction Framework via Verifier-Guided LLMs

A closed-loop AI agent system that generates, executes, and iteratively refines Proof-of-Concept (PoC) exploit code for known software vulnerabilities — using structured sanitizer feedback to guide each attempt.

Evaluated on the [CyberGym](https://arxiv.org/abs/2506.02548) benchmark (1,507 real-world CVEs).

---

## Table of Contents

- [Overview](#overview)
- [Research Question](#research-question)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Setup](#setup)
- [Running Experiments](#running-experiments)
- [Results](#results)
- [Ethical Considerations](#ethical-considerations)
- [References](#references)

---

## Overview

Most AI-generated PoC exploit code is produced in a **single shot** — the model generates once and has no idea whether the code compiled, crashed correctly, or failed silently. This works for simple exploits but collapses for complex vulnerabilities requiring longer, precisely crafted inputs.

This project builds a **Structured Error Parsing Verifier (SEP-V)** — a feedback pipeline that:

1. Takes the model's generated PoC
2. Compiles it inside an isolated Docker sandbox with AddressSanitizer + UBSan enabled
3. Executes it against the vulnerable target binary
4. Parses the raw compiler errors and sanitizer crash output into 3–5 structured, signal-rich lines
5. Feeds that back to the model so it can revise and retry — up to N times

The core hypothesis: **granular, structured feedback significantly improves PoC success rates**, especially for longer PoCs (>100 bytes) where blind single-shot generation is known to fail most severely.

---

## Research Question

> How much does access to granular task verifiers improve a baseline model's success rate on CyberGym — particularly for vulnerabilities requiring longer PoCs (>100 bytes)?

Two conditions are compared on a stratified subset of ~100 CVEs:

| Condition | Description |
|-----------|-------------|
| **Baseline** | Model generates one PoC, no feedback, result recorded |
| **Verifier-assisted** | Model gets up to 5 iterations of structured verifier feedback |

Results are broken down by PoC length bucket: **Short (<50B)**, **Medium (50–100B)**, **Long (>100B)**.

---

## How It Works

```
cybergym_subset.json
        │
        ▼
┌─────────────────┐
│  Agent Scaffold │  ← loads CVE, builds prompt, calls LLM
└────────┬────────┘
         │  PoC code
         ▼
┌─────────────────────────────────────┐
│         Verifier Pipeline           │  ← runs inside Docker sandbox
│                                     │
│  1. Compiler Check  (gcc + ASan)    │
│     └─ extracts: file, line, error  │
│                                     │
│  2. Sanitizer Check (ASan/UBSan)    │
│     └─ extracts: crash type,        │
│        address, top 2 stack frames  │
│                                     │
│  3. Execution Check (exit code)     │
│     └─ flags clean exit (no crash)  │
│                                     │
│  4. Feedback Builder                │
│     └─ compresses → 3–5 lines       │
└────────┬────────────────────────────┘
         │  structured feedback
         ▼
┌─────────────────┐
│  Agent Scaffold │  ← appends feedback to context, retries (up to N times)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Harness/Logger  │  ← logs full transcript, evaluates pass/fail
└─────────────────┘
```

**Pass/Fail criteria** (identical to CyberGym's evaluation standard):
- ✅ PoC triggers a sanitizer crash on the **pre-patch** binary
- ✅ PoC does **not** crash the **post-patch** binary

---

## Project Structure

```
cybergym-verifier/
├── README.md
├── requirements.txt
│
├── docker/
│   ├── Dockerfile.sandbox          # Isolated execution environment (GCC + ASan + UBSan, no network)
│   └── docker-compose.yml          # Container orchestration
│
├── data/
│   ├── cybergym_subset.json        # ~100 selected CVEs (stratified by PoC length)
│   └── results/                    # Trial output logs (gitignored)
│       ├── baseline.json
│       └── with_verifier.json
│
├── agent/
│   ├── __init__.py
│   ├── llm_client.py               # ollama REST API wrapper
│   ├── prompt_builder.py           # System + user prompt templates (initial + feedback)
│   ├── code_extractor.py           # Strips markdown fences and prose from model output
│   ├── agent_loop.py               # Main retry loop — the agent scaffold
│   └── context_manager.py          # Keeps conversation history within context window
│
├── verifier/
│   ├── __init__.py                 # VerifierPipeline — chains all stages
│   ├── base.py                     # VerifierResult dataclass + BaseVerifier interface
│   ├── compiler.py                 # Parses gcc/clang errors → file, line, error type
│   ├── sanitizer.py                # Parses ASan/UBSan crash → type, address, top 2 frames
│   ├── execution.py                # Detects clean exit (exit code 0, no crash triggered)
│   └── feedback_builder.py         # Compresses stage outputs → 3–5 actionable lines
│
├── harness/
│   ├── __init__.py
│   ├── runner.py                   # Runs a single trial end-to-end
│   ├── evaluator.py                # Pass/fail logic (pre-patch crash + post-patch clean)
│   └── logger.py                   # Writes full JSON transcript per trial
│
├── analysis/
│   ├── compute_metrics.py          # Aggregates results by bucket, class, condition
│   └── plot_results.py             # Generates comparison bar charts and figures
│
├── scripts/
│   ├── select_subset.py            # Stratified CVE selection from CyberGym
│   └── run_baseline.py             # Runs both baseline and verifier experiments
│
└── tests/
    ├── test_verifier.py            # Unit tests for each verifier stage
    └── test_agent.py               # Unit tests for agent scaffold components
```

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.11+ | Primary language |
| Docker + Docker Compose | Isolated sandbox — runs exploit code safely, no network access |
| ollama | Local LLM server — serves qwen2.5-coder:7b via REST API |
| qwen2.5-coder:7b | Agent model — fine-tuned for code generation tasks |
| GCC / Clang | Compiles PoC files with sanitizer flags enabled |
| AddressSanitizer (ASan) | Detects buffer overflows, use-after-free, heap corruption |
| UndefinedBehaviorSanitizer (UBSan) | Detects integer overflows, null dereferences |
| pytest | Evaluation harness test runner |
| pandas + matplotlib | Results analysis and plotting |
| pydantic | Data validation for config and verifier output schemas |

---

## Setup

### Prerequisites

- Python 3.11+
- Docker + Docker Compose
- At least 16 GB RAM (for running the 7B model locally)
- A GPU is recommended but not required

### 1. Clone the repo

```bash
git clone https://github.com/your-org/cybergym-verifier.git
cd cybergym-verifier
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt`:
```
requests
pandas
matplotlib
pydantic
rich
pytest
```

### 3. Set up the Docker sandbox

```bash
cd docker/
docker compose build

# Verify sandbox works
docker compose run --rm sandbox sh -c 'echo "sandbox ok"'

# Verify network is blocked (this should FAIL — that is correct behaviour)
docker compose run --rm sandbox sh -c 'curl google.com'

# Verify ASan is available
docker compose run --rm sandbox sh -c \
  'echo "#include<stdlib.h>\nint main(){char*p=malloc(10);p[20]=1;}" \
  > t.c && gcc -fsanitize=address t.c -o t && ./t'
```

> ⚠️ Never disable `network_mode: none` in docker-compose.yml. Running AI-generated exploit code with network access is a serious security risk.

### 4. Set up ollama and pull the model

```bash
# Install ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the model (~4–5 GB download)
ollama pull qwen2.5-coder:7b

# Verify it works
ollama run qwen2.5-coder:7b 'Write hello world in C'
```

### 5. Get the CyberGym dataset

Obtain access to the CyberGym benchmark from the paper authors or their repository. Once you have the data, run the subset selector:

```bash
python scripts/select_subset.py \
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

### Quick sanity check (5 CVEs)

```bash
python scripts/run_baseline.py \
  --subset data/cybergym_subset.json \
  --limit 5 \
  --mode both
```

### Run baseline experiment (no verifier)

```bash
python scripts/run_baseline.py \
  --subset data/cybergym_subset.json \
  --mode baseline \
  --max_attempts 1 \
  --output data/results/baseline.json
```

### Run verifier experiment (with feedback loop)

```bash
python scripts/run_baseline.py \
  --subset data/cybergym_subset.json \
  --mode verifier \
  --max_attempts 5 \
  --output data/results/with_verifier.json
```

> ⚠️ The full verifier run over ~100 CVEs with 5 attempts each can take 12–24+ hours depending on hardware. Use `tmux` or `screen` to keep the session alive.

### Compute metrics and generate plots

```bash
python analysis/compute_metrics.py \
  --baseline data/results/baseline.json \
  --verifier data/results/with_verifier.json

python analysis/plot_results.py \
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
