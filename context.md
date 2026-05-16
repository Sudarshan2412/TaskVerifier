# TaskVerifier: Vulnerability Reproduction Framework

TaskVerifier is a closed-loop AI agent system designed to generate, execute, and iteratively refine Proof-of-Concept (PoC) exploit code for known software vulnerabilities. It uses structured sanitizer feedback to guide an LLM through multiple attempts to trigger a specific crash.

## Project Structure

```text
TaskVerifier/
├── agent/                  # Core LLM agent logic
│   ├── agent_loop.py       # Main iterative retry loop (orchestrator)
│   ├── llm_client.py       # Interface to LLM (ollama/OpenRouter)
│   ├── prompt_builder.py   # Constructs system and user prompts
│   ├── code_extractor.py   # Extracts C code from LLM responses
│   └── context_manager.py  # Manages sliding window conversation history
├── verifier/               # Structured Error Parsing Verifier (SEP-V)
│   ├── __init__.py         # VerifierPipeline entry point
│   ├── compiler.py         # GCC/Clang compilation and error parsing (Docker-based)
│   ├── execution.py        # Binary execution logic
│   ├── sanitizer.py        # ASan/UBSan crash output parsing
│   ├── feedback_builder.py # Compresses raw errors into structured feedback
│   └── hallucination_detector.py # Detects hallucinated file/type references
├── logs/                   # JSON transcripts and summary reports from runs
├── data/                   # Data storage (results and subsets)
├── tasks/                  # TODO lists and project lesson logs
├── target_sources/         # C source files of target vulnerabilities
├── trial_workspace/        # Temporary space for PoC compilation/execution
├── Dockerfile              # Sandbox environment definition (Clang + Sanitizers)
├── docker-compose.yml      # Sandbox orchestration
├── runner.py               # Orchestrates a single trial (Agent + Verifier)
├── baseline_runner.py      # Runs experiments without the feedback loop
├── evaluator.py            # Pass/Fail logic (pre-patch crash vs post-patch clean)
├── logger.py               # Logging utility for experiments
├── cybergym_subset.json    # Target vulnerabilities for evaluation
├── few_shot_examples.json  # Prompting examples for the LLM
└── README.md               # Overview and setup instructions
```

## Detailed File Descriptions

### Core Logic
- **`runner.py`**: The primary entry point for running an integrated trial. It takes a CVE entry, runs the agent loop, evaluates the result, and logs the attempt.
- **`agent/agent_loop.py`**: The "brain" of the operation. It orchestrates the flow: Prompt -> LLM -> Extract -> Verify -> Feedback -> Retry.
- **`verifier/__init__.py`**: Defines the `VerifierPipeline` which sequences hallucination detection, compilation, execution, and sanitizer parsing.

### Agent Component (`agent/`)
- **`llm_client.py`**: Handles API calls. Supports history-based conversations to allow the model to learn from its previous mistakes.
- **`prompt_builder.py`**: Uses templates to create initial prompts (with few-shot examples) and feedback prompts (with structured error messages).
- **`code_extractor.py`**: A robust utility to pull C code out of markdown-heavy LLM responses.
- **`context_manager.py`**: Ensures the conversation history doesn't exceed the model's context window while preserving essential feedback.

### Verifier Component (`verifier/`)
- **`compiler.py`**: Writes `poc.c` to `trial_workspace/` and runs a Docker container to compile it using `clang` with `-fsanitize=address,undefined`.
- **`execution.py`**: Runs the compiled binary and checks for basic execution success or failure.
- **`sanitizer.py`**: Specifically looks for AddressSanitizer and UndefinedBehaviorSanitizer signatures in `stderr` to identify the crash type and location.
- **`feedback_builder.py`**: Transforms complex compiler/sanitizer logs into 3–5 actionable lines for the LLM (e.g., "Line 42: heap-buffer-overflow").
- **`hallucination_detector.py`**: Compares symbols in the generated PoC against the `target_source` to ensure the agent isn't inventing non-existent functions.

### Evaluation & Infrastructure
- **`evaluator.py`**: Implements the CyberGym standard: a PoC passes if it crashes the pre-patch binary and does NOT crash the post-patch binary.
- **`logger.py`**: Writes detailed JSON logs for every attempt, which are used later for metrics.
- **`baseline_runner.py`**: Used for comparison. It runs a single-shot generation without any verifier feedback.
- **`compute_metrics.py`**: Analyzes logs to calculate success rates across different "buckets" (short, medium, long PoCs).
- **`plot_results.py`**: Generates visual representations of the performance gain from verifier guidance.

### Documentation & Metadata
- **`README.md`**: General overview, setup, and research background.
- **`instructions.md`**: Specific steps for running experiments and handling dependencies.
- **`schema.md`**: Defines the JSON structures for CVE subsets and log outputs.
- **`verifier_api_doc.md`**: Technical specification of the Verifier's internal API.
- **`plan.md`**: Historical development plan and roadmap.
- **`sudarshan_role.md`**: Track-specific role definitions and task assignments.

## Key Workflow

1.  **Selection**: A CVE is picked from `cybergym_subset.json`.
2.  **Prompting**: `prompt_builder` creates a prompt describing the vulnerability.
3.  **Generation**: LLM produces a PoC (extracted by `code_extractor`).
4.  **Verification**:
    - `hallucination_detector` checks if the code is grounded.
    - `compiler` runs `docker run` to build the PoC with sanitizers.
    - `sanitizer` parses any resulting crash.
5.  **Iteration**: If it didn't crash as expected, `feedback_builder` creates a concise error report, and the cycle repeats.
6.  **Logging**: The entire transcript is saved to `logs/`.
