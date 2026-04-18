# Environment Validation Instructions
## For: Teammate taking over Step 7 (Environment Testing)
## Context: Aparna's Phase 1–3 work — Vulnerability Reproduction Framework

---

## What Has Already Been Done (Do Not Redo)

- CyberGym repo cloned
- `select_subset.py` written and run → `cybergym_subset.json` generated
- `schema.md` written
- `Dockerfile` and `docker-compose.yml` written
- Docker image built successfully:
  ```bash
  docker build -t cybergym-sandbox:latest .
  ```

**Your job is Step 7 and Step 8 only** — environment validation and the test report.

---

## Prerequisites — What You Need on Your Machine

- Linux or WSL2 (Ubuntu 22.04 recommended)
- Docker Desktop installed and running
- At least **15–20 GB free disk space** (for the 10-task binary subset)
- Stable internet connection
- Python 3.10+

---

## Part 0 — Clone the Repo and Set Up

```bash
# Clone the team project repo
git clone https://github.com/Sudarshan2412/TaskVerifier.git
cd TaskVerifier

# Also clone the CyberGym code repo (separate from our project repo)
cd ~
git clone https://github.com/sunblaze-ucb/cybergym.git
cd cybergym

# Install Python dependencies
sudo apt update && sudo apt install -y python3-pip python3-venv git git-lfs p7zip-full
pip3 install -e '.[dev,server]' --break-system-packages
```

---

## Part 1 — Build the Docker Image

```bash
# Go to the team project repo root
cd ~/TaskVerifier

# Build the sandbox image
docker build -t cybergym-sandbox:latest .
```

You should see `Successfully built ...` at the end. If not, stop and report the error.

---

## Part 2 — Download the 10-Task Binary Subset

This is the small subset (~few GB, NOT the full 130GB).

```bash
cd ~/cybergym

# Download only the 10-task subset
python3 scripts/server_data/download_subset.py
```

Wait for this to fully complete before moving on.

---

## Part 3 — Start the PoC Server

You need **two terminal windows open simultaneously**.
The server must keep running the entire time you test.

**Open Terminal 1 and run:**

```bash
cd ~/cybergym

PORT=8666
POC_SAVE_DIR=./server_poc
mkdir -p $POC_SAVE_DIR

python3 -m cybergym.server \
  --host 0.0.0.0 --port $PORT \
  --log_dir $POC_SAVE_DIR \
  --db_path $POC_SAVE_DIR/poc.db \
  --binary_dir ./cybergym-server-data
```

You should see something like `Server running on 0.0.0.0:8666`.
**Leave Terminal 1 alone — do not close it.**

---

## Part 4 — Run the 5 Known Tasks

**Open Terminal 2 and run:**

```bash
cd ~/cybergym

# Set these once
SERVER_IP=127.0.0.1
SERVER_PORT=8666
CYBERGYM_DATA_DIR=./cybergym_data/data
```

Now run the following block **5 times**, changing only the `TASK_ID` line each time:

```bash
# ---- CHANGE TASK_ID FOR EACH RUN ----
TASK_ID='arvo:10400'
# Other IDs to use one by one:
# arvo:3938
# arvo:1065
# arvo:368
# arvo:47101
# --------------------------------------

OUT_DIR=./cybergym_tmp/$TASK_ID
mkdir -p "$OUT_DIR"

python3 -m cybergym.task.gen_task \
  --task-id $TASK_ID \
  --out-dir "$OUT_DIR" \
  --data-dir $CYBERGYM_DATA_DIR \
  --server "http://$SERVER_IP:$SERVER_PORT" \
  --difficulty level2

# Submit a dummy PoC
echo -en "\x00\x01\x02\x03" > "$OUT_DIR/poc"
bash "$OUT_DIR/submit.sh" "$OUT_DIR/poc"

echo "Exit code was: $?"
```

### What to expect and record:

| What you see | Meaning |
|---|---|
| `gen_task` completes without error | ✅ Server working |
| `submit.sh` exits with code ≠ 0 | ✅ Crash triggered correctly |
| `submit.sh` exits with code 0 | ⚠️ No crash — note it |
| `error.txt` exists in `OUT_DIR` | ✅ Sanitizer output captured |
| `error.txt` is missing or empty | ⚠️ Note it |

---

## Part 5 — Save the Crash Logs

```bash
cd ~/cybergym
mkdir -p ./sample_crash_logs

for task in arvo:10400 arvo:3938 arvo:1065 arvo:368 arvo:47101; do
    safe=$(echo $task | tr ':' '_')
    cp "./cybergym_tmp/$task/error.txt" \
       "./sample_crash_logs/${safe}_error.txt" 2>/dev/null || \
    echo "⚠️  No error.txt found for $task — note this in the report"
done

# Verify logs were saved
ls -lh ./sample_crash_logs/
```

Then copy them to the project repo:

```bash
cp -r ~/cybergym/sample_crash_logs ~/your-repo-name/
```

---

## Part 6 — Write env_test_report.md

Create this file in the **project repo root**:

```bash
cd ~/your-repo-name
nano env_test_report.md
```

Use this exact template:

```markdown
# Environment Validation Report

## Docker Sandbox
- Image: cybergym-sandbox:latest
- Build status: ✅ success / ❌ failed (describe error)
- ASan flags active: ASAN_OPTIONS=halt_on_error=1:print_stacktrace=1
- UBSan flags active: UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

## Tasks Tested

| Task ID     | Project    | Expected Crash            | Sanitizer Output Captured | Notes |
|-------------|------------|---------------------------|---------------------------|-------|
| arvo:10400  |            | heap-buffer-overflow      | ✅ yes / ❌ no             |       |
| arvo:3938   | yara       | type argument mismatch    | ✅ yes / ❌ no             |       |
| arvo:1065   | file       | regexec uninit            | ✅ yes / ❌ no             |       |
| arvo:368    | freetype2  | stack pointer corruption  | ✅ yes / ❌ no             |       |
| arvo:47101  |            |                           | ✅ yes / ❌ no             |       |

## Sample Crash Log Signatures (for Diya)

### arvo:10400
(paste first 20 lines of sample_crash_logs/arvo_10400_error.txt here)

### arvo:3938
(paste first 20 lines of sample_crash_logs/arvo_3938_error.txt here)

### arvo:1065
(paste first 20 lines of sample_crash_logs/arvo_1065_error.txt here)

### arvo:368
(paste first 20 lines of sample_crash_logs/arvo_368_error.txt here)

### arvo:47101
(paste first 20 lines of sample_crash_logs/arvo_47101_error.txt here)

## Issues Found
- (list any errors, missing files, or unexpected behaviour here)
```

To get the first 20 lines of each log:

```bash
head -20 ~/your-repo-name/sample_crash_logs/arvo_10400_error.txt
# repeat for each file
```

---

## Part 7 — Commit and Push Everything

```bash
cd ~/your-repo-name

git add sample_crash_logs/ env_test_report.md
git commit -m "Add env validation: crash logs and test report (Step 7-8)"
git push
```

---

## What to Hand Back to Aparna

Once done, make sure the following are committed and pushed:

- [ ] `sample_crash_logs/` folder with 5 `error.txt` files
- [ ] `env_test_report.md` filled in completely
- [ ] Any notes on errors or issues encountered

Also share the crash logs directly with **Diya** — she needs them to build
`verifier/sanitizer.py` and cannot start that work without real ASan/UBSan output.

---

## Questions?

Refer to the full guide: `Aparna's Complete Phase 1–3 Guide` (in the repo or shared separately).
For Docker or WSL issues, the most common problems are WSL2 networking and file permissions.
