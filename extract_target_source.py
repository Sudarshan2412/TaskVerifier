#!/usr/bin/env python3
"""
extract_target_source.py
Extracts the vulnerable target_source snippet and poc_bucket for ARVO entries.

Usage:
  python3 extract_target_source.py <arvo_id> [<arvo_id> ...]

poc_bucket logic:
  Looks for the PoC file inside the vulnerable Docker container at common paths,
  measures its size with `wc -c`, then classifies:
    short  : < 512 bytes
    medium : 512 – 4095 bytes
    long   : >= 4096 bytes
  Falls back to null if Docker is unavailable or the PoC cannot be found.

Requires:
  - /tmp/arvo-meta cloned (git clone --depth 1 https://github.com/n132/ARVO-Meta)
  - git installed
  - Docker installed and running (for poc_bucket; optional)
  - Internet access to clone project repos (or set REPO_CACHE_DIR to a local cache)

Output:
  Prints a JSON blob with cve_id + target_source + poc_bucket for each ID.
"""

import json, os, re, sys, subprocess, tempfile, shutil

ARVO_META  = os.environ.get("ARVO_META",  "/tmp/arvo-meta")
REPO_CACHE = os.environ.get("REPO_CACHE_DIR", "/tmp/arvo-repos")

# ── poc_bucket thresholds (bytes) ────────────────────────────────────────────
POC_SHORT_MAX  = 512    # < 512  → "short"
POC_MEDIUM_MAX = 4096   # < 4096 → "medium", else "long"

# Common paths where ARVO Docker images place the PoC input
POC_CANDIDATE_PATHS = [
    "/tmp/poc",
    "/poc",
    "/tmp/crash",
    "/crash",
    "/tmp/input",
]

# ── repo map ──────────────────────────────────────────────────────────────────
REPO_MAP = {
    "boringssl":    "https://boringssl.googlesource.com/boringssl",
    "c-ares":       "https://github.com/c-ares/c-ares",
    "curl":         "https://github.com/curl/curl",
    "expat":        "https://github.com/libexpat/libexpat",
    "ffmpeg":       "https://github.com/FFmpeg/FFmpeg",
    "freetype2":    "https://gitlab.freedesktop.org/freetype/freetype",
    "graphicsmagick": "https://sourceforge.net/p/graphicsmagick/code/",
    "jq":           "https://github.com/jqlang/jq",
    "jsoncons":     "https://github.com/danielaparker/jsoncons",
    "libarchive":   "https://github.com/libarchive/libarchive",
    "libssh2":      "https://github.com/libssh2/libssh2",
    "libxml2":      "https://github.com/GNOME/libxml2",
    "libxslt":      "https://github.com/GNOME/libxslt",
    "lz4":          "https://github.com/lz4/lz4",
    "mruby":        "https://github.com/mruby/mruby",
    "oniguruma":    "https://github.com/kkos/oniguruma",
    "openssl":      "https://github.com/openssl/openssl",
    "pcre2":        "https://github.com/PCRE2Project/pcre2",
    "php":          "https://github.com/php/php-src",
    "re2":          "https://github.com/google/re2",
    "sqlite":       "https://github.com/sqlite/sqlite",
    "wireshark":    "https://gitlab.com/wireshark/wireshark",
    "zstd":         "https://github.com/facebook/zstd",
}

# ── helpers ───────────────────────────────────────────────────────────────────

def run(cmd, cwd=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{r.stderr}")
    return r.stdout

def load_meta(arvo_id):
    path = f"{ARVO_META}/archive_data/meta/{arvo_id}.json"
    with open(path) as f:
        return json.load(f)

def load_patch(arvo_id):
    path = f"{ARVO_META}/archive_data/patches/{arvo_id}.diff"
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.read()

def parse_patch_files(patch_text):
    pairs = []
    for m in re.finditer(r'^diff --git a/(.+?) b/(.+?)$', patch_text, re.MULTILINE):
        pairs.append((m.group(1), m.group(2)))
    return pairs

def get_crash_state_funcs(meta):
    comments = meta.get("report", {}).get("comments", [])
    body = (comments[0].get("content") or "") if comments else ""
    m = re.search(r'Crash State:\s*(.*?)(?:\n\n|\nSanitizer|\nRegressed|\Z)', body, re.DOTALL)
    if not m:
        return []
    lines = [l.strip() for l in m.group(1).strip().splitlines() if l.strip()]
    funcs = []
    for l in lines:
        bare = re.split(r'[<(]', l)[0].strip()
        bare = bare.split("::")[-1]
        if bare:
            funcs.append(bare)
    return funcs

def ensure_repo(project, repo_url):
    os.makedirs(REPO_CACHE, exist_ok=True)
    dest = os.path.join(REPO_CACHE, project)
    if not os.path.exists(dest):
        print(f"  [clone] {repo_url} -> {dest}", file=sys.stderr)
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, dest],
            check=True, capture_output=True
        )
    return dest

def fetch_commit(repo_dir, commit_hash):
    r = subprocess.run(
        ["git", "cat-file", "-t", commit_hash],
        cwd=repo_dir, capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  [fetch] fetching {commit_hash[:12]}...", file=sys.stderr)
        subprocess.run(
            ["git", "fetch", "--depth=2", "origin", commit_hash],
            cwd=repo_dir, capture_output=True
        )

def get_parent_commit(repo_dir, fix_commit):
    return run(["git", "rev-parse", f"{fix_commit}^"], cwd=repo_dir).strip()

def get_file_at_commit(repo_dir, commit, filepath):
    r = subprocess.run(
        ["git", "show", f"{commit}:{filepath}"],
        cwd=repo_dir, capture_output=True, text=True, errors="replace"
    )
    if r.returncode != 0:
        return None
    return r.stdout

def extract_function(source, func_name):
    pattern = re.compile(
        r'^[^\n#/].*\b' + re.escape(func_name) + r'\s*\([^;]*$',
        re.MULTILINE
    )
    for m in pattern.finditer(source):
        start = m.start()
        block_start = source.rfind('\n\n', 0, start)
        block_start = block_start + 2 if block_start != -1 else 0
        brace_pos = source.find('{', m.end())
        if brace_pos == -1:
            continue
        depth = 0
        pos = brace_pos
        while pos < len(source):
            c = source[pos]
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return source[block_start:pos+1].strip()
            pos += 1
    return None

def extract_hunk_context(patch_text, filepath):
    in_file = False
    current_block = []
    result_blocks = []
    for line in patch_text.splitlines():
        if line.startswith('diff --git'):
            if current_block:
                result_blocks.append('\n'.join(current_block))
                current_block = []
            in_file = filepath in line
            continue
        if not in_file:
            continue
        if line.startswith('@@'):
            if current_block:
                result_blocks.append('\n'.join(current_block))
            current_block = [line]
            continue
        if line.startswith('+++') or line.startswith('---'):
            continue
        if line.startswith('+'):
            continue
        current_block.append(line[1:] if line.startswith('-') else line[1:])
    if current_block:
        result_blocks.append('\n'.join(current_block))
    return '\n\n/* ... */\n\n'.join(result_blocks)

# ── poc_bucket ────────────────────────────────────────────────────────────────

def classify_poc_size(size_bytes):
    """Classify a PoC size in bytes into short / medium / long."""
    if size_bytes < POC_SHORT_MAX:
        return "short"
    elif size_bytes < POC_MEDIUM_MAX:
        return "medium"
    else:
        return "long"

def docker_available():
    r = subprocess.run(["docker", "info"], capture_output=True)
    return r.returncode == 0

def get_poc_bucket(arvo_id, meta):
    """
    Spin up the vulnerable Docker image for this ARVO entry, locate the PoC
    file, measure its size with `wc -c`, classify, then remove the container.

    Returns the bucket string ("short" / "medium" / "long") or None on failure.
    """
    if not docker_available():
        print("  [poc_bucket] Docker not available — skipping", file=sys.stderr)
        return None

    # Docker image follows the n132/arvo:<id>-vul convention
    image = f"n132/arvo:{arvo_id}-vul"
    container_name = f"arvo_poc_{arvo_id}"

    print(f"  [poc_bucket] pulling {image} ...", file=sys.stderr)
    pull = subprocess.run(
        ["docker", "pull", image],
        capture_output=True, text=True
    )
    if pull.returncode != 0:
        print(f"  [poc_bucket] pull failed: {pull.stderr.strip()}", file=sys.stderr)
        return None

    # Try each candidate path until we find the PoC
    for poc_path in POC_CANDIDATE_PATHS:
        # Run a one-shot container: just check file size
        r = subprocess.run(
            [
                "docker", "run", "--rm",
                "--name", container_name,
                image,
                "sh", "-c", f"wc -c < {poc_path} 2>/dev/null"
            ],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            raw = r.stdout.strip()
            if raw.isdigit() and int(raw) > 0:
                size = int(raw)
                bucket = classify_poc_size(size)
                print(
                    f"  [poc_bucket] {poc_path} → {size} bytes → \"{bucket}\"",
                    file=sys.stderr
                )
                return bucket

    # Fallback: copy PoC out via `docker create` + `docker cp` if run-based
    # approach fails (e.g., image entrypoint overrides sh)
    print("  [poc_bucket] run-based check failed; trying docker cp ...", file=sys.stderr)
    try:
        cid = subprocess.run(
            ["docker", "create", image],
            capture_output=True, text=True, check=True
        ).stdout.strip()

        for poc_path in POC_CANDIDATE_PATHS:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tmp_path = tf.name
            cp = subprocess.run(
                ["docker", "cp", f"{cid}:{poc_path}", tmp_path],
                capture_output=True
            )
            if cp.returncode == 0:
                size = os.path.getsize(tmp_path)
                os.unlink(tmp_path)
                subprocess.run(["docker", "rm", cid], capture_output=True)
                if size > 0:
                    bucket = classify_poc_size(size)
                    print(
                        f"  [poc_bucket] cp {poc_path} → {size} bytes → \"{bucket}\"",
                        file=sys.stderr
                    )
                    return bucket
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        subprocess.run(["docker", "rm", cid], capture_output=True)
    except Exception as e:
        print(f"  [poc_bucket] docker cp strategy failed: {e}", file=sys.stderr)

    print("  [poc_bucket] could not locate PoC in container", file=sys.stderr)
    return None

# ── main ──────────────────────────────────────────────────────────────────────

def process(arvo_id):
    print(f"\n{'='*60}\nProcessing arvo:{arvo_id}", file=sys.stderr)
    meta = load_meta(arvo_id)
    patch_text = load_patch(arvo_id)
    project = meta.get("project", "").lower()
    fix_commit = meta.get("fix_commit")

    if isinstance(fix_commit, list):
        fix_commit = fix_commit[0]

    crash_funcs = get_crash_state_funcs(meta)
    print(f"  project={project}  fix={fix_commit and fix_commit[:12]}  funcs={crash_funcs}", file=sys.stderr)

    patch_files = parse_patch_files(patch_text) if patch_text else []

    # ── target_source extraction ──────────────────────────────────────────────
    repo_url = REPO_MAP.get(project)
    source_snippet = None

    if repo_url and fix_commit and patch_files and crash_funcs:
        try:
            repo_dir = ensure_repo(project, repo_url)
            fetch_commit(repo_dir, fix_commit)
            pre_fix = get_parent_commit(repo_dir, fix_commit)
            print(f"  pre-fix commit: {pre_fix[:12]}", file=sys.stderr)

            for _, fpath in patch_files:
                src = get_file_at_commit(repo_dir, pre_fix, fpath)
                if not src:
                    continue
                for fn in crash_funcs:
                    snippet = extract_function(src, fn)
                    if snippet:
                        print(f"  found '{fn}' in {fpath}", file=sys.stderr)
                        source_snippet = snippet
                        break
                if source_snippet:
                    break
        except Exception as e:
            print(f"  [warn] repo strategy failed: {e}", file=sys.stderr)

    if not source_snippet and patch_text and patch_files:
        print("  [fallback] using patch hunk context", file=sys.stderr)
        _, fpath = patch_files[0]
        source_snippet = extract_hunk_context(patch_text, fpath)

    # ── poc_bucket ────────────────────────────────────────────────────────────
    poc_bucket = get_poc_bucket(arvo_id, meta)

    return {
        "cve_id": f"arvo:{arvo_id}",
        "target_source": source_snippet or "EXTRACTION_FAILED — check patch manually",
        "poc_bucket": poc_bucket,
        "_crash_funcs": crash_funcs,
        "_patch_files": [p for _, p in patch_files],
    }


if __name__ == "__main__":
    ids = sys.argv[1:] if len(sys.argv) > 1 else ["64574", "29764", "21176", "11011"]
    results = []
    for arvo_id in ids:
        try:
            results.append(process(arvo_id))
        except Exception as e:
            results.append({"cve_id": f"arvo:{arvo_id}", "error": str(e)})

    print(json.dumps(results, indent=2))