#!/usr/bin/env python3
"""
extract_target_source.py
Extracts the vulnerable target_source snippet and poc_bucket for ARVO entries.

Usage:
  python3 extract_target_source.py <arvo_id> [<arvo_id> ...]

CHANGE LOG vs. original (see inline "FIX:" comments for rationale):
  FIX 1: extract_function()'s regex required a non-#/-/newline char before the
         function name on the same line. When the function name is the FIRST
         token on its line (very common two-line K&R signatures, e.g.
         "static void\nFoo(args)\n{" as used throughout GraphicsMagick), that
         leading char-class ate the function name's own first letter and the
         following \b boundary could never match. Verified: 0 matches on the
         exact style used in this project's own cybergym_subset.json entries.
  FIX 2: the primary extraction strategy matched function names pulled from
         the OSS-Fuzz "Crash State:" text. That's the *crashing* frame, not
         necessarily the *patched* frame -- verified on arvo:1065 (crash
         state lists match/file_softmagic/mget; the actual fix commit touches
         file_regexec, which appears in none of those three names). New
         primary strategy: locate the function via the patch hunk's own line
         numbers against the checked-out pre-fix source, independent of
         naming or code style.
  FIX 3: REPO_MAP was missing at least "file" (used by arvo:1065) and "aom";
         added those. "llvm-project" is a monorepo with many unrelated fuzz
         targets under different subdirectories -- added with a comment
         rather than guessing a subdir that may be wrong for a given entry.
  FIX 4: fix_commit as a list only ever used index [0]; now every commit in
         the list is tried in order until one yields a usable snippet.
  FIX 5: output now includes "extraction_method" so a human/CI can tell a
         clean full-function extraction apart from the much weaker
         patch-hunk-context fallback instead of both looking identical.

poc_bucket logic (unchanged):
  Looks for the PoC file inside the vulnerable Docker container at common
  paths, measures its size with `wc -c`, then classifies:
    short  : < 512 bytes
    medium : 512 - 4095 bytes
    long   : >= 4096 bytes
  Falls back to null if Docker is unavailable or the PoC cannot be found.

Requires:
  - /tmp/arvo-meta cloned (git clone --depth 1 https://github.com/n132/ARVO-Meta)
  - git installed
  - Docker installed and running (for poc_bucket; optional)
  - Internet access to clone project repos (or set REPO_CACHE_DIR to a local cache)

Output:
  Prints a JSON blob with cve_id + target_source + poc_bucket + extraction_method
  for each ID.
"""

import json, os, re, sys, subprocess, tempfile, shutil

# FIX (arvo:12957 investigation): default paths used to be under /tmp, which
# GitHub Codespaces clears on every stop -- not just a full rebuild, a normal
# idle timeout. That meant a manual `git clone` step had to be repeated every
# session, and forgetting it produced exactly the "file not found" error this
# was debugged from. Defaulting to a location next to the script itself
# (inside the repo checkout, which persists across stops) fixes the class of
# failure instead of just this one instance -- combined with ensure_arvo_meta()
# below, which self-clones if the directory is missing, this should never
# need a manual setup step again regardless of where the script is run from.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ARVO_META  = os.environ.get("ARVO_META",  os.path.join(_SCRIPT_DIR, ".cache", "arvo-meta"))
REPO_CACHE = os.environ.get("REPO_CACHE_DIR", os.path.join(_SCRIPT_DIR, ".cache", "arvo-repos"))

# -- poc_bucket thresholds (bytes) --------------------------------------------
POC_SHORT_MAX  = 512    # < 512  -> "short"
POC_MEDIUM_MAX = 4096   # < 4096 -> "medium", else "long"

# Common paths where ARVO Docker images place the PoC input
POC_CANDIDATE_PATHS = [
    "/tmp/poc",
    "/poc",
    "/tmp/crash",
    "/crash",
    "/tmp/input",
]

# -- repo map ------------------------------------------------------------------
# NOTE: audit this against the actual project field of every entry in your
# dataset before relying on it -- this list is not guaranteed exhaustive.
# Run `python3 extract_target_source.py --audit-repo-map` (added below) to
# print any project names present in ARVO_META metadata you fetch that are
# missing here.
REPO_MAP = {
    "aom":            "https://aomedia.googlesource.com/aom",          # FIX 3
    "boringssl":      "https://boringssl.googlesource.com/boringssl",
    "c-ares":         "https://github.com/c-ares/c-ares",
    "curl":           "https://github.com/curl/curl",
    "expat":          "https://github.com/libexpat/libexpat",
    "ffmpeg":         "https://github.com/FFmpeg/FFmpeg",
    "file":           "https://github.com/file/file",                  # FIX 3
    "freetype2":      "https://gitlab.freedesktop.org/freetype/freetype",
    "graphicsmagick": "https://sourceforge.net/p/graphicsmagick/code/",
    "jq":             "https://github.com/jqlang/jq",
    "jsoncons":       "https://github.com/danielaparker/jsoncons",
    "libarchive":     "https://github.com/libarchive/libarchive",
    "libssh2":        "https://github.com/libssh2/libssh2",
    "libxml2":        "https://github.com/GNOME/libxml2",    "libxslt":        "https://github.com/GNOME/libxslt",
    "lz4":            "https://github.com/lz4/lz4",
    # "llvm-project": monorepo (clang, clang-tools-extra, llvm, etc.) --
    # deliberately left unmapped. A single repo_url is not enough here;
    # the checkout is fine but which fuzz target maps to which subdir
    # varies per entry, and get_crash_state_funcs()/find_function_bounds
    # below still work fine once repo_dir is cloned -- just point
    # REPO_MAP["llvm-project"] at "https://github.com/llvm/llvm-project"
    # once you've confirmed that's acceptable for the entries you have.
    "mruby":          "https://github.com/mruby/mruby",
    "oniguruma":      "https://github.com/kkos/oniguruma",
    "openssl":        "https://github.com/openssl/openssl",
    "pcre2":          "https://github.com/PCRE2Project/pcre2",
    "php":            "https://github.com/php/php-src",
    "re2":            "https://github.com/google/re2",
    "sqlite":         "https://github.com/sqlite/sqlite",
    "wireshark":      "https://gitlab.com/wireshark/wireshark",
    "zstd":           "https://github.com/facebook/zstd",
}

# -- helpers --------------------------------------------------------------------

def run(cmd, cwd=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{r.stderr}")
    return r.stdout

def ensure_arvo_meta():
    """
    Self-healing setup: clone ARVO-Meta if it's missing, instead of erroring
    out and requiring the user to remember a manual `git clone` step. This
    directly targets the failure mode found on arvo:12957: ARVO_META pointed
    at a location that had been silently wiped by a Codespaces stop/restart.
    If it already exists, leave it alone (no network call on every run) --
    a stale clone missing a specific newer ID is a different, rarer problem
    from "the directory doesn't exist at all," and isn't worth a `git pull`
    on every invocation.
    """
    meta_dir = os.path.join(ARVO_META, "archive_data", "meta")
    if os.path.isdir(meta_dir):
        return
    print(f"  [setup] ARVO-Meta not found at {ARVO_META} -- cloning (one-time)...", file=sys.stderr)
    os.makedirs(os.path.dirname(ARVO_META.rstrip('/')) or ".", exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", "https://github.com/n132/ARVO-Meta.git", ARVO_META],
        check=True, capture_output=True
    )

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

def parse_hunks(patch_text, filepath):
    """
    Return a list of (old_start, old_count, first_change_line) for every @@
    hunk touching `filepath` in this patch. old_start/old_count are the
    pre-image line range from the "@@ -old_start,old_count +.. @@" header.

    first_change_line is the pre-image line number of the FIRST actually
    removed ('-') line in the hunk -- NOT just old_start.

    FIX (arvo:3938): a hunk's leading lines are often unchanged context,
    which can belong to the *previous* function/construct rather than the
    one actually being patched (verified case: old_start for this CVE's
    hunk landed on the closing '}' of LLVMFuzzerInitialize, a completely
    different, untouched function -- the real change, in
    LLVMFuzzerTestOneInput, was several lines further into the same hunk).
    Anchoring on the first real '-' line instead of old_start fixes this;
    for a pure-addition hunk (no '-' lines at all) there's no old-file line
    to anchor on, so first_change_line falls back to old_start as the best
    available approximation.
    """
    hunks = []
    in_file = False
    old_start = None
    old_count = None
    cursor = None          # current old-file line number while walking a hunk body
    first_change_line = None
    in_hunk_body = False

    def _flush():
        if old_start is not None:
            hunks.append((old_start, old_count, first_change_line or old_start))

    for line in patch_text.splitlines():
        if line.startswith('diff --git'):
            if in_hunk_body:
                _flush()
            in_file = filepath in line
            in_hunk_body = False
            continue
        if not in_file:
            continue
        if line.startswith('@@'):
            if in_hunk_body:
                _flush()
            m = re.match(r'^@@ -(\d+),?(\d*) \+\d+,?\d* @@', line)
            if m:
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) else 1
                cursor = old_start
                first_change_line = None
                in_hunk_body = True
            else:
                in_hunk_body = False
            continue
        if in_hunk_body:
            if line.startswith('-'):
                if first_change_line is None:
                    first_change_line = cursor
                cursor += 1
            elif line.startswith('+'):
                pass  # added lines don't exist in the old file; cursor unchanged
            else:
                cursor += 1  # context line, consumes one old-file line

    if in_hunk_body:
        _flush()
    return hunks

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

def derive_repo_url(meta):
    """
    Derive the repo URL directly from meta['fix'] (the full commit URL ARVO-
    Meta already stores) instead of relying on REPO_MAP as the primary
    lookup. This matters for two separate reasons found on real data:
      1. REPO_MAP will always be incomplete -- new projects show up in the
         dataset faster than anyone maintains the dict.
      2. Even a complete REPO_MAP would still fail for entries where
         meta['project'] is an OSS-Fuzz-internal build-config name that
         doesn't match the project's real name (verified case: arvo:12957
         has project="capstonenext" for the capstone project -- a REPO_MAP
         keyed on "capstone" would never match "capstonenext").
    Handles GitHub, GitLab (including self-hosted, "/-/commit/" or
    "/commit/"), and googlesource/Gerrit ("/+/") URL shapes. Returns None
    if the shape isn't recognized, in which case REPO_MAP is still checked
    as a fallback (e.g. SourceForge, which doesn't have a simple commit-URL
    convention to strip).
    """
    fix = meta.get("fix", "")
    if not fix:
        return None
    for sep in ("/-/commit/", "/commit/", "/+/"):
        if sep in fix:
            return fix.split(sep)[0]
    return None

def ensure_repo(project, repo_url):
    os.makedirs(REPO_CACHE, exist_ok=True)
    dest = os.path.join(REPO_CACHE, project)

    if os.path.exists(dest):
        # FIX (found from a real failure on arvo:1972): a directory existing
        # used to be trusted unconditionally -- if an earlier run was
        # interrupted (network drop, Ctrl+C) partway through cloning a
        # project this CVE happens to share with an earlier one, the
        # resulting partial/corrupt clone would be silently reused forever,
        # with every symptom (failed fetch, failed rev-parse) blamed on
        # this specific commit instead of the real cause. A cheap health
        # check (does this even look like a working git repo?) catches
        # that before it wastes time debugging the wrong thing.
        health = subprocess.run(
            ["git", "rev-parse", "--git-dir"], cwd=dest, capture_output=True
        )
        if health.returncode != 0:
            print(f"  [repair] {dest} exists but isn't a healthy git repo -- re-cloning", file=sys.stderr)
            shutil.rmtree(dest, ignore_errors=True)

    if not os.path.exists(dest):
        print(f"  [clone] {repo_url} -> {dest}", file=sys.stderr)
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, dest],
            check=True, capture_output=True
        )
    return dest

def fetch_commit(repo_dir, commit_hash):
    """
    FIX (found from a real failure on arvo:1972): the fetch's own exit code
    used to be discarded entirely, and there was no retry if a shallow
    depth=2 fetch didn't happen to include enough history to resolve the
    commit's parent -- both failure modes surfaced downstream as a
    confusing "unknown revision" error from rev-parse, which doesn't tell
    you the fetch was the actual problem. Now: check the fetch's own
    result, and if the commit still isn't resolvable enough to find its
    parent after the fetch, retry with escalating depth before giving up.
    """
    r = subprocess.run(
        ["git", "cat-file", "-t", commit_hash],
        cwd=repo_dir, capture_output=True, text=True
    )
    if r.returncode == 0:
        return  # already present locally, nothing to do

    for depth in (2, 20, 250):
        print(f"  [fetch] fetching {commit_hash[:12]} (depth={depth})...", file=sys.stderr)
        fetch_result = subprocess.run(
            ["git", "fetch", f"--depth={depth}", "origin", commit_hash],
            cwd=repo_dir, capture_output=True, text=True
        )
        if fetch_result.returncode != 0:
            print(
                f"  [warn] fetch at depth={depth} failed: {fetch_result.stderr.strip()[:300]}",
                file=sys.stderr
            )
            continue
        # Check whether this depth was actually enough to resolve the
        # parent -- not just whether the fetch command itself succeeded.
        parent_check = subprocess.run(
            ["git", "rev-parse", f"{commit_hash}^"], cwd=repo_dir, capture_output=True
        )
        if parent_check.returncode == 0:
            return
        print(f"  [warn] depth={depth} fetched the commit but not enough history to resolve its parent -- trying deeper", file=sys.stderr)

    print(f"  [warn] could not fetch enough history for {commit_hash[:12]} even at depth=250", file=sys.stderr)

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

# -- FIX 2: line-anchored function extraction (primary strategy) --------------

def find_function_bounds_by_line(source, target_line_no):
    """
    Locate the C/C++ function enclosing 1-indexed `target_line_no` in
    `source`. No assumption about signature style, no dependence on
    function names.

    REWRITTEN (arvo:29764 regression) -- the previous version walked
    backward from target_line looking for the nearest blank line / column-0
    '}' / comment-close / preprocessor line as "the boundary." That breaks
    the moment there's a blank line *inside* the function body for
    readability (extremely common C style: a blank line between a variable
    declaration and the logic that follows) -- it can't tell "boundary
    between two functions" from "blank line inside one function," and
    verified on real code it picked the wrong (much smaller, wrong) block
    as a result.

    This version tracks real brace depth in a single forward pass over the
    whole file to find every genuine top-level block (each place depth
    goes 0->1 and back to 0) -- that's unambiguous, unlike line-pattern
    heuristics, since it only reacts to actual '{'/'}' characters. Then it
    finds which top-level block's span contains target_line_no, and trims
    the leading gap before that block down to just its signature.

    Returns (start_offset, end_offset) char offsets into `source`, or None.
    """
    lines = source.splitlines(keepends=True)
    n = len(lines)
    if target_line_no < 1 or target_line_no > n:
        return None
    idx = target_line_no - 1

    offsets = [0]
    for l in lines:
        offsets.append(offsets[-1] + len(l))
    target_offset = offsets[idx]

    # Single forward pass: record every (open_pos, close_pos) where brace
    # depth goes 0 -> 1 -> ... -> 0. This only depends on real brace
    # characters, so a blank/comment line deep inside a function can never
    # be mistaken for a top-level boundary -- it's simply inside the span
    # already, at depth > 0.
    depth = 0
    open_pos = None
    blocks = []
    for i, c in enumerate(source):
        if c == '{':
            if depth == 0:
                open_pos = i
            depth += 1
        elif c == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and open_pos is not None:
                    blocks.append((open_pos, i + 1))
                    open_pos = None

    def is_boundary(line):
        s = line.strip()
        return s == '' or line[:1] == '}' or s == '*/' or s.startswith('#')

    prev_end = 0
    for open_pos, close_pos in blocks:
        if not (prev_end <= target_offset < close_pos):
            prev_end = close_pos
            continue

        # target_offset is somewhere in [prev_end, close_pos) -- either in
        # this block's body, or in the gap before it (its signature, or
        # unrelated leading content like a license header). Trim that gap
        # down to just the signature: walk backward from the block's own
        # opening-brace line to the nearest boundary, bounded by prev_end
        # so we can never sweep into a previous, unrelated block.
        open_line_idx = source.count('\n', 0, open_pos)
        sig_start_idx = open_line_idx
        j = open_line_idx - 1
        while j >= 0 and offsets[j] >= prev_end:
            if is_boundary(lines[j]):
                break
            sig_start_idx = j
            j -= 1
        sig_start_offset = offsets[sig_start_idx]

        if target_offset < sig_start_offset:
            # target sat in the gap but on the far side of a boundary from
            # this block's signature -- it's unrelated leading content
            # (e.g. a license header, a previous unrelated comment), not
            # part of this function at all.
            return None

        # Sanity check: the text between the trimmed start and the opening
        # brace should read like a plausible function signature.
        header = source[sig_start_offset:open_pos]
        if not re.search(r'\w+\s*\([^;{]*\)\s*$', header.strip(), re.DOTALL):
            return None

        return (sig_start_offset, close_pos)

    return None

# -- name-based extraction (secondary / fallback strategy) --------------------

def extract_function(source, func_name):
    """
    FIX 1: original pattern was r'^[^\\n#/].*\\bFUNC\\s*\\([^;]*$', which
    cannot match a line where FUNC is the very first token (the leading
    [^\\n#/] eats FUNC's own first letter, breaking \\b). Anchor on
    whitespace-or-start instead of "any non-#// char" so a function name at
    column 0 still matches.
    """
    pattern = re.compile(
        r'(?:^|\s)' + re.escape(func_name) + r'\s*\([^;{]*?\)\s*$',
        re.MULTILINE
    )
    for m in pattern.finditer(source):
        line_start = source.rfind('\n', 0, m.start()) + 1
        if source[line_start:m.start()].lstrip().startswith(('#', '//', '/*')):
            continue
        start = line_start
        block_start = source.rfind('\n\n', 0, start)
        block_start = block_start + 2 if block_start != -1 else 0
        brace_pos = source.find('{', m.end())
        if brace_pos == -1:
            continue
        # reject if there's a ';' between the signature and the brace
        # (that's a prototype, not a definition)
        between = source[m.end():brace_pos]
        if ';' in between:
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
                    return source[block_start:pos + 1].strip()
            pos += 1
    return None

_NON_SOURCE_PATTERNS = (
    "changelog", "readme", "license", "authors", "news",
    ".md", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    "/test/", "test_", "_test.", "/tests/",
    "/bindings/", "/docs/", "/doc/",
)
_SOURCE_EXTENSIONS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx")

def _pick_fallback_file(patch_files):
    """
    FIX (arvo:12957): the fallback used to blindly take patch_files[0],
    which is whatever file happens to sort first in the diff -- for that
    CVE, "ChangeLog" (alphabetically before "arch/...") instead of the
    actual fix in arch/ARM/ARMInstPrinter.c. Prefer a plausible source file
    over docs/changelogs/bindings/tests/binary assets; fall back to the
    first file only if nothing looks like source at all.
    """
    candidates = [f for _, f in patch_files]
    source_like = [
        f for f in candidates
        if f.lower().endswith(_SOURCE_EXTENSIONS)
        and not any(p in f.lower() for p in _NON_SOURCE_PATTERNS)
    ]
    if source_like:
        return source_like[0]
    non_junk = [f for f in candidates if not any(p in f.lower() for p in _NON_SOURCE_PATTERNS)]
    if non_junk:
        return non_junk[0]
    return candidates[0] if candidates else None

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

# -- poc_bucket (unchanged) -----------------------------------------------------

def classify_poc_size(size_bytes):
    if size_bytes < POC_SHORT_MAX:
        return "short"
    elif size_bytes < POC_MEDIUM_MAX:
        return "medium"
    else:
        return "long"

def docker_available():
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # FileNotFoundError: docker isn't installed at all in this environment.
        # TimeoutExpired: docker daemon is present but not responding (e.g. not
        # started yet in a fresh Codespace) -- treat both as "unavailable" and
        # let target_source extraction still return a result instead of the
        # whole entry silently failing on an unrelated subsystem.
        return False

def get_poc_bucket(arvo_id, meta):
    if not docker_available():
        print("  [poc_bucket] Docker not available -- skipping", file=sys.stderr)
        return None

    image = f"n132/arvo:{arvo_id}-vul"
    container_name = f"arvo_poc_{arvo_id}"

    print(f"  [poc_bucket] pulling {image} ...", file=sys.stderr)
    pull = subprocess.run(["docker", "pull", image], capture_output=True, text=True)
    if pull.returncode != 0:
        print(f"  [poc_bucket] pull failed: {pull.stderr.strip()}", file=sys.stderr)
        return None

    for poc_path in POC_CANDIDATE_PATHS:
        r = subprocess.run(
            ["docker", "run", "--rm", "--name", container_name, image,
             "sh", "-c", f"wc -c < {poc_path} 2>/dev/null"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0:
            raw = r.stdout.strip()
            if raw.isdigit() and int(raw) > 0:
                size = int(raw)
                bucket = classify_poc_size(size)
                print(f"  [poc_bucket] {poc_path} -> {size} bytes -> \"{bucket}\"", file=sys.stderr)
                return bucket

    print("  [poc_bucket] run-based check failed; trying docker cp ...", file=sys.stderr)
    try:
        cid = subprocess.run(["docker", "create", image], capture_output=True, text=True, check=True).stdout.strip()
        for poc_path in POC_CANDIDATE_PATHS:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tmp_path = tf.name
            cp = subprocess.run(["docker", "cp", f"{cid}:{poc_path}", tmp_path], capture_output=True)
            if cp.returncode == 0:
                size = os.path.getsize(tmp_path)
                os.unlink(tmp_path)
                subprocess.run(["docker", "rm", cid], capture_output=True)
                if size > 0:
                    bucket = classify_poc_size(size)
                    print(f"  [poc_bucket] cp {poc_path} -> {size} bytes -> \"{bucket}\"", file=sys.stderr)
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

# -- main ------------------------------------------------------------------------

def _try_line_anchored(repo_dir, pre_fix, patch_files, patch_text):
    """FIX 2 primary strategy: for every hunk of every touched file, look up
    the enclosing function directly from line geometry. Returns the FIRST
    hit (touched files are usually ordered by relevance in the patch, and
    stopping at the first hit keeps behavior predictable / debuggable).

    FIX (arvo:3938): try first_change_line (the actual first removed line)
    BEFORE old_start -- old_start is just wherever the hunk's leading
    context happens to begin, which can land inside a completely different,
    untouched function when a hunk has several leading context lines
    (verified: old_start resolved to LLVMFuzzerInitialize's closing brace
    while the real change was in LLVMFuzzerTestOneInput, several lines
    later in the same hunk). first_change_line stays as a fallback candidate
    for pure-addition hunks where there's no '-' line to anchor on."""
    for _, fpath in patch_files:
        src = get_file_at_commit(repo_dir, pre_fix, fpath)
        if not src:
            continue
        for old_start, old_count, first_change_line in parse_hunks(patch_text, fpath):
            mid_line = old_start + old_count // 2
            candidates = [first_change_line, old_start, mid_line, old_start + max(old_count - 1, 0)]
            # de-dupe while preserving order
            seen = set()
            candidates = [c for c in candidates if not (c in seen or seen.add(c))]
            for candidate_line in candidates:
                bounds = find_function_bounds_by_line(src, candidate_line)
                if bounds:
                    snippet = src[bounds[0]:bounds[1]].strip()
                    if snippet:
                        print(f"  [line-anchor] {fpath}:{candidate_line} -> {len(snippet)} chars", file=sys.stderr)
                        return snippet
    return None

def _try_crash_state_names(repo_dir, pre_fix, patch_files, crash_funcs):
    """Secondary strategy: original crash-state-name matching, kept as a
    fallback for hunks that add a brand-new function (no pre-image line to
    anchor on) where line-anchoring can't apply."""
    for _, fpath in patch_files:
        src = get_file_at_commit(repo_dir, pre_fix, fpath)
        if not src:
            continue
        for fn in crash_funcs:
            snippet = extract_function(src, fn)
            if snippet:
                print(f"  [crash-state-name] found '{fn}' in {fpath}", file=sys.stderr)
                return snippet
    return None

def process(arvo_id):
    print(f"\n{'='*60}\nProcessing arvo:{arvo_id}", file=sys.stderr)
    meta = load_meta(arvo_id)
    patch_text = load_patch(arvo_id)
    project = meta.get("project", "").lower()

    fix_commits = meta.get("fix_commit")
    if fix_commits is None:
        fix_commits = []
    elif not isinstance(fix_commits, list):
        fix_commits = [fix_commits]
    # FIX 4: try every candidate commit, not just the first.

    crash_funcs = get_crash_state_funcs(meta)
    print(f"  project={project}  fix_commits={[c[:12] for c in fix_commits]}  funcs={crash_funcs}", file=sys.stderr)

    patch_files = parse_patch_files(patch_text) if patch_text else []
    # FIX (arvo:12957): derive repo_url from meta['fix'] first -- REPO_MAP is
    # now a fallback for the URL shapes derive_repo_url() doesn't recognize
    # (e.g. SourceForge), not the primary lookup. See derive_repo_url()'s
    # docstring for why REPO_MAP alone isn't reliable here.
    #
    # FIX (arvo:1972): a project's canonical repo can differ from what
    # REPO_MAP has cached -- libxml2's meta['fix'] points to
    # gitlab.gnome.org (the project's actual current host; REPO_MAP had a
    # github.com mirror). Previously only ONE derived URL was ever tried
    # (`or` short-circuits, so REPO_MAP was never consulted once
    # derive_repo_url() returned anything at all, even if that URL then
    # failed to clone). Build an ordered list of every distinct candidate
    # and try each in turn instead of committing to the first.
    candidate_urls = []
    derived = derive_repo_url(meta)
    if derived:
        candidate_urls.append(derived)
    mapped = REPO_MAP.get(project)
    if mapped and mapped not in candidate_urls:
        candidate_urls.append(mapped)

    source_snippet = None
    extraction_method = None

    if candidate_urls and fix_commits and patch_files:
        repo_dir = None
        for repo_url in candidate_urls:
            repo_cache_key = repo_url.rstrip('/').split('/')[-1]
            try:
                repo_dir = ensure_repo(repo_cache_key, repo_url)
                break
            except Exception as e:
                print(f"  [warn] clone of {repo_url} failed: {e} -- trying next candidate URL if any", file=sys.stderr)
                repo_dir = None

        if repo_dir:
            try:
                for fix_commit in fix_commits:
                    fetch_commit(repo_dir, fix_commit)
                    try:
                        pre_fix = get_parent_commit(repo_dir, fix_commit)
                    except RuntimeError as e:
                        print(f"  [warn] couldn't resolve parent of {fix_commit[:12]}: {e}", file=sys.stderr)
                        continue
                    print(f"  pre-fix commit: {pre_fix[:12]}", file=sys.stderr)

                    source_snippet = _try_line_anchored(repo_dir, pre_fix, patch_files, patch_text)
                    if source_snippet:
                        extraction_method = "patch_line_lookup"
                        break

                    if crash_funcs:
                        source_snippet = _try_crash_state_names(repo_dir, pre_fix, patch_files, crash_funcs)
                        if source_snippet:
                            extraction_method = "crash_state_function_match"
                            break
            except Exception as e:
                print(f"  [warn] repo strategy failed: {e}", file=sys.stderr)

    if not source_snippet and patch_text and patch_files:
        print("  [fallback] using patch hunk context (LOW CONFIDENCE -- review manually)", file=sys.stderr)
        fpath = _pick_fallback_file(patch_files)
        if fpath:
            source_snippet = extract_hunk_context(patch_text, fpath)
        extraction_method = "patch_hunk_context_fallback"

    if not source_snippet:
        extraction_method = "failed"

    try:
        poc_bucket = get_poc_bucket(arvo_id, meta)
    except Exception as e:
        # Never let a poc_bucket failure discard a successful target_source
        # extraction -- these are independent pieces of output.
        print(f"  [warn] poc_bucket step failed: {e}", file=sys.stderr)
        poc_bucket = None

    return {
        "cve_id": f"arvo:{arvo_id}",
        "target_source": source_snippet or "EXTRACTION_FAILED -- check patch manually",
        "extraction_method": extraction_method,
        "poc_bucket": poc_bucket,
        "_crash_funcs": crash_funcs,
        "_patch_files": [p for _, p in patch_files],
    }


if __name__ == "__main__":
    ids = sys.argv[1:] if len(sys.argv) > 1 else ["64574", "29764", "21176", "11011"]
    ensure_arvo_meta()
    results = []
    for arvo_id in ids:
        try:
            results.append(process(arvo_id))
        except Exception as e:
            results.append({"cve_id": f"arvo:{arvo_id}", "error": str(e)})

    print(json.dumps(results, indent=2))