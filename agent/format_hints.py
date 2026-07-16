"""
agent/format_hints.py — Format-hint registry for PoC prompt construction.

Replaces the hardcoded if/elif chain in prompt_builder.py with a data-driven
registry that maps fuzz-target name patterns to reusable hint objects.

Design goals
------------
* Adding support for a new file format requires only appending one entry to
  FORMAT_HINTS — no changes to prompt-building logic.
* Both the initial prompt and every retry prompt pull from the SAME registry,
  so hints are never silently dropped on retry (the root cause of the arvo:368
  15-attempt failure and similar failures on arvo:10147, oss-fuzz:371445205).
* Hints are format-agnostic structures; the registry knows nothing about any
  specific CVE.

Public API
----------
    get_format_hint(fuzz_target: str) -> str | None
        Returns the hint string for the given fuzz target binary path,
        or None if no entry matches.

    All hint strings are safe to inject verbatim into either the initial
    or the retry prompt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class FormatHintEntry:
    """
    One entry in the format-hint registry.

    Attributes
    ----------
    patterns : tuple[str, ...]
        Substrings (case-insensitive) matched against the fuzz-target binary
        name (basename only).  The entry matches when ANY pattern is found.
    initial_hint : str
        Injected into the FIRST attempt prompt.  Should explain the correct
        input format, required magic bytes, and any non-obvious constraints
        that prevent the parser from reaching the vulnerable code path.
    retry_hint : str | None
        Injected into EVERY retry prompt.  If None, falls back to initial_hint.
        Use a shorter, reminder-style version to save tokens on retries.
    max_tokens : int
        Soft token cap for this hint (estimated at 4 chars/token).
        Hints longer than this are truncated at the last sentence boundary.
        Default 600 tokens; set lower for very long hints (e.g. CFF = 400).
    """
    patterns: tuple[str, ...]
    initial_hint: str
    retry_hint: str | None = None
    max_tokens: int = 600

    def get_retry_hint(self) -> str:
        """Return the retry-specific hint, falling back to the initial hint."""
        return self.retry_hint if self.retry_hint is not None else self.initial_hint


def _truncate_hint(hint: str, max_tokens: int) -> str:
    """
    Truncate *hint* to approximately *max_tokens* (estimated at 4 chars/token).
    Truncates at the last sentence boundary ('. ') before the character limit
    to avoid cutting in the middle of a structural requirement.

    Format-agnostic: applies to any hint regardless of content.
    """
    char_limit = max_tokens * 4
    if len(hint) <= char_limit:
        return hint
    truncated = hint[:char_limit]
    last_sentence = truncated.rfind(". ")
    if last_sentence > char_limit // 2:
        truncated = truncated[:last_sentence + 1]
    return truncated + "\n[Format hint truncated for token budget]"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# Order matters only for readability; matching is substring-based and the
# first matching entry wins.  Add new entries at the bottom of this list.
# ---------------------------------------------------------------------------

FORMAT_HINTS: list[FormatHintEntry] = [

    # ── GraphicsMagick / ImageMagick MVG / SVG / PS / PDF / JPEG / PNG ──────
    FormatHintEntry(
        patterns=("mvg", "svg", "_ps_", "coder_pdf", "coder_jpeg", "coder_png"),
        initial_hint=(
            "The fuzz target expects a GraphicsMagick/ImageMagick format file.\n"
            "The input must be a valid text or binary file for the format inferred\n"
            "from the binary name (e.g. MVG, SVG, PS, PDF, JPEG, PNG).\n\n"

            "=== MVG FORMAT: VERIFIED-CORRECT STRUCTURE ===\n"
            "\n"
            "RULE 1 — IsMVG() detection: the file MUST start with the literal word\n"
            "  `viewbox` (lowercase) as the very first 7 bytes. Do NOT start with\n"
            "  `push graphic-context` — that causes the format detector to reject\n"
            "  the file immediately, before any drawing code runs.\n"
            "\n"
            "RULE 2 — Coordinates: the `text` primitive takes SPACE-separated coords:\n"
            "  CORRECT:  text 0 0 '...'\n"
            "  WRONG:    text 0,0 '...'   (comma causes parse failure)\n"
            "\n"
            "RULE 3 — Writing a literal '%' to the file from C:\n"
            "  CORRECT:  fputc('%', f);\n"
            "  WRONG:    fprintf(f, \"%%\");  // fprintf consumes %%, writes '%'\n"
            "            // BUT if you later read it back, the raw file byte IS '%',\n"
            "            // so both methods produce the same byte in the file.\n"
            "            // However: use fputc to be safe and explicit.\n"
            "\n"
            "RULE 4 — The `text` primitive passes its string to AnnotateImage which\n"
            "  calls TranslateTextEx. Inside TranslateTextEx, the `%[` escape reads\n"
            "  into a stack buffer `char key[MaxTextExtent]`. If you supply exactly\n"
            "  MaxTextExtent (or more) characters between '[' and ']', the null-\n"
            "  terminator write `key[i]='\\0'` at index MaxTextExtent overflows.\n"
            "\n"
            "VERIFIED MINIMAL TEMPLATE (produces a file that reaches TranslateTextEx):\n"
            "```c\n"
            "FILE *f = fopen(\"/tmp/poc\", \"wb\");\n"
            "fprintf(f, \"viewbox 0 0 1 1\\n\");   // MUST be first line\n"
            "fprintf(f, \"text 0 0 '\");           // space-separated coords, single quote\n"
            "fputc('%', f);                      // literal percent sign\n"
            "fputc('[', f);\n"
            "for (int i = 0; i < N; i++) fputc('A', f);  // N >= MaxTextExtent\n"
            "fputc(']', f);\n"
            "fprintf(f, \"'\\n\");\n"
            "fclose(f);\n"
            "```\n"
            "\n"
            "DIAGNOSIS CHECKLIST (if the target exits without crashing):\n"
            "  1. Does the file start with 'viewbox'? (check byte 0-6)\n"
            "  2. Is the 'text' command using spaces, not commas, for coordinates?\n"
            "  3. Is the '%' written as a raw byte (fputc), not fprintf escape?\n"
            "  4. Is there a ']' to close the %[...] sequence?\n"
            "  5. Are there enough characters (>= MaxTextExtent) between '[' and ']'?\n"
        ),
        retry_hint=(
            "REMINDER (MVG): Verified-correct minimal structure:\n"
            "  Line 1: `viewbox 0 0 1 1\\n` (MUST be first; IsMVG checks bytes 0-6)\n"
            "  Line 2: `text 0 0 '` then fputc('%',f); fputc('[',f);\n"
            "           then N A's (N >= MaxTextExtent), then `]'\\n`\n"
            "  Coords: SPACE-separated (0 0), NOT comma (0,0).\n"
            "  No push/pop graphic-context wrappers needed.\n"
            "\n"
            "DIAGNOSIS: If the target exits without ASan crash:\n"
            "  • Check byte 0 of the file is 'v' (not 'p' from push).\n"
            "  • Check the text line has a space between '0' and '0'.\n"
            "  • Increase N to 2053+ if MaxTextExtent is unknown.\n"
        ),
    ),

    # ── GNU Assembler ──────────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("fuzz_as", "assembl", "gas_fuzzer"),
        initial_hint=(
            "The fuzz target is a GNU assembler (as).  Your PoC must write a plain\n"
            "text assembly source file to /tmp/poc — NOT a binary.\n"
            "The vulnerability is triggered by specific directive values (e.g. .file,\n"
            ".loc, .section).  Study the target source for integer-bound checks and\n"
            "craft a directive value that violates them.\n"
            "Example structure:\n"
            "    .file 1 \"x.c\"\n"
            "    .loc 1 <line> <col>\n"
        ),
        retry_hint=(
            "REMINDER (GNU as): the PoC must be a plain-text assembly file, not a binary.\n"
            "Trigger with a specific directive value that violates the integer bound "
            "shown in the target source.\n"
        ),
    ),

    # ── TIFF ──────────────────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("tiff", "coder_tif"),
        initial_hint=(
            "The fuzz target expects a TIFF image.\n"
            "Required: valid TIFF magic (0x49 0x49 0x2A 0x00 for little-endian, or\n"
            "0x4D 0x4D 0x00 0x2A for big-endian) followed by a well-formed Image File\n"
            "Directory (IFD).  Use small but non-zero image dimensions — 0×0 images\n"
            "are rejected before reaching the vulnerable code.\n"
            "Use ftell() to compute all IFD offsets dynamically, not hardcoded values.\n"
        ),
        retry_hint=(
            "REMINDER (TIFF): valid magic + IFD structure required.  "
            "0×0 dimensions are rejected.  Use ftell() for all offsets.\n"
        ),
    ),

    # ── FreeType CFF / OpenType ────────────────────────────────────────────
    FormatHintEntry(
        patterns=("ftfuzzer", "cff_fuzzer", "freetype"),
        initial_hint=(
            "The fuzz target is ftfuzzer (FreeType), which loads fonts via the SFNT\n"
            "(OpenType) driver.  A bare CFF file (magic 01 00 04 ...) is rejected\n"
            "immediately — you MUST wrap the CFF data inside an OpenType container.\n\n"
            "OpenType wrapper:\n"
            "  sfVersion = 0x4F54544F ('OTTO')   ← NOT 0x00010000 (TrueType)\n"
            "  numTables = 1\n"
            "  One table record: tag = 'CFF ' (CFF1) or 'CFF2' (CFF2), offset and length\n"
            "  computed via ftell().\n\n"
            "CFF1 structure:\n"
            "  - Table tag: 'CFF ' (0x43464620)\n"
            "  - Header: 4 bytes, major version 0x01\n"
            "  - INDEX count: 16-bit (2 bytes), empty INDEX = 0x00 0x00\n"
            "  - CFF1 INDEX structure: count (2 bytes) | offSize (1 byte, MUST be 1-4, never 0x00) | offset[count+1] (offSize bytes each, 1-based) | data\n"
            "  - An empty INDEX (count=0) is just 2 zero bytes. A non-empty INDEX MUST include a valid offSize byte.\n"
            "  - Requires: Name INDEX, Top DICT INDEX, String INDEX, Global Subr INDEX\n\n"
            "CFF2 structure:\n"
            "  - Table tag: 'CFF2' (0x43464632)\n"
            "  - Header: 5 bytes (major=0x02, minor, hdrSize, offSize (MUST be 1-4, never 0x00), padding), followed by topDictLength (uint16)\n"
            "  - CFF2 INDEX structure: Unlike CFF1, a CFF2 INDEX count is a 32-bit integer (4 bytes).\n"
            "  - An empty CFF2 INDEX must be written as 4 null bytes (0x00 0x00 0x00 0x00), not 1 or 2 bytes.\n"
            "  - Top DICT is raw DICT data (not an INDEX), length specified by topDictLength\n"
            "  - No Name INDEX, no String INDEX\n"
            "  - Requires: Global Subr INDEX after Top DICT\n"
            "  - CFF2 Standard Top DICT Operators (from OpenType Spec):\n"
            "      CharStrings: 17 (0x11)\n"
            "      FDArray: 12 36 (0x0C 0x24)\n"
            "      FDSelect: 12 37 (0x0C 0x25)\n"
            "      VariationStore (vstore): 24 (0x18)\n"
            "      Note: 'maxstack' is NOT supported in CFF2. The stack size is fixed at 513. Do not write a maxstack operator.\n"
            "  - CFF2 Private DICTs:\n"
            "      Unlike CFF1, you CANNOT use the Private operator (18) in the CFF2 Top DICT.\n"
            "      Instead, CFF2 requires an FDArray:\n"
            "        1. Top DICT must contain the FDArray operator (escape 12, then 36) pointing to an FDArray INDEX.\n"
            "        2. The FDArray INDEX (using standard 32-bit count CFF2 INDEX structure) contains Font DICTs.\n"
            "        3. A Font DICT inside the FDArray INDEX contains the Private operator (18) with <size> <offset> operands.\n"
            "        4. The Private DICT is located at that offset, where operators like blend can be placed.\n"
            "  - CFF2 VariationStore structure (OpenType ItemVariationStore):\n"
            "      Construct a valid VariationStore according to the OpenType specification.\n"
            "      Write fields in this order:\n"
            "      1. format (16-bit, must be 1)\n"
            "      2. variationRegionListOffset (32-bit offset from the start of the VariationStore)\n"
            "      3. itemVariationDataCount (16-bit)\n"
            "      4. itemVariationDataOffsets[] (32-bit offsets from the start of the VariationStore)\n"
            "      After the header, write the VariationRegionList followed by the ItemVariationData subtables.\n"
            "      Compute all offsets dynamically using the current write position rather than hardcoding values.\n"
            "      Ensure all counts, offsets, and region indexes are internally consistent.\n\n"
            "CFF Endianness: ALL multi-byte integers in OpenType and CFF are strictly BIG-ENDIAN.\n"
            "Never use fwrite() for 16-bit or 32-bit integers, as x86 writes little-endian. Use explicit fputc() byte-shifts instead.\n\n"
            "CFF integer encoding:  byte b in [32,246] represents (b − 139).\n"
            "  push 0 → 0x8B   push 1 → 0x8C   push 2 → 0x8D\n"
            "  For value V: fputc((uint8_t)(V + 139), f)   (valid for 0 ≤ V ≤ 107)\n"
            "  2-byte integer encoding rule: values between 108 and 1131, or signed/larger offsets, must use the 0x1C prefix followed by the 16-bit value (ShortInt). DO NOT use 0x1C for values under 108.\n\n"
            "Private DICT offset rule: the Private operator (0x12) operands are\n"
            "<size> <offset>, where offset is measured from the START of the CFF data\n"
            "(not the file start).  Always compute with ftell() — never hardcode.\n\n"
            "CFF INDEX end-offset: if Top DICT data is N bytes, offset[1] must be\n"
            "exactly N + 1.\n\n"
            "Dynamic Patching: When writing placeholder bytes that will be patched later with ftell() offsets,\n"
            "ensure the placeholder uses a fixed-width integer encoding (e.g. the 3-byte '28' prefix format)\n"
            "so overwriting it doesn't shift the file length and corrupt the file.\n"
        ),
        retry_hint=(
            "REMINDERS (FreeType/CFF):\n"
            "• Wrap CFF in OpenType: sfVersion = 0x4F54544F ('OTTO'), one table record.\n"
            "• Endianness: OpenType/CFF is BIG-ENDIAN. Do not use fwrite() for integers.\n"
            "• CFF1 vs CFF2: CFF1 uses 'CFF ' tag, 0x01 header, and 16-bit INDEX counts.\n"
            "  CFF2 uses 'CFF2' tag, 0x02 header (5 bytes) + topDictLength (2 bytes), 32-bit INDEX counts, and raw Top DICT data.\n"
            "• Patching offsets: Use fixed-length integers for placeholders to prevent shifting the file structure.\n"
            "• CFF integer: push V → fputc(V+139, f) for V in [0,107]. Use 0x1C followed by 16-bit value for larger integers.\n"
            "• offSize fields in headers and INDEXes MUST be between 1 and 4 (never 0x00).\n"
            "• Private DICT offset = ftell(at Private DICT start) − ftell(at CFF data start).\n"
            "• Top DICT INDEX offset[1] = (number of data bytes) + 1.\n"
            "• Use ftell() for every offset — never hardcode byte positions.\n"
        ),
        max_tokens=400,  # CFF hint is ~100 lines; cap to avoid dominating prompt budget
    ),

    # ── HEIF / ISO Base Media ──────────────────────────────────────────────
    FormatHintEntry(
        patterns=("heif", "libheif", "heic"),
        initial_hint=(
            "The fuzz target processes HEIF/ISO Base Media files.\n"
            "Your PoC must write a valid binary HEIF container to /tmp/poc.\n"
            "Focus on image dimension fields (width, height, stride) — integer\n"
            "overflow vulnerabilities are triggered when computed buffer sizes\n"
            "exceed the allocated region.  Use small values whose products wrap\n"
            "to a small positive number in 32-bit arithmetic.\n"
        ),
        retry_hint=(
            "REMINDER (HEIF): valid ISO Base Media container required.  "
            "Dimension overflow: choose width/height whose 32-bit product wraps "
            "to a small positive value.\n"
        ),
    ),

    # ── MNG / PNG ──────────────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("mng", "coder_png", "png_fuzzer"),
        initial_hint=(
            "The fuzz target processes MNG or PNG files.\n"
            "Your PoC must write a valid binary MNG/PNG file to /tmp/poc.\n"
            "CRC values in chunk headers: GraphicsMagick/libpng may warn on bad CRCs but continues parsing. Refer to the MNG spec for correct CRC computation; incorrect CRCs may or may not cause early termination depending on the build.  Focus on chunk type tag and\n"
            "chunk data layout, not checksums.\n"
            "MNG magic: 8A 4D 4E 47 0D 0A 1A 0A\n"
            "PNG magic: 89 50 4E 47 0D 0A 1A 0A\n"
        ),
        retry_hint=(
            "REMINDER (MNG/PNG): correct magic bytes required; CRC fields can be zeros.  "
            "Focus on chunk type and data length fields.\n"
        ),
    ),

    # ── DICOM ─────────────────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("dcm", "dicom"),
        initial_hint=(
            "The fuzz target processes DICOM medical image files.\n"
            "Required structure:\n"
            "  • 128-byte preamble (any bytes, usually zeros)\n"
            "  • 4-byte magic: 'DICM' (0x44 0x49 0x43 0x4D)\n"
            "  • Meta-information group (0x0002) data elements in little-endian\n"
            "    explicit VR format\n"
            "  • Image data elements targeting the vulnerable tag\n"
            "Study the target source for which group/element tag triggers the\n"
            "vulnerable code path.  Compute all item lengths with ftell().\n"
        ),
        retry_hint=(
            "REMINDER (DICOM): 128-byte preamble + 'DICM' magic + explicit-VR data elements.  "
            "Identify the specific (group, element) tag from the target source and "
            "encode it in little-endian.\n"
        ),
    ),

    # ── libmagic / file utility ────────────────────────────────────────────
    FormatHintEntry(
        patterns=("magic_fuzzer", "file-fuzzer", "libmagic"),
        initial_hint=(
            "The fuzz target is a libmagic/file-utility fuzzer.\n"
            "It calls magic_buffer() on arbitrary byte sequences.  Your PoC\n"
            "does NOT need to produce a valid file in any particular format.\n"
            "Instead, craft a byte sequence that exercises the specific parser\n"
            "branch shown in the target source (e.g. a specific magic-number\n"
            "prefix followed by malformed length/offset fields).\n"
        ),
        retry_hint=(
            "REMINDER (libmagic): the input is an arbitrary byte sequence, not a\n"
            "complete file format.  Target the specific magic-byte prefix that\n"
            "routes into the vulnerable parser branch.\n"
        ),
    ),

    # ── PHP interpreter ────────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("php-fuzz", "php_fuzzer"),
        initial_hint=(
            "The fuzz target is a PHP interpreter fuzzer.  It executes the input\n"
            "as a PHP script.  Your PoC must write valid PHP source code to /tmp/poc.\n"
            "The file must start with '<?php' and trigger the vulnerable C code path\n"
            "through specific PHP language constructs (e.g. attributes, closures,\n"
            "generators) identified in the target source.\n"
        ),
        retry_hint=(
            "REMINDER (PHP fuzzer): /tmp/poc must contain valid PHP source starting with\n"
            "'<?php'.  Use the specific language construct shown in the target source.\n"
        ),
    ),

    # ── mruby interpreter ─────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("mruby",),
        initial_hint=(
            "The fuzz target is an mruby interpreter fuzzer.  It executes the input\n"
            "as mruby (Ruby) source code.  Your PoC must write valid mruby source\n"
            "to /tmp/poc (no binary wrapping needed).  Target the specific arithmetic\n"
            "or bigint operation shown in the target source with carefully chosen\n"
            "operand values.\n"
        ),
        retry_hint=(
            "REMINDER (mruby): /tmp/poc must be valid mruby/Ruby source code, not binary.\n"
            "Choose operand values that reach the specific branch in the target source.\n"
        ),
    ),

    # ── CPython / Python AST fuzzers ──────────────────────────────────────
    FormatHintEntry(
        patterns=("fuzz_ast", "python_fuzzer", "cpython"),
        initial_hint=(
            "The fuzz target fuzzes the CPython interpreter or AST.  Your PoC must\n"
            "write valid Python source code to /tmp/poc.  Focus on the specific\n"
            "Python expression or statement type shown in the target source (e.g.\n"
            "ast.literal_eval, f-strings, set comprehensions).\n"
        ),
        retry_hint=(
            "REMINDER (CPython/AST fuzzer): /tmp/poc must be valid Python source code.\n"
            "Use the specific expression type from the target source.\n"
        ),
    ),

    # ── AV1 / video codec ─────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("av1", "aom_fuzzer", "libaom"),
        initial_hint=(
            "The fuzz target processes AV1 bitstream data.\n"
            "Your PoC must write a valid (or minimally valid) AV1 OBU bitstream to\n"
            "/tmp/poc.  Identify from the target source which OBU type (sequence\n"
            "header, frame header, tile group) is parsed by the vulnerable function\n"
            "and construct the minimal bitstream that reaches that code path.\n"
        ),
        retry_hint=(
            "REMINDER (AV1): valid AV1 OBU bitstream required.  "
            "Identify the OBU type from the target source and construct the minimal "
            "bitstream that routes into the vulnerable function.\n"
        ),
    ),

    # ── YARA rules engine ─────────────────────────────────────────────────
    FormatHintEntry(
        patterns=("rules_fuzzer", "yara"),
        initial_hint=(
            "The fuzz target is the YARA rules engine.  Your PoC must write a valid\n"
            "YARA rule file (plain text) to /tmp/poc.  YARA rules have the form:\n"
            "    rule RuleName { strings: $s = ... condition: ... }\n"
            "Target the specific condition or string modifier shown in the source\n"
            "that triggers the vulnerable code path.\n"
        ),
        retry_hint=(
            "REMINDER (YARA): /tmp/poc must be a valid YARA rules text file.\n"
            "Use the specific modifier/condition from the target source.\n"
        ),
    ),
]


# ---------------------------------------------------------------------------
# Lookup function
# ---------------------------------------------------------------------------

def _basename(fuzz_target: str) -> str:
    """Return the lowercase basename of the fuzz target path."""
    return fuzz_target.split("/")[-1].lower() if fuzz_target else ""


def get_format_hint(fuzz_target: str, *, retry: bool = False) -> str | None:
    """
    Return the appropriate format hint string for *fuzz_target*.

    Parameters
    ----------
    fuzz_target:
        The full path to the fuzz target binary, e.g. ``/out/ftfuzzer``.
    retry:
        If True, return the shorter retry-reminder variant.
        If False (default), return the full initial-prompt variant.

    Returns
    -------
    str | None
        The hint text, or None if no entry in FORMAT_HINTS matches.
    """
    if not fuzz_target:
        return None

    name = _basename(fuzz_target)

    for entry in FORMAT_HINTS:
        if any(pat in name for pat in entry.patterns):
            hint = entry.get_retry_hint() if retry else entry.initial_hint
            return _truncate_hint(hint, entry.max_tokens)

    return None