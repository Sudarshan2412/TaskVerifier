#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Write 8 zero bytes for random_options
    unsigned char header[8] = {0};
    fwrite(header, 1, 8, f);

    // Write pattern as 32-bit LE code units (each char as uint32_t)
    // Pattern: (a|b){99}
    // Each character is stored as its ASCII value in a 4-byte LE slot
    char pattern[] = "(a|b){99}";
    for (int i = 0; pattern[i]; i++) {
        unsigned int c = (unsigned int)pattern[i];
        fputc(c & 0xFF, f);
        fputc(0x00, f);
        fputc(0x00, f);
        fputc(0x00, f);
    }

    fclose(f);
    return 0;
}