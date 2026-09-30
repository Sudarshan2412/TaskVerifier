#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Configuration parameters for the 46-byte header
    uint16_t width = 176;   // QCIF width
    uint16_t height = 144;  // QCIF height
    uint8_t color_format = 0;      // IV_YUV_420
    uint8_t arch_type = 0;         // ARM_NONEON
    uint8_t rc_mode = 0;           // RC_MODE_0
    uint8_t num_cores = 0;         // maps to 1 core
    uint8_t num_b_frames = 0;
    uint8_t enc_speed = 0;
    uint8_t constrained_intra = 0;
    uint8_t intra_4x4 = 0;
    uint8_t i_qp = 20;             // I-frame QP (4-51)
    uint8_t p_qp = 20;             // P-frame QP
    uint8_t b_qp = 20;             // B-frame QP
    uint16_t bitrate = 100;        // 100 kbps (in 1000s of bits)

    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Write 46-byte header
    // Bytes 0-1: width (big-endian)
    fputc((width >> 8) & 0xFF, f);
    fputc(width & 0xFF, f);
    // Bytes 2-3: height (big-endian)
    fputc((height >> 8) & 0xFF, f);
    fputc(height & 0xFF, f);
    // Byte 4: color format
    fputc(color_format, f);
    // Byte 5: arch type
    fputc(arch_type, f);
    // Byte 6: rc mode
    fputc(rc_mode, f);
    // Byte 7: num cores
    fputc(num_cores, f);
    // Byte 8: num b frames
    fputc(num_b_frames, f);
    // Byte 9: enc speed
    fputc(enc_speed, f);
    // Byte 10: constrained intra flag
    fputc(constrained_intra, f);
    // Byte 11: intra 4x4 flag
    fputc(intra_4x4, f);
    // Bytes 12-14: QP values
    fputc(i_qp, f);
    fputc(p_qp, f);
    fputc(b_qp, f);
    // Bytes 15-16: bitrate (big-endian)
    fputc((bitrate >> 8) & 0xFF, f);
    fputc(bitrate & 0xFF, f);
    // Bytes 17-45: padding (set to reasonable defaults)
    for (int i = 17; i < 46; i++) {
        fputc(0, f);
    }

    // Write YUV 420 data
    // Y plane (width * height)
    for (int i = 0; i < width * height; i++) {
        fputc(0x80, f);  // gray luma
    }
    // U plane (width/2 * height/2)
    for (int i = 0; i < (width/2) * (height/2); i++) {
        fputc(0x80, f);  // neutral chroma
    }
    // V plane (width/2 * height/2)
    for (int i = 0; i < (width/2) * (height/2); i++) {
        fputc(0x80, f);  // neutral chroma
    }

    fclose(f);
    return 0;
}