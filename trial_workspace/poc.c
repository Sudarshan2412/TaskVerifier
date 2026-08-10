#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    // Write a 32-byte payload: 31 bytes of 0x00 (valid NOP fetch packet header + 7 NOP instructions)
    // followed by 0x7E at the last byte position
    // The TMS320C64x fetch packet starts with a header byte, followed by 8 instruction slots
    // A NOP instruction is encoded as 0x00000000
    
    for (int i = 0; i < 31; i++) {
        fputc(0x00, f);
    }
    fputc(0x7E, f);  // Last byte = 126, could be part of an instruction encoding
    
    fclose(f);
    return 0;
}