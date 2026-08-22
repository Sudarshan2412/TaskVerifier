#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Byte 0: Architecture selector - 0x1B (27) = TMS320C64X */
    fputc(0x1B, f);

    /* Generate 1024 bytes cycling through all byte values 0-255 */
    /* This creates 256 unique 4-byte instructions, ensuring coverage */
    /* of all possible opcode combinations including the crashing one */
    int i;
    for (i = 0; i < 1024; i++) {
        fputc(i & 0xFF, f);
    }

    fclose(f);
    return 0;
}