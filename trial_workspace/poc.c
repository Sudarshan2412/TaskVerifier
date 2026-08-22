#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* First byte: selects TMS320C64x architecture */
    fputc(27, f);

    /* Generate all possible 32-bit little-endian instructions where
     * the value 126 (0x7E) appears in the upper bits (bits 18-26)
     * which could be a 9-bit control register field.
     * 
     * In little-endian byte order:
     * Byte 0 = bits 7-0 (LSB)
     * Byte 1 = bits 15-8
     * Byte 2 = bits 23-16
     * Byte 3 = bits 31-24 (MSB)
     * 
     * For a 9-bit field at bits 18-26:
     * Bits 18-23 are in byte 2 (bits 2-7 of byte 2)
     * Bits 24-26 are in byte 3 (bits 0-2 of byte 3)
     * Value 126 = 0b001111110
     * Bits 18-23 = 0b111110 = 62 (0x3E)
     * Bits 24-26 = 0b001 = 1
     * So byte 2 should have 0x3E in bits 7-2, and byte 3 should have 0x01 in bits 2-0
     */
    
    /* Try with 126 in bits 18-26 (9-bit control register field) */
    fputc(0x00, f);  /* Byte 0: bits 7-0 */
    fputc(0x00, f);  /* Byte 1: bits 15-8 */
    fputc(0xF8, f);  /* Byte 2: bits 23-16, with 0x3E shifted left 2 = 0xF8 */
    fputc(0x01, f);  /* Byte 3: bits 31-24, with 0x01 in bits 2-0 */

    /* Also try with 126 in bits 0-7 (8-bit field) */
    fputc(0x7E, f);  /* Byte 0: bits 7-0 = 126 */
    fputc(0x00, f);  /* Byte 1 */
    fputc(0x00, f);  /* Byte 2 */
    fputc(0x00, f);  /* Byte 3 */

    /* Try with 126 in bits 8-15 (8-bit field) */
    fputc(0x00, f);  /* Byte 0 */
    fputc(0x7E, f);  /* Byte 1: bits 15-8 = 126 */
    fputc(0x00, f);  /* Byte 2 */
    fputc(0x00, f);  /* Byte 3 */

    /* Try with 126 in bits 16-23 (8-bit field) */
    fputc(0x00, f);  /* Byte 0 */
    fputc(0x00, f);  /* Byte 1 */
    fputc(0x7E, f);  /* Byte 2: bits 23-16 = 126 */
    fputc(0x00, f);  /* Byte 3 */

    /* Try with 126 in bits 24-31 (8-bit field) */
    fputc(0x00, f);  /* Byte 0 */
    fputc(0x00, f);  /* Byte 1 */
    fputc(0x00, f);  /* Byte 2 */
    fputc(0x7E, f);  /* Byte 3: bits 31-24 = 126 */

    fclose(f);
    return 0;
}