#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    fprintf(f, "<?php\n");
    fprintf(f, "#[Attribute]\n");
    fprintf(f, "class A {\n");
    fprintf(f, "    public function __construct(public string $s = '') {}\n");
    fprintf(f, "}\n");
    fprintf(f, "#[A(s: 'test')]\n");
    fprintf(f, "class B {}\n");
    fprintf(f, "new B();\n");
    
    fclose(f);
    return 0;
}