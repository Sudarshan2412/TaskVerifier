#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* JSON number with 2 digits and very negative exponent */
    /* This should produce a number where decToString writes more than digits+14 chars */
    fprintf(f, "1.0e-1999999997");
    
    fclose(f);
    return 0;
}