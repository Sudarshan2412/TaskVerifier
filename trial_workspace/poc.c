#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    /* Write a minimal MIME email header to trigger the regex parsing path */
    fprintf(f, "From: test@example.com\r\n");
    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "Content-Type: text/plain;\r\n");
    /* Add a long header to stress the regex engine */
    fprintf(f, "X-Long: ");
    for (int i = 0; i < 4096; i++) {
        fputc('X', f);
    }
    fprintf(f, "\r\n\r\nbody\n");
    fclose(f);
    return 0;
}