#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    for (int i = 0; i < 128; i++) {
        fputc(0x00, f);
    }
    fputc('D', f);
    fputc('I', f);
    fputc('C', f);
    fputc('M', f);

    fclose(f);
    return 0;
}