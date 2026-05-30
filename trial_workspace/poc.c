#include <stdio.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "w");
    if (!f) return 1;
    fprintf(f, "#!/bin/sh\n");
    fclose(f);
    return 0;
}