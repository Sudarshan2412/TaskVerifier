#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned char poc[] = {0x00};
    size_t poc_len = sizeof(poc);

    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { 
        printf("Error opening file\n");
        return 1; 
    }
    fwrite(poc, 1, poc_len, f);
    fclose(f);
    return 0;
}