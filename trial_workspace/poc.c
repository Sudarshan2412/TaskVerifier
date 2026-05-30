#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    
    /* Write a file that looks like a C source file to trigger regex matching */
    /* The file(1) command uses regex patterns to identify file types */
    /* Writing a .c file pattern should trigger the regex code path */
    fprintf(f, "#include <stdio.h>\nint main() { return 0; }\n");
    
    fclose(f);
    return 0;
}