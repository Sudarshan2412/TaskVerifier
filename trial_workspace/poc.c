#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* First 128 bytes of padding */
    for (int i = 0; i < 128; i++) {
        fputc(0, f);
    }

    /* DICM magic at offset 128 */
    fwrite("DICM", 1, 4, f);

    /* DICOM header: group 0x0002, element 0x0010, length 4, data zeros */
    fputc(0x02, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Additional pixel data fields to exercise DICOM parsing */
    fputc(0x7f, f); fputc(0xe0, f); fputc(0x00, f); fputc(0x10, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    fclose(f);
    return 0;
}