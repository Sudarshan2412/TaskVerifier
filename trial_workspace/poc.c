#include <stdio.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) return 1;

    // TIFF header (little-endian)
    fputc(0x49, f); fputc(0x49, f);
    fputc(0x2A, f); fputc(0x00, f);
    uint32_t ifd_offset = 8;
    fwrite(&ifd_offset, 4, 1, f);

    // IFD with 10 entries
    uint16_t num_entries = 10;
    fwrite(&num_entries, 2, 1, f);

    // Tag 256: ImageWidth = 16 (SHORT)
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x10, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 257: ImageLength = 1 (SHORT)
    fputc(0x01, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 258: BitsPerSample = 8,8,8,8 (SHORT, count=4) -> at offset 134
    fputc(0x02, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x04, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x86, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 259: Compression = 1 (SHORT)
    fputc(0x03, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 262: PhotometricInterpretation = 2 (RGB) (SHORT)
    fputc(0x06, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x02, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 273: StripOffsets = 150 (LONG)
    fputc(0x11, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x96, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 277: SamplesPerPixel = 4 (SHORT)
    fputc(0x15, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x04, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 278: RowsPerStrip = 1 (SHORT)
    fputc(0x16, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Tag 279: StripByteCounts = 64 (LONG)
    fputc(0x17, f); fputc(0x01, f);
    fputc(0x04, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    uint32_t bytecount = 64;
    fwrite(&bytecount, 4, 1, f);

    // Tag 339: SampleFormat (SHORT, count=4) -> at offset 142
    fputc(0x53, f); fputc(0x01, f);
    fputc(0x03, f); fputc(0x00, f);
    fputc(0x04, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x8E, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // Next IFD offset = 0
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    // BitsPerSample array at offset 134: 8,8,8,8
    fputc(0x08, f); fputc(0x00, f);
    fputc(0x08, f); fputc(0x00, f);
    fputc(0x08, f); fputc(0x00, f);
    fputc(0x08, f); fputc(0x00, f);

    // SampleFormat array at offset 142: 1,1,1,1 (UINT)
    fputc(0x01, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f);
    fputc(0x01, f); fputc(0x00, f);

    // Pixel data: 16 pixels * 4 bytes = 64 bytes
    // Each pixel: R=0, G=0, B=0, A=1 (opacity != MaxRGB)
    for (int i = 0; i < 16; i++) {
        fputc(0x00, f);  // R
        fputc(0x00, f);  // G
        fputc(0x00, f);  // B
        fputc(0x01, f);  // A (opacity = 1, not MaxRGB)
    }

    fclose(f);
    return 0;
}