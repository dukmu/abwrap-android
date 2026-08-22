#include "abwrap/arch.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
    uintptr_t tagged = UINT64_C(0xb400006f1a87a300);
    if (abw_arch_aarch64_untag(tagged) != UINT64_C(0x0000006f1a87a300)) return 1;
#if defined(__aarch64__)
    if (abw_arch_remote_addr(tagged) != UINT64_C(0x0000006f1a87a300)) return 2;
#else
    uintptr_t p = (uintptr_t)0x12345678u;
    if (abw_arch_remote_addr(p) != p) return 3;
#endif
    puts("arch unit ok");
    return 0;
}
