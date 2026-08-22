#include "abwrap/arch.h"

#include <errno.h>

#if defined(__aarch64__)
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#endif

uintptr_t abw_arch_aarch64_untag(uintptr_t addr) {
    return addr & UINT64_C(0x0000ffffffffffff);
}

uintptr_t abw_arch_remote_addr(uintptr_t addr) {
#if defined(__aarch64__)
    return abw_arch_aarch64_untag(addr);
#else
    return addr;
#endif
}

int abw_arch_commit_syscall_nr(pid_t pid, long nr) {
#if defined(__aarch64__)
    /* Linux arm64 exposes this regset as one sizeof(int) element. */
    int value = (int)nr;
    struct iovec io = {.iov_base = &value, .iov_len = sizeof(value)};
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_ARM_SYSTEM_CALL, &io) == 0)
        return 0;
    return -errno;
#else
    (void)pid;
    (void)nr;
    return 0;
#endif
}
