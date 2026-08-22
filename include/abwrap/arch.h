#pragma once

#include <stdint.h>
#include <sys/types.h>

/*
 * Return a kernel-usable userspace virtual address for remote-memory I/O.
 *
 * Android/aarch64 commonly uses tagged userspace pointers (TBI, Scudo,
 * optionally MTE). Syscall argument registers may therefore contain a tag in
 * the upper byte even though /proc/<pid>/mem, process_vm_* and ptrace memory
 * access expect the canonical virtual address. Current Android devices use a
 * <=48-bit userspace VA on supported arm64 ABIs, so strip the tag/high bits.
 * Other architectures are returned unchanged.
 */
uintptr_t abw_arch_aarch64_untag(uintptr_t addr);
uintptr_t abw_arch_remote_addr(uintptr_t addr);

/*
 * Commit an overridden syscall number for a stopped tracee.
 *
 * On x86_64 the syscall number lives in the normal ptrace register set
 * (orig_rax), so tracer.c only needs to update that register set and this is a
 * no-op. On aarch64 Linux/Android the active syscall number is exposed through
 * the NT_ARM_SYSTEM_CALL regset; changing x8 alone is not sufficient on a
 * syscall/seccomp ptrace stop. This helper updates that architecture-specific
 * state after NT_PRSTATUS has been committed.
 */
int abw_arch_commit_syscall_nr(pid_t pid, long nr);
