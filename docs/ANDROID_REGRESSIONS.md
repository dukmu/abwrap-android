# Android-specific regressions and invariants

This document records behavior that must stay covered because generic desktop Linux tests are not sufficient for Android/Termux.

## Tagged aarch64 pointers

Android's arm64 userspace can pass tagged pointers in syscall argument registers (TBI; Scudo and MTE make this common). A pathname pointer may therefore look like `0xb400006f1a87a300` while the actual userspace VA is `0x0000006f1a87a300`.

`src/arch.c` canonicalizes remote-memory addresses before `process_vm_*`, `/proc/<pid>/mem`, or ptrace memory access. This is intentionally isolated from policy/path code. A failure here can make every path syscall fail even though the bind table is correct; the typical symptom is `ls: ... Permission denied` on both RW and RO binds.

`tests/test_arch.c` checks the canonicalization logic on every build. `tests/termux_smoke.sh` is the device-level regression test.

## aarch64 syscall-number override

At a ptrace/seccomp syscall stop on arm64, the active syscall number is represented by the `NT_ARM_SYSTEM_CALL` regset. Merely writing `x8 = -1` in `NT_PRSTATUS` is not sufficient on the tested Android path. If abwrap only patches the normal register set, the kernel can still execute the original syscall and abwrap may later overwrite only its return value.

This failure is particularly dangerous for RO enforcement: a tracee can observe `EROFS` while the host file was actually truncated or modified. It also breaks emulated proc magic links: Python may receive the virtual return length while the buffer still contains the beginning of the real host path.

`src/arch.c` therefore commits an overridden syscall number with `PTRACE_SETREGSET(NT_ARM_SYSTEM_CALL)` after the normal register set is written. Device tests verify both the returned error and host-side immutability.

## Remote-memory transport order

`src/remote.c` tries:

1. `process_vm_readv/process_vm_writev`;
2. `/proc/<pid>/mem` with canonicalized address;
3. ptrace word access.

Android kernels and SELinux policy vary, so no single transport is assumed. All methods still operate only on a child already being traced by abwrap.

## Directory reads are reads

`getdents/getdents64` are never rejected merely because the directory belongs to a `--ro-bind`. Real read-only mounts allow directory enumeration. RO policy applies to mutations, not reads. This invariant prevents `ls`, Python importlib, package managers, and language runtimes from failing on RO trees.

## Python bytecode cache

For a module inside a writable bind, Python must be able to create `__pycache__/*.pyc`.

For the same module inside a read-only bind, import must still succeed while cache creation is denied by normal RO filesystem semantics. abwrap does not inject a special importlib policy and does not deny directory enumeration to influence Python behavior.


## Broad root bind and `/proc/self/fd`

A broad `--bind / /` or `--ro-bind / /` also exposes the real host `/proc`. Generic pathname symlink walking must not resolve `/proc/self` in the supervisor, because Android's dynamic linker repeatedly calls `readlink("/proc/self/fd/N")` while loading libraries. Doing so uses the supervisor PID and produces misleading `ENOENT` linker warnings even though the target process owns the FD.

3.0.1 automatically overlays the hybrid proc implementation when virtual `/proc` resolves to the real host procfs. `self`, `thread-self`, `fd/N`, `cwd`, `exe`, and proc dirfd/openat behavior therefore remain tracee-relative even when the caller only specified a root bind. The Termux diagnostics suite has a dedicated linker-warning regression for this case.

## Read-only root and special endpoints

A filesystem mounted read-only still permits I/O through an already-existing device/FIFO/socket endpoint. In particular, `printf ... >/dev/null` must continue to work under `--ro-bind / /`. abwrap therefore rejects filesystem mutation on RO binds while allowing an open with write intent when the resolved existing object is a character/block device, FIFO, or socket. Android's normal UID/SELinux permissions still decide whether that endpoint itself is usable.

## Termux native regression suite

On Termux:

```sh
pkg install clang cmake ninja python bash coreutils findutils grep
./scripts/termux-test.sh
```

The wrapper builds native C unit/probe targets with `BUILD_TESTING=ON` and then runs `tests/termux_diagnostics.sh`. The diagnostics log first records the host result for `ls /` and requires sandbox root access to preserve that result; this avoids treating Android app-UID restrictions as a sandbox bug. `$PREFIX` is separately mounted RO to positively verify directory enumeration. It also covers Android-linker `/proc/self/fd`, proc dirfd/openat, direct-syscall RO enforcement plus host integrity, representative Bash script behavior plus RO host integrity, independently runnable Python stdlib/filesystem/proc-fd/bytecode/subprocess cases, and all requested backends.
