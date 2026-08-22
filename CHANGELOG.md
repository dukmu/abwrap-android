# Changelog

## 3.0.3

- Fix Android/aarch64 syscall cancellation: when abwrap denies or emulates a syscall, it now updates the `NT_ARM_SYSTEM_CALL` ptrace regset in addition to the normal register set. On Android arm64, changing `x8` alone can leave the in-flight syscall active.
- Fix a serious false-denial condition exposed by Termux diagnostics: a raw write to an RO bind could really modify the host file while the tracee was given synthetic `EROFS`. Host-integrity checks now run immediately after denied operations.
- Fix Python `os.readlink('/proc/self/fd/N')` returning host-path bytes truncated to the virtual-path length. This had the same syscall-cancellation root cause.
- Treat Android `/` access as host-permission parity in device diagnostics. Termux app UIDs may legitimately receive `EACCES` from `ls /`; a separate `$PREFIX` RO bind is the positive directory-listing regression.
- Split the Python device workload into independent stdlib, filesystem, proc-fd, RW-bytecode, RO-bytecode, and subprocess cases, while retaining one aggregate script run.
- Add host-side integrity assertions for raw-syscall, Bash, and Python RO mutation tests so synthetic error returns cannot hide real writes.

## 3.0.2

- Fix Termux/non-root `EACCES` during automatic `/proc` virtualization. The private synthetic proc backing was created `0500` and then populated with child entries; this only worked in root-run host tests. It is now supervisor-private **and owner-writable** (`0700` directories / `0600` placeholders), while the virtual `/proc` rule remains read-only to the sandboxed process.
- Add a policy unit regression asserting that the private proc backing is writable by its owner.
- Make state-directory selection robust when `$HOME/.cache` cannot be created: explicit `--state-dir` still fails clearly, while implicit state falls back through `$TMPDIR`, `$HOME/.cache`, `/tmp`, and the current directory.
- Extend Termux diagnostics with UID/GID/umask and state-directory preflight information, without dumping environment variables.
- Add a non-root host regression runner so permission mistakes masked by root CI are caught before packaging.

## 3.0.1

- Fixed Termux/Android linker compatibility when a broad `--bind / /` or `--ro-bind / /` exposes host `/proc`: abwrap now automatically overlays the hybrid proc implementation when virtual `/proc` resolves to the real host procfs. This keeps `/proc/self/fd/N` tied to the tracee instead of accidentally resolving `self` in the supervisor.
- Preserved normal I/O semantics for already-existing device/FIFO/socket endpoints under a read-only bind, including writable `/dev/null` with `--ro-bind / /`; filesystem mutation remains read-only.
- Fixed ptrace-backend exec stop phase tracking.
- Made native C unit tests build on Termux/Android; policy tests use `$TMPDIR` instead of assuming `/tmp`, and Android uses the Bionic-compatible statfs header.
- Added `scripts/build-termux-native.sh` and one-command `scripts/termux-test.sh`.
- Added `tests/termux_diagnostics.sh`, which writes a sanitized, shareable log with CTest results, explicit seccomp/ptrace/auto backend cases, `/proc/self/fd` linker checks, root RO listing, raw-syscall RO enforcement, and common Bash/Python workloads.
- Added script-file workloads covering Bash pipelines/redirection/source/subshell/temp files and Python filesystem operations, stdlib extension imports, subprocess, `/proc/self/fd`, and RW/RO bytecode-cache behavior.

## 3.0.0

- Fixed Android/aarch64 tagged-pointer handling for traced pathname arguments. Remote addresses are canonicalized before `process_vm_*`, `/proc/<pid>/mem`, and ptrace fallback access.
- Added a three-stage remote-memory backend to tolerate Android kernel/SELinux variation without relaxing sandbox policy.
- Added explicit root-listing regressions for both `--bind / /` and `--ro-bind / /`.
- Added Python integration regressions: RW binds create `__pycache__`; RO binds remain importable and immutable.
- Kept directory enumeration read-only-safe; abwrap never denies `getdents*` merely because a bind is RO.
- Added `--dev-bind` and `--dev-bind-try` compatibility aliases.
- Compatibility no-op flags are silent by default; diagnostics move behind `--verbose`.
- Added Android/Termux device smoke suite and Android regression documentation.
- Retained hybrid virtual `/proc`, raw syscall mediation, seccomp-selective tracing with ptrace fallback, and the 0.2 hardening set.
- Integration suite expanded from 38 to 42 scenarios, plus architecture and policy unit tests.

## 0.2.0

- Added hybrid virtual `/proc` and proc magic-link handling.
- Hardened xattr/statfs/inotify/fallocate/clone escape surfaces.

## 0.1.0

- Initial userspace path sandbox with RO/RW bind policy and selective seccomp/ptrace backend.
