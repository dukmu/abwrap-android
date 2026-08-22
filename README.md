# abwrap

`abwrap` is a from-scratch, unprivileged userspace filesystem sandbox for Android/Linux environments where Bubblewrap-style user/mount namespaces are unavailable.

The primary target is **no-root Android userland**: Termux-like runtimes, native app child-process runtimes, embedded agent/tool runtimes, compilers, interpreters, and user-run plugins. It provides a practical subset of the `bwrap` CLI with syscall-level read-only bind enforcement and a virtualized `/proc` view.

## Design

Bubblewrap normally builds a new mount namespace. `abwrap` instead keeps a virtual path namespace in a supervisor:

1. The child installs a small seccomp-BPF filter using `SECCOMP_RET_TRACE` when the kernel permits it.
2. Only filesystem- and sandbox-integrity-sensitive syscalls stop in the supervisor.
3. Path arguments are resolved against virtual binds/symlinks, checked for RO/RW policy, then rewritten to host backing paths.
4. Ordinary compute, futex, `read/write`, timers, networking, etc. remain native.
5. If additive seccomp is unavailable, `--backend auto` falls back to `PTRACE_SYSCALL`.

No `LD_PRELOAD`, mount namespace, user namespace, FUSE, root permission, or copied Bubblewrap/PRoot source is required.

### Android/aarch64 handling

Android ABI details live in `src/arch.c` + `src/remote.c`. On aarch64, tagged syscall pointers are canonicalized before remote-memory access, and remote I/O can fall back through `process_vm_*`, `/proc/<pid>/mem`, then ptrace word access.

3.0.3 also fixes syscall cancellation on Android arm64. At a ptrace/seccomp syscall stop, changing register `x8` alone does not reliably replace the active syscall number. abwrap now commits overridden syscall numbers through the Linux arm64 `NT_ARM_SYSTEM_CALL` regset after updating the normal register set. This matters for both emulation and enforcement: without it, a denied RO mutation could execute on the host while the tracee only saw a synthetic `EROFS`, and emulated `/proc/self/fd` `readlink` could return a virtual length over host-path bytes.

Directory enumeration is always treated as a read. A read-only bind therefore remains listable when the underlying Android UID may list the source. Android host permissions remain authoritative; for example, many Termux app UIDs cannot enumerate `/`, so `--ro-bind / / -- ls /` is expected to preserve that host denial. Python on an RW bind can create `__pycache__`; Python on an RO bind can import normally but cannot mutate that bind.

## Implemented semantics

- `--ro-bind SRC DST`: real syscall-policy read-only semantics. Path mutations return `EROFS`.
- `--bind SRC DST`: writable virtual bind.
- Hidden-by-default virtual root with longest-prefix nested binds.
- Virtual symlink resolution: absolute symlinks restart at virtual `/`, preventing host-root escape.
- Path mediation for open/create/truncate, unlink/rmdir, rename, hard/symbolic links, mkdir/mknod, chmod/chown, timestamps, xattrs, `statfs`, inotify watches, exec, cwd changes, and FD-based mutations such as `fallocate`.
- Direct raw syscalls are mediated; libc interposition is not part of the trust model.
- Descendants remain traced across fork/clone/exec.
- `getcwd()` and relevant `readlink()` results are translated back to virtual paths.
- `--tmpfs`/`--dir` use private ephemeral disk-backed directories removed at exit.
- Inherited FDs >2 are closed unless `--preserve-fd` is used.
- Mount APIs, `chroot`, `pivot_root`, `setns`, `unshare`, `open_by_handle_at`, `io_uring_setup`, `pidfd_getfd`, tracee `ptrace`, cross-process `process_vm_*`, and clone requests using `CLONE_UNTRACED` or namespace-creation flags are blocked to protect the supervisor/path policy.

### Virtual `/proc` (`--proc DST`)

`--proc` no longer exposes the host proc root directly. It creates a hybrid virtual proc view:

- proc root enumeration contains common global entries plus only sandbox process IDs;
- `self` / `thread-self` are dynamic;
- `root`, `cwd`, `exe`, `fd/N`, and `map_files/*` are treated as magic links and checked against the virtual filesystem policy;
- `/proc/self/maps` and `smaps` rewrite host backing paths to virtual paths and hide unmapped ones;
- `mounts`, `mountinfo`, and `mountstats` are generated from the virtual bind table;
- `status` hides the ptrace supervisor by reporting `TracerPid: 0`;
- relative `openat()` from a proc directory FD is reverse-mapped back into virtual proc semantics;
- proc writes are `EROFS`, except legitimate magic-link reopening of an explicitly RW sandbox object or an already-held non-filesystem FD such as stdout.

PIDs remain real host PIDs; this is **not** a PID namespace emulator. See [docs/PROCFS.md](docs/PROCFS.md).

## Quick start

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

mkdir -p demo
printf 'original\n' > demo/a.txt

build/abwrap \
  --ro-bind /bin /bin \
  --ro-bind /usr/bin /usr/bin \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind "$PWD/demo" /work \
  --proc /proc \
  -- /bin/sh -c 'cat /proc/self/status | head; echo bad > /work/a.txt'
```

Writable bind:

```bash
build/abwrap --ro-bind / / --bind "$PWD/demo" /work --proc /proc -- \
  /bin/sh -c 'echo ok > /work/a.txt'
```

## Android / Termux

NDK cross-build:

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
./scripts/build-android.sh arm64-v8a
```

3.0.2 fixed a Termux-only non-root regression in the synthetic `/proc` backing. 3.0.3 adds the arm64 syscall-number fix described above and changes device diagnostics to compare Android host-root access with sandbox access instead of assuming `/` must be enumerable.

Native Termux build **with unit tests**:

```bash
pkg install clang cmake ninja python bash coreutils findutils grep
./scripts/build-termux-native.sh
ctest --test-dir build-termux --output-on-failure
```

For a device report that can be sent back unchanged, run:

```bash
./scripts/termux-test.sh
```

This rebuilds `abwrap` plus the native C unit/probe binaries, then runs the Termux diagnostics suite. A single log is written under `logs/termux-diagnostics-*.log`. The report intentionally does not dump the process environment, so unrelated tokens/keys are not copied into the log. By default it exercises `auto`, explicit `seccomp`, and explicit `ptrace` backends; an unsupported explicit backend is reported as a failed diagnostic while the rest of the suite continues.

The device suite includes real script-file workloads rather than only `bash -c`/`python -c`: Bash directory listing, `cat`, pipelines, redirection, functions, subshells, `source`, child Bash, temp files and RO-write failure; Python directory traversal, ordinary file/rename/symlink operations, `tempfile`, shared-extension imports (`ssl`/`sqlite3`), subprocess, `/proc/self/fd`, RW `__pycache__` creation, and successful import without bytecode mutation on an RO bind. Python cases are also run independently so one failure does not mask later bytecode/subprocess checks. Every denied RO write with a meaningful host-side effect has a corresponding host-integrity assertion.

Typical run:

```bash
build-termux/abwrap --android-base \
  --bind "$HOME/project" /work \
  --chdir /work \
  -- "$PREFIX/bin/python" script.py
```

`--android-base` exposes existing Android runtime paths (`/system`, `/apex`, `/vendor`, `/product`, `/odm`, `/dev`, `$PREFIX`), enables the virtual `/proc`, and creates an ephemeral `/tmp`.

See [docs/ANDROID.md](docs/ANDROID.md) and [docs/ANDROID_REGRESSIONS.md](docs/ANDROID_REGRESSIONS.md).

## Tests

```bash
./scripts/run-tests.sh
```

The host integration suite covers the original scenarios plus regressions for broad root-bind `/proc/self/fd` handling, writable special endpoints such as `/dev/null` under an RO root, and true host integrity after denied raw syscalls. Native Termux testing additionally compiles `arch_unit_test`, `policy_unit_test`, and the raw/openat/filesystem syscall probes, then runs common Bash/Python workloads through the actual device linker/runtime. Root listing is checked as host-permission parity; `$PREFIX` is used as the positive RO-directory-enumeration case.

Warning-clean builds:

```bash
cmake -S . -B build-gcc -DABW_ENABLE_WERROR=ON -DBUILD_TESTING=ON -DCMAKE_C_COMPILER=gcc
cmake --build build-gcc -j && ctest --test-dir build-gcc --output-on-failure

cmake -S . -B build-clang -DABW_ENABLE_WERROR=ON -DBUILD_TESTING=ON -DCMAKE_C_COMPILER=clang
cmake --build build-clang -j && ctest --test-dir build-clang --output-on-failure
```

## Compatibility boundary

`abwrap` is a **filesystem/process userland sandbox**, not a kernel namespace emulator. It does not claim PID/IPC/UTS/network namespace isolation, UID remapping, cgroups, Binder isolation, or kernel mount flags. Namespace-related bwrap flags are accepted as compatibility no-ops so callers can share argument construction; they are silent by default and reported only with `--verbose`.

Android's existing UID, SELinux, seccomp, and procfs restrictions stay authoritative. If the kernel/OEM blocks an operation the supervisor needs, abwrap fails closed rather than bypassing the platform restriction.

Details: [ARCHITECTURE](docs/ARCHITECTURE.md), [PROCFS](docs/PROCFS.md), [COMPATIBILITY](docs/COMPATIBILITY.md), [SECURITY](docs/SECURITY.md), [PERFORMANCE](docs/PERFORMANCE.md).

## Supported architectures

- Android/Linux `aarch64`
- Linux/Android `x86_64`

32-bit ARM is not included because it requires a separately tested register/syscall ABI backend.

## License

MIT. No Bubblewrap or PRoot source files are included or copied; public behavior and documentation are design references only.
