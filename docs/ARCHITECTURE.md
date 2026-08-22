# Architecture

## Components

`abwrap` is split into focused subsystems:

- **CLI / policy builder** (`src/main.c`): parses the bwrap-compatible subset, builds binds, environment/cwd, ephemeral storage, and starts the tracee.
- **Virtual path resolver** (`src/policy.c`): path normalization, longest-prefix binds, virtual symlink walking, RO/RW mode, host↔virtual reverse mapping.
- **Virtual proc layer** (`src/procfs.c`): synthetic proc root, sandbox-PID visibility, proc magic links, path sanitization, generated mount/status views, proc dirfd reverse mapping.
- **Selective trap filter** (`src/seccomp_filter.c`): `SECCOMP_RET_TRACE` for filesystem and supervisor-integrity syscalls only.
- **Architecture / remote-memory layer** (`src/arch.c`, `src/remote.c`): Android/aarch64 tagged-address handling, architecture-specific syscall-number override, and tracee memory transport.
- **Supervisor** (`src/tracer.c`): syscall argument rewriting, error/emulated-return injection, clone/fork/exec tracking, output post-processing.

No preload library is part of the enforcement path.

## Backing layout

Each run creates a private host session directory:

```text
session/
├── rootfs/        # physical skeleton backing virtual /
└── internal/      # never part of virtual root
    ├── ephemeral/ # --tmpfs/--dir backing
    ├── procroot/  # synthetic /proc root directory
    └── procgen/   # generated maps/mount/status snapshots
```

The implicit virtual `/` rule points at `rootfs/`, not at the session directory. Internal paths are additionally rejected by host→virtual reverse mapping unless they belong to an explicit synthetic rule (for example the backing of `/tmp` or the proc root). This keeps supervisor state inaccessible even under broad user binds.

## Selective fast path

```text
application
  |
  | futex/read/write/math/socket/timer/...
  +----------------------------------------> kernel
  |
  | openat/statx/rename/readlink/exec/...
  v
seccomp SECCOMP_RET_TRACE
  |
  v
abwrap supervisor
  | virtual path normalization
  | bind + symlink/proc resolution
  | RO/RW / magic-link checks
  | rewrite pathname in tracee memory
  v
kernel syscall
```

Only operations needing mediation stop in the supervisor in the preferred backend. Some emulated outputs require one syscall-exit stop to patch the return value.

## Read-only enforcement

Examples:

- `open/openat/openat2`: `O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, or a complete `O_TMPFILE` request requires RW policy.
- `unlink/rmdir/rename/link/symlink/mkdir/mknod`: mutation destination must be RW; rename/hard-link source is checked as well.
- `truncate/chmod/chown/utimensat`, path xattr mutation: RW required.
- `ftruncate/fallocate/fchmod/fchown/fsetxattr/fremovexattr`: FD target is reverse-mapped to its virtual bind before mutation.
- `statfs`, xattr reads, `inotify_add_watch`, and `name_to_handle_at` are path-mediated so hidden host paths cannot be used as an information oracle.
- bind mountpoint removal returns `EBUSY`.

The `O_TMPFILE` test checks the full flag pattern so `O_DIRECTORY` alone remains a read operation.

## Proc path model

The proc root is synthetic, so `getdents` cannot enumerate unrelated host PIDs. When a tracee opens a selected proc node, the supervisor may:

1. map it to a controlled real `/proc/<sandbox-pid>/...` node;
2. resolve a magic link (`root/cwd/exe/fd/map_files`) through virtual filesystem policy;
3. generate a sanitized snapshot (`maps`, `smaps`, `mount*`, `status`);
4. deny it if the PID/FD/path cannot be proven visible.

Host proc directory FDs are reverse-translated back to virtual proc paths, preserving `openat(dirfd, ...)` behavior.

## Tracee memory rewrite

Translated paths are written to bounded scratch space below the tracee stack pointer using `process_vm_writev` when available and `PTRACE_POKEDATA` fallback otherwise. The tracee SP itself is not changed. All injected strings are bounded by `PATH_MAX`.

For emulated proc `readlink()` operations, the supervisor writes the virtual result directly to the tracee buffer, replaces the syscall number with an invalid one, then patches the syscall return value at the exit stop. On aarch64, replacing an in-flight syscall requires the dedicated `NT_ARM_SYSTEM_CALL` ptrace regset; changing `x8` alone is not used as the enforcement mechanism.

## Process inheritance

`PTRACE_O_TRACECLONE`, `PTRACE_O_TRACEFORK`, `PTRACE_O_TRACEVFORK`, and `PTRACE_O_TRACEEXEC` keep descendants under one policy. `clone/clone3` requests using `CLONE_UNTRACED` or namespace-creation flags are rejected before execution. TGIDs are tracked separately from TIDs so proc root enumeration follows process rather than thread IDs. `PTRACE_O_EXITKILL` is requested when supported.

## Fallback backend

If the child cannot install the additive seccomp filter, `--backend auto` falls back to `PTRACE_SYSCALL`. The policy engine and proc behavior are the same, but every syscall incurs ptrace entry/exit stops.

## Ephemeral directories

`--tmpfs` is disk-backed because an unprivileged Android app generally cannot mount tmpfs. It gives private lifetime/visibility semantics, not tmpfs memory accounting or mount flags. The entire session tree is removed when the supervisor exits.
