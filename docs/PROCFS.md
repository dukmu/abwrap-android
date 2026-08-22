# Virtual `/proc` design

`--proc DST` creates a **hybrid virtual procfs view**. It does not mount a new procfs and it does not claim PID-namespace semantics. The goal is to preserve the proc interfaces ordinary userland programs expect while preventing procfs from becoming a path-policy bypass or a source of host backing-path leaks.

## Root and PID visibility

The proc root (`DST`) is a synthetic directory stored outside the virtual root backing tree. It contains common global proc entries plus only process IDs observed in the traced sandbox process tree. Unrelated host PIDs are therefore not enumerable through `readdir/getdents` on the sandbox proc root.

PIDs are still real host PIDs. `/proc/self/status`, `stat`, signals, `wait*`, and other PID-bearing interfaces are **not renumbered**. This is intentionally different from `CLONE_NEWPID`.

`self` and `thread-self` are handled dynamically per tracee. `readlink()` returns the current TGID and `TGID/task/TID` respectively.

## Host-backed read-only nodes

Most global proc nodes and ordinary per-process nodes are forwarded to the real host procfs after access control. Android's SELinux, hidepid-style restrictions, and procfs permissions remain authoritative.

Writes to proc nodes are rejected with `EROFS`, except when the path is a proc magic link that resolves to an explicitly writable sandbox object (for example `/proc/self/fd/N` referring to a file under a `--bind` RW tree). Reopening stdout through `/proc/self/fd/1` remains compatible.

## Magic links

The following are treated as capabilities, not ordinary symlinks:

- `/proc/self/root`
- `/proc/self/cwd`
- `/proc/self/exe`
- `/proc/<sandbox-pid>/...` equivalents
- `/proc/*/fd/N`
- `/proc/*/map_files/*`

`root` is resolved against the virtual `/`; `cwd` and `exe` are reverse-mapped back into the virtual namespace; `fd/N` and `map_files/*` are reopened only after the target is proven to be visible under the sandbox policy. An inherited descriptor pointing at a hidden host file can still be used as that descriptor, but it cannot be converted back into an unrestricted pathname via `/proc/self/fd/N`.

Absolute magic-link targets that cannot be reverse-mapped are reported as unavailable rather than exposing the supervisor's host path.

## Generated views

Some kernel-generated files are replaced with snapshots:

- `maps`, `smaps`: visible host paths are translated back to virtual paths; unmapped pathnames become `[abwrap-hidden]`.
- `mounts`, `mountinfo`, `mountstats`: generated from the virtual bind table, so host backing directories are not disclosed.
- `status`: copied from the real proc entry with `TracerPid` rewritten to `0`, preventing the ptrace supervisor from looking like an application debugger.

Synthetic mount IDs are compatibility IDs, not host kernel mount IDs. Therefore an application that correlates `fdinfo:mnt_id` with kernel mount IDs may observe a difference.

## Directory-FD semantics

Programs frequently do:

```c
int d = open("/proc/self", O_RDONLY | O_DIRECTORY);
openat(d, "status", O_RDONLY);
```

The supervisor reverse-maps host proc directory FDs back to the virtual proc namespace, so relative `openat/statx/readlinkat/...` continue through the same policy.

## Known semantic differences

- No PID namespace or PID renumbering.
- `lstat()` metadata for synthetic `self`/`thread-self` entries may not exactly match a kernel procfs symlink on every path; `readlink()` semantics are virtualized explicitly.
- Global proc values such as CPU, memory, uptime, cgroups, and network state describe the host environment visible to the Android app; they are not resource-namespace emulations.
- `maps/smaps/status` snapshots require the supervisor to read `/proc/<tracee>/...`. If an OEM SELinux policy blocks that even for the ptracing parent, the operation fails closed.
- `/proc/<pid>/fd` visibility is needed for robust `*at(dirfd, ...)` and FD mutation enforcement. OEM kernels that hide it can reduce compatibility; the sandbox does not bypass that restriction.
