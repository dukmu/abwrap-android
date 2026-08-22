# Security model and limitations

## Intended use

`abwrap` confines **user-run tools, interpreters, build steps, plugins, agents, and command-line applications** when Android does not provide usable mount/user namespaces to the caller. It complements Android's app sandbox; it is not a replacement for Android UID/SELinux isolation.

## Filesystem guarantee

Subject to explicitly inherited/passed file-descriptor capabilities, path-based filesystem access is limited to configured virtual binds and synthetic directories. A read-only bind is enforced at the syscall-policy layer before the translated host path reaches the kernel.

Absolute and relative symlinks are resolved in virtual namespace semantics. Internal session backing is stored outside the virtual root backing tree and is explicitly excluded from reverse mapping, including when a broad host bind such as `--ro-bind / /` exists.

## `/proc` guarantee

`--proc` uses a synthetic root rather than exposing host `/proc` directly. Unrelated host PIDs are not enumerable from the proc root. `root/cwd/exe/fd/map_files` magic links are validated against the same virtual path policy. Generated `maps/smaps` and mount views do not disclose private session backing paths.

This does not create PID/resource namespaces. Real host PIDs and host resource values remain visible where the corresponding proc interface is intentionally exposed.

## Blocked bypass/integrity primitives

The tracee is denied:

- `mount`, `umount2`, `pivot_root`, `chroot`;
- new mount API calls (`fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`, `move_mount`, `mount_setattr`, `statmount`, `listmount`) when present;
- `setns`, `unshare`, and `clone/clone3` requests using `CLONE_UNTRACED` or namespace-creation flags;
- `open_by_handle_at`;
- `io_uring_setup` (avoids asynchronous filesystem operations outside the pathname mediation path);
- `pidfd_getfd`;
- `fanotify_init/fanotify_mark` (fanotify cannot be constrained to the virtual path policy reliably);
- tracee `ptrace` and cross-process `process_vm_readv/process_vm_writev` (protects the supervisor and avoids importing/manipulating outside process capabilities).

Path-observing interfaces that can bypass ordinary `openat` mediation are also covered: xattr path operations, `statfs`, `inotify_add_watch`, and `name_to_handle_at`. FD mutations such as `fallocate`, `fsetxattr`, and `fremovexattr` are checked against the bind's RO/RW mode.

Inherited FDs >2 are closed by default.

## Existing descriptors and IPC

An inherited descriptor is already a capability. `abwrap` does not revoke the ability to `read/write` that descriptor. It prevents hidden filesystem descriptors from being reopened as unrestricted paths through proc magic links. A deliberately cooperating same-UID process that sends new FDs over an explicitly exposed Unix socket remains outside the filesystem-only threat model.

## Fail-closed behavior

Path translation failures, unavailable reverse mappings, failed tracee-memory access, invisible proc PID targets, and blocked FD reverse mapping produce syscall errors. The tool does not retry the original untranslated host pathname.

If ptrace cannot initialize, startup fails. `--backend seccomp` fails if the selective filter cannot be installed; `auto` may fall back to all-syscall ptrace.

## Out of scope

- PID, IPC, UTS, user, cgroup, or network namespace emulation;
- network filtering;
- Binder/service isolation beyond Android's platform policy;
- defense against kernel/ptrace/seccomp vulnerabilities;
- revocation of deliberately inherited stdio or explicitly preserved FDs;
- hostile same-UID peers when the sandboxed program is deliberately given an FD-passing IPC channel.
