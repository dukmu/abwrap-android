# bwrap compatibility matrix

The target is practical CLI compatibility for userland tools when kernel namespace facilities are unavailable.

| Option | Status | Semantics |
|---|---|---|
| `--ro-bind SRC DST` | implemented | virtual bind; mutations return `EROFS` |
| `--ro-bind-try SRC DST` | implemented | missing source ignored |
| `--bind SRC DST` | implemented | writable virtual bind |
| `--bind-try SRC DST` | implemented | missing source ignored |
| `--dev-bind SRC DST` | implemented | writable bind alias |
| `--dev-bind-try SRC DST` | implemented | missing source ignored |
| `--tmpfs DST` | compatible | private ephemeral disk-backed RW directory |
| `--dir DST` | compatible | ephemeral RW directory |
| `--symlink TARGET DST` | implemented | synthetic virtual symlink |
| `--proc DST` | implemented/hybrid | synthetic proc root + controlled host-backed nodes + generated views |
| `--dev DST` | compatible | host `/dev` exposed RO; Android SELinux remains authoritative |
| `--chdir DIR` | implemented | virtual cwd; `getcwd()` translated |
| `--clearenv` | implemented | environment cleared before exec |
| `--setenv`, `--unsetenv` | implemented | environment update |
| `--argv0` | implemented | initial `argv[0]` override |
| `--preserve-fd N` | implemented | preserve selected inherited FD >2 |
| `--die-with-parent` | implemented | `PR_SET_PDEATHSIG=SIGKILL` |
| `--new-session` | implemented | `setsid()` |
| `--unshare-*` | accepted; verbose notice | no namespace creation; tracee `unshare()` is blocked |
| `--share-net` | accepted; verbose notice | network unchanged |
| `--uid`, `--gid` | accepted; verbose notice | no UID/GID remap |
| `--hostname` | accepted; verbose notice | no UTS namespace |
| `--cap-add`, `--cap-drop` | accepted; verbose notice | Android app capability set unchanged |
| `--seccomp FD` | rejected | arbitrary caller BPF cannot be safely merged with internal tracing policy |
| `--file`, `--bind-data`, `--ro-bind-data` | rejected | FD-backed synthetic-file interface not implemented |

## Executables

Android dynamic ELF files normally use `/system/bin/linker` or `/system/bin/linker64`; `--android-base` exposes standard runtime paths. The kernel resolves `PT_INTERP` and absolute shebang interpreters before userland gets another pathname syscall, so a completely foreign rootfs whose interpreter exists only at a remapped virtual path is outside the current model. Invoking the interpreter explicitly remains a practical workaround.

## `/proc`

`--proc` implements a hybrid virtual procfs rather than a direct host bind. Root PID enumeration is limited to traced sandbox processes; path-bearing magic links are policy-checked; `maps/smaps`, mount views, and `TracerPid` are sanitized. CPU/memory/cgroup/network values are still host values visible to the Android app. PIDs are not renumbered. See `docs/PROCFS.md`.

## File descriptors

FDs >2 are closed before sandbox entry unless explicitly preserved. Existing FDs are capabilities: direct `read/write` remains possible because the caller deliberately handed the descriptor to the child. `/proc/self/fd/N` cannot be used to convert a hidden host-file FD into an unrestricted pathname. Reopening a visible FD respects the matched bind's RO/RW mode.

## Kernel-generated path semantics

`getcwd`, selected `readlink`, proc `maps/smaps`, and proc mount tables are virtualized. Other kernel interfaces that encode host topology but are not filesystem capabilities may still expose host-level identifiers (for example real PIDs, cgroup paths, inode/device numbers, or some fdinfo fields).
