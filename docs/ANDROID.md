# Android build and deployment

## NDK cross-build

Recommended baseline: API 26+.

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
./scripts/build-android.sh arm64-v8a
```

Optional API override:

```bash
ANDROID_API=28 ./scripts/build-android.sh arm64-v8a
```

x86_64 emulator build:

```bash
./scripts/build-android.sh x86_64
```

Output is under `build-android/<abi>/abwrap` unless `BUILD_DIR` is set.

## Termux native build and tests

```bash
pkg install clang cmake ninja python bash coreutils findutils grep
./scripts/build-termux-native.sh
ctest --test-dir build-termux --output-on-failure
```

For the full device compatibility report:

```bash
./scripts/termux-test.sh
```

A sanitized log is written to `logs/termux-diagnostics-*.log`. It records platform/tool versions, each command, stdout/stderr and exit status, but does not dump the full environment.

Typical invocation:

```bash
build-termux/abwrap --android-base \
  --bind "$HOME/work" /work \
  --chdir /work \
  -- "$PREFIX/bin/python" script.py
```

`--android-base` binds existing Android runtime paths read-only, enables virtual `/proc`, binds `$PREFIX` read-only when present, and creates an ephemeral writable `/tmp`.

## Regular APK embedding

Two Android constraints are separate from abwrap's filesystem policy:

1. The app must be allowed to ptrace its own descendants. AOSP normally supports debugger-style same-app tracing, but vendor SELinux policy can differ.
2. Modern Android restricts executing arbitrary writable `app_data_file` content. Package native executables in an executable-labeled APK/native-library location or use another platform-supported execution path; do not assume a binary copied to `filesDir` can be `execve()`'d.

The session backing directory stores data only and does not need executable permission.

## Startup capability behavior

- `PTRACE_TRACEME` failure: startup fails.
- `--backend auto`: try selective seccomp tracing, then ptrace fallback.
- `--backend seccomp`: fail if additive filter installation is rejected.
- `--backend ptrace`: force all-syscall tracing for compatibility/debugging.
- `--verbose`: prints selected backend/session diagnostics.

## Proc/OEM requirements

The virtual proc implementation intentionally does not bypass Android proc restrictions. For best compatibility the ptracing parent needs access to its tracees' `/proc/<pid>/cwd`, `/proc/<pid>/fd`, and (for sanitized snapshots) files such as `maps`, `smaps`, and `status`.

If an OEM policy blocks these:

- hidden/relative dirfd mapping can fail closed;
- FD-based RO checks can fail closed;
- generated proc snapshots can be unavailable.

Global proc nodes still remain subject to Android SELinux and file permissions.

## Kernel assumptions

No dependency on user namespaces, mount namespaces, Landlock, FUSE, root capabilities, or privileged mounts. Required basics are normal process creation/exec, descendant ptrace, register access, and sufficient same-process proc visibility. Additive seccomp-BPF is optional because ptrace fallback exists.
