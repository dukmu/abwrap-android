# Design references

This repository is implemented from scratch. No source code from Bubblewrap or PRoot is vendored or copied.

Public behavior/documentation used while designing the interface and constraints:

- Bubblewrap project: https://github.com/containers/bubblewrap
- PRoot project: https://github.com/proot-me/proot
- Android Application Sandbox: https://source.android.com/docs/security/app-sandbox
- AOSP SELinux policy (`untrusted_app_all.te`, `app_neverallows.te`): https://android.googlesource.com/platform/system/sepolicy/
- Android bionic dynamic linker: https://android.googlesource.com/platform/bionic/
- Linux seccomp userspace API: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html

The key architectural departure is selective `SECCOMP_RET_TRACE`: only filesystem-sensitive syscalls enter ptrace in the fast backend.
