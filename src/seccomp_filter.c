#define _GNU_SOURCE
#include "abwrap/seccomp_filter.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#ifndef SECCOMP_RET_TRACE
#define SECCOMP_RET_TRACE 0x7ff00000U
#endif

#define STMT(code, k) ((struct sock_filter)BPF_STMT((code), (k)))
#define JUMP(code, k, jt, jf) ((struct sock_filter)BPF_JUMP((code), (k), (jt), (jf)))
#define TRACE_SYSCALL(nr) \
    JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE)

int abw_install_trace_filter(void) {
    struct sock_filter filter[] = {
        STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#ifdef SYS_open
        TRACE_SYSCALL(SYS_open),
#endif
#ifdef SYS_openat
        TRACE_SYSCALL(SYS_openat),
#endif
#ifdef SYS_openat2
        TRACE_SYSCALL(SYS_openat2),
#endif
#ifdef SYS_creat
        TRACE_SYSCALL(SYS_creat),
#endif
#ifdef SYS_stat
        TRACE_SYSCALL(SYS_stat),
#endif
#ifdef SYS_lstat
        TRACE_SYSCALL(SYS_lstat),
#endif
#ifdef SYS_newfstatat
        TRACE_SYSCALL(SYS_newfstatat),
#endif
#ifdef SYS_statx
        TRACE_SYSCALL(SYS_statx),
#endif
#ifdef SYS_statfs
        TRACE_SYSCALL(SYS_statfs),
#endif
#ifdef SYS_faccessat
        TRACE_SYSCALL(SYS_faccessat),
#endif
#ifdef SYS_faccessat2
        TRACE_SYSCALL(SYS_faccessat2),
#endif
#ifdef SYS_access
        TRACE_SYSCALL(SYS_access),
#endif
#ifdef SYS_readlink
        TRACE_SYSCALL(SYS_readlink),
#endif
#ifdef SYS_readlinkat
        TRACE_SYSCALL(SYS_readlinkat),
#endif
#ifdef SYS_getxattr
        TRACE_SYSCALL(SYS_getxattr),
#endif
#ifdef SYS_lgetxattr
        TRACE_SYSCALL(SYS_lgetxattr),
#endif
#ifdef SYS_listxattr
        TRACE_SYSCALL(SYS_listxattr),
#endif
#ifdef SYS_llistxattr
        TRACE_SYSCALL(SYS_llistxattr),
#endif
#ifdef SYS_setxattr
        TRACE_SYSCALL(SYS_setxattr),
#endif
#ifdef SYS_lsetxattr
        TRACE_SYSCALL(SYS_lsetxattr),
#endif
#ifdef SYS_removexattr
        TRACE_SYSCALL(SYS_removexattr),
#endif
#ifdef SYS_lremovexattr
        TRACE_SYSCALL(SYS_lremovexattr),
#endif
#ifdef SYS_inotify_add_watch
        TRACE_SYSCALL(SYS_inotify_add_watch),
#endif
#ifdef SYS_name_to_handle_at
        TRACE_SYSCALL(SYS_name_to_handle_at),
#endif
#ifdef SYS_clone
        TRACE_SYSCALL(SYS_clone),
#endif
#ifdef SYS_clone3
        TRACE_SYSCALL(SYS_clone3),
#endif
#ifdef SYS_execve
        TRACE_SYSCALL(SYS_execve),
#endif
#ifdef SYS_execveat
        TRACE_SYSCALL(SYS_execveat),
#endif
#ifdef SYS_chdir
        TRACE_SYSCALL(SYS_chdir),
#endif
#ifdef SYS_fchdir
        TRACE_SYSCALL(SYS_fchdir),
#endif
#ifdef SYS_getcwd
        TRACE_SYSCALL(SYS_getcwd),
#endif
#ifdef SYS_chroot
        TRACE_SYSCALL(SYS_chroot),
#endif
#ifdef SYS_unlink
        TRACE_SYSCALL(SYS_unlink),
#endif
#ifdef SYS_unlinkat
        TRACE_SYSCALL(SYS_unlinkat),
#endif
#ifdef SYS_rename
        TRACE_SYSCALL(SYS_rename),
#endif
#ifdef SYS_renameat
        TRACE_SYSCALL(SYS_renameat),
#endif
#ifdef SYS_renameat2
        TRACE_SYSCALL(SYS_renameat2),
#endif
#ifdef SYS_mkdir
        TRACE_SYSCALL(SYS_mkdir),
#endif
#ifdef SYS_mkdirat
        TRACE_SYSCALL(SYS_mkdirat),
#endif
#ifdef SYS_rmdir
        TRACE_SYSCALL(SYS_rmdir),
#endif
#ifdef SYS_link
        TRACE_SYSCALL(SYS_link),
#endif
#ifdef SYS_linkat
        TRACE_SYSCALL(SYS_linkat),
#endif
#ifdef SYS_symlink
        TRACE_SYSCALL(SYS_symlink),
#endif
#ifdef SYS_symlinkat
        TRACE_SYSCALL(SYS_symlinkat),
#endif
#ifdef SYS_truncate
        TRACE_SYSCALL(SYS_truncate),
#endif
#ifdef SYS_ftruncate
        TRACE_SYSCALL(SYS_ftruncate),
#endif
#ifdef SYS_chmod
        TRACE_SYSCALL(SYS_chmod),
#endif
#ifdef SYS_fchmod
        TRACE_SYSCALL(SYS_fchmod),
#endif
#ifdef SYS_fchmodat
        TRACE_SYSCALL(SYS_fchmodat),
#endif
#ifdef SYS_fchmodat2
        TRACE_SYSCALL(SYS_fchmodat2),
#endif
#ifdef SYS_chown
        TRACE_SYSCALL(SYS_chown),
#endif
#ifdef SYS_lchown
        TRACE_SYSCALL(SYS_lchown),
#endif
#ifdef SYS_fchown
        TRACE_SYSCALL(SYS_fchown),
#endif
#ifdef SYS_fchownat
        TRACE_SYSCALL(SYS_fchownat),
#endif
#ifdef SYS_fsetxattr
        TRACE_SYSCALL(SYS_fsetxattr),
#endif
#ifdef SYS_fremovexattr
        TRACE_SYSCALL(SYS_fremovexattr),
#endif
#ifdef SYS_fallocate
        TRACE_SYSCALL(SYS_fallocate),
#endif
#ifdef SYS_utime
        TRACE_SYSCALL(SYS_utime),
#endif
#ifdef SYS_utimes
        TRACE_SYSCALL(SYS_utimes),
#endif
#ifdef SYS_futimesat
        TRACE_SYSCALL(SYS_futimesat),
#endif
#ifdef SYS_utimensat
        TRACE_SYSCALL(SYS_utimensat),
#endif
#ifdef SYS_mknod
        TRACE_SYSCALL(SYS_mknod),
#endif
#ifdef SYS_mknodat
        TRACE_SYSCALL(SYS_mknodat),
#endif
#ifdef SYS_mount
        TRACE_SYSCALL(SYS_mount),
#endif
#ifdef SYS_umount2
        TRACE_SYSCALL(SYS_umount2),
#endif
#ifdef SYS_pivot_root
        TRACE_SYSCALL(SYS_pivot_root),
#endif
#ifdef SYS_open_by_handle_at
        TRACE_SYSCALL(SYS_open_by_handle_at),
#endif
#ifdef SYS_io_uring_setup
        TRACE_SYSCALL(SYS_io_uring_setup),
#endif
#ifdef SYS_fsopen
        TRACE_SYSCALL(SYS_fsopen),
#endif
#ifdef SYS_fspick
        TRACE_SYSCALL(SYS_fspick),
#endif
#ifdef SYS_open_tree
        TRACE_SYSCALL(SYS_open_tree),
#endif
#ifdef SYS_move_mount
        TRACE_SYSCALL(SYS_move_mount),
#endif
#ifdef SYS_mount_setattr
        TRACE_SYSCALL(SYS_mount_setattr),
#endif
#ifdef SYS_pidfd_getfd
        TRACE_SYSCALL(SYS_pidfd_getfd),
#endif
#ifdef SYS_setns
        TRACE_SYSCALL(SYS_setns),
#endif
#ifdef SYS_unshare
        TRACE_SYSCALL(SYS_unshare),
#endif
#ifdef SYS_ptrace
        TRACE_SYSCALL(SYS_ptrace),
#endif
#ifdef SYS_process_vm_readv
        TRACE_SYSCALL(SYS_process_vm_readv),
#endif
#ifdef SYS_process_vm_writev
        TRACE_SYSCALL(SYS_process_vm_writev),
#endif
#ifdef SYS_fanotify_init
        TRACE_SYSCALL(SYS_fanotify_init),
#endif
#ifdef SYS_fanotify_mark
        TRACE_SYSCALL(SYS_fanotify_mark),
#endif
#ifdef SYS_fsconfig
        TRACE_SYSCALL(SYS_fsconfig),
#endif
#ifdef SYS_fsmount
        TRACE_SYSCALL(SYS_fsmount),
#endif
#ifdef SYS_statmount
        TRACE_SYSCALL(SYS_statmount),
#endif
#ifdef SYS_listmount
        TRACE_SYSCALL(SYS_listmount),
#endif
        STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -errno;
#ifdef SYS_seccomp
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0) return -errno;
#else
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) return -errno;
#endif
    return 0;
}
