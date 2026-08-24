#define _GNU_SOURCE
#include "abwrap/tracer.h"
#include "abwrap/arch.h"
#include "abwrap/remote.h"
#include "abwrap/procfs.h"
#include "abwrap/util.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#include <sys/user.h>
#elif defined(__aarch64__)
#include <elf.h>
#else
#error "abwrap currently supports x86_64 and aarch64"
#endif

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef PTRACE_O_EXITKILL
#define PTRACE_O_EXITKILL (1 << 20)
#endif
#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP (1 << PTRACE_EVENT_SECCOMP)
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef AT_SYMLINK_FOLLOW
#define AT_SYMLINK_FOLLOW 0x400
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000
#endif
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef IN_DONT_FOLLOW
#define IN_DONT_FOLLOW 0x02000000
#endif

struct abw_open_how {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

typedef struct {
#if defined(__x86_64__)
    struct user_regs_struct raw;
#elif defined(__aarch64__)
    struct {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } raw;
#endif
} abw_regs_t;

typedef enum { POST_NONE = 0, POST_GETCWD, POST_READLINK } post_kind_t;

typedef struct trace_state {
    pid_t pid;
    pid_t tgid;
    bool in_syscall;
    int pending_errno;
    post_kind_t post_kind;
    uintptr_t post_buf;
    size_t post_size;
    bool pending_ret_valid;
    long pending_ret;
    bool syscall_nr_override_valid;
    long syscall_nr_override;
    struct trace_state *next;
} trace_state_t;

static trace_state_t *states;

static pid_t tracee_tgid(pid_t pid) {
    char path[128];
    if (snprintf(path, sizeof(path), "/proc/%d/status", pid) >= (int)sizeof(path)) return pid;
    FILE *f = fopen(path, "r");
    if (!f) return pid;
    char line[256];
    long value = pid;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "Tgid:%ld", &value) == 1) break;
    }
    fclose(f);
    return value > 0 ? (pid_t)value : pid;
}

static bool traced_pid_visible(pid_t pid, void *opaque) {
    (void)opaque;
    for (trace_state_t *s = states; s; s = s->next)
        if (s->pid == pid || s->tgid == pid) return true;
    return false;
}

static bool traced_tgid_present(pid_t tgid) {
    for (trace_state_t *s = states; s; s = s->next) if (s->tgid == tgid) return true;
    return false;
}

static trace_state_t *state_get(pid_t pid, bool create) {
    for (trace_state_t *s = states; s; s = s->next) if (s->pid == pid) return s;
    if (!create) return NULL;
    trace_state_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->pid = pid;
    s->tgid = tracee_tgid(pid);
    s->next = states;
    states = s;
    return s;
}

static void state_remove(pid_t pid) {
    trace_state_t **pp = &states;
    while (*pp) {
        if ((*pp)->pid == pid) {
            trace_state_t *old = *pp;
            *pp = old->next;
            free(old);
            return;
        }
        pp = &(*pp)->next;
    }
}

static int regs_get(pid_t pid, abw_regs_t *r) {
#if defined(__x86_64__)
    return ptrace(PTRACE_GETREGS, pid, 0, &r->raw) == 0 ? 0 : -errno;
#elif defined(__aarch64__)
    struct iovec io = {.iov_base = &r->raw, .iov_len = sizeof(r->raw)};
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0 ? 0 : -errno;
#endif
}

static int regs_set(pid_t pid, const abw_regs_t *r) {
#if defined(__x86_64__)
    return ptrace(PTRACE_SETREGS, pid, 0, &r->raw) == 0 ? 0 : -errno;
#elif defined(__aarch64__)
    struct iovec io = {.iov_base = (void *)&r->raw, .iov_len = sizeof(r->raw)};
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &io) == 0 ? 0 : -errno;
#endif
}

static long regs_nr(const abw_regs_t *r) {
#if defined(__x86_64__)
    return (long)r->raw.orig_rax;
#else
    return (long)r->raw.regs[8];
#endif
}

static void regs_set_nr(abw_regs_t *r, long nr) {
#if defined(__x86_64__)
    r->raw.orig_rax = (unsigned long)nr;
#else
    r->raw.regs[8] = (uint64_t)nr;
#endif
}

static void regs_request_syscall_nr(trace_state_t *st, abw_regs_t *r, long nr) {
    regs_set_nr(r, nr);
    st->syscall_nr_override_valid = true;
    st->syscall_nr_override = nr;
}

static int regs_commit_entry(pid_t pid, const abw_regs_t *r, trace_state_t *st) {
    int rc = regs_set(pid, r);
    if (rc != 0) return rc;
    if (!st->syscall_nr_override_valid) return 0;
    long nr = st->syscall_nr_override;
    st->syscall_nr_override_valid = false;
    return abw_arch_commit_syscall_nr(pid, nr);
}

static uint64_t regs_arg(const abw_regs_t *r, int n) {
#if defined(__x86_64__)
    switch (n) {
        case 0: return r->raw.rdi;
        case 1: return r->raw.rsi;
        case 2: return r->raw.rdx;
        case 3: return r->raw.r10;
        case 4: return r->raw.r8;
        case 5: return r->raw.r9;
        default: return 0;
    }
#else
    return n >= 0 && n < 6 ? r->raw.regs[n] : 0;
#endif
}

static void regs_set_arg(abw_regs_t *r, int n, uint64_t v) {
#if defined(__x86_64__)
    switch (n) {
        case 0: r->raw.rdi = v; break;
        case 1: r->raw.rsi = v; break;
        case 2: r->raw.rdx = v; break;
        case 3: r->raw.r10 = v; break;
        case 4: r->raw.r8 = v; break;
        case 5: r->raw.r9 = v; break;
    }
#else
    if (n >= 0 && n < 6) r->raw.regs[n] = v;
#endif
}

static uintptr_t regs_sp(const abw_regs_t *r) {
#if defined(__x86_64__)
    return (uintptr_t)r->raw.rsp;
#else
    return (uintptr_t)r->raw.sp;
#endif
}

static void regs_set_ret(abw_regs_t *r, long v) {
#if defined(__x86_64__)
    r->raw.rax = (unsigned long)v;
#else
    r->raw.regs[0] = (uint64_t)v;
#endif
}

static long regs_ret(const abw_regs_t *r) {
#if defined(__x86_64__)
    return (long)r->raw.rax;
#else
    return (long)r->raw.regs[0];
#endif
}

static int proc_link(pid_t pid, const char *kind, int fd, char out[PATH_MAX]) {
    char path[128];
    if (fd >= 0) snprintf(path, sizeof(path), "/proc/%d/%s/%d", pid, kind, fd);
    else snprintf(path, sizeof(path), "/proc/%d/%s", pid, kind);
    ssize_t n = readlink(path, out, PATH_MAX - 1);
    if (n < 0) return -errno;
    out[n] = '\0';
    char *deleted = strstr(out, " (deleted)");
    if (deleted) *deleted = '\0';
    return 0;
}

static int virtual_base_for_dirfd(pid_t pid, int dirfd, const abw_policy_t *policy, char out[PATH_MAX]) {
    char host[PATH_MAX];
    int rc;
    if (dirfd == AT_FDCWD) rc = proc_link(pid, "cwd", -1, host);
    else rc = proc_link(pid, "fd", dirfd, host);
    if (rc != 0) return rc;
    rc = abw_policy_reverse(policy, host, out);
    if (rc == 0) return 0;
    int pr = abw_procfs_reverse_host(policy, pid, host, traced_pid_visible, NULL, out);
    return pr > 0 ? 0 : (pr < 0 ? pr : rc);
}

static int remote_virtual_path(pid_t pid, uintptr_t ptr, int dirfd,
                               const abw_policy_t *policy, char out[PATH_MAX]) {
    char raw[PATH_MAX];
    int rc = abw_remote_read_string(pid, ptr, raw);
    if (rc != 0) return rc;
    if (raw[0] == '/') return abw_path_normalize(raw, out);
    char base[PATH_MAX];
    rc = virtual_base_for_dirfd(pid, dirfd, policy, base);
    if (rc != 0) return rc;
    return abw_virtual_abspath(base, raw, out);
}

static int write_scratch_path(pid_t pid, abw_regs_t *regs, int arg_index, int slot, const char *host_path) {
    size_t n = strlen(host_path) + 1;
    if (n > PATH_MAX) return -ENAMETOOLONG;
    uintptr_t sp = regs_sp(regs);
    uintptr_t base = (sp - (uintptr_t)(PATH_MAX * 3 + 1024)) & ~(uintptr_t)15;
    uintptr_t addr = base + (uintptr_t)slot * PATH_MAX;
    int rc = abw_remote_write(pid, addr, host_path, n);
    if (rc != 0) return rc;
    regs_set_arg(regs, arg_index, addr);
    return 0;
}

static int rewrite_path(pid_t pid, abw_regs_t *regs, int arg_index, int dirfd,
                        bool follow_final, bool allow_missing_final,
                        bool require_write, bool protect_mountpoint,
                        const abw_policy_t *policy, int slot,
                        abw_resolved_path_t *resolved_out) {
    char vpath[PATH_MAX];
    int rc = remote_virtual_path(pid, (uintptr_t)regs_arg(regs, arg_index), dirfd, policy, vpath);
    if (rc != 0) return rc;
    if (protect_mountpoint && abw_policy_is_mountpoint(policy, vpath)) return -EBUSY;
    abw_resolved_path_t resolved;
    memset(&resolved, 0, sizeof(resolved));
    abw_mode_t proc_mode = ABW_MODE_RO;
    char proc_host[PATH_MAX];
    int ph = abw_procfs_translate(policy, pid, vpath, follow_final, require_write,
                                  traced_pid_visible, NULL, proc_host, &proc_mode);
    if (ph < 0) return ph;
    if (ph > 0) {
        snprintf(resolved.virtual_path, sizeof(resolved.virtual_path), "%s", vpath);
        snprintf(resolved.host_path, sizeof(resolved.host_path), "%s", proc_host);
        resolved.mode = proc_mode;
        resolved.rule = NULL;
    } else {
        rc = abw_policy_resolve(policy, vpath, follow_final, allow_missing_final, &resolved);
        if (rc != 0) return rc;
        if (require_write && resolved.mode != ABW_MODE_RW) return -EROFS;
    }
    rc = write_scratch_path(pid, regs, arg_index, slot, resolved.host_path);
    if (rc != 0) return rc;
    if (resolved_out) *resolved_out = resolved;
    return 0;
}

static int fd_mode(pid_t pid, int fd, const abw_policy_t *policy, abw_mode_t *mode) {
    char host[PATH_MAX], virt[PATH_MAX];
    int rc = proc_link(pid, "fd", fd, host);
    if (rc != 0) return rc;
    char internal[PATH_MAX];
    if (snprintf(internal, sizeof(internal), "%s/internal", policy->session_root) < (int)sizeof(internal)) {
        const char *suffix = NULL;
        if (abw_path_prefix(internal, host, &suffix)) {
            /* Ephemeral (--tmpfs/--dir) backing files live under
             * session_root/internal/ephemeral and are legitimate RW targets
             * for the sandboxed process (e.g. futimens/futimesat on a file
             * created inside --tmpfs). Keep hard-blocking every other
             * internal path (session metadata, scratch, supervisor state). */
            char ephem[PATH_MAX];
            const char *ephem_suffix = NULL;
            if (snprintf(ephem, sizeof(ephem), "%s/internal/ephemeral", policy->session_root) >= (int)sizeof(ephem)
                || !abw_path_prefix(ephem, host, &ephem_suffix)) {
                *mode = ABW_MODE_RO;
                return 0;
            }
        }
    }
    rc = abw_policy_reverse(policy, host, virt);
    if (rc != 0) {
        int pr = abw_procfs_reverse_host(policy, pid, host, traced_pid_visible, NULL, virt);
        if (pr > 0) { *mode = ABW_MODE_RO; return 0; }
        return pr < 0 ? pr : rc;
    }
    abw_resolved_path_t r;
    rc = abw_policy_resolve(policy, virt, false, false, &r);
    if (rc != 0) return rc;
    *mode = r.mode;
    return 0;
}

static bool open_write_intent(uint64_t flags) {
    if ((flags & O_ACCMODE) != O_RDONLY) return true;
    if (flags & (O_CREAT | O_TRUNC)) return true;
    if ((flags & O_TMPFILE) == O_TMPFILE) return true;
    return false;
}

static bool ro_mount_allows_special_open(const char *host_path) {
    struct stat st;
    if (stat(host_path, &st) != 0) return false;
    /* MS_RDONLY protects filesystem metadata/data; it does not make existing
     * device/FIFO/socket endpoints unusable.  /dev/null is the common case. */
    return S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode) ||
           S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode);
}

static int rewrite_open_path(pid_t pid, abw_regs_t *regs, int arg_index, int dirfd,
                             bool follow_final, bool allow_missing_final,
                             uint64_t flags, const abw_policy_t *policy, int slot) {
    abw_resolved_path_t resolved;
    int rc = rewrite_path(pid, regs, arg_index, dirfd, follow_final, allow_missing_final,
                          false, false, policy, slot, &resolved);
    if (rc != 0) return rc;
    if (open_write_intent(flags) && resolved.mode != ABW_MODE_RW &&
        !ro_mount_allows_special_open(resolved.host_path))
        return -EROFS;
    return 0;
}

static bool dangerous_clone_flags(uint64_t flags) {
    const uint64_t denied = (uint64_t)CLONE_UNTRACED | CLONE_NEWNS | CLONE_NEWCGROUP |
                            CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER |
                            CLONE_NEWPID | CLONE_NEWNET;
    return (flags & denied) != 0;
}

static bool dangerous_kernel_fs_syscall(long nr) {
#ifdef SYS_mount
    if (nr == SYS_mount) return true;
#endif
#ifdef SYS_umount2
    if (nr == SYS_umount2) return true;
#endif
#ifdef SYS_pivot_root
    if (nr == SYS_pivot_root) return true;
#endif
#ifdef SYS_chroot
    if (nr == SYS_chroot) return true;
#endif
#ifdef SYS_open_by_handle_at
    if (nr == SYS_open_by_handle_at) return true;
#endif
#ifdef SYS_io_uring_setup
    if (nr == SYS_io_uring_setup) return true;
#endif
#ifdef SYS_fsopen
    if (nr == SYS_fsopen) return true;
#endif
#ifdef SYS_fspick
    if (nr == SYS_fspick) return true;
#endif
#ifdef SYS_open_tree
    if (nr == SYS_open_tree) return true;
#endif
#ifdef SYS_move_mount
    if (nr == SYS_move_mount) return true;
#endif
#ifdef SYS_mount_setattr
    if (nr == SYS_mount_setattr) return true;
#endif
#ifdef SYS_pidfd_getfd
    if (nr == SYS_pidfd_getfd) return true;
#endif
#ifdef SYS_setns
    if (nr == SYS_setns) return true;
#endif
#ifdef SYS_unshare
    if (nr == SYS_unshare) return true;
#endif
#ifdef SYS_ptrace
    if (nr == SYS_ptrace) return true;
#endif
#ifdef SYS_process_vm_readv
    if (nr == SYS_process_vm_readv) return true;
#endif
#ifdef SYS_process_vm_writev
    if (nr == SYS_process_vm_writev) return true;
#endif
#ifdef SYS_fanotify_init
    if (nr == SYS_fanotify_init) return true;
#endif
#ifdef SYS_fanotify_mark
    if (nr == SYS_fanotify_mark) return true;
#endif
#ifdef SYS_fsconfig
    if (nr == SYS_fsconfig) return true;
#endif
#ifdef SYS_fsmount
    if (nr == SYS_fsmount) return true;
#endif
#ifdef SYS_statmount
    if (nr == SYS_statmount) return true;
#endif
#ifdef SYS_listmount
    if (nr == SYS_listmount) return true;
#endif
    return false;
}

static int emulate_proc_readlink(pid_t pid, abw_regs_t *r, trace_state_t *st,
                                 int path_arg, int dirfd, int buf_arg, int size_arg,
                                 const abw_policy_t *policy) {
    char vpath[PATH_MAX], text[PATH_MAX];
    int rc = remote_virtual_path(pid, (uintptr_t)regs_arg(r, path_arg), dirfd, policy, vpath);
    if (rc != 0) return rc;
    size_t text_len = 0;
    rc = abw_procfs_readlink(policy, pid, vpath, traced_pid_visible, NULL, text, &text_len);
    if (rc <= 0) return rc;
    size_t cap = (size_t)regs_arg(r, size_arg);
    if (cap == 0) return -EINVAL;
    size_t n = text_len < cap ? text_len : cap;
    rc = abw_remote_write(pid, (uintptr_t)regs_arg(r, buf_arg), text, n);
    if (rc != 0) return rc;
    st->pending_ret_valid = true;
    st->pending_ret = (long)n;
    st->post_kind = POST_NONE;
    regs_request_syscall_nr(st, r, -1);
    return 1;
}

static int handle_entry(pid_t pid, abw_regs_t *r, trace_state_t *st, const abw_policy_t *policy, bool verbose) {
    long nr = regs_nr(r);
    int rc = 0;
    bool recognized = true;

#ifdef SYS_clone
    if (nr == SYS_clone && dangerous_clone_flags(regs_arg(r, 0))) return -EPERM;
#endif
#ifdef SYS_clone3
    if (nr == SYS_clone3) {
        uint64_t flags = 0;
        size_t sz = (size_t)regs_arg(r, 1);
        if (sz < sizeof(flags)) return -EINVAL;
        int rr = abw_remote_read(pid, (uintptr_t)regs_arg(r, 0), &flags, sizeof(flags));
        if (rr != 0) return rr;
        if (dangerous_clone_flags(flags)) return -EPERM;
    }
#endif
    if (dangerous_kernel_fs_syscall(nr)) return -EPERM;

#ifdef SYS_open
    if (nr == SYS_open) {
        uint64_t flags = regs_arg(r, 1);
        rc = rewrite_open_path(pid, r, 0, AT_FDCWD, !(flags & O_NOFOLLOW),
                               !!(flags & O_CREAT), flags, policy, 0);
    } else
#endif
#ifdef SYS_openat
    if (nr == SYS_openat) {
        int dirfd = (int)regs_arg(r, 0);
        uint64_t flags = regs_arg(r, 2);
        rc = rewrite_open_path(pid, r, 1, dirfd, !(flags & O_NOFOLLOW),
                               !!(flags & O_CREAT), flags, policy, 0);
    } else
#endif
#ifdef SYS_openat2
    if (nr == SYS_openat2) {
        int dirfd = (int)regs_arg(r, 0);
        struct abw_open_how how = {0};
        size_t sz = (size_t)regs_arg(r, 3);
        if (sz < sizeof(uint64_t)) rc = -EINVAL;
        else {
            size_t take = sz < sizeof(how) ? sz : sizeof(how);
            rc = abw_remote_read(pid, (uintptr_t)regs_arg(r, 2), &how, take);
            if (rc == 0) rc = rewrite_open_path(pid, r, 1, dirfd, !(how.flags & O_NOFOLLOW),
                                                !!(how.flags & O_CREAT), how.flags, policy, 0);
        }
    } else
#endif
#ifdef SYS_creat
    if (nr == SYS_creat) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, true, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_stat
    if (nr == SYS_stat) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_lstat
    if (nr == SYS_lstat) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_newfstatat
    if (nr == SYS_newfstatat) {
        int dirfd = (int)regs_arg(r, 0);
        int flags = (int)regs_arg(r, 3);
        uintptr_t p = (uintptr_t)regs_arg(r, 1);
        if (p == 0 && (flags & AT_EMPTY_PATH)) rc = 0;
        else rc = rewrite_path(pid, r, 1, dirfd, !(flags & AT_SYMLINK_NOFOLLOW), false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_statx
    if (nr == SYS_statx) {
        int dirfd = (int)regs_arg(r, 0);
        int flags = (int)regs_arg(r, 2);
        rc = rewrite_path(pid, r, 1, dirfd, !(flags & AT_SYMLINK_NOFOLLOW), false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_statfs
    if (nr == SYS_statfs) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_access
    if (nr == SYS_access) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_faccessat
    if (nr == SYS_faccessat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_faccessat2
    if (nr == SYS_faccessat2) {
        int flags = (int)regs_arg(r, 3);
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), !(flags & AT_SYMLINK_NOFOLLOW), false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_readlink
    if (nr == SYS_readlink) {
        int em = emulate_proc_readlink(pid, r, st, 0, AT_FDCWD, 1, 2, policy);
        rc = em > 0 ? 0 : (em < 0 ? em : rewrite_path(pid, r, 0, AT_FDCWD, false, false, false, false, policy, 0, NULL));
    } else
#endif
#ifdef SYS_readlinkat
    if (nr == SYS_readlinkat) {
        int em = emulate_proc_readlink(pid, r, st, 1, (int)regs_arg(r, 0), 2, 3, policy);
        rc = em > 0 ? 0 : (em < 0 ? em : rewrite_path(pid, r, 1, (int)regs_arg(r, 0), false, false, false, false, policy, 0, NULL));
    } else
#endif
#ifdef SYS_getxattr
    if (nr == SYS_getxattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_lgetxattr
    if (nr == SYS_lgetxattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_listxattr
    if (nr == SYS_listxattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_llistxattr
    if (nr == SYS_llistxattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_setxattr
    if (nr == SYS_setxattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_lsetxattr
    if (nr == SYS_lsetxattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_removexattr
    if (nr == SYS_removexattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_lremovexattr
    if (nr == SYS_lremovexattr) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_inotify_add_watch
    if (nr == SYS_inotify_add_watch) {
        uint32_t mask = (uint32_t)regs_arg(r, 2);
        rc = rewrite_path(pid, r, 1, AT_FDCWD, !(mask & IN_DONT_FOLLOW), false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_name_to_handle_at
    if (nr == SYS_name_to_handle_at) {
        int dirfd = (int)regs_arg(r, 0);
        int flags = (int)regs_arg(r, 4);
        char raw[PATH_MAX];
        int rr = abw_remote_read_string(pid, (uintptr_t)regs_arg(r, 1), raw);
        if (rr == 0 && raw[0] == '\0' && (flags & AT_EMPTY_PATH)) {
            abw_mode_t m;
            rc = fd_mode(pid, dirfd, policy, &m);
        } else {
            rc = rr != 0 ? rr : rewrite_path(pid, r, 1, dirfd, !!(flags & AT_SYMLINK_FOLLOW), false,
                                               false, false, policy, 0, NULL);
        }
    } else
#endif
#ifdef SYS_execve
    if (nr == SYS_execve) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_execveat
    if (nr == SYS_execveat) {
        int dirfd = (int)regs_arg(r, 0);
        int flags = (int)regs_arg(r, 4);
        char raw[PATH_MAX];
        int rr = abw_remote_read_string(pid, (uintptr_t)regs_arg(r, 1), raw);
        if (rr == 0 && raw[0] == '\0' && (flags & AT_EMPTY_PATH)) {
            abw_mode_t m;
            rc = fd_mode(pid, dirfd, policy, &m);
        } else {
            rc = rewrite_path(pid, r, 1, dirfd, !(flags & AT_SYMLINK_NOFOLLOW), false, false, false, policy, 0, NULL);
        }
    } else
#endif
#ifdef SYS_chdir
    if (nr == SYS_chdir) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, false, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_fchdir
    if (nr == SYS_fchdir) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
    } else
#endif
#ifdef SYS_getcwd
    if (nr == SYS_getcwd) {
        rc = 0;
    } else
#endif
#ifdef SYS_unlink
    if (nr == SYS_unlink) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_unlinkat
    if (nr == SYS_unlinkat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), false, false, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_rmdir
    if (nr == SYS_rmdir) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_mkdir
    if (nr == SYS_mkdir) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, true, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_mkdirat
    if (nr == SYS_mkdirat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), false, true, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_rename
    if (nr == SYS_rename) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, true, policy, 0, NULL);
        if (rc == 0) rc = rewrite_path(pid, r, 1, AT_FDCWD, false, true, true, true, policy, 1, NULL);
    } else
#endif
#ifdef SYS_renameat
    if (nr == SYS_renameat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), false, false, true, true, policy, 0, NULL);
        if (rc == 0) rc = rewrite_path(pid, r, 3, (int)regs_arg(r, 2), false, true, true, true, policy, 1, NULL);
    } else
#endif
#ifdef SYS_renameat2
    if (nr == SYS_renameat2) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), false, false, true, true, policy, 0, NULL);
        if (rc == 0) rc = rewrite_path(pid, r, 3, (int)regs_arg(r, 2), false, true, true, true, policy, 1, NULL);
    } else
#endif
#ifdef SYS_link
    if (nr == SYS_link) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, false, policy, 0, NULL);
        if (rc == 0) rc = rewrite_path(pid, r, 1, AT_FDCWD, false, true, true, true, policy, 1, NULL);
    } else
#endif
#ifdef SYS_linkat
    if (nr == SYS_linkat) {
        int flags = (int)regs_arg(r, 4);
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), !!(flags & AT_SYMLINK_FOLLOW), false, true, false, policy, 0, NULL);
        if (rc == 0) rc = rewrite_path(pid, r, 3, (int)regs_arg(r, 2), false, true, true, true, policy, 1, NULL);
    } else
#endif
#ifdef SYS_symlink
    if (nr == SYS_symlink) {
        rc = rewrite_path(pid, r, 1, AT_FDCWD, false, true, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_symlinkat
    if (nr == SYS_symlinkat) {
        rc = rewrite_path(pid, r, 2, (int)regs_arg(r, 1), false, true, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_truncate
    if (nr == SYS_truncate) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_chmod
    if (nr == SYS_chmod) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_fchmodat
    if (nr == SYS_fchmodat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_fchmodat2
    if (nr == SYS_fchmodat2) {
        int flags = (int)regs_arg(r, 3);
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), !(flags & AT_SYMLINK_NOFOLLOW), false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_chown
    if (nr == SYS_chown) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_lchown
    if (nr == SYS_lchown) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_fchownat
    if (nr == SYS_fchownat) {
        int flags = (int)regs_arg(r, 4);
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), !(flags & AT_SYMLINK_NOFOLLOW), false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_utime
    if (nr == SYS_utime) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_utimes
    if (nr == SYS_utimes) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_futimesat
    if (nr == SYS_futimesat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), true, false, true, false, policy, 0, NULL);
    } else
#endif
#ifdef SYS_utimensat
    if (nr == SYS_utimensat) {
        uintptr_t pp = (uintptr_t)regs_arg(r, 1);
        if (pp == 0) {
            abw_mode_t m;
            rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
            if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
        } else {
            int flags = (int)regs_arg(r, 3);
            rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), !(flags & AT_SYMLINK_NOFOLLOW), false, true, false, policy, 0, NULL);
        }
    } else
#endif
#ifdef SYS_mknod
    if (nr == SYS_mknod) {
        rc = rewrite_path(pid, r, 0, AT_FDCWD, false, true, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_mknodat
    if (nr == SYS_mknodat) {
        rc = rewrite_path(pid, r, 1, (int)regs_arg(r, 0), false, true, true, true, policy, 0, NULL);
    } else
#endif
#ifdef SYS_ftruncate
    if (nr == SYS_ftruncate) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
        if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
    } else
#endif
#ifdef SYS_fchmod
    if (nr == SYS_fchmod) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
        if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
    } else
#endif
#ifdef SYS_fchown
    if (nr == SYS_fchown) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
        if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
    } else
#endif
#ifdef SYS_fsetxattr
    if (nr == SYS_fsetxattr) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
        if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
    } else
#endif
#ifdef SYS_fremovexattr
    if (nr == SYS_fremovexattr) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
        if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
    } else
#endif
#ifdef SYS_fallocate
    if (nr == SYS_fallocate) {
        abw_mode_t m;
        rc = fd_mode(pid, (int)regs_arg(r, 0), policy, &m);
        if (rc == 0 && m != ABW_MODE_RW) rc = -EROFS;
    } else
#endif
    {
        recognized = false;
    }

    if (recognized && verbose) {
        if (rc == 0) abw_info(true, "pid %d syscall %ld allowed/translated", pid, nr);
        else abw_info(true, "pid %d syscall %ld denied: %s", pid, nr, strerror(-rc));
    }
    return recognized ? rc : 0;
}

static bool syscall_needs_post(long nr) {
#ifdef SYS_getcwd
    if (nr == SYS_getcwd) return true;
#endif
#ifdef SYS_readlink
    if (nr == SYS_readlink) return true;
#endif
#ifdef SYS_readlinkat
    if (nr == SYS_readlinkat) return true;
#endif
    return false;
}

static void setup_postprocess(trace_state_t *st, long nr, const abw_regs_t *r) {
    st->post_kind = POST_NONE;
#ifdef SYS_getcwd
    if (nr == SYS_getcwd) {
        st->post_kind = POST_GETCWD;
        st->post_buf = (uintptr_t)regs_arg(r, 0);
        st->post_size = (size_t)regs_arg(r, 1);
        return;
    }
#endif
#ifdef SYS_readlink
    if (nr == SYS_readlink) {
        st->post_kind = POST_READLINK;
        st->post_buf = (uintptr_t)regs_arg(r, 1);
        st->post_size = (size_t)regs_arg(r, 2);
        return;
    }
#endif
#ifdef SYS_readlinkat
    if (nr == SYS_readlinkat) {
        st->post_kind = POST_READLINK;
        st->post_buf = (uintptr_t)regs_arg(r, 2);
        st->post_size = (size_t)regs_arg(r, 3);
        return;
    }
#endif
}

static int finish_postprocess(pid_t pid, trace_state_t *st, abw_regs_t *r, const abw_policy_t *policy) {
    if (st->post_kind == POST_NONE) return 0;
    long ret = regs_ret(r);
    post_kind_t kind = st->post_kind;
    st->post_kind = POST_NONE;
    if (ret <= 0 || st->post_buf == 0 || st->post_size == 0) return 0;

    if (kind == POST_GETCWD) {
        char host[PATH_MAX], virt[PATH_MAX];
        int rc = abw_remote_read(pid, st->post_buf, host, (size_t)ret < PATH_MAX ? (size_t)ret : PATH_MAX - 1);
        if (rc != 0) return rc;
        host[PATH_MAX - 1] = '\0';
        rc = abw_policy_reverse(policy, host, virt);
        if (rc != 0) return 0;
        size_t n = strlen(virt) + 1;
        if (n > st->post_size) {
            regs_set_ret(r, -ERANGE);
            return regs_set(pid, r);
        }
        rc = abw_remote_write(pid, st->post_buf, virt, n);
        if (rc != 0) return rc;
        regs_set_ret(r, (long)n);
        return regs_set(pid, r);
    }

    if (kind == POST_READLINK) {
        size_t nread = (size_t)ret;
        if (nread >= PATH_MAX) nread = PATH_MAX - 1;
        char host[PATH_MAX], virt[PATH_MAX];
        int rc = abw_remote_read(pid, st->post_buf, host, nread);
        if (rc != 0) return rc;
        host[nread] = '\0';
        if (host[0] != '/' || abw_policy_reverse(policy, host, virt) != 0) return 0;
        size_t outn = strlen(virt);
        if (outn > st->post_size) outn = st->post_size;
        rc = abw_remote_write(pid, st->post_buf, virt, outn);
        if (rc != 0) return rc;
        regs_set_ret(r, (long)outn);
        return regs_set(pid, r);
    }
    return 0;
}

static int set_ptrace_options(pid_t pid, abw_backend_t backend) {
    long essential = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
                     PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (backend == ABW_BACKEND_SECCOMP_TRACE) essential |= PTRACE_O_TRACESECCOMP;
    long opts = essential | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)opts) == 0) return 0;
    if (errno != EINVAL) return -errno;
    /* Older Android kernels may lack EXITKILL; process-tree tracing remains essential. */
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)essential) == 0) return 0;
    return -errno;
}

static int resume_pid(pid_t pid, abw_backend_t backend, int sig) {
    int req = backend == ABW_BACKEND_PTRACE ? PTRACE_SYSCALL : PTRACE_CONT;
    if (ptrace(req, pid, 0, (void *)(long)sig) != 0) return -errno;
    return 0;
}

static int deny_current_seccomp_syscall(pid_t pid, abw_regs_t *r, int err) {
    trace_state_t *st = state_get(pid, true);
    if (!st) return -ENOMEM;
    st->pending_errno = err;
    regs_request_syscall_nr(st, r, -1); /* skip real syscall; patch errno at exit */
    int rc = regs_commit_entry(pid, r, st);
    if (rc != 0) return rc;
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) return -errno;
    return 1; /* caller must not resume again */
}

int abw_trace_loop(pid_t root_pid, const abw_trace_config_t *cfg) {
    int root_status = 127;
    bool root_seen_exit = false;
    trace_state_t *root_state = state_get(root_pid, true);
    if (!root_state) return 125;
    if (abw_procfs_materialize_pid(cfg->policy, root_state->tgid) != 0) return 125;

    for (;;) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) break;
            return 125;
        }

        if (WIFEXITED(status)) {
            if (pid == root_pid) {
                root_status = WEXITSTATUS(status);
                root_seen_exit = true;
            }
            trace_state_t *exit_st = state_get(pid, false);
            pid_t tgid = exit_st ? exit_st->tgid : pid;
            state_remove(pid);
            if (!traced_tgid_present(tgid)) abw_procfs_remove_pid(cfg->policy, tgid);
            continue;
        }
        if (WIFSIGNALED(status)) {
            if (pid == root_pid) {
                root_status = 128 + WTERMSIG(status);
                root_seen_exit = true;
            }
            trace_state_t *exit_st = state_get(pid, false);
            pid_t tgid = exit_st ? exit_st->tgid : pid;
            state_remove(pid);
            if (!traced_tgid_present(tgid)) abw_procfs_remove_pid(cfg->policy, tgid);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        unsigned event = (unsigned)status >> 16;
        trace_state_t *st = state_get(pid, true);
        if (!st) return 125;

        if (sig == SIGSTOP) {
            if (set_ptrace_options(pid, cfg->backend) != 0) {
                kill(pid, SIGKILL);
                return 125;
            }
            if (resume_pid(pid, cfg->backend, 0) != 0) return 125;
            continue;
        }

        if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
            unsigned long child = 0;
            ptrace(PTRACE_GETEVENTMSG, pid, 0, &child);
            trace_state_t *child_st = state_get((pid_t)child, true);
            if (!child_st) return 125;
            if (abw_procfs_materialize_pid(cfg->policy, child_st->tgid) != 0) return 125;
            resume_pid(pid, cfg->backend, 0);
            continue;
        }

        if (cfg->backend == ABW_BACKEND_SECCOMP_TRACE && event == PTRACE_EVENT_SECCOMP) {
            abw_regs_t r;
            int rc = regs_get(pid, &r);
            if (rc != 0) return 125;
            long snr = regs_nr(&r);
            rc = handle_entry(pid, &r, st, cfg->policy, cfg->verbose);
            if (rc < 0) {
                int d = deny_current_seccomp_syscall(pid, &r, -rc);
                if (d < 0) return 125;
                continue;
            }
            if (regs_commit_entry(pid, &r, st) != 0) return 125;
            if (st->pending_ret_valid || syscall_needs_post(snr)) {
                if (!st->pending_ret_valid) setup_postprocess(st, snr, &r);
                if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) return 125;
            } else {
                if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) return 125;
            }
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            abw_regs_t r;
            if (regs_get(pid, &r) != 0) return 125;
            if (cfg->backend == ABW_BACKEND_SECCOMP_TRACE) {
                if (st->pending_ret_valid) {
                    regs_set_ret(&r, st->pending_ret);
                    st->pending_ret_valid = false;
                    if (regs_set(pid, &r) != 0) return 125;
                } else if (st->pending_errno) {
                    regs_set_ret(&r, -st->pending_errno);
                    st->pending_errno = 0;
                    if (regs_set(pid, &r) != 0) return 125;
                } else if (st->post_kind != POST_NONE) {
                    if (finish_postprocess(pid, st, &r, cfg->policy) != 0) return 125;
                }
                if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) return 125;
                continue;
            }

            if (!st->in_syscall) {
                st->in_syscall = true;
                long snr = regs_nr(&r);
                int rc = handle_entry(pid, &r, st, cfg->policy, cfg->verbose);
                if (rc < 0) {
                    st->pending_errno = -rc;
                    st->post_kind = POST_NONE;
                    regs_request_syscall_nr(st, &r, -1);
                } else if (!st->pending_ret_valid && syscall_needs_post(snr)) {
                    setup_postprocess(st, snr, &r);
                }
                if (regs_commit_entry(pid, &r, st) != 0) return 125;
            } else {
                st->in_syscall = false;
                if (st->pending_ret_valid) {
                    regs_set_ret(&r, st->pending_ret);
                    st->pending_ret_valid = false;
                    if (regs_set(pid, &r) != 0) return 125;
                } else if (st->pending_errno) {
                    regs_set_ret(&r, -st->pending_errno);
                    st->pending_errno = 0;
                    if (regs_set(pid, &r) != 0) return 125;
                } else if (st->post_kind != POST_NONE) {
                    if (finish_postprocess(pid, st, &r, cfg->policy) != 0) return 125;
                }
            }
            if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) return 125;
            continue;
        }

        if (sig == SIGTRAP && event == PTRACE_EVENT_EXEC) {
            /* In PTRACE_SYSCALL mode the exec event replaces an intermediate
             * stop, but a syscall-exit stop can still follow.  Preserve the
             * entry/exit phase so the next stop is not misclassified as a new
             * syscall entry.  Seccomp mode does not use this phase bit. */
            if (cfg->backend == ABW_BACKEND_SECCOMP_TRACE) st->in_syscall = false;
            resume_pid(pid, cfg->backend, 0);
            continue;
        }

        /* Do not reinject synthetic ptrace SIGTRAP. Pass real signals through. */
        int deliver = sig == SIGTRAP ? 0 : sig;
        if (resume_pid(pid, cfg->backend, deliver) != 0) return 125;
    }

    (void)root_seen_exit;
    return root_status;
}
