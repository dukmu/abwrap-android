#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#if defined(__ANDROID__)
#include <sys/vfs.h>
#else
#include <sys/statfs.h>
#endif
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_UNTRACED
#define CLONE_UNTRACED 0x00800000
#endif

static int ret_errno(long rc) {
    if (rc >= 0) return 0;
    return errno ? errno : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    const char *mode = argv[1];
    const char *path = argc >= 3 ? argv[2] : NULL;

#ifdef SYS_setxattr
    if (!strcmp(mode, "setxattr") && path) {
        const char v = 'x';
        return ret_errno(syscall(SYS_setxattr, path, "user.abwrap", &v, 1, 0));
    }
#endif
#ifdef SYS_getxattr
    if (!strcmp(mode, "getxattr") && path) {
        char b[16];
        return ret_errno(syscall(SYS_getxattr, path, "user.abwrap", b, sizeof(b)));
    }
#endif
#ifdef SYS_statfs
    if (!strcmp(mode, "statfs") && path) {
        struct statfs st;
        return ret_errno(syscall(SYS_statfs, path, &st));
    }
#endif
#ifdef SYS_inotify_init1
#ifdef SYS_inotify_add_watch
    if (!strcmp(mode, "inotify") && path) {
        long fd = syscall(SYS_inotify_init1, IN_CLOEXEC);
        if (fd < 0) return errno ? errno : 1;
        long rc = syscall(SYS_inotify_add_watch, fd, path, IN_ALL_EVENTS);
        int e = ret_errno(rc);
        close((int)fd);
        return e;
    }
#endif
#endif
#ifdef SYS_fallocate
    if (!strcmp(mode, "fallocate") && path) {
        long fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) return errno ? errno : 1;
        long rc = syscall(SYS_fallocate, fd, 0, 0, 4096);
        int e = ret_errno(rc);
        close((int)fd);
        return e;
    }
#endif
#ifdef SYS_clone
    if (!strcmp(mode, "clone-untraced")) {
        long rc = syscall(SYS_clone, (unsigned long)(SIGCHLD | CLONE_UNTRACED), 0, 0, 0, 0);
        if (rc == 0) _exit(0);
        if (rc < 0) return errno ? errno : 1;
        int st = 0;
        (void)waitpid((pid_t)rc, &st, 0);
        return 0;
    }
#endif
    return 64;
}
