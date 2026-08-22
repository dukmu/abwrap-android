#define _GNU_SOURCE
#include "abwrap/remote.h"
#include "abwrap/arch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <unistd.h>

static int proc_mem_open(pid_t pid, int flags) {
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%ld/mem", (long)pid);
    if (n < 0 || (size_t)n >= sizeof(path)) return -ENAMETOOLONG;
    int fd = open(path, flags | O_CLOEXEC);
    return fd < 0 ? -errno : fd;
}

static int proc_mem_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    int fd = proc_mem_open(pid, O_RDONLY);
    if (fd < 0) return fd;
    ssize_t n = pread(fd, buf, len, (off_t)abw_arch_remote_addr(addr));
    int saved = errno;
    close(fd);
    if (n == (ssize_t)len) return 0;
    return n < 0 ? -saved : -EIO;
}

static int proc_mem_write(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
    int fd = proc_mem_open(pid, O_WRONLY);
    if (fd < 0) return fd;
    ssize_t n = pwrite(fd, buf, len, (off_t)abw_arch_remote_addr(addr));
    int saved = errno;
    close(fd);
    if (n == (ssize_t)len) return 0;
    return n < 0 ? -saved : -EIO;
}

int abw_remote_read(pid_t pid, uintptr_t addr, void *buf, size_t len) {
    uintptr_t canon = abw_arch_remote_addr(addr);
#if defined(__linux__)
    struct iovec local = {.iov_base = buf, .iov_len = len};
    struct iovec remote = {.iov_base = (void *)canon, .iov_len = len};
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len) return 0;
#endif
    /* Android kernels/SELinux configurations vary. /proc/<pid>/mem works on
     * common Termux parent->child tracing setups even when process_vm_* is
     * restricted, and handles aarch64 tagged pointers once canonicalized. */
    int pm = proc_mem_read(pid, canon, buf, len);
    if (pm == 0) return 0;

    size_t off = 0;
    unsigned char *dst = (unsigned char *)buf;
    while (off < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(canon + off), 0);
        if (word == -1 && errno) return -errno;
        size_t take = sizeof(word);
        if (take > len - off) take = len - off;
        memcpy(dst + off, &word, take);
        off += take;
    }
    return 0;
}

int abw_remote_write(pid_t pid, uintptr_t addr, const void *buf, size_t len) {
    uintptr_t canon = abw_arch_remote_addr(addr);
#if defined(__linux__)
    struct iovec local = {.iov_base = (void *)buf, .iov_len = len};
    struct iovec remote = {.iov_base = (void *)canon, .iov_len = len};
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n == (ssize_t)len) return 0;
#endif
    int pm = proc_mem_write(pid, canon, buf, len);
    if (pm == 0) return 0;

    size_t off = 0;
    const unsigned char *src = (const unsigned char *)buf;
    while (off < len) {
        long word = 0;
        size_t take = sizeof(word);
        if (take > len - off) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void *)(canon + off), 0);
            if (word == -1 && errno) return -errno;
            take = len - off;
        }
        memcpy(&word, src + off, take);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(canon + off), (void *)word) != 0) return -errno;
        off += take;
    }
    return 0;
}

int abw_remote_read_string(pid_t pid, uintptr_t addr, char out[PATH_MAX]) {
    if (!addr) return -EFAULT;
    uintptr_t canon = abw_arch_remote_addr(addr);

    /* Read in small chunks. This is substantially faster than one ptrace word
     * at a time when process_vm_readv or /proc/<pid>/mem is available, and it
     * avoids crossing an unmapped page with a full PATH_MAX request. */
    size_t off = 0;
    while (off < PATH_MAX) {
        unsigned char chunk[64];
        size_t want = sizeof(chunk);
        if (want > PATH_MAX - off) want = PATH_MAX - off;
        int rc = abw_remote_read(pid, canon + off, chunk, want);
        if (rc != 0) {
            /* Near a page boundary, fall back to ptrace word reads so a short
             * valid C string is still readable even if the next page is not. */
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(canon + off), 0);
            if (word == -1 && errno) return rc;
            want = sizeof(word);
            if (want > PATH_MAX - off) want = PATH_MAX - off;
            memcpy(chunk, &word, want);
        }
        memcpy(out + off, chunk, want);
        for (size_t i = 0; i < want; ++i) {
            if (out[off + i] == '\0') return 0;
        }
        off += want;
    }
    out[PATH_MAX - 1] = '\0';
    return -ENAMETOOLONG;
}
