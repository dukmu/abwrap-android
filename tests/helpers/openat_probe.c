#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s DIR RELPATH\n", argv[0]);
        return 64;
    }
    long dfd = syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dfd < 0) return errno ? errno : 1;
    long fd = syscall(SYS_openat, dfd, argv[2], O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return errno ? errno : 1;
    char buf[256];
    long n = syscall(SYS_read, fd, buf, sizeof(buf));
    if (n < 0) return errno ? errno : 1;
    if (n > 0 && syscall(SYS_write, STDOUT_FILENO, buf, (size_t)n) < 0) return errno ? errno : 1;
    syscall(SYS_close, fd);
    syscall(SYS_close, dfd);
    return 0;
}
