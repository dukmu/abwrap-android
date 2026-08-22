#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s read|write PATH\n", argv[0]);
        return 64;
    }
    int flags = !strcmp(argv[1], "write") ? (O_WRONLY | O_CREAT | O_TRUNC) : O_RDONLY;
    long fd = syscall(SYS_openat, AT_FDCWD, argv[2], flags, 0644);
    if (fd < 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        return errno ? errno : 1;
    }
    if (!strcmp(argv[1], "write")) {
        const char msg[] = "raw-write\n";
        if (syscall(SYS_write, fd, msg, sizeof(msg)-1) < 0) return errno ? errno : 1;
    }
    syscall(SYS_close, fd);
    return 0;
}
