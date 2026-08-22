#define _GNU_SOURCE
#include "abwrap/util.h"

#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void abw_warn(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "abwrap: warning: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void abw_info(bool enabled, const char *fmt, ...) {
    if (!enabled) return;
    va_list ap;
    fprintf(stderr, "abwrap: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void abw_die(const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "abwrap: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

bool abw_path_prefix(const char *prefix, const char *path, const char **suffix_out) {
    size_t n = strlen(prefix);
    if (strcmp(prefix, "/") == 0) {
        if (path[0] != '/') return false;
        if (suffix_out) *suffix_out = path + 1;
        return true;
    }
    if (strncmp(prefix, path, n) != 0) return false;
    if (path[n] != '\0' && path[n] != '/') return false;
    if (suffix_out) {
        const char *s = path + n;
        if (*s == '/') s++;
        *suffix_out = s;
    }
    return true;
}

int abw_join_path(const char *a, const char *b, char *out, size_t out_sz) {
    int rc;
    if (!b || !*b) rc = snprintf(out, out_sz, "%s", a);
    else if (strcmp(a, "/") == 0) rc = snprintf(out, out_sz, "/%s", b[0] == '/' ? b + 1 : b);
    else rc = snprintf(out, out_sz, "%s/%s", a, b[0] == '/' ? b + 1 : b);
    return (rc < 0 || (size_t)rc >= out_sz) ? -ENAMETOOLONG : 0;
}

int abw_mkdir_p(const char *path, unsigned mode) {
    char tmp[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) return -ENAMETOOLONG;
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -errno;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -errno;
    return 0;
}

int abw_rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT ? 0 : -errno;
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        return unlink(path) == 0 ? 0 : -errno;
    }
    DIR *d = opendir(path);
    if (!d) return -errno;
    struct dirent *de;
    int rc = 0;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char child[4096];
        if (snprintf(child, sizeof(child), "%s/%s", path, de->d_name) >= (int)sizeof(child)) {
            rc = -ENAMETOOLONG;
            break;
        }
        rc = abw_rm_rf(child);
        if (rc != 0) break;
    }
    closedir(d);
    if (rc == 0 && rmdir(path) != 0) rc = -errno;
    return rc;
}
