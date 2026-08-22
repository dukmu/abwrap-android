#define _GNU_SOURCE
#include "abwrap/procfs.h"
#include "abwrap/util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned long proc_generation;

static int copy_path(char out[PATH_MAX], const char *s) {
    size_t n = strlen(s);
    if (n >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(out, s, n + 1);
    return 0;
}

static int host_proc_path(pid_t pid, const char *suffix, char out[PATH_MAX]) {
    int n = suffix && *suffix
        ? snprintf(out, PATH_MAX, "/proc/%d/%s", pid, suffix)
        : snprintf(out, PATH_MAX, "/proc/%d", pid);
    return n < 0 || n >= PATH_MAX ? -ENAMETOOLONG : 0;
}

static int read_proc_link(pid_t pid, const char *suffix, char out[PATH_MAX]) {
    char p[PATH_MAX];
    int rc = host_proc_path(pid, suffix, p);
    if (rc != 0) return rc;
    ssize_t n = readlink(p, out, PATH_MAX - 1);
    if (n < 0) return -errno;
    out[n] = '\0';
    return 0;
}

static int read_tgid(pid_t tid, pid_t *tgid);

static bool all_digits(const char *s, size_t n) {
    if (!n) return false;
    for (size_t i = 0; i < n; ++i) if (!isdigit((unsigned char)s[i])) return false;
    return true;
}

static int parse_pid_component(const char *rel, pid_t caller,
                               abw_proc_pid_visible_fn visible, void *opaque,
                               pid_t *target, const char **suffix) {
    const char *slash = strchr(rel, '/');
    size_t n = slash ? (size_t)(slash - rel) : strlen(rel);
    if (n == 4 && !strncmp(rel, "self", 4)) {
        *target = caller;
        (void)read_tgid(caller, target);
    } else if (n == 11 && !strncmp(rel, "thread-self", 11)) {
        *target = caller;
    } else if (all_digits(rel, n)) {
        char num[32];
        if (n >= sizeof(num)) return -ENOENT;
        memcpy(num, rel, n); num[n] = '\0';
        long v = strtol(num, NULL, 10);
        if (v <= 0 || v > 1<<30) return -ENOENT;
        *target = (pid_t)v;
        if (*target != caller && (!visible || !visible(*target, opaque))) return -ENOENT;
    } else {
        return 0;
    }
    *suffix = slash ? slash + 1 : "";
    return 1;
}

static int virtual_from_host(const abw_policy_t *policy, const char *host, char out[PATH_MAX]) {
    char clean[PATH_MAX];
    int rc = copy_path(clean, host);
    if (rc != 0) return rc;
    char *deleted = strstr(clean, " (deleted)");
    if (deleted) *deleted = '\0';
    rc = abw_policy_reverse(policy, clean, out);
    return rc;
}

static int proc_internal_dir(const abw_policy_t *policy, pid_t pid, char out[PATH_MAX]) {
    int n = snprintf(out, PATH_MAX, "%s/internal/procgen/%d", policy->session_root, pid);
    if (n < 0 || n >= PATH_MAX) return -ENAMETOOLONG;
    return abw_mkdir_p(out, 0700);
}

static void proc_escape(const char *in, char *out, size_t cap) {
    size_t pos = 0;
    for (; *in && pos + 1 < cap; ++in) {
        const char *esc = NULL;
        if (*in == ' ') esc = "\\040";
        else if (*in == '\t') esc = "\\011";
        else if (*in == '\n') esc = "\\012";
        else if (*in == '\\') esc = "\\134";
        if (esc) {
            size_t n = strlen(esc);
            if (pos + n >= cap) break;
            memcpy(out + pos, esc, n); pos += n;
        } else out[pos++] = *in;
    }
    out[pos] = '\0';
}

static int generate_mount_view(const abw_policy_t *policy, const char *kind, FILE *out) {
    if (!strcmp(kind, "mounts")) {
        for (size_t i = 0; i < policy->rule_count; ++i) {
            const abw_rule_t *r = &policy->rules[i];
            char dst[PATH_MAX * 2];
            proc_escape(r->dst, dst, sizeof(dst));
            const char *fstype = policy->proc_enabled && !strcmp(r->dst, policy->proc_dst) ? "proc" :
                                 (r->synthetic && i ? "tmpfs" : "abwrap");
            fprintf(out, "abwrap %s %s %s,nosuid,nodev 0 0\n",
                    dst, fstype, r->mode == ABW_MODE_RW ? "rw" : "ro");
        }
        return ferror(out) ? -EIO : 0;
    }
    if (!strcmp(kind, "mountstats")) {
        for (size_t i = 0; i < policy->rule_count; ++i) {
            const abw_rule_t *r = &policy->rules[i];
            char dst[PATH_MAX * 2];
            proc_escape(r->dst, dst, sizeof(dst));
            const char *fstype = policy->proc_enabled && !strcmp(r->dst, policy->proc_dst) ? "proc" :
                                 (r->synthetic && i ? "tmpfs" : "abwrap");
            fprintf(out, "device abwrap mounted on %s with fstype %s\n", dst, fstype);
        }
        return ferror(out) ? -EIO : 0;
    }
    if (!strcmp(kind, "mountinfo")) {
        for (size_t i = 0; i < policy->rule_count; ++i) {
            const abw_rule_t *r = &policy->rules[i];
            char dst[PATH_MAX * 2];
            proc_escape(r->dst, dst, sizeof(dst));
            const char *fstype = policy->proc_enabled && !strcmp(r->dst, policy->proc_dst) ? "proc" :
                                 (r->synthetic && i ? "tmpfs" : "abwrap");
            fprintf(out, "%zu 0 0:0 / %s %s,nosuid,nodev - %s abwrap %s\n",
                    100 + i, dst, r->mode == ABW_MODE_RW ? "rw" : "ro", fstype,
                    r->mode == ABW_MODE_RW ? "rw" : "ro");
        }
        return ferror(out) ? -EIO : 0;
    }
    return -EINVAL;
}

static int rewrite_maps_stream(const abw_policy_t *policy, pid_t pid, const char *kind, FILE *out) {
    char src[PATH_MAX];
    int rc = host_proc_path(pid, kind, src);
    if (rc != 0) return rc;
    FILE *in = fopen(src, "r");
    if (!in) return -errno;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, in)) >= 0) {
        char *path = strchr(line, '/');
        if (!path) {
            if (fwrite(line, 1, (size_t)n, out) != (size_t)n) { rc = -EIO; break; }
            continue;
        }
        char *end = line + n;
        while (end > path && (end[-1] == '\n' || end[-1] == '\r')) --end;
        char saved = *end;
        *end = '\0';
        char virt[PATH_MAX];
        int rr = virtual_from_host(policy, path, virt);
        *path = '\0';
        if (fputs(line, out) == EOF) { rc = -EIO; *end = saved; break; }
        if (rr == 0) {
            if (fputs(virt, out) == EOF) rc = -EIO;
            if (strstr(path, " (deleted)") && fputs(" (deleted)", out) == EOF) rc = -EIO;
        } else if (fputs("[abwrap-hidden]", out) == EOF) rc = -EIO;
        *path = '/';
        *end = saved;
        if (rc == 0 && fputc('\n', out) == EOF) rc = -EIO;
        if (rc != 0) break;
    }
    free(line);
    if (ferror(in) && rc == 0) rc = -EIO;
    fclose(in);
    return rc;
}

static int rewrite_status_stream(pid_t pid, FILE *out) {
    char src[PATH_MAX];
    int rc = host_proc_path(pid, "status", src);
    if (rc != 0) return rc;
    FILE *in = fopen(src, "r");
    if (!in) return -errno;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, in)) >= 0) {
        if (!strncmp(line, "TracerPid:", 10)) {
            if (fputs("TracerPid:\t0\n", out) == EOF) { rc = -EIO; break; }
        } else if (fwrite(line, 1, (size_t)n, out) != (size_t)n) {
            rc = -EIO; break;
        }
    }
    free(line);
    if (ferror(in) && rc == 0) rc = -EIO;
    fclose(in);
    return rc;
}

static int generate_proc_file(const abw_policy_t *policy, pid_t pid, const char *kind,
                              char out_path[PATH_MAX]) {
    char dir[PATH_MAX];
    int rc = proc_internal_dir(policy, pid, dir);
    if (rc != 0) return rc;
    char final[PATH_MAX], tmp[PATH_MAX];
    if (snprintf(final, sizeof(final), "%s/%s", dir, kind) >= (int)sizeof(final)) return -ENAMETOOLONG;
    unsigned long seq = ++proc_generation;
    if (snprintf(tmp, sizeof(tmp), "%s/.%s.%lu.tmp", dir, kind, seq) >= (int)sizeof(tmp)) return -ENAMETOOLONG;
    int outfd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (outfd < 0) return -errno;
    FILE *f = fdopen(outfd, "w");
    if (!f) { int e = errno; close(outfd); unlink(tmp); return -e; }
    if (!strcmp(kind, "maps") || !strcmp(kind, "smaps")) rc = rewrite_maps_stream(policy, pid, kind, f);
    else if (!strcmp(kind, "status")) rc = rewrite_status_stream(pid, f);
    else rc = generate_mount_view(policy, kind, f);
    if (fflush(f) != 0 && rc == 0) rc = -errno;
    if (fclose(f) != 0 && rc == 0) rc = -errno;
    if (rc != 0) { unlink(tmp); return rc; }
    chmod(tmp, 0400);
    if (rename(tmp, final) != 0) { rc = -errno; unlink(tmp); return rc; }
    return copy_path(out_path, final);
}

static int resolve_virtual_target(const abw_policy_t *policy, const char *base_virtual,
                                  const char *rest, bool follow_final, bool write_intent,
                                  char host_path[PATH_MAX], abw_mode_t *mode) {
    char v[PATH_MAX];
    int rc = rest && *rest ? abw_virtual_abspath(base_virtual, rest, v) : copy_path(v, base_virtual);
    if (rc != 0) return rc;
    abw_resolved_path_t r;
    rc = abw_policy_resolve(policy, v, follow_final, false, &r);
    if (rc != 0) return rc;
    if (write_intent && r.mode != ABW_MODE_RW) return -EROFS;
    *mode = r.mode;
    return copy_path(host_path, r.host_path);
}

static int magic_fd_translate(const abw_policy_t *policy, pid_t target, const char *suffix,
                              bool follow_final, bool write_intent,
                              char host_path[PATH_MAX], abw_mode_t *mode) {
    const char *nstart = suffix + 3; /* after fd/ */
    const char *slash = strchr(nstart, '/');
    size_t nlen = slash ? (size_t)(slash - nstart) : strlen(nstart);
    if (!all_digits(nstart, nlen)) return -ENOENT;
    char fdpart[64];
    if (nlen >= sizeof(fdpart)) return -ENOENT;
    memcpy(fdpart, nstart, nlen); fdpart[nlen] = '\0';
    int fd = atoi(fdpart);
    char link_suffix[96], target_text[PATH_MAX];
    snprintf(link_suffix, sizeof(link_suffix), "fd/%d", fd);
    int rc = read_proc_link(target, link_suffix, target_text);
    if (rc != 0) return rc;

    if (!follow_final && !slash) return host_proc_path(target, link_suffix, host_path) == 0 ? (*mode = ABW_MODE_RO, 1) : -ENAMETOOLONG;
    if (target_text[0] == '/') {
        char virt[PATH_MAX];
        rc = virtual_from_host(policy, target_text, virt);
        if (rc != 0) return -ENOENT;
        if (slash) {
            rc = resolve_virtual_target(policy, virt, slash + 1, follow_final, write_intent, host_path, mode);
            return rc == 0 ? 1 : rc;
        }
        abw_resolved_path_t r;
        rc = abw_policy_resolve(policy, virt, true, false, &r);
        if (rc != 0) return rc;
        if (write_intent && r.mode != ABW_MODE_RW) return -EROFS;
        *mode = r.mode;
        rc = host_proc_path(target, link_suffix, host_path);
        return rc == 0 ? 1 : rc;
    }
    if (slash) return -ENOTDIR;
    *mode = ABW_MODE_RW; /* pipe/socket/anon_inode: capability already held by tracee */
    rc = host_proc_path(target, link_suffix, host_path);
    return rc == 0 ? 1 : rc;
}

int abw_procfs_translate(const abw_policy_t *policy, pid_t caller,
                         const char *vpath, bool follow_final, bool write_intent,
                         abw_proc_pid_visible_fn visible, void *opaque,
                         char host_path[PATH_MAX], abw_mode_t *mode) {
    char rel[PATH_MAX];
    int m = abw_policy_proc_relative(policy, vpath, rel);
    if (m <= 0) return m;
    *mode = ABW_MODE_RO;
    if (!*rel) {
        if (write_intent) return -EROFS;
        return copy_path(host_path, policy->proc_host_root) == 0 ? 1 : -ENAMETOOLONG;
    }

    pid_t target = -1;
    const char *suffix = NULL;
    int pr = parse_pid_component(rel, caller, visible, opaque, &target, &suffix);
    if (pr < 0) return pr;
    if (pr == 0) {
        if (write_intent) return -EROFS;
        /* Global proc nodes keep host semantics, but the proc root itself stays synthetic
         * so unrelated host PIDs are not enumerable. /proc/mounts is virtualized because
         * the host mount table would otherwise disclose backing paths. */
        if (!strcmp(rel, "mounts")) {
            int rc = generate_proc_file(policy, caller, "mounts", host_path);
            return rc == 0 ? 1 : rc;
        }
        if (snprintf(host_path, PATH_MAX, "/proc/%s", rel) >= PATH_MAX) return -ENAMETOOLONG;
        return 1;
    }

    if (!*suffix) {
        if (write_intent) return -EROFS;
        int rc = host_proc_path(target, NULL, host_path);
        return rc == 0 ? 1 : rc;
    }

    if (!strcmp(suffix, "maps") || !strcmp(suffix, "smaps") || !strcmp(suffix, "status") ||
        !strcmp(suffix, "mounts") || !strcmp(suffix, "mountinfo") ||
        !strcmp(suffix, "mountstats")) {
        if (write_intent) return -EROFS;
        const char *kind = !strcmp(suffix, "mountstats") ? "mountstats" : suffix;
        int rc = generate_proc_file(policy, target, kind, host_path);
        return rc == 0 ? 1 : rc;
    }

    if (!strncmp(suffix, "fd/", 3))
        return magic_fd_translate(policy, target, suffix, follow_final, write_intent, host_path, mode);

    const char *magic[] = {"root", "cwd", "exe"};
    for (size_t i = 0; i < sizeof(magic)/sizeof(magic[0]); ++i) {
        size_t n = strlen(magic[i]);
        if (strncmp(suffix, magic[i], n) || (suffix[n] && suffix[n] != '/')) continue;
        const char *rest = suffix[n] == '/' ? suffix + n + 1 : "";
        if (!strcmp(magic[i], "root")) {
            if (!follow_final && !*rest) {
                int rc = host_proc_path(target, "root", host_path);
                return rc == 0 ? 1 : rc;
            }
            return resolve_virtual_target(policy, "/", rest, follow_final, write_intent, host_path, mode) == 0 ? 1 : -ENOENT;
        }
        char host_target[PATH_MAX], virt[PATH_MAX];
        int rc = read_proc_link(target, magic[i], host_target);
        if (rc != 0) return rc;
        rc = virtual_from_host(policy, host_target, virt);
        if (rc != 0) return -ENOENT;
        if (!follow_final && !*rest) {
            rc = host_proc_path(target, magic[i], host_path);
            return rc == 0 ? 1 : rc;
        }
        rc = resolve_virtual_target(policy, virt, rest, follow_final, write_intent, host_path, mode);
        return rc == 0 ? 1 : rc;
    }

    if (!strncmp(suffix, "map_files/", 10)) {
        char link[PATH_MAX];
        int rc = read_proc_link(target, suffix, link);
        if (rc != 0) return rc;
        if (link[0] == '/') {
            char virt[PATH_MAX];
            if (virtual_from_host(policy, link, virt) != 0) return -ENOENT;
            abw_resolved_path_t r;
            rc = abw_policy_resolve(policy, virt, true, false, &r);
            if (rc != 0) return rc;
            if (write_intent && r.mode != ABW_MODE_RW) return -EROFS;
            *mode = r.mode;
        } else if (write_intent) return -EROFS;
        rc = host_proc_path(target, suffix, host_path);
        return rc == 0 ? 1 : rc;
    }

    if (write_intent) return -EROFS;
    int rc = host_proc_path(target, suffix, host_path);
    return rc == 0 ? 1 : rc;
}

int abw_procfs_reverse_host(const abw_policy_t *policy, pid_t caller,
                            const char *host_path, abw_proc_pid_visible_fn visible,
                            void *opaque, char virtual_path[PATH_MAX]) {
    if (!policy->proc_enabled) return 0;
    const char *suffix = NULL;
    if (!abw_path_prefix("/proc", host_path, &suffix)) return 0;
    const char *rel = suffix ? suffix : "";
    while (*rel == '/') ++rel;
    if (*rel) {
        const char *slash = strchr(rel, '/');
        size_t n = slash ? (size_t)(slash - rel) : strlen(rel);
        if (all_digits(rel, n)) {
            char num[32];
            if (n >= sizeof(num)) return -ENOENT;
            memcpy(num, rel, n); num[n] = '\0';
            pid_t target = (pid_t)strtol(num, NULL, 10);
            pid_t self_tgid = caller;
            (void)read_tgid(caller, &self_tgid);
            if (target != caller && target != self_tgid && (!visible || !visible(target, opaque))) return -ENOENT;
        }
    }
    if (!*rel) return copy_path(virtual_path, policy->proc_dst) == 0 ? 1 : -ENAMETOOLONG;
    char tmp[PATH_MAX];
    int rc = abw_join_path(policy->proc_dst, rel, tmp, sizeof(tmp));
    if (rc != 0) return rc;
    rc = abw_path_normalize(tmp, virtual_path);
    return rc == 0 ? 1 : rc;
}

static int read_tgid(pid_t tid, pid_t *tgid) {
    char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "/proc/%d/status", tid) >= (int)sizeof(p)) return -ENAMETOOLONG;
    FILE *f = fopen(p, "r");
    if (!f) return -errno;
    char line[256];
    int rc = -ENOENT;
    while (fgets(line, sizeof(line), f)) {
        long v;
        if (sscanf(line, "Tgid:%ld", &v) == 1) { *tgid = (pid_t)v; rc = 0; break; }
    }
    fclose(f);
    return rc;
}

int abw_procfs_readlink(const abw_policy_t *policy, pid_t caller,
                        const char *vpath, abw_proc_pid_visible_fn visible,
                        void *opaque, char out[PATH_MAX], size_t *out_len) {
    char rel[PATH_MAX];
    int m = abw_policy_proc_relative(policy, vpath, rel);
    if (m <= 0) return m;
    if (!strcmp(rel, "self")) {
        pid_t tgid = caller;
        (void)read_tgid(caller, &tgid);
        int n = snprintf(out, PATH_MAX, "%d", tgid);
        if (n < 0 || n >= PATH_MAX) return -ENAMETOOLONG;
        *out_len = (size_t)n; return 1;
    }
    if (!strcmp(rel, "thread-self")) {
        pid_t tgid = caller;
        (void)read_tgid(caller, &tgid);
        int n = snprintf(out, PATH_MAX, "%d/task/%d", tgid, caller);
        if (n < 0 || n >= PATH_MAX) return -ENAMETOOLONG;
        *out_len = (size_t)n; return 1;
    }

    pid_t target = -1;
    const char *suffix = NULL;
    int pr = parse_pid_component(rel, caller, visible, opaque, &target, &suffix);
    if (pr <= 0 || !*suffix) return pr < 0 ? pr : 0;

    if (!strcmp(suffix, "root")) {
        strcpy(out, "/"); *out_len = 1; return 1;
    }
    if (!strcmp(suffix, "cwd") || !strcmp(suffix, "exe") ||
        !strncmp(suffix, "fd/", 3) || !strncmp(suffix, "map_files/", 10)) {
        char host[PATH_MAX];
        int rc = read_proc_link(target, suffix, host);
        if (rc != 0) return rc;
        if (host[0] == '/') {
            rc = virtual_from_host(policy, host, out);
            if (rc != 0) return -ENOENT;
        } else {
            rc = copy_path(out, host);
            if (rc != 0) return rc;
        }
        *out_len = strlen(out);
        return 1;
    }
    return 0;
}

int abw_procfs_materialize_pid(const abw_policy_t *policy, pid_t pid) {
    if (!policy->proc_enabled) return 0;
    char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/%d", policy->proc_host_root, pid) >= (int)sizeof(p)) return -ENAMETOOLONG;
    if (mkdir(p, 0500) != 0 && errno != EEXIST) return -errno;
    return 0;
}

void abw_procfs_remove_pid(const abw_policy_t *policy, pid_t pid) {
    if (!policy->proc_enabled) return;
    char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/%d", policy->proc_host_root, pid) < (int)sizeof(p)) (void)rmdir(p);
}
