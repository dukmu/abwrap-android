#define _GNU_SOURCE
#include "abwrap/policy.h"
#include "abwrap/util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int copy_path(char dst[PATH_MAX], const char *src) {
    size_t n = strlen(src);
    if (n >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(dst, src, n + 1);
    return 0;
}

static bool reserved_virtual_path(const char *path) {
    const char *suffix = NULL;
    return abw_path_prefix("/.abwrap-internal", path, &suffix) ||
           abw_path_prefix("/.ephemeral", path, &suffix);
}

static bool internal_host_path(const abw_policy_t *p, const char *path) {
    char internal[PATH_MAX];
    if (snprintf(internal, sizeof(internal), "%s/internal", p->session_root) >= (int)sizeof(internal)) return false;
    const char *suffix = NULL;
    return abw_path_prefix(internal, path, &suffix);
}

int abw_path_normalize(const char *path, char out[PATH_MAX]) {
    if (!path || path[0] != '/') return -EINVAL;
    char tmp[PATH_MAX];
    if (copy_path(tmp, path) != 0) return -ENAMETOOLONG;

    const char *parts[PATH_MAX / 2];
    size_t lens[PATH_MAX / 2];
    size_t count = 0;
    char *save = NULL;
    for (char *tok = strtok_r(tmp, "/", &save); tok; tok = strtok_r(NULL, "/", &save)) {
        if (!strcmp(tok, ".") || !*tok) continue;
        if (!strcmp(tok, "..")) {
            if (count > 0) count--;
            continue;
        }
        if (count >= sizeof(parts) / sizeof(parts[0])) return -ENAMETOOLONG;
        parts[count] = tok;
        lens[count] = strlen(tok);
        count++;
    }

    size_t pos = 0;
    out[pos++] = '/';
    for (size_t i = 0; i < count; ++i) {
        if (i > 0) out[pos++] = '/';
        if (pos + lens[i] >= PATH_MAX) return -ENAMETOOLONG;
        memcpy(out + pos, parts[i], lens[i]);
        pos += lens[i];
    }
    out[pos] = '\0';
    return 0;
}

int abw_virtual_abspath(const char *cwd, const char *path, char out[PATH_MAX]) {
    if (!path || !*path) return -ENOENT;
    if (path[0] == '/') return abw_path_normalize(path, out);
    char tmp[PATH_MAX];
    if (!cwd || cwd[0] != '/') cwd = "/";
    if (snprintf(tmp, sizeof(tmp), "%s%s%s", cwd, !strcmp(cwd, "/") ? "" : "/", path) >= (int)sizeof(tmp))
        return -ENAMETOOLONG;
    return abw_path_normalize(tmp, out);
}

static int ensure_parent(const char *path) {
    char tmp[PATH_MAX];
    if (copy_path(tmp, path) != 0) return -ENAMETOOLONG;
    char *slash = strrchr(tmp, '/');
    if (!slash) return -EINVAL;
    if (slash == tmp) slash[1] = '\0';
    else *slash = '\0';
    return abw_mkdir_p(tmp, 0700);
}

int abw_policy_init(abw_policy_t *p, const char *base_tmpdir) {
    memset(p, 0, sizeof(*p));
    const char *base = NULL;
    char fallback[PATH_MAX];

    /* An explicit --state-dir is a contract: report its error instead of
     * silently placing state elsewhere. Environment/default candidates may
     * fall back because Android and minimal Linux userlands differ. */
    if (base_tmpdir && *base_tmpdir) {
        int rc = abw_mkdir_p(base_tmpdir, 0700);
        if (rc != 0) return rc;
        base = base_tmpdir;
    } else {
        const char *tmp = getenv("TMPDIR");
        if (tmp && *tmp && abw_mkdir_p(tmp, 0700) == 0) base = tmp;

        if (!base) {
            const char *home = getenv("HOME");
            if (home && *home &&
                snprintf(fallback, sizeof(fallback), "%s/.cache", home) < (int)sizeof(fallback) &&
                abw_mkdir_p(fallback, 0700) == 0) {
                base = fallback;
            }
        }
        if (!base && access("/tmp", W_OK | X_OK) == 0) base = "/tmp";
        if (!base) base = ".";
    }
    char templ[PATH_MAX];
    if (snprintf(templ, sizeof(templ), "%s/abwrap.XXXXXX", base) >= (int)sizeof(templ)) return -ENAMETOOLONG;
    char *r = mkdtemp(templ);
    if (!r) return -errno;
    copy_path(p->session_root, r);
    if (snprintf(p->root_host, sizeof(p->root_host), "%s/rootfs", p->session_root) >= (int)sizeof(p->root_host)) return -ENAMETOOLONG;
    int rc = abw_mkdir_p(p->root_host, 0700);
    if (rc != 0) return rc;
    char internal[PATH_MAX];
    if (snprintf(internal, sizeof(internal), "%s/internal", p->session_root) >= (int)sizeof(internal)) return -ENAMETOOLONG;
    rc = abw_mkdir_p(internal, 0700);
    if (rc != 0) return rc;

    /* Implicit synthetic root: visible mount-point skeleton, read-only. */
    abw_rule_t *rule = &p->rules[p->rule_count++];
    copy_path(rule->src, p->root_host);
    copy_path(rule->dst, "/");
    rule->mode = ABW_MODE_RO;
    rule->synthetic = true;
    return 0;
}

void abw_policy_destroy(abw_policy_t *p) {
    if (p && p->session_root[0]) abw_rm_rf(p->session_root);
}

static int canonical_source(const char *src, char out[PATH_MAX]) {
    char *rp = realpath(src, NULL);
    if (!rp) return -errno;
    int rc = copy_path(out, rp);
    free(rp);
    return rc;
}

int abw_policy_add_bind(abw_policy_t *p, const char *src, const char *dst, abw_mode_t mode, bool try_only) {
    if (p->rule_count >= ABW_MAX_RULES) return -E2BIG;
    struct stat st;
    if (lstat(src, &st) != 0) return try_only && errno == ENOENT ? 0 : -errno;
    char ndst[PATH_MAX], csrc[PATH_MAX];
    int rc = abw_path_normalize(dst, ndst);
    if (rc != 0) return rc;
    if (reserved_virtual_path(ndst)) return -EPERM;
    rc = canonical_source(src, csrc);
    if (rc != 0) return rc;

    abw_rule_t *rule = &p->rules[p->rule_count++];
    copy_path(rule->src, csrc);
    copy_path(rule->dst, ndst);
    rule->mode = mode;
    rule->synthetic = false;
    return 0;
}

int abw_policy_add_ephemeral(abw_policy_t *p, const char *dst, const char *kind) {
    (void)kind;
    if (p->rule_count >= ABW_MAX_RULES) return -E2BIG;
    char ndst[PATH_MAX];
    int rc = abw_path_normalize(dst, ndst);
    if (rc != 0) return rc;
    if (reserved_virtual_path(ndst)) return -EPERM;
    char host[PATH_MAX];
    if (snprintf(host, sizeof(host), "%s/internal/ephemeral/%zu", p->session_root, p->rule_count) >= (int)sizeof(host)) return -ENAMETOOLONG;
    rc = abw_mkdir_p(host, 0700);
    if (rc != 0) return rc;
    abw_rule_t *rule = &p->rules[p->rule_count++];
    copy_path(rule->src, host);
    copy_path(rule->dst, ndst);
    rule->mode = ABW_MODE_RW;
    rule->synthetic = true;
    return 0;
}

int abw_policy_add_proc(abw_policy_t *p, const char *dst) {
    if (p->proc_enabled) {
        char ndst[PATH_MAX];
        int rc = abw_path_normalize(dst, ndst);
        if (rc != 0) return rc;
        return !strcmp(ndst, p->proc_dst) ? 0 : -EEXIST;
    }
    if (p->rule_count >= ABW_MAX_RULES) return -E2BIG;
    char ndst[PATH_MAX];
    int rc = abw_path_normalize(dst, ndst);
    if (rc != 0) return rc;
    if (reserved_virtual_path(ndst)) return -EPERM;
    if (snprintf(p->proc_host_root, sizeof(p->proc_host_root),
                 "%s/internal/procroot", p->session_root) >= (int)sizeof(p->proc_host_root))
        return -ENAMETOOLONG;
    /* Internal proc backing must remain writable by the unprivileged supervisor.
     * Read-only semantics are enforced by the virtual policy, not host mode bits.
     * Using 0500 here made creation of self/thread-self/etc fail with EACCES
     * for normal Termux UIDs (root-host tests masked the bug). */
    rc = abw_mkdir_p(p->proc_host_root, 0700);
    if (rc != 0) return rc;

    const char *dirs[] = {"self", "thread-self", "sys", "net", "fs", "irq", "bus", "driver", "sysvipc"};
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", p->proc_host_root, dirs[i]) >= (int)sizeof(path)) return -ENAMETOOLONG;
        if (mkdir(path, 0700) != 0 && errno != EEXIST) return -errno;
    }
    const char *files[] = {"cpuinfo", "meminfo", "version", "uptime", "loadavg", "stat", "filesystems",
                           "devices", "misc", "modules", "cmdline", "consoles", "diskstats", "interrupts",
                           "iomem", "ioports", "kallsyms", "key-users", "locks", "mounts", "partitions",
                           "softirqs", "swaps", "timer_list", "vmstat", "zoneinfo"};
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); ++i) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", p->proc_host_root, files[i]) >= (int)sizeof(path)) return -ENAMETOOLONG;
        int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) return -errno;
        close(fd);
    }

    abw_rule_t *rule = &p->rules[p->rule_count++];
    copy_path(rule->src, p->proc_host_root);
    copy_path(rule->dst, ndst);
    rule->mode = ABW_MODE_RO;
    rule->synthetic = true;
    copy_path(p->proc_dst, ndst);
    p->proc_enabled = true;
    return 0;
}

int abw_policy_add_symlink(abw_policy_t *p, const char *target, const char *dst) {
    if (p->symlink_count >= ABW_MAX_SYMLINKS) return -E2BIG;
    char ndst[PATH_MAX];
    int rc = abw_path_normalize(dst, ndst);
    if (rc != 0) return rc;
    if (reserved_virtual_path(ndst)) return -EPERM;
    abw_symlink_t *s = &p->symlinks[p->symlink_count++];
    rc = copy_path(s->target, target);
    if (rc != 0) return rc;
    return copy_path(s->dst, ndst);
}

static int materialize_mountpoint(abw_policy_t *p, const char *dst) {
    if (!strcmp(dst, "/")) return 0;
    char host[PATH_MAX];
    const char *rel = dst[0] == '/' ? dst + 1 : dst;
    int rc = abw_join_path(p->root_host, rel, host, sizeof(host));
    if (rc != 0) return rc;
    return abw_mkdir_p(host, 0700);
}

int abw_policy_prepare(abw_policy_t *p) {
    for (size_t i = 1; i < p->rule_count; ++i) {
        int rc = materialize_mountpoint(p, p->rules[i].dst);
        if (rc != 0) return rc;
    }
    for (size_t i = 0; i < p->symlink_count; ++i) {
        char host[PATH_MAX];
        const char *rel = p->symlinks[i].dst[0] == '/' ? p->symlinks[i].dst + 1 : p->symlinks[i].dst;
        int rc = abw_join_path(p->root_host, rel, host, sizeof(host));
        if (rc != 0) return rc;
        rc = ensure_parent(host);
        if (rc != 0) return rc;
        unlink(host);
        if (symlink(p->symlinks[i].target, host) != 0) return -errno;
    }
    return 0;
}

static const abw_rule_t *find_rule(const abw_policy_t *p, const char *vpath, const char **suffix) {
    const abw_rule_t *best = NULL;
    size_t best_len = 0;
    const char *best_suffix = NULL;
    for (size_t i = 0; i < p->rule_count; ++i) {
        const char *s = NULL;
        if (!abw_path_prefix(p->rules[i].dst, vpath, &s)) continue;
        size_t n = strlen(p->rules[i].dst);
        if (!best || n > best_len || (n == best_len && i > 0)) {
            best = &p->rules[i];
            best_len = n;
            best_suffix = s;
        }
    }
    if (suffix) *suffix = best_suffix;
    return best;
}

static int map_no_symlink(const abw_policy_t *p, const char *vpath, abw_resolved_path_t *out) {
    if (reserved_virtual_path(vpath)) return -ENOENT;
    const char *suffix = NULL;
    const abw_rule_t *r = find_rule(p, vpath, &suffix);
    if (!r) return -ENOENT;
    char host[PATH_MAX];
    int rc = abw_join_path(r->src, suffix ? suffix : "", host, sizeof(host));
    if (rc != 0) return rc;
    if (internal_host_path(p, host) && !(r->synthetic && internal_host_path(p, r->src))) return -ENOENT;
    copy_path(out->virtual_path, vpath);
    copy_path(out->host_path, host);
    out->mode = r->mode;
    out->rule = r;
    return 0;
}

static int append_remaining(const char *base, const char *remaining, char out[PATH_MAX]) {
    if (!remaining || !*remaining) return copy_path(out, base);
    return abw_join_path(base, remaining, out, PATH_MAX);
}

int abw_policy_resolve(const abw_policy_t *p, const char *virtual_path,
                       bool follow_final, bool allow_missing_final,
                       abw_resolved_path_t *out) {
    char current[PATH_MAX];
    int rc = abw_path_normalize(virtual_path, current);
    if (rc != 0) return rc;

    for (int depth = 0; depth <= ABW_MAX_SYMLINK_DEPTH; ++depth) {
        if (depth == ABW_MAX_SYMLINK_DEPTH) return -ELOOP;
        if (!strcmp(current, "/")) return map_no_symlink(p, current, out);

        char work[PATH_MAX];
        copy_path(work, current);
        char accum[PATH_MAX] = "/";
        char *save = NULL;
        char *tok = strtok_r(work, "/", &save);
        while (tok) {
            bool is_final = (save == NULL || *save == '\0');
            char next_accum[PATH_MAX];
            size_t alen = strlen(accum), tlen = strlen(tok);
            size_t need = !strcmp(accum, "/") ? 1 + tlen : alen + 1 + tlen;
            if (need >= sizeof(next_accum)) return -ENAMETOOLONG;
            if (!strcmp(accum, "/")) {
                next_accum[0] = '/';
                memcpy(next_accum + 1, tok, tlen + 1);
            } else {
                memcpy(next_accum, accum, alen);
                next_accum[alen] = '/';
                memcpy(next_accum + alen + 1, tok, tlen + 1);
            }
            copy_path(accum, next_accum);

            abw_resolved_path_t mapped;
            rc = map_no_symlink(p, accum, &mapped);
            if (rc != 0) return rc;
            struct stat st;
            if (lstat(mapped.host_path, &st) != 0) {
                if (errno == ENOENT && is_final && allow_missing_final) {
                    return map_no_symlink(p, accum, out);
                }
                return -errno;
            }

            if (S_ISLNK(st.st_mode) && (!is_final || follow_final)) {
                char target[PATH_MAX];
                ssize_t n = readlink(mapped.host_path, target, sizeof(target) - 1);
                if (n < 0) return -errno;
                target[n] = '\0';

                char parent[PATH_MAX];
                copy_path(parent, accum);
                char *slash = strrchr(parent, '/');
                if (!slash || slash == parent) copy_path(parent, "/");
                else *slash = '\0';

                char expanded[PATH_MAX];
                if (target[0] == '/') rc = abw_path_normalize(target, expanded);
                else {
                    char tmp[PATH_MAX];
                    if (snprintf(tmp, sizeof(tmp), "%s%s%s", parent, !strcmp(parent, "/") ? "" : "/", target) >= (int)sizeof(tmp)) return -ENAMETOOLONG;
                    rc = abw_path_normalize(tmp, expanded);
                }
                if (rc != 0) return rc;
                char with_rest[PATH_MAX];
                rc = append_remaining(expanded, save, with_rest);
                if (rc != 0) return rc;
                rc = abw_path_normalize(with_rest, current);
                if (rc != 0) return rc;
                goto restart_resolution;
            }
            tok = strtok_r(NULL, "/", &save);
        }
        return map_no_symlink(p, current, out);
restart_resolution:
        ;
    }
    return -ELOOP;
}

int abw_policy_reverse(const abw_policy_t *p, const char *host_path, char out[PATH_MAX]) {
    char canon[PATH_MAX];
    char *rp = realpath(host_path, NULL);
    if (rp) {
        copy_path(canon, rp);
        free(rp);
    } else {
        if (errno != ENOENT) return -errno;
        if (copy_path(canon, host_path) != 0) return -ENAMETOOLONG;
    }
    const abw_rule_t *best = NULL;
    const char *best_suffix = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < p->rule_count; ++i) {
        const char *suffix = NULL;
        if (!abw_path_prefix(p->rules[i].src, canon, &suffix)) continue;
        size_t n = strlen(p->rules[i].src);
        if (!best || n > best_len) {
            best = &p->rules[i];
            best_len = n;
            best_suffix = suffix;
        }
    }
    if (!best) return -ENOENT;
    if (internal_host_path(p, canon) && !(best->synthetic && internal_host_path(p, best->src))) return -ENOENT;
    char tmp[PATH_MAX];
    int rc = abw_join_path(best->dst, best_suffix ? best_suffix : "", tmp, sizeof(tmp));
    if (rc != 0) return rc;
    return abw_path_normalize(tmp, out);
}

int abw_policy_proc_relative(const abw_policy_t *p, const char *virtual_path, char rel[PATH_MAX]) {
    if (!p->proc_enabled) return 0;
    char norm[PATH_MAX];
    int rc = abw_path_normalize(virtual_path, norm);
    if (rc != 0) return rc;
    const char *suffix = NULL;
    const abw_rule_t *r = find_rule(p, norm, &suffix);
    if (!r || strcmp(r->src, p->proc_host_root) != 0 || strcmp(r->dst, p->proc_dst) != 0) return 0;
    const char *s = suffix ? suffix : "";
    if (*s == '/') ++s;
    rc = copy_path(rel, s);
    return rc == 0 ? 1 : rc;
}

int abw_policy_is_mountpoint(const abw_policy_t *p, const char *virtual_path) {
    char norm[PATH_MAX];
    if (abw_path_normalize(virtual_path, norm) != 0) return 0;
    for (size_t i = 1; i < p->rule_count; ++i) if (!strcmp(p->rules[i].dst, norm)) return 1;
    return 0;
}

int abw_policy_find_executable(const abw_policy_t *p, const char *command,
                               const char *virtual_cwd, const char *path_env,
                               char out_virtual[PATH_MAX]) {
    if (strchr(command, '/')) {
        char v[PATH_MAX];
        int rc = abw_virtual_abspath(virtual_cwd, command, v);
        if (rc != 0) return rc;
        abw_resolved_path_t r;
        rc = abw_policy_resolve(p, v, true, false, &r);
        if (rc != 0) return rc;
        if (access(r.host_path, X_OK) != 0) return -errno;
        return copy_path(out_virtual, v);
    }

    if (!path_env) path_env = "/system/bin:/system/xbin:/usr/bin:/bin";
    char buf[8192];
    if (strlen(path_env) >= sizeof(buf)) return -ENAMETOOLONG;
    strcpy(buf, path_env);
    char *save = NULL;
    for (char *dir = strtok_r(buf, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        if (!*dir) dir = ".";
        char candidate[PATH_MAX], abs[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", dir, command) >= (int)sizeof(candidate)) continue;
        if (abw_virtual_abspath(virtual_cwd, candidate, abs) != 0) continue;
        abw_resolved_path_t r;
        if (abw_policy_resolve(p, abs, true, false, &r) == 0 && access(r.host_path, X_OK) == 0) {
            return copy_path(out_virtual, abs);
        }
    }
    return -ENOENT;
}
