#define _GNU_SOURCE
#include "abwrap/policy.h"
#include "abwrap/seccomp_filter.h"
#include "abwrap/tracer.h"
#include "abwrap/util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define ABW_VERSION "3.0.3"

typedef enum { ENV_SET, ENV_UNSET } env_kind_t;
typedef struct {
    env_kind_t kind;
    char *name;
    char *value;
} env_op_t;

typedef struct {
    abw_backend_t backend;
    bool verbose;
    bool clearenv;
    bool die_with_parent;
    bool new_session;
    bool android_base;
    char *chdir;
    char *argv0;
    char *state_dir;
    env_op_t env_ops[ABW_MAX_ENV_OPS];
    size_t env_count;
    int preserve_fds[64];
    size_t preserve_fd_count;
} options_t;

static void usage(FILE *f) {
    fprintf(f,
        "abwrap " ABW_VERSION " - Android-compatible userspace filesystem sandbox\n\n"
        "Usage: abwrap [OPTIONS...] -- COMMAND [ARGS...]\n\n"
        "Filesystem:\n"
        "  --ro-bind SRC DST       expose SRC at DST, deny mutations with EROFS\n"
        "  --ro-bind-try SRC DST   same, ignore missing SRC\n"
        "  --bind SRC DST          writable bind\n"
        "  --bind-try SRC DST      writable bind, ignore missing SRC\n"
        "  --dev-bind SRC DST      bwrap-compatible writable bind alias\n"
        "  --dev-bind-try SRC DST  same, ignore missing SRC\n"
        "  --tmpfs DST             ephemeral writable directory (disk-backed on Android)\n"
        "  --dir DST               ephemeral writable directory\n"
        "  --symlink TARGET DST    synthetic symlink in the virtual root\n"
        "  --proc DST              hybrid virtual proc view at DST\n"
        "  --dev DST               expose host /dev read-only at DST\n"
        "  --android-base          add /system,/apex,/vendor,/product,/odm,/proc,/dev RO if present\n\n"
        "Process/environment:\n"
        "  --chdir DIR             virtual working directory\n"
        "  --clearenv              clear environment before exec\n"
        "  --setenv NAME VALUE     set environment variable\n"
        "  --unsetenv NAME         unset environment variable\n"
        "  --argv0 VALUE           override argv[0]\n"
        "  --die-with-parent       SIGKILL child if supervisor dies\n"
        "  --new-session           call setsid() in child\n"
        "  --preserve-fd FD        keep an inherited fd > 2 (default: close)\n\n"
        "Runtime:\n"
        "  --backend auto|seccomp|ptrace\n"
        "                         auto: selective seccomp+ptrace, fallback to ptrace\n"
        "  --state-dir DIR         session backing directory parent\n"
        "  --verbose               trace policy decisions\n"
        "  --version               print version\n"
        "  --help                  show this help\n\n"
        "Accepted compatibility flags with degraded/no-op semantics:\n"
        "  --unshare-all --unshare-user --unshare-pid --unshare-ipc --unshare-uts\n"
        "  --unshare-cgroup --unshare-net --share-net --cap-drop CAP --cap-add CAP\n"
        "  --uid UID --gid GID --hostname NAME\n");
}

static bool compat_flag_noarg(const char *s) {
    return !strcmp(s, "--unshare-all") || !strcmp(s, "--unshare-user") ||
           !strcmp(s, "--unshare-user-try") || !strcmp(s, "--unshare-pid") ||
           !strcmp(s, "--unshare-ipc") || !strcmp(s, "--unshare-uts") ||
           !strcmp(s, "--unshare-cgroup") || !strcmp(s, "--unshare-cgroup-try") ||
           !strcmp(s, "--unshare-net") || !strcmp(s, "--share-net") ||
           !strcmp(s, "--disable-userns") || !strcmp(s, "--assert-userns-disabled");
}

static bool compat_flag_arg(const char *s) {
    return !strcmp(s, "--cap-drop") || !strcmp(s, "--cap-add") ||
           !strcmp(s, "--uid") || !strcmp(s, "--gid") || !strcmp(s, "--hostname");
}


static int auto_virtualize_host_proc(abw_policy_t *p) {
    if (p->proc_enabled) return 0;

    abw_resolved_path_t r;
    int rc = abw_policy_resolve(p, "/proc", false, false, &r);
    if (rc == -ENOENT) return 0;
    if (rc != 0) return rc;

    /* A broad bind such as --ro-bind / / exposes the host procfs.  If we let
     * the generic symlink resolver walk /proc/self, it resolves "self" in the
     * supervisor process rather than in the tracee.  Overlay the virtual proc
     * implementation whenever virtual /proc maps to the real host /proc. */
    char *rp = realpath(r.host_path, NULL);
    if (!rp) return errno == ENOENT ? 0 : -errno;
    bool host_proc = !strcmp(rp, "/proc");
    free(rp);
    if (!host_proc) return 0;
    return abw_policy_add_proc(p, "/proc");
}

static int add_android_base(abw_policy_t *p) {
    const char *paths[] = {"/system", "/apex", "/vendor", "/product", "/odm", "/dev"};
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        if (access(paths[i], F_OK) == 0) {
            int rc = abw_policy_add_bind(p, paths[i], paths[i], ABW_MODE_RO, true);
            if (rc != 0) return rc;
        }
    }
    if (!p->proc_enabled && access("/proc", F_OK) == 0) {
        int rc = abw_policy_add_proc(p, "/proc");
        if (rc != 0) return rc;
    }
    const char *prefix = getenv("PREFIX");
    if (prefix && prefix[0] == '/' && access(prefix, F_OK) == 0) {
        int rc = abw_policy_add_bind(p, prefix, prefix, ABW_MODE_RO, true);
        if (rc != 0) return rc;
    }
    return abw_policy_add_ephemeral(p, "/tmp", "tmpfs");
}

static int add_env_op(options_t *o, env_kind_t kind, char *name, char *value) {
    if (o->env_count >= ABW_MAX_ENV_OPS) return -E2BIG;
    o->env_ops[o->env_count++] = (env_op_t){.kind = kind, .name = name, .value = value};
    return 0;
}

static const char *effective_path(const options_t *o) {
    const char *path = o->clearenv ? NULL : getenv("PATH");
    for (size_t i = 0; i < o->env_count; ++i) {
        if (strcmp(o->env_ops[i].name, "PATH")) continue;
        path = o->env_ops[i].kind == ENV_SET ? o->env_ops[i].value : NULL;
    }
    return path;
}

static void apply_env(const options_t *o) {
    if (o->clearenv) {
#if defined(__GLIBC__) || defined(__BIONIC__) || defined(__ANDROID__)
        clearenv();
#else
        environ = NULL;
#endif
    }
    for (size_t i = 0; i < o->env_count; ++i) {
        env_op_t *e = (env_op_t *)&o->env_ops[i];
        if (e->kind == ENV_SET) {
            if (setenv(e->name, e->value, 1) != 0) _exit(126);
        } else {
            if (unsetenv(e->name) != 0) _exit(126);
        }
    }
}

static bool fd_preserved(const options_t *o, int fd, int status_fd) {
    if (fd <= 2 || fd == status_fd) return true;
    for (size_t i = 0; i < o->preserve_fd_count; ++i) if (o->preserve_fds[i] == fd) return true;
    return false;
}

static void close_unpreserved_fds(const options_t *o, int status_fd) {
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int dfd = dirfd(d);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            char *end = NULL;
            long v = strtol(de->d_name, &end, 10);
            if (!end || *end || v < 0 || v > 1<<20) continue;
            int fd = (int)v;
            if (fd == dfd || fd_preserved(o, fd, status_fd)) continue;
            close(fd);
        }
        closedir(d);
        return;
    }
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    for (int fd = 3; fd < maxfd; ++fd) if (!fd_preserved(o, fd, status_fd)) close(fd);
}

static int parse_backend(const char *s, abw_backend_t *out) {
    if (!strcmp(s, "auto")) *out = ABW_BACKEND_AUTO;
    else if (!strcmp(s, "seccomp")) *out = ABW_BACKEND_SECCOMP_TRACE;
    else if (!strcmp(s, "ptrace")) *out = ABW_BACKEND_PTRACE;
    else return -EINVAL;
    return 0;
}

static void warn_compat(const options_t *opt, const char *flag) {
    if (opt->verbose)
        abw_warn("%s accepted for bwrap compatibility but kernel namespace semantics are not emulated", flag);
}

int main(int argc, char **argv) {
    options_t opt = {.backend = ABW_BACKEND_AUTO};
    abw_policy_t policy;

    /* Parse state-dir early so policy backing lands in a writable Android location. */
    for (int i = 1; i < argc - 1; ++i) if (!strcmp(argv[i], "--state-dir")) opt.state_dir = argv[i + 1];
    int rc = abw_policy_init(&policy, opt.state_dir);
    if (rc != 0) abw_die("cannot create session root: %s", strerror(-rc));

    int cmd_index = -1;
    for (int i = 1; i < argc; ++i) {
        char *a = argv[i];
        if (!strcmp(a, "--")) { cmd_index = i + 1; break; }
        if (a[0] != '-') { cmd_index = i; break; }
        if (!strcmp(a, "--help")) { usage(stdout); abw_policy_destroy(&policy); return 0; }
        if (!strcmp(a, "--version")) { puts("abwrap " ABW_VERSION); abw_policy_destroy(&policy); return 0; }
        if (!strcmp(a, "--verbose")) { opt.verbose = true; continue; }
        if (!strcmp(a, "--clearenv")) { opt.clearenv = true; continue; }
        if (!strcmp(a, "--die-with-parent")) { opt.die_with_parent = true; continue; }
        if (!strcmp(a, "--new-session")) { opt.new_session = true; continue; }
        if (!strcmp(a, "--android-base")) { opt.android_base = true; continue; }

        if (!strncmp(a, "--backend=", 10)) {
            if (parse_backend(a + 10, &opt.backend) != 0) abw_die("invalid backend: %s", a + 10);
            continue;
        }
        if (!strcmp(a, "--backend")) {
            if (++i >= argc || parse_backend(argv[i], &opt.backend) != 0) abw_die("--backend requires auto|seccomp|ptrace");
            continue;
        }
        if (!strcmp(a, "--state-dir")) { if (++i >= argc) abw_die("--state-dir requires DIR"); opt.state_dir = argv[i]; continue; }
        if (!strcmp(a, "--chdir")) { if (++i >= argc) abw_die("--chdir requires DIR"); opt.chdir = argv[i]; continue; }
        if (!strcmp(a, "--argv0")) { if (++i >= argc) abw_die("--argv0 requires VALUE"); opt.argv0 = argv[i]; continue; }
        if (!strcmp(a, "--preserve-fd")) {
            if (++i >= argc || opt.preserve_fd_count >= 64) abw_die("bad --preserve-fd");
            opt.preserve_fds[opt.preserve_fd_count++] = atoi(argv[i]);
            continue;
        }
        if (!strcmp(a, "--setenv")) {
            if (i + 2 >= argc) abw_die("--setenv requires NAME VALUE");
            char *name = argv[++i];
            char *value = argv[++i];
            if (add_env_op(&opt, ENV_SET, name, value) != 0) abw_die("too many env operations");
            continue;
        }
        if (!strcmp(a, "--unsetenv")) {
            if (++i >= argc) abw_die("--unsetenv requires NAME");
            if (add_env_op(&opt, ENV_UNSET, argv[i], NULL) != 0) abw_die("too many env operations");
            continue;
        }

        if (!strcmp(a, "--ro-bind") || !strcmp(a, "--ro-bind-try") ||
            !strcmp(a, "--bind") || !strcmp(a, "--bind-try") ||
            !strcmp(a, "--dev-bind") || !strcmp(a, "--dev-bind-try")) {
            bool ro = !strncmp(a, "--ro-", 5);
            bool try_only = strstr(a, "-try") != NULL;
            if (i + 2 >= argc) abw_die("%s requires SRC DST", a);
            char *src = argv[++i], *dst = argv[++i];
            rc = abw_policy_add_bind(&policy, src, dst, ro ? ABW_MODE_RO : ABW_MODE_RW, try_only);
            if (rc != 0) abw_die("%s %s -> %s: %s", a, src, dst, strerror(-rc));
            continue;
        }
        if (!strcmp(a, "--tmpfs") || !strcmp(a, "--dir")) {
            if (++i >= argc) abw_die("%s requires DST", a);
            rc = abw_policy_add_ephemeral(&policy, argv[i], a + 2);
            if (rc != 0) abw_die("%s %s: %s", a, argv[i], strerror(-rc));
            continue;
        }
        if (!strcmp(a, "--symlink")) {
            if (i + 2 >= argc) abw_die("--symlink requires TARGET DST");
            char *target = argv[++i], *dst = argv[++i];
            rc = abw_policy_add_symlink(&policy, target, dst);
            if (rc != 0) abw_die("--symlink: %s", strerror(-rc));
            continue;
        }
        if (!strcmp(a, "--proc") || !strcmp(a, "--dev")) {
            if (++i >= argc) abw_die("%s requires DST", a);
            if (!strcmp(a, "--proc")) rc = abw_policy_add_proc(&policy, argv[i]);
            else rc = abw_policy_add_bind(&policy, "/dev", argv[i], ABW_MODE_RO, false);
            if (rc != 0) abw_die("%s: %s", a, strerror(-rc));
            continue;
        }
        if (compat_flag_noarg(a)) { warn_compat(&opt, a); continue; }
        if (compat_flag_arg(a)) {
            warn_compat(&opt, a);
            if (++i >= argc) abw_die("%s requires an argument", a);
            continue;
        }
        if (!strcmp(a, "--seccomp") || !strcmp(a, "--file") || !strcmp(a, "--bind-data") || !strcmp(a, "--ro-bind-data")) {
            abw_die("%s is not safely emulatable in this userspace backend", a);
        }
        abw_die("unknown option: %s", a);
    }

    if (cmd_index < 0 || cmd_index >= argc) { usage(stderr); abw_policy_destroy(&policy); return 2; }
    if (opt.android_base) {
        rc = add_android_base(&policy);
        if (rc != 0) abw_die("--android-base: %s", strerror(-rc));
    }
    rc = auto_virtualize_host_proc(&policy);
    if (rc != 0) abw_die("auto /proc virtualization: %s", strerror(-rc));
    rc = abw_policy_prepare(&policy);
    if (rc != 0) abw_die("prepare virtual root: %s", strerror(-rc));

    char vcwd[PATH_MAX];
    if (opt.chdir) {
        rc = abw_virtual_abspath("/", opt.chdir, vcwd);
        if (rc != 0) abw_die("invalid --chdir: %s", strerror(-rc));
    } else {
        strcpy(vcwd, "/");
    }
    abw_resolved_path_t cwd_res;
    rc = abw_policy_resolve(&policy, vcwd, true, false, &cwd_res);
    if (rc != 0) abw_die("chdir %s: %s", vcwd, strerror(-rc));
    struct stat cwd_st;
    if (stat(cwd_res.host_path, &cwd_st) != 0 || !S_ISDIR(cwd_st.st_mode)) abw_die("chdir target is not a directory: %s", vcwd);

    char vexec[PATH_MAX];
    rc = abw_policy_find_executable(&policy, argv[cmd_index], vcwd, effective_path(&opt), vexec);
    if (rc != 0) abw_die("command not found in virtual filesystem: %s (%s)", argv[cmd_index], strerror(-rc));

    char **child_argv = &argv[cmd_index];
    if (opt.argv0) child_argv[0] = opt.argv0;

    int mode_pipe[2];
    if (pipe(mode_pipe) != 0) abw_die("pipe: %s", strerror(errno));
    pid_t child = fork();
    if (child < 0) abw_die("fork: %s", strerror(errno));
    if (child == 0) {
        close(mode_pipe[0]);
        if (opt.die_with_parent) prctl(PR_SET_PDEATHSIG, SIGKILL);
        if (opt.new_session) (void)setsid();
        if (chdir(cwd_res.host_path) != 0) _exit(126);
        apply_env(&opt);

        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) {
            char c = 'E'; (void)write(mode_pipe[1], &c, 1); _exit(125);
        }
        /* Close inherited descriptors before installing SECCOMP_RET_TRACE:
         * opendir("/proc/self/fd") itself performs filesystem syscalls. */
        close_unpreserved_fds(&opt, mode_pipe[1]);

        abw_backend_t selected = opt.backend;
        if (selected == ABW_BACKEND_AUTO || selected == ABW_BACKEND_SECCOMP_TRACE) {
            int frc = abw_install_trace_filter();
            if (frc == 0) selected = ABW_BACKEND_SECCOMP_TRACE;
            else if (opt.backend == ABW_BACKEND_SECCOMP_TRACE) {
                char c = 'E'; (void)write(mode_pipe[1], &c, 1); _exit(125);
            } else {
                selected = ABW_BACKEND_PTRACE;
            }
        }
        char c = selected == ABW_BACKEND_SECCOMP_TRACE ? 'S' : 'P';
        (void)write(mode_pipe[1], &c, 1);
        close(mode_pipe[1]);
        raise(SIGSTOP);
        execve(vexec, child_argv, environ);
        _exit(errno == ENOENT ? 127 : 126);
    }

    close(mode_pipe[1]);
    char mode = 0;
    ssize_t nr = read(mode_pipe[0], &mode, 1);
    close(mode_pipe[0]);
    if (nr != 1 || mode == 'E') {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        abw_policy_destroy(&policy);
        abw_die("sandbox backend initialization failed (ptrace/seccomp blocked by kernel or SELinux)");
    }
    abw_backend_t selected = mode == 'S' ? ABW_BACKEND_SECCOMP_TRACE : ABW_BACKEND_PTRACE;
    if (opt.verbose && opt.backend == ABW_BACKEND_AUTO && selected == ABW_BACKEND_PTRACE)
        abw_warn("selective seccomp unavailable; using slower ptrace fallback");
    abw_info(opt.verbose, "backend=%s session=%s", selected == ABW_BACKEND_SECCOMP_TRACE ? "seccomp-trace" : "ptrace", policy.session_root);

    abw_trace_config_t cfg = {.policy = &policy, .backend = selected, .verbose = opt.verbose};
    int status = abw_trace_loop(child, &cfg);
    abw_policy_destroy(&policy);
    return status;
}
