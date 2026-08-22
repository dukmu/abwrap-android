#define _GNU_SOURCE
#include "abwrap/policy.h"
#include "abwrap/util.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void must_at(int rc, int line) {
    if (rc != 0) {
        fprintf(stderr, "unexpected error at line %d: %s\n", line, strerror(-rc));
        abort();
    }
}
#define must(x) must_at((x), __LINE__)

static void write_file(const char *p, const char *s) {
    FILE *f = fopen(p, "w");
    assert(f);
    fputs(s, f);
    fclose(f);
}

int main(void) {
    char out[PATH_MAX];
    must(abw_path_normalize("/a/./b/../c//", out));
    assert(strcmp(out, "/a/c") == 0);
    must(abw_virtual_abspath("/work/sub", "../x", out));
    assert(strcmp(out, "/work/x") == 0);

    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir || !tmpdir[0]) tmpdir = "/tmp";
    char templ[PATH_MAX];
    int tn = snprintf(templ, sizeof(templ), "%s/abwrap-policy-test.XXXXXX", tmpdir);
    assert(tn > 0 && tn < (int)sizeof(templ));
    char *base = mkdtemp(templ);
    assert(base);
    char ro[PATH_MAX], rw[PATH_MAX], target[PATH_MAX];
    snprintf(ro, sizeof(ro), "%s/ro", base);
    snprintf(rw, sizeof(rw), "%s/rw", base);
    snprintf(target, sizeof(target), "%s/target", base);
    mkdir(ro, 0700); mkdir(rw, 0700); mkdir(target, 0700);
    char target_file[PATH_MAX];
    must(abw_join_path(target, "v", target_file, sizeof(target_file)));
    write_file(target_file, "ok");
    abw_policy_t p;
    must(abw_policy_init(&p, base));
    must(abw_policy_add_bind(&p, ro, "/tree", ABW_MODE_RO, false));
    must(abw_policy_add_bind(&p, rw, "/tree/w", ABW_MODE_RW, false));
    must(abw_policy_add_bind(&p, target, "/target", ABW_MODE_RO, false));
    must(abw_policy_add_proc(&p, "/proc"));
    /* The synthetic proc backing is supervisor-private but must stay writable
     * to an ordinary (non-root) UID so it can materialize entries at runtime. */
    struct stat proc_st;
    assert(stat(p.proc_host_root, &proc_st) == 0);
    assert((proc_st.st_mode & S_IWUSR) != 0);
    must(abw_policy_prepare(&p));

    abw_resolved_path_t r;
    must(abw_policy_resolve(&p, "/tree/w/new", false, true, &r));
    assert(r.mode == ABW_MODE_RW);
    must(abw_policy_resolve(&p, "/tree/new", false, true, &r));
    assert(r.mode == ABW_MODE_RO);
    assert(abw_policy_is_mountpoint(&p, "/tree") == 1);
    assert(abw_policy_is_mountpoint(&p, "/tree/no") == 0);

    must(abw_policy_reverse(&p, target_file, out));
    assert(strcmp(out, "/target/v") == 0);

    char rel[PATH_MAX];
    assert(abw_policy_proc_relative(&p, "/proc/self/status", rel) == 1);
    assert(strcmp(rel, "self/status") == 0);
    assert(abw_policy_resolve(&p, "/.abwrap-internal", true, false, &r) == -ENOENT);

    abw_policy_destroy(&p);
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
    (void)system(cmd);
    return 0;
}
