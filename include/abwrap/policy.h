#pragma once

#include "abwrap/common.h"
#include <sys/types.h>

typedef struct {
    char src[PATH_MAX];
    char dst[PATH_MAX];
    abw_mode_t mode;
    bool synthetic;
} abw_rule_t;

typedef struct {
    char target[PATH_MAX];
    char dst[PATH_MAX];
} abw_symlink_t;

typedef struct {
    abw_rule_t rules[ABW_MAX_RULES];
    size_t rule_count;
    abw_symlink_t symlinks[ABW_MAX_SYMLINKS];
    size_t symlink_count;
    char session_root[PATH_MAX];
    char root_host[PATH_MAX];
    bool proc_enabled;
    char proc_dst[PATH_MAX];
    char proc_host_root[PATH_MAX];
} abw_policy_t;

typedef struct {
    char virtual_path[PATH_MAX];
    char host_path[PATH_MAX];
    abw_mode_t mode;
    const abw_rule_t *rule;
} abw_resolved_path_t;

int abw_policy_init(abw_policy_t *p, const char *base_tmpdir);
void abw_policy_destroy(abw_policy_t *p);
int abw_policy_add_bind(abw_policy_t *p, const char *src, const char *dst, abw_mode_t mode, bool try_only);
int abw_policy_add_ephemeral(abw_policy_t *p, const char *dst, const char *kind);
int abw_policy_add_proc(abw_policy_t *p, const char *dst);
int abw_policy_add_symlink(abw_policy_t *p, const char *target, const char *dst);
int abw_policy_prepare(abw_policy_t *p);
int abw_policy_resolve(const abw_policy_t *p, const char *virtual_path,
                       bool follow_final, bool allow_missing_final,
                       abw_resolved_path_t *out);
int abw_policy_reverse(const abw_policy_t *p, const char *host_path, char out[PATH_MAX]);
int abw_policy_proc_relative(const abw_policy_t *p, const char *virtual_path, char rel[PATH_MAX]);
int abw_policy_is_mountpoint(const abw_policy_t *p, const char *virtual_path);
int abw_policy_find_executable(const abw_policy_t *p, const char *command,
                               const char *virtual_cwd, const char *path_env,
                               char out_virtual[PATH_MAX]);
int abw_virtual_abspath(const char *cwd, const char *path, char out[PATH_MAX]);
int abw_path_normalize(const char *path, char out[PATH_MAX]);
