#pragma once

#include "abwrap/policy.h"
#include <sys/types.h>

typedef bool (*abw_proc_pid_visible_fn)(pid_t pid, void *opaque);

/* Returns 1 when vpath is handled as virtual procfs, 0 when it is not a proc path,
 * or a negative errno. host_path is suitable for the actual kernel syscall. */
int abw_procfs_translate(const abw_policy_t *policy, pid_t caller,
                         const char *vpath, bool follow_final, bool write_intent,
                         abw_proc_pid_visible_fn visible, void *opaque,
                         char host_path[PATH_MAX], abw_mode_t *mode);

/* Emulates proc magic-link readlink results. Returns 1 if handled, 0 otherwise,
 * or a negative errno. The result is not NUL-terminated from the tracee's point
 * of view, matching readlink(2). */
int abw_procfs_reverse_host(const abw_policy_t *policy, pid_t caller,
                            const char *host_path, abw_proc_pid_visible_fn visible,
                            void *opaque, char virtual_path[PATH_MAX]);

int abw_procfs_readlink(const abw_policy_t *policy, pid_t caller,
                        const char *vpath, abw_proc_pid_visible_fn visible,
                        void *opaque, char out[PATH_MAX], size_t *out_len);

int abw_procfs_materialize_pid(const abw_policy_t *policy, pid_t pid);
void abw_procfs_remove_pid(const abw_policy_t *policy, pid_t pid);
