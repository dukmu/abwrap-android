#pragma once

#include "abwrap/common.h"
#include "abwrap/policy.h"
#include <sys/types.h>

typedef struct {
    const abw_policy_t *policy;
    abw_backend_t backend;
    bool verbose;
} abw_trace_config_t;

int abw_trace_loop(pid_t root_pid, const abw_trace_config_t *cfg);
