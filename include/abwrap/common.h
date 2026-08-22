#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ABW_MAX_RULES 256
#define ABW_MAX_SYMLINKS 128
#define ABW_MAX_ENV_OPS 256
#define ABW_MAX_SYMLINK_DEPTH 40

typedef enum {
    ABW_MODE_RO = 0,
    ABW_MODE_RW = 1,
} abw_mode_t;

typedef enum {
    ABW_BACKEND_AUTO = 0,
    ABW_BACKEND_SECCOMP_TRACE,
    ABW_BACKEND_PTRACE,
} abw_backend_t;
