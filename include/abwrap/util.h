#pragma once

#include <stdbool.h>
#include <stddef.h>

void abw_warn(const char *fmt, ...);
void abw_info(bool enabled, const char *fmt, ...);
void abw_die(const char *fmt, ...) __attribute__((noreturn));
int abw_mkdir_p(const char *path, unsigned mode);
int abw_rm_rf(const char *path);
bool abw_path_prefix(const char *prefix, const char *path, const char **suffix_out);
int abw_join_path(const char *a, const char *b, char *out, size_t out_sz);
