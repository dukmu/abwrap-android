#pragma once

#include "abwrap/common.h"
#include <sys/types.h>

int abw_remote_read(pid_t pid, uintptr_t addr, void *buf, size_t len);
int abw_remote_write(pid_t pid, uintptr_t addr, const void *buf, size_t len);
int abw_remote_read_string(pid_t pid, uintptr_t addr, char out[PATH_MAX]);
