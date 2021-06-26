#pragma once

#include <stddef.h>

#include "macro.h"

typedef int (*config_accept_func)(const char *key, const char *value, size_t lineno);

int parse_config_file(const char *path, config_accept_func func) _nonnull_ _wur_;
