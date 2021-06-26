#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "macro.h"

char *safe_strncpy(char *restrict dest, const char *restrict src, size_t size) _access_roc_(2, 3) _access_woc_(1, 3);

_wur_ _nonnull_ static inline bool string_eq(const char *a, const char *b)
{
	return (0 == strcmp(a, b));
}
