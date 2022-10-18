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

#define a_snprintf(str, size, ...)                           \
	do {                                                 \
		int rc__ = snprintf(str, size, __VA_ARGS__); \
		assert(0 < rc__ && (size_t)rc__ < (size));   \
	} while (0)

#define a_strftime(str, size, ...)                              \
	do {                                                    \
		size_t rc__ = strftime(str, size, __VA_ARGS__); \
		assert(rc__ != 0);                              \
	} while (0)
