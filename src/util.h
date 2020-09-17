#pragma once

#include <stddef.h>

#include "macro.h"

char *safe_strncpy(char *restrict dest, const char *restrict src, size_t size) _access_roc_(2, 3) _access_woc_(1, 3);
