#include "util.h"

#include <assert.h>

char *safe_strncpy(char *dest, const char *src, size_t size)
{
	assert(dest);
	assert(size > 0);
	assert(src);

	if (size > 0) {
		size_t i;
		for (i = 0; i < size - 1 && src[i]; ++i)
			dest[i] = src[i];
		dest[i] = '\0';
	}

	return dest;
}
