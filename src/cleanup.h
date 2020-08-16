#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#define TAKE_PTR(ptr)                      \
	({                                 \
		typeof(ptr) _ptr_ = (ptr); \
		(ptr) = NULL;              \
		_ptr_;                     \
	})

#define TAKE_FD(fd)              \
	({                       \
		int _fd_ = (fd); \
		(fd) = -1;       \
		_fd_;            \
	})

#define _cleanup_(func) __attribute__((cleanup(func)))

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func) \
	static inline void func##p(type *p)     \
	{                                       \
		if (*p)                         \
			func(*p);               \
	}                                       \
	struct __useless_struct_to_allow_trailing_semicolon__


DEFINE_TRIVIAL_CLEANUP_FUNC(char *, free);
#define _cleanup_free_ _cleanup_(freep)


static inline void close_fd(int fd)
{
	if (fd > 2) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
	}
}
DEFINE_TRIVIAL_CLEANUP_FUNC(int, close_fd);
#define _cleanup_close_ _cleanup_(close_fdp)

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE *, fclose);
#define _cleanup_fclose_ _cleanup_(fclosep)
