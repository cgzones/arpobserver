#pragma once

#define STRINGIFY(s) #s
#define STR(s)       STRINGIFY(s)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#if defined(__GNUC__) && __GNUC__ >= 10

#	define _access_ro_(index)         __attribute__((access(read_only, index)))
#	define _access_roc_(index, check) __attribute__((access(read_only, index, check)))
#	define _access_rw_(index)         __attribute__((access(read_write, index)))
#	define _access_rwc_(index, check) __attribute__((access(read_write, index, check)))
#	define _access_wo_(index)         __attribute__((access(write_only, index)))
#	define _access_woc_(index, check) __attribute__((access(write_only, index, check)))

#else

#	define _access_ro_(index)
#	define _access_roc_(index, check)
#	define _access_rw_(index)
#	define _access_rwc_(index, check)
#	define _access_wo_(index)
#	define _access_woc_(index, check)

#endif

#define _format_(type, index, check) __attribute__((format(type, index, check)))
#define _nonnull_                    __attribute__((nonnull))
#define _noreturn_                   __attribute__((noreturn))
#define _packed_                     __attribute__((packed))
#define _unused_                     __attribute__((unused))
#define _wur_                        __attribute__((warn_unused_result))
