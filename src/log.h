#pragma once

#include <errno.h>
#include <syslog.h>

#include "macro.h"


void log_open(const char *ident) _nonnull_;

void log_max_priority(int priority);

enum log_mode
{
	LOG_MODE_OFF = 0,
	LOG_MODE_SYSLOG = 1,
	LOG_MODE_STDERR = 1 << 1,
	LOG_MODE_STDOUT = 1 << 2,
};
void log_mode(enum log_mode mode);

__attribute__((format(printf, 3, 4))) int _log_msg(int priority, int passed_errno, const char *format, ...);

#define log_error(format, ...) _log_msg(LOG_ERR, (errno), (format), ##__VA_ARGS__)

#define log_errno_error(passed_errno, format, ...) _log_msg(LOG_ERR, (passed_errno), (format), ##__VA_ARGS__)

#define log_warn(format, ...) _log_msg(LOG_WARNING, (errno), (format), ##__VA_ARGS__)

#define log_errno_warn(passed_errno, format, ...) _log_msg(LOG_WARNING, (passed_errno), (format), ##__VA_ARGS__)

#define log_notice(format, ...) _log_msg(LOG_NOTICE, (errno), (format), ##__VA_ARGS__)

#define log_errno_notice(passed_errno, format, ...) _log_msg(LOG_NOTICE, (passed_errno), (format), ##__VA_ARGS__)

#define log_info(format, ...) _log_msg(LOG_INFO, (errno), (format), ##__VA_ARGS__)

#define log_errno_info(passed_errno, format, ...) _log_msg(LOG_INFO, (passed_errno), (format), ##__VA_ARGS__)

#define log_debug(format, ...) _log_msg(LOG_DEBUG, (errno), (format), ##__VA_ARGS__)

#define log_errno_debug(passed_errno, format, ...) _log_msg(LOG_DEBUG, (passed_errno), (format), ##__VA_ARGS__)

#define log_oom() log_error("Cannot allocate memory [%s():%d]: %m", __func__, __LINE__)

void log_close(void);
