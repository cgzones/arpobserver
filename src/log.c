#include "log.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

struct log_ctx_s {
	enum log_mode mode;
	int max_priority;
	const char *ident;
};

static struct log_ctx_s _ctx = {LOG_MODE_STDERR, LOG_INFO, NULL};

static const char *const log_level[] = {
	"EMERG", "ALERT", "CRIT ", "ERR  ", "WARN ", "NOTE ", "INFO ", "DEBUG",
};

void log_open(const char *ident)
{
	int flags = 0;

	assert(ident);

	_ctx.ident = ident;

	openlog(ident, flags, LOG_DAEMON);
}

void log_max_priority(int priority)
{
	assert(priority >= LOG_WARNING);
	assert(priority <= LOG_DEBUG);

	_ctx.max_priority = priority;
}

void log_mode(enum log_mode mode)
{
	assert(_ctx.ident);   // make sure we have called log_open already

	_ctx.mode = mode;
}

int _log_msg(int priority, int passed_errno, const char *format, ...)
{
	va_list pvar;
	char buffer[BUFSIZ];

	assert(_ctx.ident);   // make sure we have called log_open already
	assert(priority >= LOG_EMERG);
	assert(priority <= LOG_DEBUG);
	assert(passed_errno >= 0);

	// LOG_EMERG
	// LOG_ALERT
	// LOG_CRIT
	// LOG_ERR
	// LOG_WARNING
	// LOG_NOTICE
	// LOG_INFO
	// LOG_DEBUG

	if (priority > _ctx.max_priority)
		return passed_errno != 0 ? -passed_errno : -EBADRQC;

	va_start(pvar, format);
	errno = passed_errno;
	vsnprintf(buffer, sizeof(buffer), format, pvar);
	va_end(pvar);

	if (_ctx.mode & LOG_MODE_SYSLOG)
		syslog(priority, "%s: %s", log_level[priority], buffer);

	if (_ctx.mode & LOG_MODE_STDERR) {
		fprintf(stderr, "%s: %s: %s\n", _ctx.ident, log_level[priority], buffer);
		fflush(stderr);
	}

	if (_ctx.mode & LOG_MODE_STDOUT) {
		fprintf(stdout, "%s: %s: %s\n", _ctx.ident, log_level[priority], buffer);
		fflush(stdout);
	}

	return passed_errno != 0 ? -passed_errno : -EBADRQC;
}

void log_close()
{
	closelog();
}
