#include "daemonize.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "log.h"

int daemonize(const char *working_dir)
{
	int r;
	int fd;

	r = fork();
	if (r < 0)
		return log_error("Failed to fork: %m");

	if (r > 0) /* exit parent */
		exit(EXIT_SUCCESS);
	/* continue child (daemon) */

	if (setsid() < 0)
		return log_error("Failed to setsid: %m");

	r = fork();
	if (r < 0)
		return log_error("Failed to fork: %m");

	if (r > 0) /* exit parent */
		exit(EXIT_SUCCESS);
	/* continue child (daemon) */

	if (!working_dir)
		working_dir = "/";
	if (chdir(working_dir) < 0)
		return log_error("Cannot change working directory to '%s': %m", working_dir);

	umask(027);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* redirect standard i/o to /dev/null */
	fd = open("/dev/null", O_RDWR | O_CLOEXEC); /* stdin */
	if (fd < 0)
		return log_error("Cannot open /dev/null: %m");

	/* stdout */
	if (fcntl(fd, F_DUPFD_CLOEXEC) < 0)
		return log_error("Cannot dup to stdout: %m");

	/* stderr */
	if (fcntl(fd, F_DUPFD_CLOEXEC) < 0)
		return log_error("Cannot dup to stdout: %m");


	/* ignore child */
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
		return log_error("Cannot register SIGCHLD: %m");
	/* ignore tty signals */
	if (signal(SIGTSTP, SIG_IGN) == SIG_ERR)
		return log_error("Cannot register SIGTSTP: %m");
	if (signal(SIGTTOU, SIG_IGN) == SIG_ERR)
		return log_error("Cannot register SIGTTOU: %m");
	if (signal(SIGTTIN, SIG_IGN) == SIG_ERR)
		return log_error("Cannot register SIGTTIN: %m");

	return 0;
}
