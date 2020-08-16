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
	fd = open("/dev/null", O_RDWR); /* stdin */
	if (fd < 0)
		return log_error("Cannot open /dev/null: %m");

	/* stdout */
	if (dup(fd) < 0)
		return log_error("Cannot dup to stdout: %m");

	/* stderr */
	if (dup(fd) < 0)
		return log_error("Cannot dup to stdout: %m");


	/* ignore child */
	signal(SIGCHLD, SIG_IGN);
	/* ignore tty signals */
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);

	return 0;
}
