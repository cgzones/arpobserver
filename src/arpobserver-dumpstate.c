#include <getopt.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>

#include "config.h"
#include "dllist.h"
#include "log.h"
#include "shm.h"
#include "statefile.h"
#include "util.h"

#define DUMP_ARGV0 "arpobserver-dumpstate"

static const char *state_file_path = CHECK_DEFAULT_STATE_FILE;
static bool verbose = false;

static void wrapper_free(void *p)
{
	free_shm_log_entry(p);
}

static void usage(void)
{
	printf("Usage: " DUMP_ARGV0 " [OPTIONS]\n"
	       "Print the current ARP Observer state.\n\n"
	       "  -h, --help\t\t\tDisplay this help and exit.\n"
	       "  -s, --state=STATEFILE\t\tOverride the default state file (" CHECK_DEFAULT_STATE_FILE ").\n"
	       "  -v, --verbose\t\t\tEnable verbose output.\n"
	       "  -V, --version\t\t\tShow version information and exit.\n");
}

int main(int argc, char *argv[])
{
	_cleanup_dllist_ struct dllist_head *state = NULL;
	struct stat statbuf;
	char state_mtime_str[32];
	struct tm timeresult;

	const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"state", required_argument, NULL, 's'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "hs:Vv", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 's':
			state_file_path = optarg;
			break;

		case 'V':
			printf("%s %s\n", DUMP_ARGV0, VERSION);
			exit(EXIT_SUCCESS);

		case 'v':
			verbose = true;
			break;

		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	log_open(DUMP_ARGV0);
	if (verbose)
		log_max_priority(LOG_DEBUG);
	else
		log_max_priority(LOG_NOTICE);

	state = dllist_init(wrapper_free);
	if (!state) {
		log_oom();
		return EXIT_FAILURE;
	}

	if (read_state_file(state_file_path, state) < 0)
		return EXIT_FAILURE;

	printf("\n                     " DUMP_ARGV0 "\n"
	       "\n  state from %s:\n\n",
	       state_file_path);

	dump_state(state);

	if (stat(state_file_path, &statbuf) < 0) {
		log_error("Cannot stat state file '%s': %m", state_file_path);
		return EXIT_FAILURE;
	}

	a_strftime(state_mtime_str, sizeof(state_mtime_str), "%Y-%m-%d %H:%M:%S %z", localtime_r(&statbuf.st_mtime, &timeresult));
	printf("State file last updated: %s\n", state_mtime_str);

	return EXIT_SUCCESS;
}
