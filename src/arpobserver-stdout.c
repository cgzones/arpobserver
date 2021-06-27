#include <assert.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>

#include "config.h"
#include "log.h"
#include "shm.h"
#include "shm_client.h"

#define STDOUT_ARGV0 "arpobserver-stdout"


static void process_entry(const struct shm_log_entry *e, _unused_ void *arg)
{
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];

	assert(e);

	convert_mac_addr_to_str(e->mac_address, mac_str);

	if (convert_ip_addr_to_str(e->ip_address, e->ip_len, ip_str) < 0) {
		log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
		return;
	}

	log_info("%lu %s %u %s %s %s\n", e->timestamp, e->interface, e->vlan_tag, mac_str, ip_str, pkt_origin_str[e->origin]);
}

static void usage(void)
{
	printf("Usage: " STDOUT_ARGV0 " [OPTIONS]\n"
	       "Forward arpobsever address events to stdout.\n\n"
	       "  -h, --help\t\t\tDisplay this menu.\n"
	       "  -v, --verbose\t\t\tEnable verbose output.\n"
	       "  -V, --version\t\t\tShow version information and exit.\n");
}

int main(int argc, char *argv[])
{
	int rc;
	bool verbose = false;

	const struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "hVv", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'V':
			printf("%s %s\n", STDOUT_ARGV0, VERSION);
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

	log_open("arpobserver-syslog");
	log_mode(LOG_MODE_STDOUT);
	if (verbose)
		log_max_priority(LOG_DEBUG);

	rc = main_loop(process_entry, NULL, NULL);

	log_close();

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
