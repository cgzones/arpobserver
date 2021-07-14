#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cleanup.h"
#include "config.h"
#include "configfile.h"
#include "dllist.h"
#include "log.h"
#include "protect.h"
#include "shm.h"
#include "shm_client.h"
#include "statefile.h"
#include "util.h"

#define CHECK_ARGV0         "arpobserver-checkd"
#define DEFAULT_CONFIG_PATH SYSCONFDIR "/" PACKAGE "/check.conf"

static const char *state_file_path = CHECK_DEFAULT_STATE_FILE;
static bool verbose = false;
static time_t lease_time = 24 * 60 * 60;      // 1d
static unsigned lease_remember_factor = 5;    // 5 * lease_time
static time_t state_sync_interval = 60 * 5;   // 5m
static time_t last_sync_time = 0;

#define FMT_TIMESTAMP_SIZE 16
static char *format_timestamp(char *buffer, size_t size, time_t time)
{
	struct tm t;
	size_t rc;

	assert(buffer);
	assert(size >= FMT_TIMESTAMP_SIZE);

	localtime_r(&time, &t);
	rc = strftime(buffer, size, "%b %d %T", &t);
	if (rc == 0)
		snprintf(buffer, size, "<invalid>");

	return buffer;
}

static const uint8_t *
	find_ip_address(const struct dllist_head *state, char interface[IFNAMSIZ], uint8_t mac_address[ETHER_ADDR_LEN], uint8_t ip_len)
{
	assert(state);
	assert(mac_address);
	assert(ip_len == IP4_LEN || ip_len == IP6_LEN);

	for (struct dllist_entry *cur_e = state->first; cur_e; cur_e = cur_e->next) {
		const struct shm_log_entry *data = cur_e->data;

		if (data->ip_len != ip_len)
			continue;

		if (!string_eq(data->interface, interface))
			continue;

		if (0 != memcmp(data->mac_address, mac_address, sizeof(data->mac_address)))
			continue;

		return data->ip_address;
	}

	return NULL;
}

static void process_entry(const struct shm_log_entry *e, void *arg)
{
	time_t now;
	struct dllist_head *state = arg;
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	const struct protect_entry *found_match;
	bool event_logged = false;

	assert(e);
	assert(state);

	if (convert_ip_addr_to_str(e->ip_address, e->ip_len, ip_str) < 0) {
		log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
		return;
	}

	convert_mac_addr_to_str(e->mac_address, mac_str);

	log_debug("arp packet: %" PRIu64 " %s %u %s %s %s", e->timestamp, e->interface, e->vlan_tag, mac_str, ip_str,
		  pkt_origin_str[e->origin]);

	if (verbose) {
		size_t i = 1;

		log_debug("cache has %zu entries", state->size);

		for (const struct dllist_entry *cur_e = state->first; cur_e; cur_e = cur_e->next) {
			char last_updated[32];
			char cur_mac_str[MAC_STR_LEN];
			char cur_ip_str[INET6_ADDRSTRLEN];
			const struct shm_log_entry *data = cur_e->data;
			struct tm timeresult;

			assert(data);

			convert_mac_addr_to_str(data->mac_address, cur_mac_str);

			if (convert_ip_addr_to_str(data->ip_address, data->ip_len, cur_ip_str) < 0) {
				log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
				continue;
			}

			strftime(last_updated, sizeof(last_updated), "%Y-%m-%d %H:%M:%S %z", localtime_r(&data->timestamp, &timeresult));

			log_debug("  cache entry %3lu: %s %16s %18s %s", i, last_updated, data->interface, cur_mac_str, cur_ip_str);
			i++;
		}
	}

	found_match = protect_match(e->mac_address, e->ip_address, e->ip_len);
	if (found_match) {
		char protected_mac_str[MAC_STR_LEN];
		char protected_ip_str[INET6_ADDRSTRLEN];
		int r;

		convert_mac_addr_to_str(found_match->mac_address, protected_mac_str);
		if (e->ip_len == IP4_LEN)
			r = convert_ip4_addr_to_str(found_match->ip4_address, protected_ip_str);
		else
			r = convert_ip6_addr_to_str(found_match->ip6_address, protected_ip_str);
		if (r < 0)
			snprintf(protected_ip_str, sizeof(protected_ip_str), CONVERSION_FAILURE_STR);

		log_warn("Event -- IF = [%s] & MAC = [%s] & IP = [%s] conflicts with protected entry: MAC = [%s] & IP = [%s]", e->interface,
			 mac_str, ip_str, protected_mac_str, protected_ip_str);
		return;
	}

	// just add if the state is empty
	if (state->size == 0) {
		_cleanup_shmlogentry_ struct shm_log_entry *new_data = NULL;

		new_data = malloc(sizeof(struct shm_log_entry));
		if (!new_data) {
			log_oom();
			return;
		}

		memcpy(new_data, e, sizeof(struct shm_log_entry));

		if (dllist_push_back(state, TAKE_PTR(new_data)) < 0) {
			log_oom();
			return;
		}

		log_info("Event -- New initial entry: IF = [%s] & MAC = [%s] & IP = [%s]", e->interface, mac_str, ip_str);
		return;
	}

	now = time(NULL);

	if (state_sync_interval != 0 && last_sync_time + state_sync_interval < now) {
		(void)!write_state_file(state_file_path, state);
		last_sync_time = now;
	}

	for (struct dllist_entry *cur_e = state->first; cur_e;) {
		bool ip_type_match;
		bool ip_match;
		bool mac_match;
		bool if_match;
		struct shm_log_entry *data = cur_e->data;

		assert(data);

		// state entry outdated
		if (data->timestamp + lease_remember_factor * lease_time <= now) {
			if (verbose) {
				char mac_str_del[MAC_STR_LEN];
				char ip_str_del[INET6_ADDRSTRLEN];
				char format_buffer[FMT_TIMESTAMP_SIZE];

				if (convert_ip_addr_to_str(data->ip_address, data->ip_len, ip_str_del) < 0)
					snprintf(ip_str_del, sizeof(ip_str_del), CONVERSION_FAILURE_STR);

				convert_mac_addr_to_str(data->mac_address, mac_str_del);

				log_debug("Event -- deleted outdated cache entry last seen %s: IF = [%s] & MAC = [%s] & IP = [%s]",
					  format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp), data->interface,
					  mac_str_del, ip_str_del);
			}

			cur_e = dllist_delete_entry(state, cur_e);

			continue;
		}

		ip_type_match = (data->ip_len == e->ip_len);
		ip_match = ip_type_match && (0 == memcmp(data->ip_address, e->ip_address, e->ip_len));
		mac_match = (0 == memcmp(data->mac_address, e->mac_address, sizeof e->mac_address));
		if_match = string_eq(data->interface, e->interface);

		// complete match
		if (ip_match && mac_match) {
			log_debug("Event -- complete cache entry match for MAC [%s] & IP [%s]", mac_str, ip_str);

			if (!if_match) {
				log_warn("Event -- IF changed for MAC [%s] & IP [%s] from [%s] to [%s]", mac_str, ip_str, data->interface,
					 e->interface);
				safe_strncpy(data->interface, e->interface, IFNAMSIZ);
			}

			data->timestamp = e->timestamp;

			dllist_promote_entry(state, cur_e);

			// do not add to list -- we updated the entry
			return;
		}

		// only ip match
		if (ip_match) {
			char data_mac_str[MAC_STR_LEN];
			const time_t last_seen_time = now - data->timestamp;
			char format_buffer[FMT_TIMESTAMP_SIZE];

			convert_mac_addr_to_str(data->mac_address, data_mac_str);

			if (if_match) {
				if (lease_time <= last_seen_time)
					log_info("Event -- MAC changed for IP [%s], last seen %s, after a lease time of %" PRIu64
						 " seconds from [%s] to [%s]",
						 ip_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						 last_seen_time, data_mac_str, mac_str);
				else
					log_warn("Event -- MAC changed for IP [%s], last seen %s, from [%s] to [%s]", ip_str,
						 format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp), data_mac_str,
						 mac_str);
			} else {
				if (lease_time <= last_seen_time)
					log_notice("Event -- IF and MAC changed for IP [%s], last seen %s, after a lease time of %" PRIu64
						   " seconds from [%s] & [%s] to [%s] & [%s]",
						   ip_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						   last_seen_time, data->interface, data_mac_str, e->interface, mac_str);
				else
					log_warn("Event -- IF and MAC changed for IP [%s], last seen %s, from [%s] & [%s] to [%s] & [%s]",
						 ip_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						 data->interface, data_mac_str, e->interface, mac_str);
			}

			event_logged = true;
			cur_e = dllist_delete_entry(state, cur_e);

			// add the new entry at the end -- it might collide with other mac addresses as well
			continue;
		}

		// only mac match and ip types match
		if (mac_match && ip_type_match) {
			const time_t last_seen_time = now - data->timestamp;
			char data_ip_str[INET6_ADDRSTRLEN];
			uint8_t other_ip_len = (data->ip_len == IP4_LEN) ? IP6_LEN : IP4_LEN;
			const uint8_t *other_ip;
			char other_ip_str[INET6_ADDRSTRLEN];
			char format_buffer[FMT_TIMESTAMP_SIZE];

			if (convert_ip_addr_to_str(data->ip_address, data->ip_len, data_ip_str) < 0) {
				log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
				cur_e = dllist_delete_entry(state, cur_e);
				continue;
			}

			other_ip = find_ip_address(state, data->interface, data->mac_address, other_ip_len);
			if (other_ip) {
				if (convert_ip_addr_to_str(other_ip, other_ip_len, other_ip_str) < 0) {
					log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
					snprintf(other_ip_str, sizeof(other_ip_str), "error");
				}
			} else
				snprintf(other_ip_str, sizeof(other_ip_str), "none");

			if (if_match) {
				if (lease_time <= last_seen_time)
					log_info("Event -- IP changed for MAC [%s], last seen %s, after a lease time of %" PRIu64
						 " seconds from [%s] to [%s] (other IP [%s])",
						 mac_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						 last_seen_time, data_ip_str, ip_str, other_ip_str);
				else
					log_warn("Event -- IP changed for MAC [%s], last seen %s, from [%s] to [%s] (other IP [%s])",
						 mac_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						 data_ip_str, ip_str, other_ip_str);
			} else {
				if (lease_time <= last_seen_time)
					log_notice("Event -- IF and IP changed for MAC [%s], last seen %s, after a lease time of %" PRIu64
						   " seconds from [%s] & [%s] to [%s] & [%s] (other IP [%s])",
						   mac_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						   last_seen_time, data->interface, data_ip_str, e->interface, ip_str, other_ip_str);

				else
					log_warn(
						"Event -- IF and IP changed for MAC [%s], last seen %s, from [%s] & [%s] to [%s] & [%s] (other IP [%s])",
						mac_str, format_timestamp(format_buffer, sizeof(format_buffer), data->timestamp),
						data->interface, data_ip_str, e->interface, ip_str, other_ip_str);
			}

			event_logged = true;
			cur_e = dllist_delete_entry(state, cur_e);

			// add the new entry at the end -- it might collide with other ip addresses as well
			continue;
		}

		cur_e = cur_e->next;
	}

	// add current entry to the start of the list
	{
		_cleanup_shmlogentry_ struct shm_log_entry *new_data = NULL;

		new_data = malloc(sizeof(struct shm_log_entry));
		if (!new_data) {
			log_oom();
			return;
		}

		memcpy(new_data, e, sizeof(struct shm_log_entry));

		if (dllist_push_front(state, TAKE_PTR(new_data)) < 0) {
			log_oom();
			return;
		}

		if (event_logged)
			log_debug("Event -- added cache entry for IF = [%s] & MAC = [%s] & IP = [%s]", e->interface, mac_str, ip_str);
		else
			log_info("Event -- New entry for IF = [%s] & MAC = [%s] & IP = [%s]", e->interface, mac_str, ip_str);
	}
}

static volatile sig_atomic_t stop_loop = 0;
static void signal_handler(int sig)
{
	log_debug("Signal %s [%d] caught.", strsignal(sig) ?: "(unknown)", sig);
	stop_loop = 1;
}
static int setup_signals(void)
{
	struct sigaction new_sig;
	struct sigaction old_sig;
	new_sig.sa_handler = signal_handler;
	sigemptyset(&new_sig.sa_mask);
	new_sig.sa_flags = SA_RESTART;

	if (sigaction(SIGINT, &new_sig, &old_sig) < 0)
		return log_error("Cannot setup signal handler for SIGINT: %m");

	if (sigaction(SIGTERM, &new_sig, &old_sig) < 0)
		return log_error("Cannot setup signal handler for SIGTERM: %m");

	return 0;
}

static void wrapper_free(void *p)
{
	free_shm_log_entry(p);
}

static int config_accept(const char *key, const char *value, size_t lineno)
{
	if (string_eq("LeaseTime", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || (*endptr != '\0' && !string_eq(endptr, "d")) || res < 1 || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		lease_time = (time_t)res * 24 * 60 * 60;

		return 0;
	}

	if (string_eq("LeaseRememberFactor", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || *endptr != '\0' || res < 1 || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		lease_remember_factor = (unsigned)res;

		return 0;
	}

	if (string_eq("ProtectIP", key))
		return protect_ip(value);

	if (string_eq("ProtectMAC", key))
		return protect_mac(value);

	if (string_eq("ProtectMACIPPairing", key))
		return protect_mac_ip_pairing(value);

	if (string_eq("ShmLogName", key)) {
		if (value[0] != '/' || value[1] == '\0')
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		free(shm_filename);
		shm_filename = strdup(value);
		if (!shm_filename)
			return log_oom();

		return 0;
	}

	if (string_eq("StateSyncInterval", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || (*endptr != '\0' && !string_eq(endptr, "m")) || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		state_sync_interval = (time_t)res;

		return 0;
	}

	return log_error("Unsupported configuration option '%s' at line %zu (with value '%s').", key, lineno, value);
}

static void usage(void)
{
	printf("Usage: " CHECK_ARGV0 " [OPTIONS]\n"
	       "Daemon to check for suspicious address events.\n\n"
	       "  -c, --config=FILE          Override the default configuration file (" DEFAULT_CONFIG_PATH ").\n"
	       "  -h, --help                 Display this menu.\n"
	       "  -s, --state=FILE           Override the default state file (" CHECK_DEFAULT_STATE_FILE ").\n"
	       "      --syslog               Log via syslog (Default is stderr).\n"
	       "  -v, --verbose              Enable verbose output.\n"
	       "  -V, --version              Show version information and exit.\n");
}

#define ARG_SYSLOG 128

int main(int argc, char *argv[])
{
	int rc;
	const char *config_path = DEFAULT_CONFIG_PATH;
	_cleanup_close_ int state_fd = -1;
	enum log_mode lmode = LOG_MODE_STDERR;
	_cleanup_dllist_ struct dllist_head *current_state = NULL;

	const struct option long_options[] = {
		{"config", required_argument, NULL, 'c'},
		{"help", no_argument, NULL, 'h'},
		{"state", required_argument, NULL, 's'},
		{"syslog", no_argument, NULL, ARG_SYSLOG},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0},
	};

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "c:hs:Vv", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			break;

		case 'c':
			config_path = optarg;
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 's':
			state_file_path = optarg;
			break;

		case 'V':
			printf("%s %s\n", CHECK_ARGV0, VERSION);
			exit(EXIT_SUCCESS);

		case 'v':
			verbose = true;
			break;

		case ARG_SYSLOG:
			lmode = LOG_MODE_SYSLOG;
			break;

		case '?':
		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	log_open(CHECK_ARGV0);
	log_mode(lmode);
	if (verbose)
		log_max_priority(LOG_DEBUG);

	if (parse_config_file(config_path, config_accept) < 0)
		return EXIT_FAILURE;

	log_info("Loaded %zu protected entries.", protect_list_size());

	state_fd = lock_state_file(state_file_path);
	if (state_fd < 0)
		return EXIT_FAILURE;

	current_state = dllist_init(wrapper_free);
	if (!current_state) {
		log_oom();
		return EXIT_FAILURE;
	}

	if (read_state_file(state_file_path, current_state) < 0)
		return EXIT_FAILURE;

	if (getuid() == 0 || geteuid() == 0)
		log_notice("%s is not recommend to run with root privileges.", CHECK_ARGV0);


	last_sync_time = time(NULL);

	if (setup_signals() < 0)
		return EXIT_FAILURE;

#ifdef NDEBUG
	log_info("Starting %s", CHECK_ARGV0);
#else
	log_info("Starting %s (asserts enabled)", CHECK_ARGV0);
#endif

	rc = main_loop(process_entry, &stop_loop, current_state);

	log_info("Stopping %s", CHECK_ARGV0);

	(void)!write_state_file(state_file_path, current_state);

	free_protect_list();

	free(shm_filename);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
