#include <assert.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arpobserver.h"
#include "check_packet.h"
#include "configfile.h"
#include "daemonize.h"
#include "log.h"
#include "mcache.h"
#include "output_flatfile.h"
#include "output_shm.h"
#include "output_sqlite.h"
#include "parse.h"
#include "process.h"
#include "shm.h"
#include "storage.h"
#include "util.h"

#define MAIN_ARGV0           "arpobserverd"
#define DEFAULT_CONFIG_PATH  SYSCONFDIR "/" PACKAGE "/main.conf"
#define DEFAULT_SHM_LOG_SIZE 1024


struct arpobserver_config global_cfg;

static const char *const ip4_filter = "arp";
static const char *const ip6_filter = "ip6 and not tcp and not udp and not esp and not ah";
static const char *const def_filter = "ip6 and not tcp and not udp and not esp and not ah or arp";

static int drop_root(const char *uname)
{
	const struct passwd *pw;

	assert(uname);

	pw = getpwnam(uname);
	if (!pw) {
		char *endptr;
		unsigned long res;

		errno = 0;
		res = strtoul(uname, &endptr, 10);
		if (res < INT_MAX && errno == 0 && *endptr == '\0')
			pw = getpwuid((uid_t)res);

		if (!pw)
			return log_error("User '%s' not found: %m", uname);
	}

	if (initgroups(uname, pw->pw_gid) < 0)
		return log_error("Cannot set initial groups of user '%s' and gid %d: %m", uname, pw->pw_gid);

	if (setgid(pw->pw_gid) < 0)
		return log_error("Cannot switch groud id to %d: %m", pw->pw_gid);

	if (setuid(pw->pw_uid) < 0)
		return log_error("Cannot switch user id to %d: %m", pw->pw_uid);

	if (setuid(0) != -1)
		return log_errno_error(EEXIST, "Failed to switch to user '%s' (uid=%d, gid=%d) permanently; able to switch back!",
				       pw->pw_name ?: uname, pw->pw_uid, pw->pw_gid);

	log_info("Changed user to '%s', uid = %d, gid = %d", pw->pw_name ?: uname, pw->pw_uid, pw->pw_gid);

	return 0;
}

static void pcap_callback(const struct iface_config *ifc, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	struct pkt p;
	int rc;

	assert(ifc);
	assert(header);
	assert(packet);

	memset(&p, 0, sizeof(p));

	p.raw_packet = packet;

	p.pos = packet;
	p.len = header->caplen;

	p.ifc = ifc;
	p.pcap_header = header;

	rc = parse_packet(&p);
	if (rc < 0)
		return;

	switch (p.kind) {
	case KIND_ARP:
		if (!check_arp(&p))
			process_arp(&p);
		break;
	case KIND_NA:
		if (!check_na(&p))
			process_na(&p);
		break;
	case KIND_NS:
		if (!check_ns(&p))
			process_ns(&p);
		break;
	case KIND_RA:
		if (!check_ra(&p))
			process_ra(&p);
		break;
	case KIND_RS:
		if (!check_rs(&p))
			process_rs(&p);
		break;
	default:
		log_error("Invalid parsed packet type: %d\n", p.kind);
		break;
	}
}

static unsigned timeout_cycles_without_packets = 0;

static void read_cb(_unused_ evutil_socket_t fd, _unused_ short events, void *arg)
{
	struct pcap_pkthdr header;
	const uint8_t *packet;
	struct iface_config *ifc = arg;

	assert(ifc);

	timeout_cycles_without_packets = 0;

	packet = pcap_next(ifc->pcap_handle, &header);

	if (!packet)
		return;

	pcap_callback(ifc, &header, packet);
}

static int add_iface(const char *iface)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char const *filter;
	_cleanup_iface_config_ struct iface_config *ifc = NULL;
	int rc;

	assert(iface);

	if (global_cfg.v4_flag)
		filter = ip4_filter;
	else if (global_cfg.v6_flag)
		filter = ip6_filter;
	else
		filter = def_filter;

	ifc = calloc(1, sizeof(struct iface_config));
	if (!ifc)
		return log_oom();

	ifc->name = strdup(iface);
	if (!ifc->name)
		return log_oom();

	if (global_cfg.hashsize < 1 || global_cfg.hashsize > 65536)
		return log_errno_error(EINVAL, "Hash size (%d) must be >= 1 and <= 65536", global_cfg.hashsize);

	if (global_cfg.ratelimit) {
		ifc->cache = calloc(global_cfg.hashsize, sizeof(struct mcache_node));
		if (!ifc->cache)
			return log_oom();
	}

	ifc->pcap_handle = pcap_open_live(iface, SNAP_LEN, global_cfg.promisc_flag, 1000, errbuf);
	if (ifc->pcap_handle == NULL) {
		if (global_cfg.all_interfaces)
			log_info("Skipping interface %s: cannot open: %s", iface, errbuf);
		else
			log_warn("Skipping interface %s: cannot open: %s", iface, errbuf);
		return 0;
	}

	rc = pcap_datalink(ifc->pcap_handle);
	if (rc != DLT_EN10MB) {
		if (global_cfg.all_interfaces)
			log_info("Skipping interface %s: invalid data link layer %s (%s).", iface, pcap_datalink_val_to_name(rc),
				 pcap_datalink_val_to_description(rc));
		else
			log_warn("Skipping interface %s: invalid data link layer %s (%s).", iface, pcap_datalink_val_to_name(rc),
				 pcap_datalink_val_to_description(rc));
		return 0;
	}

	rc = pcap_compile(ifc->pcap_handle, &ifc->pcap_filter, filter, 0, 0);
	if (rc == -1) {
		if (global_cfg.all_interfaces)
			log_info("Skipping interface %s: cannot compile filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		else
			log_warn("Skipping interface %s: cannot compile filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		return 0;
	}

	rc = pcap_setfilter(ifc->pcap_handle, &ifc->pcap_filter);
	if (rc == -1) {
		if (global_cfg.all_interfaces)
			log_info("Skipping iface %s: cannot set filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		else
			log_warn("Skipping iface %s: cannot set filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		return 0;
	}
	ifc->filter_active = 0;

	rc = pcap_fileno(ifc->pcap_handle);
	assert(rc != -1);

	ifc->event = event_new(global_cfg.eb, rc, EV_READ | EV_PERSIST, read_cb, ifc);
	if (!ifc->event)
		return log_error("Failed to create new event for interface %s: %m", ifc->name);

	if (event_add(ifc->event, NULL) < 0) {
		log_error("Failed to add event for interface %s: %m", ifc->name);
		event_free(ifc->event);
		ifc->event = NULL;
		return -1;
	}

	log_info("Opened interface %s (%s).", iface, pcap_datalink_val_to_description(pcap_datalink(ifc->pcap_handle)));

	ifc->next = global_cfg.interfaces;
	global_cfg.interfaces = TAKE_PTR(ifc);

	return 0;
}

static struct iface_config *del_iface(struct iface_config *ifc)
{
	struct iface_config *next = ifc->next;

	event_free(ifc->event);
	ifc->event = NULL;
	pcap_freecode(&ifc->pcap_filter);
	pcap_close(ifc->pcap_handle);
	ifc->pcap_handle = NULL;

	log_debug("Closed interface %s", ifc->name);

	if (ifc->cache) {
		for (unsigned i = 0; i < global_cfg.hashsize; i++) {
			if (*(ifc->cache + i))
				cache_prune(*(ifc->cache + i), ifc->cache + i);
		}
		free(ifc->cache);
	}

	free(ifc->name);
	free(ifc);

	return next;
}

static void reload_cb(evutil_socket_t fd, _unused_ short events, _unused_ void *arg)
{
	log_debug("Received signal (%d), %s", fd, strsignal(fd));
	log_debug("Reopening output");

	(void)!output_flatfile_reload();
	(void)!output_sqlite_reload();
	(void)!output_shm_reload();
}

static void stop_cb(evutil_socket_t fd, _unused_ short events, _unused_ void *arg)
{
	log_debug("Received signal (%d), %s", fd, strsignal(fd));
	log_debug("Stopping output");

	if (event_base_loopbreak(global_cfg.eb) < 0)
		log_warn("event_base_loopbreak() failed: %m");
}

static void timeout_cb(_unused_ evutil_socket_t fd, _unused_ short events, _unused_ void *arg)
{
	log_debug("Timeout occurred.");

	(void)!output_shm_timeout();

	if (timeout_cycles_without_packets > NO_PACKET_TIMEOUT_MULTIPLIER) {
		static time_t last_notified = 0;

		if (time(NULL) - last_notified > 5 * 60) {
			last_notified = time(NULL);
			log_warn("No packet received for %u seconds, timeout is %u seconds", timeout_cycles_without_packets * TIMEOUT_SEC,
				 (NO_PACKET_TIMEOUT_MULTIPLIER + 1) * TIMEOUT_SEC);
		}
	}

	timeout_cycles_without_packets++;
}

static int libevent_init(void)
{
	const struct timeval timeout = {.tv_sec = TIMEOUT_SEC, .tv_usec = 0};

	/* init */
	global_cfg.eb = event_base_new();
	if (!global_cfg.eb)
		return log_error("Failed to create new base event: %m");

	/* SIGINT */
	global_cfg.sigint_ev = event_new(global_cfg.eb, SIGINT, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	if (!global_cfg.sigint_ev)
		return log_error("Failed to create new event for SIGINT: %m");
	if (event_add(global_cfg.sigint_ev, NULL) < 0)
		return log_error("Failed to add new event for SIGINT: %m");

	/* SIGTERM */
	global_cfg.sigterm_ev = event_new(global_cfg.eb, SIGTERM, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	if (!global_cfg.sigterm_ev)
		return log_error("Failed to create new event for SIGTERM: %m");
	if (event_add(global_cfg.sigterm_ev, NULL) < 0)
		return log_error("Failed to add new event for SIGTERM: %m");


	/* SIGHUP */
	global_cfg.sighup_ev = event_new(global_cfg.eb, SIGHUP, EV_SIGNAL | EV_PERSIST, reload_cb, NULL);
	if (!global_cfg.sighup_ev)
		return log_error("Failed to create new event for SIGHUP: %m");
	if (event_add(global_cfg.sighup_ev, NULL) < 0)
		return log_error("Failed to add new event for SIGHUP: %m");

	/* timeout */
	global_cfg.timeout_ev = event_new(global_cfg.eb, -1, EV_PERSIST, timeout_cb, NULL);
	if (!global_cfg.sighup_ev)
		return log_error("Failed to create new event for timeout: %m");
	if (event_add(global_cfg.timeout_ev, &timeout) < 0)
		return log_error("Failed to add new event for timeout: %m");

	return 0;
}

static void libevent_close(void)
{
	event_free(global_cfg.timeout_ev);
	event_free(global_cfg.sigint_ev);
	event_free(global_cfg.sigterm_ev);
	event_free(global_cfg.sighup_ev);

	event_base_free(global_cfg.eb);
}

static void save_pid(void)
{
	FILE *f;

	if (!global_cfg.pid_file)
		return;

	f = fopen(global_cfg.pid_file, "we");
	if (!f) {
		log_error("Cannot open pid file '%s': %m", global_cfg.pid_file);
		return;
	}

	fprintf(f, "%d\n", getpid());

	if (fclose(f) != 0)
		log_error("Failure during closing pid file '%s': %m", global_cfg.pid_file);
}

static void del_pid(void)
{
	if (!global_cfg.pid_file)
		return;

	if (unlink(global_cfg.pid_file) < 0)
		log_warn("Cannot delete pid file '%s': %m", global_cfg.pid_file);
}

static int config_accept(const char *key, const char *value, size_t lineno)
{
	if (string_eq("ArpBridge", key)) {
		if (value[0] == '\0')
			return 0;

		return arpbridgelist_add(value);
	}

	if (string_eq("HashSize", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || *endptr != '\0' || res < 1 || res >= 65536)
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		global_cfg.hashsize = (unsigned)res;

		return 0;
	}

	if (string_eq("IgnoreIP", key)) {
		if (value[0] == '\0')
			return 0;

		return ignorelist_add_ip(value);
	}

	if (string_eq("IPMode", key)) {
		if (string_eq("all", value)) {
			global_cfg.v4_flag = false;
			global_cfg.v6_flag = false;

			return 0;
		}

		if (string_eq("ipv4", value)) {
			global_cfg.v4_flag = true;
			global_cfg.v6_flag = false;

			return 0;
		}

		if (string_eq("ipv6", value)) {
			global_cfg.v4_flag = false;
			global_cfg.v6_flag = true;

			return 0;
		}

		return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
	}

	if (string_eq("Promisc", key)) {
		if (string_eq("yes", value)) {
			global_cfg.promisc_flag = 1;

			return 0;
		}

		if (string_eq("no", value)) {
			global_cfg.promisc_flag = 0;

			return 0;
		}

		return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
	}

	if (string_eq("RateLimit", key)) {
		char *endptr;
		long int res = strtol(value, &endptr, 10);
		if (res == LONG_MAX || *endptr != '\0' || res < -1 || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		global_cfg.ratelimit = (int)res;

		return 0;
	}


	if (string_eq("ShmLogName", key)) {
		if (value[0] != '/' || value[1] == '\0')
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		free(global_cfg.shm_data.filename);
		global_cfg.shm_data.filename = strdup(value);
		if (!global_cfg.shm_data.filename)
			return log_oom();

		return 0;
	}

	if (string_eq("ShmLogSize", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || *endptr != '\0' || res < 1 || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s at line %zu.", value, key, lineno);
		global_cfg.shm_data.size = res;

		return 0;
	}

#ifdef HAVE_LIBSQLITE3
	if (string_eq("Sqlite3File", key)) {
		if (value[0] == '\0')
			return 0;

		free(global_cfg.sqlite_filename);
		global_cfg.sqlite_filename = strdup(value);
		if (!global_cfg.sqlite_filename)
			return log_oom();

		return 0;
	}

	if (string_eq("Sqlite3Table", key)) {
		size_t len = strlen(value);
		if (len >= 64)
			return log_error("Invalid value '%s' (too long: %zu > 64) for option %s at line %zu.", value, len, key, lineno);

		free(global_cfg.sqlite_tablename);
		global_cfg.sqlite_tablename = strdup(value);
		if (!global_cfg.sqlite_tablename)
			return log_oom();

		return 0;
	}
#endif /* HAVE_LIBSQLITE3 */

	return log_error("Unsupported configuration option '%s' at line %zu (with value '%s').", key, lineno, value);
}

static void usage(void)
{
	printf("Usage: " MAIN_ARGV0 " [OPTIONS] [INTERFACES]\n"
	       "Keep track of ethernet/ip address pairings for IPv4 and IPv6.\n"
	       "\n"
	       " Options for data output:\n"
	       "  -o, --output=FILE          Output data to plain text FILE.\n"
	       "  -v, --verbose              Enable verbose output.\n"
	       "\n"
	       " Misc options:\n"
	       "  -A, --all-interfaces       Capture on all available interfaces by default.\n"
	       "  -c, --config=FILE          Read the configuration from FILE (default: %s).\n"
	       "  -d, --daemon               Start as a daemon.\n"
	       "  -L, --list-interfaces      List all available interfaces and exit.\n"
	       "  -p, --pid=FILE             Write process id to FILE.\n"
	       "      --syslog               Log to syslog instead of stderr.\n"
	       "  -u, --user=USER            Switch to USER after opening network interfaces.\n"
	       "\n"
	       "  -h, --help                 Display this help and exit.\n"
	       "  -V, --version              Show version information and exit.\n"
	       "\n"
	       "If no interfaces given and '-A' not used, the first non loopback interface is used.\n",
	       DEFAULT_CONFIG_PATH);
}

static int list_interfaces(void)
{
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];
	int r;

	r = pcap_findalldevs(&alldevsp, errbuf);
	if (r != 0) {
		fprintf(stderr, "Error while getting list of interface devices: %s", errbuf);
		return EXIT_FAILURE;
	}

	if (alldevsp) {
		unsigned i = 1;
		for (const pcap_if_t *devsp = alldevsp; devsp; devsp = devsp->next) {
			if (devsp->flags & PCAP_IF_LOOPBACK)
				continue;

			printf(" %2u: %32s - %s\n", i++, devsp->name, devsp->description ?: "");
		}
	} else {
		printf("No interfaces available.\n");
	}

	pcap_freealldevs(alldevsp);

	return EXIT_SUCCESS;
}

#define ARG_SYSLOG 128

int main(int argc, char *argv[])
{
	bool syslog = false;
	bool verbose = false;
	const char *config_path = DEFAULT_CONFIG_PATH;

	// clang-format off
	const struct option long_options[] = {
		{"all-interfaces",  no_argument,       NULL, 'A'},
		{"config",          required_argument, NULL, 'c'},
		{"daemon",          no_argument,       NULL, 'd'},
		{"help",            no_argument,       NULL, 'h'},
		{"list-interfaces", no_argument,       NULL, 'L'},
		{"output",          required_argument, NULL, 'o'},
		{"pid",             required_argument, NULL, 'p'},
		{"syslog",          no_argument,       NULL, ARG_SYSLOG},
		{"user",            required_argument, NULL, 'u'},
		{"verbose",         no_argument,       NULL, 'v'},
		{"version",         no_argument,       NULL, 'V'},
		{0, 0, 0, 0},
	};
	// clang-format on

	/* Default configuration */
	memset(&global_cfg, 0, sizeof(global_cfg));
	global_cfg.all_interfaces = false;
	global_cfg.daemon_flag = false;
	global_cfg.ratelimit = 0;
	global_cfg.hashsize = 1;
	global_cfg.promisc_flag = 1;
	global_cfg.ratelimit = 0;
	global_cfg.sqlite_filename = NULL;
	global_cfg.uname = NULL;
	global_cfg.shm_data.size = DEFAULT_SHM_LOG_SIZE;
	global_cfg.shm_data.filename = NULL;
	global_cfg.v4_flag = false;
	global_cfg.v6_flag = false;
#ifdef HAVE_LIBSQLITE3
	global_cfg.sqlite_tablename = NULL;
#endif

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "Ac:dhLo:p:u:vV", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;

		case 'A':
			global_cfg.all_interfaces = true;
			break;

		case 'c':
			config_path = optarg;
			break;

		case 'd':
			global_cfg.daemon_flag = true;
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

		case 'L':
			exit(list_interfaces());

		case 'o':
			global_cfg.data_file = optarg;
			break;

		case 'p':
			global_cfg.pid_file = optarg;
			break;

		case ARG_SYSLOG:
			syslog = true;
			break;

		case 'u':
			global_cfg.uname = optarg;
			break;

		case 'v':
			verbose = true;
			break;

		case 'V':
			printf("%s %s\n", MAIN_ARGV0, VERSION);
			exit(EXIT_SUCCESS);

		default:
			usage();
			exit(EXIT_FAILURE);
		}
	}

	log_open(MAIN_ARGV0);

	if (global_cfg.daemon_flag) {
		log_mode(LOG_MODE_SYSLOG);

		if (daemonize(NULL) < 0)
			return EXIT_FAILURE;
	} else if (syslog)
		log_mode(LOG_MODE_SYSLOG);

	if (verbose)
		log_max_priority(LOG_DEBUG);

	if (parse_config_file(config_path, config_accept) < 0)
		return EXIT_FAILURE;

	save_pid();

	if (libevent_init() < 0)
		return EXIT_FAILURE;

	if (global_cfg.ratelimit > 0)
		log_debug("Ratelimiting duplicate entries to 1 per %d seconds.", global_cfg.ratelimit);
	else if (global_cfg.ratelimit == -1)
		log_debug("Duplicate entries suppressed indefinitely.");
	else
		log_debug("Duplicate entries ratelimiting disabled.");

	if (global_cfg.promisc_flag)
		log_info("PROMISC mode enabled.");
	else
		log_info("PROMISC mode disabled.");

	if (optind < argc) {
		global_cfg.all_interfaces = false;
		for (int i = optind; i < argc; i++)
			add_iface(argv[i]);
	} else {
		pcap_if_t *alldevsp;
		char errbuf[PCAP_ERRBUF_SIZE];
		int r;

		r = pcap_findalldevs(&alldevsp, errbuf);
		if (r != 0) {
			log_error("Error while getting list of interface devices: %s", errbuf);
			return EXIT_FAILURE;
		}

		if (alldevsp) {
			if (global_cfg.all_interfaces) {
				for (const pcap_if_t *devsp = alldevsp; devsp; devsp = devsp->next) {
					if (devsp->flags & PCAP_IF_LOOPBACK)
						continue;

					add_iface(devsp->name);
				}
			} else
				add_iface(alldevsp->name);
		}

		pcap_freealldevs(alldevsp);
	}

	if (!global_cfg.interfaces) {
		log_error("No suitable interfaces found!");
		return EXIT_FAILURE;
	}

	if (global_cfg.uname) {
		if (drop_root(global_cfg.uname) < 0)
			return EXIT_FAILURE;
	} else
		log_notice("Not dropping root permissions.");

	if (output_flatfile_init() < 0)
		return EXIT_FAILURE;

	if (output_sqlite_init() < 0)
		return EXIT_FAILURE;

	if (output_shm_init() < 0)
		return EXIT_FAILURE;

#ifdef NDEBUG
	log_info("Starting %s v%s..", MAIN_ARGV0, VERSION);
#else
	log_info("Starting %s v%s (asserts enabled)..", MAIN_ARGV0, VERSION);
#endif

	/* main loop */
	if (event_base_dispatch(global_cfg.eb) < 0)
		log_error("Event loop failed: %m");

	log_info("Stopping %s..", MAIN_ARGV0);

	output_shm_close();
	output_sqlite_close();
	output_flatfile_close();

	for (struct iface_config *ifc = global_cfg.interfaces; ifc; ifc = del_iface(ifc)) {}

	libevent_close();
	log_close();

	del_pid();
	ignorelist_free();
	arpbridgelist_free();

	free(global_cfg.shm_data.filename);
	free(global_cfg.sqlite_filename);
	free(global_cfg.sqlite_tablename);

	return EXIT_SUCCESS;
}
