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

#define MAIN_ARGV0           "arpobserverd"
#define DEFAULT_CONFIG_PATH  SYSCONFDIR "/" PACKAGE "/main.conf"
#define DEFAULT_SHM_LOG_SIZE 1024


struct arpobserver_config global_cfg;

// TODO: review
static const char *const ip4_filter = "arp";
static const char *const ip6_filter = "ip6 and not tcp and not udp and not esp and not ah";
static const char *const def_filter = "ip6 and not tcp and not udp and not esp and not ah or arp";

static int drop_root(const char *uname)
{
	struct passwd *pw;

	assert(uname);

	pw = getpwnam(uname);

	if (!pw)
		return log_error("User '%s' not found: %m", uname);

	if (initgroups(uname, pw->pw_gid) < 0)
		return log_error("Cannot set initial groups of user '%s' and gid %d: %m", uname, pw->pw_gid);

	if (setgid(pw->pw_gid) < 0)
		return log_error("Cannot switch groud id to %d: %m", pw->pw_gid);

	if (setuid(pw->pw_uid) < 0)
		return log_error("Cannot switch user id to %d: %m", pw->pw_uid);

	if (setuid(0) != -1)
		return log_errno_error(EEXIST, "Failed to switch to user '%s' (uid=%d, gid=%d) permanently; able to switch back!", uname,
				       pw->pw_uid, pw->pw_gid);

	log_debug("Changed user to '%s', uid = %d, gid = %d", uname, pw->pw_uid, pw->pw_gid);

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

	if (p.arp) {
		if (!check_arp(&p))
			process_arp(&p);
	} else if (p.ns) {
		if (!check_ns(&p))
			process_ns(&p);
	} else if (p.na) {
		if (!check_na(&p))
			process_na(&p);
	} else if (p.ra) {
		if (!check_ra(&p))
			process_ra(&p);
	} else if (p.rs) {
		if (!check_rs(&p))
			process_rs(&p);
	}
}

static unsigned timeout_cycles_without_packets = 0;

#if HAVE_LIBEVENT2
static void read_cb(evutil_socket_t fd, short events, void *arg)
#else
static void read_cb(int fd, short events, void *arg)
#endif
{
	struct pcap_pkthdr header;
	const uint8_t *packet;
	struct iface_config *ifc = arg;

	assert(ifc);

	timeout_cycles_without_packets = 0;

	packet = pcap_next(ifc->pcap_handle, &header);

	if (packet)
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
		return log_errno_error(EINVAL, "%s: hash size (%d) must be >= 1 and <= 65536", __FUNCTION__, global_cfg.hashsize);

	if (global_cfg.ratelimit) {
		ifc->cache = calloc((unsigned)global_cfg.hashsize, sizeof(struct mcache_node));
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

#if HAVE_LIBEVENT2
	ifc->event = event_new(global_cfg.eb, rc, EV_READ | EV_PERSIST, read_cb, ifc);
	if (!ifc->event) {
		log_error("%s: event_new(...)", __FUNCTION__);
		return -1;
	}

	event_add(ifc->event, NULL);
#else
	event_set(&ifc->event, rc, EV_READ | EV_PERSIST, read_cb, ifc);
	event_add(&ifc->event, NULL);
#endif

	log_info("Opened interface %s (%s).", iface, pcap_datalink_val_to_description(pcap_datalink(ifc->pcap_handle)));

	ifc->next = global_cfg.interfaces;
	global_cfg.interfaces = TAKE_PTR(ifc);

	return 0;
}

static struct iface_config *del_iface(struct iface_config *ifc)
{
	struct iface_config *next = ifc->next;

#if HAVE_LIBEVENT2
	event_free(ifc->event);
#endif
	pcap_freecode(&ifc->pcap_filter);
	pcap_close(ifc->pcap_handle);

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

#if HAVE_LIBEVENT2
static void reload_cb(evutil_socket_t fd, short events, void *arg)
#else
static void reload_cb(int fd, short events, void *arg)
#endif
{
	log_debug("Received signal (%d), %s", fd, strsignal(fd));
	log_debug("Reopening output");

	(void)!output_flatfile_reload();
	(void)!output_sqlite_reload();
	(void)!output_shm_reload();
}

#if HAVE_LIBEVENT2
static void stop_cb(evutil_socket_t fd, short events, void *arg)
#else
static void stop_cb(int fd, short events, void *arg)
#endif
{
	log_debug("Received signal (%d), %s", fd, strsignal(fd));
	log_debug("Stopping output");

#if HAVE_LIBEVENT2
	event_base_loopbreak(global_cfg.eb);
#else
	event_loopbreak();
#endif
}

#if HAVE_LIBEVENT2
static void timeout_cb(evutil_socket_t fd, short events, void *arg)
#else
static void timeout_cb(int fd, short events, void *arg)
#endif
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
	// TODO: error handling of event functions

	struct timeval timeout = {.tv_sec = TIMEOUT_SEC, .tv_usec = 0};   // non-const for libevent 1.4

	/* init */
#if HAVE_LIBEVENT2
	global_cfg.eb = event_base_new();

	if (!global_cfg.eb) {
		log_error("%s: event_base_new() failed", __FUNCTION__);
		return -1;
	}
#else
	event_init();
#endif

	/* SIGINT */
#if HAVE_LIBEVENT2
	global_cfg.sigint_ev = event_new(global_cfg.eb, SIGINT, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(global_cfg.sigint_ev, NULL);
#else
	event_set(&global_cfg.sigint_ev, SIGINT, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(&global_cfg.sigint_ev, NULL);
#endif

	/* SIGTERM */
#if HAVE_LIBEVENT2
	global_cfg.sigterm_ev = event_new(global_cfg.eb, SIGTERM, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(global_cfg.sigterm_ev, NULL);
#else
	event_set(&global_cfg.sigterm_ev, SIGTERM, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(&global_cfg.sigterm_ev, NULL);
#endif

	/* SIGHUP */
#if HAVE_LIBEVENT2
	global_cfg.sighup_ev = event_new(global_cfg.eb, SIGHUP, EV_SIGNAL | EV_PERSIST, reload_cb, NULL);
	event_add(global_cfg.sighup_ev, NULL);
#else
	event_set(&global_cfg.sighup_ev, SIGHUP, EV_SIGNAL | EV_PERSIST, reload_cb, NULL);
	event_add(&global_cfg.sighup_ev, NULL);
#endif

	/* timeout */
#if HAVE_LIBEVENT2
	global_cfg.timeout_ev = event_new(global_cfg.eb, -1, EV_PERSIST, timeout_cb, NULL);
	event_add(global_cfg.timeout_ev, &timeout);
#else
	event_set(&global_cfg.timeout_ev, -1, EV_PERSIST, timeout_cb, NULL);
	event_add(&global_cfg.timeout_ev, &timeout);
#endif

	return 0;
}

static void libevent_close(void)
{
#if HAVE_LIBEVENT2
	event_free(global_cfg.sigint_ev);
	event_free(global_cfg.sigterm_ev);
	event_free(global_cfg.sighup_ev);

	event_base_free(global_cfg.eb);
#endif
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
	fclose(f);
}

static void del_pid(void)
{
	if (!global_cfg.pid_file)
		return;

	if (unlink(global_cfg.pid_file) < 0)
		log_warn("Cannot delete pid file '%s': %m", global_cfg.pid_file);
}

static int config_accept(const char *key, const char *value)
{
	if (0 == strcmp("HashSize", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || *endptr != '\0' || res < 1 || res >= 65536)
			return log_error("Invalid value '%s' for option %s.", value, key);
		global_cfg.hashsize = (unsigned)res;

		return 0;
	}

	if (0 == strcmp("IgnoreIP", key)) {
		if (value[0] == '\0')
			return 0;

		return ignorelist_add_ip(optarg);
	}

	if (0 == strcmp("IPMode", key)) {
		if (0 == strcmp("all", value)) {
			global_cfg.v4_flag = false;
			global_cfg.v6_flag = false;

			return 0;
		}

		if (0 == strcmp("ipv4", value)) {
			global_cfg.v4_flag = true;
			global_cfg.v6_flag = false;

			return 0;
		}

		if (0 == strcmp("ipv6", value)) {
			global_cfg.v4_flag = false;
			global_cfg.v6_flag = true;

			return 0;
		}

		return log_error("Invalid value '%s' for option %s.", value, key);
	}

	if (0 == strcmp("Promisc", key)) {
		if (0 == strcmp("yes", value)) {
			global_cfg.promisc_flag = 1;

			return 0;
		}

		if (0 == strcmp("no", value)) {
			global_cfg.promisc_flag = 0;

			return 0;
		}

		return log_error("Invalid value '%s' for option %s.", value, key);
	}

	if (0 == strcmp("RateLimit", key)) {
		char *endptr;
		long int res = strtol(value, &endptr, 10);
		if (res == LONG_MAX || *endptr != '\0' || res < -1 || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s.", value, key);
		global_cfg.ratelimit = (int)res;

		return 0;
	}


	if (0 == strcmp("ShmLogName", key)) {
		if (value[0] != '/' || value[1] == '\0')
			return log_error("Invalid value '%s' for option %s.", value, key);
		free(global_cfg.shm_data.filename);
		global_cfg.shm_data.filename = strdup(value);
		if (!global_cfg.shm_data.filename)
			return log_oom();

		return 0;
	}

	if (0 == strcmp("ShmLogSize", key)) {
		char *endptr;
		unsigned long int res = strtoul(value, &endptr, 10);
		if (res == ULONG_MAX || *endptr != '\0' || res < 1 || res >= INT_MAX)
			return log_error("Invalid value '%s' for option %s.", value, key);
		global_cfg.shm_data.size = res;

		return 0;
	}

#if HAVE_LIBSQLITE3
	if (0 == strcmp("Sqlite3File", key)) {
		if (value[0] == '\0')
			return 0;

		free(global_cfg.sqlite_filename);
		global_cfg.sqlite_filename = strdup(value);
		if (!global_cfg.sqlite_filename)
			return log_oom();

		return 0;
	}

	if (0 == strcmp("Sqlite3Table", key)) {
		free(global_cfg.sqlite_tablename);
		global_cfg.sqlite_tablename = strdup(value);
		if (!global_cfg.sqlite_tablename)
			return log_oom();

		return 0;
	}
#endif /* HAVE_LIBSQLITE3 */

	return log_error("Unsupported configuration option '%s' (with value '%s').", key, value);
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

#define ARG_SYSLOG 128

int main(int argc, char *argv[])
{
	bool syslog = false;
	bool verbose = false;
	const char *config_path = DEFAULT_CONFIG_PATH;

	const struct option long_options[] = {
		{"all-interfaces", no_argument, NULL, 'A'},
		{"config", required_argument, NULL, 'c'},
		{"daemon", no_argument, NULL, 'd'},
		{"help", no_argument, NULL, 'h'},
		{"output", required_argument, NULL, 'o'},
		{"pid", required_argument, NULL, 'p'},
		{"syslog", no_argument, NULL, ARG_SYSLOG},
		{"user", required_argument, NULL, 'u'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0},
	};

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
#if HAVE_LIBSQLITE3
	global_cfg.sqlite_tablename = NULL;
#endif

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "Ac:dho:p:u:vV", long_options, &option_index);

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
	log_info("Starting %s..", MAIN_ARGV0);
#else
	log_info("Starting %s (asserts enabled)..", MAIN_ARGV0);
#endif

	/* main loop */
#if HAVE_LIBEVENT2
	event_base_dispatch(global_cfg.eb);
#else
	event_dispatch();
#endif

	log_info("Stopping %s..", MAIN_ARGV0);

	output_shm_close();
	output_sqlite_close();
	output_flatfile_close();

	for (struct iface_config *ifc = global_cfg.interfaces; ifc; ifc = del_iface(ifc)) {}

	libevent_close();
	log_close();

	del_pid();
	ignorelist_free();

	free(global_cfg.shm_data.filename);
	free(global_cfg.sqlite_filename);
	free(global_cfg.sqlite_tablename);

	return EXIT_SUCCESS;
}
