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
#define DEFAULT_SHM_LOG_SIZE 1024


struct arpobserver_config cfg;

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

	if (cfg.v4_flag)
		filter = ip4_filter;
	else if (cfg.v6_flag)
		filter = ip6_filter;
	else
		filter = def_filter;

	ifc = calloc(1, sizeof(struct iface_config));
	if (!ifc)
		return log_oom();

	ifc->name = strdup(iface);
	if (!ifc->name)
		return log_oom();

	if (cfg.hashsize < 1 || cfg.hashsize > 65536)
		return log_errno_error(EINVAL, "%s: hash size (%d) must be >= 1 and <= 65536", __FUNCTION__, cfg.hashsize);

	if (cfg.ratelimit) {
		ifc->cache = calloc((unsigned)cfg.hashsize, sizeof(struct mcache_node));
		if (!ifc->cache)
			return log_oom();
	}

	ifc->pcap_handle = pcap_open_live(iface, SNAP_LEN, cfg.promisc_flag, 1000, errbuf);
	if (ifc->pcap_handle == NULL) {
		if (cfg.all_interfaces)
			log_info("Skipping interface %s: cannot open: %s", iface, errbuf);
		else
			log_warn("Skipping interface %s: cannot open: %s", iface, errbuf);
		return 0;
	}

	rc = pcap_datalink(ifc->pcap_handle);
	if (rc != DLT_EN10MB) {
		if (cfg.all_interfaces)
			log_info("Skipping interface %s: invalid data link layer %s (%s).", iface, pcap_datalink_val_to_name(rc),
				 pcap_datalink_val_to_description(rc));
		else
			log_warn("Skipping interface %s: invalid data link layer %s (%s).", iface, pcap_datalink_val_to_name(rc),
				 pcap_datalink_val_to_description(rc));
		return 0;
	}

	rc = pcap_compile(ifc->pcap_handle, &ifc->pcap_filter, filter, 0, 0);
	if (rc == -1) {
		if (cfg.all_interfaces)
			log_info("Skipping interface %s: cannot compile filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		else
			log_warn("Skipping interface %s: cannot compile filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		return 0;
	}

	rc = pcap_setfilter(ifc->pcap_handle, &ifc->pcap_filter);
	if (rc == -1) {
		if (cfg.all_interfaces)
			log_info("Skipping iface %s: cannot set filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		else
			log_warn("Skipping iface %s: cannot set filter: %s", iface, pcap_geterr(ifc->pcap_handle));
		return 0;
	}
	ifc->filter_active = 0;

	rc = pcap_fileno(ifc->pcap_handle);
	assert(rc != -1);

#if HAVE_LIBEVENT2
	ifc->event = event_new(cfg.eb, rc, EV_READ | EV_PERSIST, read_cb, ifc);
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

	ifc->next = cfg.interfaces;
	cfg.interfaces = TAKE_PTR(ifc);

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
		for (int i = 0; i < cfg.hashsize; i++) {
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
	event_base_loopbreak(cfg.eb);
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
	cfg.eb = event_base_new();

	if (!cfg.eb) {
		log_error("%s: event_base_new() failed", __FUNCTION__);
		return -1;
	}
#else
	event_init();
#endif

	/* SIGINT */
#if HAVE_LIBEVENT2
	cfg.sigint_ev = event_new(cfg.eb, SIGINT, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(cfg.sigint_ev, NULL);
#else
	event_set(&cfg.sigint_ev, SIGINT, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(&cfg.sigint_ev, NULL);
#endif

	/* SIGTERM */
#if HAVE_LIBEVENT2
	cfg.sigterm_ev = event_new(cfg.eb, SIGTERM, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(cfg.sigterm_ev, NULL);
#else
	event_set(&cfg.sigterm_ev, SIGTERM, EV_SIGNAL | EV_PERSIST, stop_cb, NULL);
	event_add(&cfg.sigterm_ev, NULL);
#endif

	/* SIGHUP */
#if HAVE_LIBEVENT2
	cfg.sighup_ev = event_new(cfg.eb, SIGHUP, EV_SIGNAL | EV_PERSIST, reload_cb, NULL);
	event_add(cfg.sighup_ev, NULL);
#else
	event_set(&cfg.sighup_ev, SIGHUP, EV_SIGNAL | EV_PERSIST, reload_cb, NULL);
	event_add(&cfg.sighup_ev, NULL);
#endif

	/* timeout */
#if HAVE_LIBEVENT2
	cfg.timeout_ev = event_new(cfg.eb, -1, EV_PERSIST, timeout_cb, NULL);
	event_add(cfg.timeout_ev, &timeout);
#else
	event_set(&cfg.timeout_ev, -1, EV_PERSIST, timeout_cb, NULL);
	event_add(&cfg.timeout_ev, &timeout);
#endif

	return 0;
}

static void libevent_close(void)
{
#if HAVE_LIBEVENT2
	event_free(cfg.sigint_ev);
	event_free(cfg.sigterm_ev);
	event_free(cfg.sighup_ev);

	event_base_free(cfg.eb);
#endif
}

static void save_pid(void)
{
	FILE *f;

	if (!cfg.pid_file)
		return;

	f = fopen(cfg.pid_file, "we");
	if (!f) {
		log_error("Cannot open pid file '%s': %m", cfg.pid_file);
		return;
	}

	fprintf(f, "%d\n", getpid());
	fclose(f);
}

static void del_pid(void)
{
	if (!cfg.pid_file)
		return;

	if (unlink(cfg.pid_file) < 0)
		log_warn("Cannot delete pid file '%s': %m", cfg.pid_file);
}

static void usage(void)
{
	printf("Usage: " MAIN_ARGV0 " [OPTIONS] [INTERFACES]\n"
	       "Keep track of ethernet/ip address pairings for IPv4 and IPv6.\n"
	       "\n"
	       " Options for data output:\n"
	       "  -L, --shm-log-size=NUM     Change shared memory log size (default: %s).\n"
	       "  -m, --shm-log-name=NAME    Change shared memory log name (default: %s).\n"
	       "  -o, --output=FILE          Output data to plain text FILE.\n"
	       "  -q, --quiet                Suppress any output to stdout and stderr.\n"
	       "      --sqlite3=FILE         Output data to sqlite3 database FILE.\n"
	       "      --sqlite3-table=TBL    Use sqlite table TBL (default: %s).\n"
	       "  -v, --verbose              Enable debug messages.\n"
	       "\n"
	       " Options for data filtering:\n"
	       "  -4, --ipv4-only            Capture only IPv4 packets.\n"
	       "  -6, --ipv6-only            Capture only IPv6 packets.\n"
	       "      --ignore-ip=IP         Ignore pairings with specified IP.\n"
	       "  -H, --hashsize=NUM         Size of ratelimit hash table. Default is 1 (no hash table).\n"
	       "  -r, --ratelimit=NUM        Ratelimit duplicate ethernet/ip pairings to 1 every NUM seconds.\n"
	       "                             If NUM = 0, ratelimiting is disabled.\n"
	       "                             If NUM = -1, suppress duplicate entries indefinitely.\n"
	       "                             Default is 0.\n"
	       "\n"
	       " Misc options:\n"
	       "  -A, --all-interfaces       Capture on all available interfaces by default.\n"
	       "  -d, --daemon               Start as a daemon (implies '-q').\n"
	       "  -p, --pid=FILE             Write process id to FILE.\n"
	       "      --no-promisc           Disable promisc mode on network interfaces.\n"
	       "      --syslog               Log to syslog instead of stderr.\n"
	       "  -u, --user=USER            Switch to USER after opening network interfaces.\n"
	       "\n"
	       "  -h, --help                 Display this help and exit.\n"
	       "  -V, --version              Show version information and exit.\n"
	       "\n"
	       "If no interfaces given, the first non loopback interface is used (except '-A' is used).\n"
	       "Ignoring IP address option '--ignore-ip' can be used multiple times.\n",
	       STR(DEFAULT_SHM_LOG_SIZE), DEFAULT_SHM_LOG_NAME, PACKAGE);
}

#define ARG_IGNORE_IP     128
#define ARG_NO_PRMOISC    129
#define ARG_SQLITE3_FILE  130
#define ARG_SQLITE3_TABLE 131
#define ARG_SYSLOG        132

int main(int argc, char *argv[])
{
	bool syslog = false;
	bool verbose = false;

	const struct option long_options[] = {
		{"all-interfaces", no_argument, NULL, 'A'},
		{"daemon", no_argument, NULL, 'd'},
		{"hashsize", required_argument, NULL, 'H'},
		{"help", no_argument, NULL, 'h'},
		{"ignore-ip", required_argument, NULL, ARG_IGNORE_IP},
		{"ipv4-only", no_argument, NULL, '4'},
		{"ipv6-only", no_argument, NULL, '6'},
		{"no-promisc", no_argument, NULL, ARG_NO_PRMOISC},
		{"output", required_argument, NULL, 'o'},
		{"pid", required_argument, NULL, 'p'},
		{"quiet", no_argument, NULL, 'q'},
		{"ratelimit", required_argument, NULL, 'r'},
		{"shm-log-name", required_argument, NULL, 'm'},
		{"shm-log-size", required_argument, NULL, 'L'},
		{"sqlite3", required_argument, NULL, ARG_SQLITE3_FILE},
		{"sqlite3-table", required_argument, NULL, ARG_SQLITE3_TABLE},
		{"syslog", no_argument, NULL, ARG_SYSLOG},
		{"user", required_argument, NULL, 'u'},
		{"verbose", no_argument, NULL, 'v'},
		{"version", no_argument, NULL, 'V'},
		{0, 0, 0, 0},
	};

	/* Default configuration */
	memset(&cfg, 0, sizeof(cfg));
	cfg.all_interfaces = false;
	cfg.daemon_flag = false;
	cfg.ratelimit = 0;
	cfg.hashsize = 1;
	cfg.quiet = false;
	cfg.promisc_flag = 1;
	cfg.ratelimit = 0;
	cfg.sqlite_file = NULL;
	cfg.uname = NULL;
	cfg.shm_data.size = DEFAULT_SHM_LOG_SIZE;
	cfg.shm_data.name = DEFAULT_SHM_LOG_NAME;
	cfg.v4_flag = false;
	cfg.v6_flag = false;
#if HAVE_LIBSQLITE3
	cfg.sqlite_table = PACKAGE;
#endif

	for (;;) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "Ab:dH:h46o:p:qr:m:L:u:vV", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			break;

		case '4':
			cfg.v4_flag = true;
			cfg.v6_flag = false;
			break;

		case '6':
			cfg.v6_flag = true;
			cfg.v4_flag = false;
			break;

		case 'A':
			cfg.all_interfaces = true;
			break;

		case 'd':
			cfg.daemon_flag = true;
			__attribute__((fallthrough));
		case 'q':
			cfg.quiet = true;
			break;

		case 'H':
			cfg.hashsize = (int)strtol(optarg, NULL, 10);
			if (cfg.hashsize < 1 || cfg.hashsize > 65536)
				exit(EXIT_FAILURE);
			break;

		case ARG_IGNORE_IP:
			if (ignorelist_add_ip(optarg) < 0)
				exit(EXIT_FAILURE);
			break;

		case 'L':
			cfg.shm_data.size = (uint64_t)strtol(optarg, NULL, 10);
			if (cfg.shm_data.size < 1)
				exit(EXIT_FAILURE);
			break;

		case 'm':
			cfg.shm_data.name = optarg;
			break;

		case 'o':
			cfg.data_file = optarg;
			break;

		case 'p':
			cfg.pid_file = optarg;
			break;

		case ARG_NO_PRMOISC:
			cfg.promisc_flag = 0;
			break;

		case 'r':
			cfg.ratelimit = (int)strtol(optarg, NULL, 10);
			if (cfg.ratelimit < -1)
				exit(EXIT_FAILURE);
			break;

#if HAVE_LIBSQLITE3
		case ARG_SQLITE3_FILE:
			cfg.sqlite_file = optarg;
			break;

		case ARG_SQLITE3_TABLE:
			cfg.sqlite_table = optarg;
			break;
#endif

		case ARG_SYSLOG:
			syslog = true;
			break;

		case 'u':
			cfg.uname = optarg;
			break;

		case 'h':
			usage();
			exit(EXIT_SUCCESS);

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

	if (cfg.daemon_flag) {
		log_mode(LOG_MODE_SYSLOG);

		if (daemonize(NULL) < 0)
			return EXIT_FAILURE;
	} else if (syslog)
		log_mode(LOG_MODE_SYSLOG);

	if (verbose)
		log_max_priority(LOG_DEBUG);

	save_pid();

	if (libevent_init() < 0)
		return EXIT_FAILURE;

	if (cfg.ratelimit > 0)
		log_debug("Ratelimiting duplicate entries to 1 per %d seconds.", cfg.ratelimit);
	else if (cfg.ratelimit == -1)
		log_debug("Duplicate entries suppressed indefinitely.");
	else
		log_debug("Duplicate entries ratelimiting disabled.");

	if (cfg.promisc_flag)
		log_info("PROMISC mode enabled.");
	else
		log_info("PROMISC mode disabled.");

	if (optind < argc) {
		cfg.all_interfaces = false;
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
			if (cfg.all_interfaces) {
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

	if (!cfg.interfaces) {
		log_error("No suitable interfaces found!");
		return EXIT_FAILURE;
	}

	if (cfg.uname) {
		if (drop_root(cfg.uname) < 0)
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
	event_base_dispatch(cfg.eb);
#else
	event_dispatch();
#endif

	log_info("Stopping %s..", MAIN_ARGV0);

	output_shm_close();
	output_sqlite_close();
	output_flatfile_close();

	for (struct iface_config *ifc = cfg.interfaces; ifc; ifc = del_iface(ifc)) {}

	libevent_close();
	log_close();

	del_pid();
	ignorelist_free();

	return EXIT_SUCCESS;
}
