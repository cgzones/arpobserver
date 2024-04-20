#pragma once

#include <event.h>
#include <stdint.h>

#include "cleanup.h"
#include "config.h"
#include "mcache.h"

#ifdef HAVE_LIBSQLITE3
#	include <sqlite3.h>
#endif

#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <sys/socket.h>

struct iface_config
{
	char *name;
	uint8_t addr[ETHER_ADDR_LEN];
	struct event *event;

	pcap_t *pcap_handle;

	struct mcache_node **cache;

	struct iface_config *next;
};

static inline void free_iface_config(struct iface_config *p)
{
	if (!p)
		return;

	if (p->pcap_handle)
		pcap_close(p->pcap_handle);
	free(p->name);
	free(p->cache);
	free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(struct iface_config *, free_iface_config);
#define _cleanup_iface_config_ _cleanup_(free_iface_configp)

struct arpobserver_config
{
	int ratelimit;
	unsigned hashsize;

	bool promisc_flag;
	bool immediate_mode;
	bool direction_inonly;
	bool v4_flag;
	bool v6_flag;
	bool daemon_flag;

	const char *uname;

	const char *pid_file;
	const char *data_file;

	struct
	{
		struct shm_log *log;
		char *filename;
		uint64_t size;
	} shm_data;

#ifdef HAVE_LIBSQLITE3
	char *sqlite_filename;
	char *sqlite_tablename;
#endif

	struct event_base *eb;

	struct event *sigint_ev;
	struct event *sigterm_ev;
	struct event *sighup_ev;
	struct event *timeout_ev;

	struct iface_config *interfaces;
};


extern struct arpobserver_config global_cfg;
