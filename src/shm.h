#pragma once

#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

#include "cleanup.h"
#include "common.h"

#define DEFAULT_SHM_LOG_NAME "/arpobserver-shm-log"
#define MAGIC                0xc0decaff
#define POLL_INTERVAL_MSEC   333   // milliseconds
#define WAIT_INTERVAL_SEC    1     // seconds

/* NOTE: must not contain any pointers */
struct shm_log_entry {
	time_t timestamp;
	char interface[IFNAMSIZ];
	uint8_t ip_address[IP6_LEN];
	uint8_t mac_address[ETHER_ADDR_LEN];
	uint8_t ip_len;
	uint8_t origin;
	uint16_t vlan_tag;
};

/* NOTE: must not contain any pointers */
struct shm_log {
	uint64_t magic;
	uint64_t size;
	uint64_t last_idx;
	uint8_t active;
	struct shm_log_entry data[];
};

typedef void (*entry_callback_t)(const struct shm_log_entry *e, void *arg);

static inline void free_shm_log_entry(struct shm_log_entry *p)
{
	free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(struct shm_log_entry *, free_shm_log_entry);
#define _cleanup_shmlogentry_ _cleanup_(free_shm_log_entryp)
