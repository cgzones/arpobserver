#pragma once

#include <netinet/if_ether.h>
#include <stdint.h>
#include <sys/types.h>

#include "common.h"

struct mcache_node {
	uint8_t l2_addr[ETHER_ADDR_LEN];
	uint8_t ip_addr[IP6_LEN];
	time_t tstamp;
	uint8_t addr_len;
	uint16_t vlan_tag;

	struct mcache_node *next;
};

void cache_prune(struct mcache_node *dead_node, struct mcache_node **cache) _nonnull_;

void cache_del(struct mcache_node *dead_node, struct mcache_node **cache) _nonnull_;

int cache_add(const uint8_t *l2_addr, const uint8_t *ip_addr, uint8_t len, time_t tstamp, uint16_t vlan_tag, struct mcache_node **cache)
	_access_ro_(1) _access_roc_(2, 3) _wur_;

struct mcache_node *cache_lookup(const uint8_t *l2_addr,
				 const uint8_t *ip_addr,
				 uint8_t len,
				 time_t tstamp,
				 uint16_t vlan_tag,
				 struct mcache_node **cache) _access_ro_(1) _access_roc_(2, 3) _wur_;
