#pragma once

#include <stdbool.h>
#include <stdlib.h>

#include "cleanup.h"
#include "common.h"


struct ip_node {
	uint8_t ip_addr[IP6_LEN];
	uint8_t addr_len;

	struct ip_node *next;
};

static inline void free_ip_node(struct ip_node *p)
{
	free(p);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(struct ip_node *, free_ip_node);
#define _cleanup_ip_node_ _cleanup_(free_ip_nodep)


int ignorelist_add_ip(const char *ip_str) _nonnull_ _wur_;
void ignorelist_free(void);

int arpbridgelist_add(const char *mac_str) _nonnull_ _wur_;
bool arpbridgelist_contains(const uint8_t addr[ETHER_ADDR_LEN]) _wur_;
void arpbridgelist_free(void);

void save_pairing(const struct pkt *p) _nonnull_;
