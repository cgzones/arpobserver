#pragma once

#include <net/ethernet.h>
#include <stdbool.h>
#include <stdint.h>

#include "common.h"
#include "macro.h"

int protect_ip(const char *ip_str) _nonnull_ _wur_;
int protect_mac(const char *mac_str) _nonnull_ _wur_;
int protect_mac_ip_pairing(const char *mac_ip_str) _nonnull_ _wur_;

struct protect_entry
{
	uint8_t ip4_address[IP4_LEN];
	uint8_t ip6_address[IP6_LEN];
	uint8_t mac_address[ETHER_ADDR_LEN];
	bool ip4_set;
	bool ip6_set;
	bool mac_set;
};

const struct protect_entry *protect_match(const uint8_t *mac_addr, const uint8_t *ip_addr, enum ip_type_len ip_addr_len) _access_ro_(1)
	_access_roc_(2, 3) _wur_;

size_t protect_list_size(void) _wur_;
void free_protect_list(void);
