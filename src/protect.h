#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "common.h"

int protect_ip(const char *ip_str) _wur_;
int protect_mac(const char *mac_str) _wur_;
int protect_mac_ip_pairing(const char *mac_ip_str) _wur_;

bool protect_match(const uint8_t *mac_addr, const uint8_t *ip_addr, enum ip_type_len ip_addr_len) _wur_;

void free_protect_list(void);
