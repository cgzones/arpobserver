#pragma once

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "macro.h"


#define MAC_STR_LEN 18

#define TIMEOUT_SEC                  30
#define NO_PACKET_TIMEOUT_MULTIPLIER 5

enum ip_type_len
{
	IP4_LEN = 4,
	IP6_LEN = 16,
};

extern const char *const pkt_origin_str[];
extern const char *const pkt_origin_desc[];

#define SNAP_LEN 9000

#define CONVERSION_FAILURE_STR "FAILED_CONV"

void convert_mac_addr_to_str(const uint8_t addr[ETHER_ADDR_LEN], char *str) _nonnull_;

int convert_mac_str_to_addr(const char *str, uint8_t addr[ETHER_ADDR_LEN]) _nonnull_ _wur_;

int convert_ip4_addr_to_str(const uint8_t addr[IP4_LEN], char *str) _nonnull_ _wur_;

int convert_ip4_str_to_addr(const char *str, uint8_t addr[IP4_LEN]) _nonnull_ _wur_;

int convert_ip6_addr_to_str(const uint8_t addr[IP6_LEN], char *str) _nonnull_ _wur_;

int convert_ip6_str_to_addr(const char *str, uint8_t addr[IP6_LEN]) _nonnull_ _wur_;

int convert_ip_addr_to_str(const void *addr, uint8_t addr_len, char *str) _access_roc_(1, 2) _nonnull_ _wur_;
