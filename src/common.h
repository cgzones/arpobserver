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

enum pkt_origin
{
	ARP_REQ,
	ARP_REP,
	ARP_ACD,
	ND_NS,
	ND_NA,
	ND_DAD,
	ND_RA,
	ND_RS,
};

extern const char *const pkt_origin_str[];
extern const char *const pkt_origin_desc[];

#define SNAP_LEN 9000

struct pkt {
	const uint8_t *raw_packet;

	const uint8_t *pos;
	size_t len;

	const struct iface_config *ifc;
	const struct pcap_pkthdr *pcap_header;

	uint16_t vlan_tag;
	const struct ether_header *ether;
	const struct ether_arp *arp;
	const struct ip6_hdr *ip6;
	const struct icmp6_hdr *icmp6;
	const struct nd_neighbor_solicit *ns;
	const struct nd_neighbor_advert *na;
	const struct nd_router_advert *ra;
	const struct nd_router_solicit *rs;
	const struct nd_opt_hdr *opt_slla;
	const struct nd_opt_hdr *opt_tlla;

	const uint8_t *l2_addr;
	const uint8_t *ip_addr;
	uint8_t ip_len;
	enum pkt_origin origin;
};


#define CONVERSION_FAILURE_STR "FAILED_CONV"

void convert_mac_addr_to_str(const uint8_t addr[ETHER_ADDR_LEN], char *str) _nonnull_;

int convert_mac_str_to_addr(const char *str, uint8_t addr[ETHER_ADDR_LEN]) _nonnull_ _wur_;

int convert_ip4_addr_to_str(const uint8_t addr[IP4_LEN], char *str) _nonnull_ _wur_;

int convert_ip4_str_to_addr(const char *str, uint8_t addr[IP4_LEN]) _nonnull_ _wur_;

int convert_ip6_addr_to_str(const uint8_t addr[IP6_LEN], char *str) _nonnull_ _wur_;

int convert_ip6_str_to_addr(const char *str, uint8_t addr[IP6_LEN]) _nonnull_ _wur_;

int convert_ip_addr_to_str(const void *addr, uint8_t addr_len, char *str) _access_roc_(1, 2) _nonnull_ _wur_;
