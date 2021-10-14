#pragma once

#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <stdint.h>


enum pkt_kind
{
	KIND_ARP,
	KIND_NA,
	KIND_NS,
	KIND_RA,
	KIND_RS,
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

struct pkt {
	const uint8_t *raw_packet;

	const uint8_t *pos;
	size_t len;

	const struct iface_config *ifc;
	const struct pcap_pkthdr *pcap_header;

	uint16_t vlan_tag;

	struct ether_header ether;
	struct ip6_hdr ip6;
	struct icmp6_hdr icmp6;

	enum pkt_kind kind;
	union {
		struct ether_arp arp;
		struct nd_neighbor_advert na;
		struct nd_neighbor_solicit ns;
		struct nd_router_advert ra;
		struct nd_router_solicit rs;
	};

	const struct nd_opt_hdr *opt_slla;
	const struct nd_opt_hdr *opt_tlla;

	const uint8_t *l2_addr;
	const uint8_t *ip_addr;
	uint8_t ip_len;
	enum pkt_origin origin;
};
