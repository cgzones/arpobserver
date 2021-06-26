#include "check_packet.h"

#include <assert.h>

#include "arpobserver.h"
#include "base64.h"
#include "log.h"

#define IN6_IS_ADDR_SN_MULTICAST(a, b)                                                                                           \
	(((const uint32_t *)(a))[0] == htobe32(0xff020000) && ((const uint32_t *)(a))[1] == 0                                    \
	 && ((const uint32_t *)(a))[2] == htobe32(0x00000001) && ((const uint8_t *)(a))[12] == 0xff                              \
	 && ((const uint8_t *)(a))[13] == ((const uint8_t *)(b))[13] && ((const uint8_t *)(a))[14] == ((const uint8_t *)(b))[14] \
	 && ((const uint8_t *)(a))[15] == ((const uint8_t *)(b))[15])

int check_arp(const struct pkt *p)
{
	const struct ether_arp *arp;

	assert(p);

	arp = p->arp;

	if (arp->ea_hdr.ar_hln != ETHER_ADDR_LEN) {
		log_warn("%s: Malformed ARP packet. Wrong hardware size (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 arp->ea_hdr.ar_hln, ETHER_ADDR_LEN, base64_encode_packet(p));
		return -1;
	}

	if (arp->ea_hdr.ar_pln != IP4_LEN) {
		log_warn("%s: Malformed ARP packet. Wrong protocol size (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 arp->ea_hdr.ar_pln, IP4_LEN, base64_encode_packet(p));
		return -1;
	}

	// MS Network Load Balancer use physical device MAC address in ethernet
	// frame but virtual MAC address in ARP sender address field. In
	// networks where MS NLB is used it produces bunch of warnings.

	if (memcmp(p->ether->ether_shost, arp->arp_sha, ETHER_ADDR_LEN) != 0) {
		char mac_ether[MAC_STR_LEN];
		char mac_arp[MAC_STR_LEN];
		char ip_arp[INET_ADDRSTRLEN];

		convert_mac_addr_to_str(p->ether->ether_shost, mac_ether);
		convert_mac_addr_to_str(arp->arp_sha, mac_arp);
		if (convert_ip4_addr_to_str(arp->arp_spa, ip_arp) < 0)
			snprintf(ip_arp, sizeof(ip_arp), CONVERSION_FAILURE_STR);
		log_warn("%s: Malformed ARP packet. Erhernet and ARP source address mismatch (%s != %s) [%s]. Packet dump: %s",
			 p->ifc->name, mac_ether, mac_arp, ip_arp, base64_encode_packet(p));
		return -1;
	}

	return 0;
}

int check_ns(const struct pkt *p)
{
	const struct nd_neighbor_solicit *ns;
	const struct ip6_hdr *ip6;
	char ip6_addr[INET6_ADDRSTRLEN];
	char ip6_addr2[INET6_ADDRSTRLEN];

	assert(p);

	ns = p->ns;
	ip6 = p->ip6;

	if (ip6->ip6_hlim != 255) {
		log_warn("%s: Malformed ICMPv6 NS packet. Wrong IPv6 Hop Limit (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 ip6->ip6_hlim, 255, base64_encode_packet(p));
		return -1;
	}

	if (p->icmp6->icmp6_code != 0) {
		log_warn("%s: Malformed ICMPv6 NS packet. Wrong ICMPv6 Code (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 p->icmp6->icmp6_code, 0, base64_encode_packet(p));
		return -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target)) {
		if (convert_ip6_addr_to_str((const uint8_t *)&ns->nd_ns_target, ip6_addr) < 0)
			snprintf(ip6_addr, sizeof(ip6_addr), CONVERSION_FAILURE_STR);
		log_warn("%s: Malformed ICMPv6 NS packet. Target address is multicast (%s). Packet dump: %s", p->ifc->name, ip6_addr,
			 base64_encode_packet(p));
		return -1;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
		if (!IN6_IS_ADDR_SN_MULTICAST(&ip6->ip6_dst, &ns->nd_ns_target)) {
			if (convert_ip6_addr_to_str((const uint8_t *)&ip6->ip6_dst, ip6_addr) < 0)
				snprintf(ip6_addr, sizeof(ip6_addr), CONVERSION_FAILURE_STR);
			if (convert_ip6_addr_to_str((const uint8_t *)&ns->nd_ns_target, ip6_addr2) < 0)
				snprintf(ip6_addr2, sizeof(ip6_addr2), CONVERSION_FAILURE_STR);
			log_warn(
				"%s: Malformed ICMPv6 NS packet. Src IP is unspecified and dst IP is not solicited-note multicast address (%s, %s). Packet dump: %s",
				p->ifc->name, ip6_addr, ip6_addr2, base64_encode_packet(p));
			return -1;
		}
		if (p->opt_slla) {
			log_warn(
				"%s: Malformed ICMPv6 NS packet. Src IP is unspecified and source link-layer address option is present. Packet dump: %s",
				p->ifc->name, base64_encode_packet(p));
			return -1;
		}
	}

	return 0;
}

int check_na(const struct pkt *p)
{
	const struct nd_neighbor_advert *na;
	const struct ip6_hdr *ip6;

	assert(p);

	na = p->na;
	ip6 = p->ip6;

	if (ip6->ip6_hlim != 255) {
		log_warn("%s: Malformed ICMPv6 NA packet. Wrong IPv6 Hop Limit (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 ip6->ip6_hlim, 255, base64_encode_packet(p));
		return -1;
	}

	if (p->icmp6->icmp6_code != 0) {
		log_warn("%s: Malformed ICMPv6 NA packet. Wrong ICMPv6 Code (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 p->icmp6->icmp6_code, 0, base64_encode_packet(p));
		return -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&na->nd_na_target)) {
		char ip6_addr[INET6_ADDRSTRLEN];

		if (convert_ip6_addr_to_str((const uint8_t *)&na->nd_na_target, ip6_addr) < 0)
			snprintf(ip6_addr, sizeof(ip6_addr), CONVERSION_FAILURE_STR);
		log_warn("%s: Malformed ICMPv6 NA packet. Target address is multicast (%s). Packet dump: %s", p->ifc->name, ip6_addr,
			 base64_encode_packet(p));
		return -1;
	}

	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) && na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED) {
		log_warn("%s: Malformed ICMPv6 NA packet. Dst IP is multicast address, but Solicited flag is set. Packet dump: %s",
			 p->ifc->name, base64_encode_packet(p));
		return -1;
	}

	return 0;
}

int check_ra(const struct pkt *p)
{
	// const struct nd_router_advert *ra;
	const struct ip6_hdr *ip6;

	assert(p);

	// ra = p->ra;
	ip6 = p->ip6;

	if (ip6->ip6_hlim != 255) {
		log_warn("%s: Malformed ICMPv6 RA packet. Wrong IPv6 Hop Limit (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 ip6->ip6_hlim, 255, base64_encode_packet(p));
		return -1;
	}

	if (p->icmp6->icmp6_code != 0) {
		log_warn("%s: Malformed ICMPv6 RA packet. Wrong ICMPv6 Code (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 p->icmp6->icmp6_code, 0, base64_encode_packet(p));
		return -1;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) && p->opt_slla) {
		log_warn(
			"%s: Malformed ICMPv6 RA packet. Src IP is unspecified and source link-layer address option is present. Packet dump: %s",
			p->ifc->name, base64_encode_packet(p));
		return -1;
	}

	return 0;
}

int check_rs(const struct pkt *p)
{
	// const struct nd_router_solicit *rs;
	const struct ip6_hdr *ip6;

	assert(p);

	// rs = p->rs;
	ip6 = p->ip6;

	if (ip6->ip6_hlim != 255) {
		log_warn("%s: Malformed ICMPv6 RS packet. Wrong IPv6 Hop Limit (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 ip6->ip6_hlim, 255, base64_encode_packet(p));
		return -1;
	}

	if (p->icmp6->icmp6_code != 0) {
		log_warn("%s: Malformed ICMPv6 RS packet. Wrong ICMPv6 Code (got %d, expected %d). Packet dump: %s", p->ifc->name,
			 p->icmp6->icmp6_code, 0, base64_encode_packet(p));
		return -1;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) && p->opt_slla) {
		log_warn(
			"%s: Malformed ICMPv6 RS packet. Src IP is unspecified and source link-layer address option is present. Packet dump: %s",
			p->ifc->name, base64_encode_packet(p));
		return -1;
	}

	return 0;
}
