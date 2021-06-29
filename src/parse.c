#include "parse.h"

#include <assert.h>

#include "arpobserver.h"
#include "base64.h"
#include "log.h"

_nonnull_ _wur_ static int parse_arp(struct pkt *p)
{
	const struct ether_arp *arp;

	assert(p);

	if (p->len < sizeof(struct ether_arp)) {
		log_warn("%s: Error parsing ARP packet. Packet is too small (%zu of %zu bytes). Packet dump: %s", p->ifc->name, p->len,
			 sizeof(struct ether_arp), base64_encode_packet(p));
		return -2;
	}

	arp = (const struct ether_arp *)p->pos;
	p->arp = arp;
	p->pos += sizeof(struct ether_arp);
	p->len -= sizeof(struct ether_arp);

	if (be16toh(arp->arp_hrd) != ARPHRD_ETHER) {
		log_notice("%s: Ignoring ARP packet with hardware address format %d", p->ifc->name, be16toh(arp->arp_hrd));
		return -1;
	}

	if (be16toh(arp->arp_pro) != ETHERTYPE_IP) {
		log_notice("%s: Ignoring ARP packet with protocol address format %d", p->ifc->name, be16toh(arp->arp_pro));
		return -1;
	}

	return 0;
}

_nonnull_ _wur_ static int parse_nd(struct pkt *p)
{
	assert(p);

	if (p->icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
		if (p->len < sizeof(struct nd_neighbor_solicit)) {
			log_warn("%s: Error parsing ICMPv6 ND_NS packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_neighbor_solicit), base64_encode_packet(p));
			return -2;
		}
		p->ns = (const struct nd_neighbor_solicit *)p->pos;
		p->pos += sizeof(struct nd_neighbor_solicit);
		p->len -= sizeof(struct nd_neighbor_solicit);
	} else if (p->icmp6->icmp6_type == ND_NEIGHBOR_ADVERT) {
		if (p->len < sizeof(struct nd_neighbor_advert)) {
			log_warn("%s: Error parsing ICMPv6 ND_NA packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_neighbor_advert), base64_encode_packet(p));
			return -2;
		}
		p->na = (const struct nd_neighbor_advert *)p->pos;
		p->pos += sizeof(struct nd_neighbor_advert);
		p->len -= sizeof(struct nd_neighbor_advert);
	} else if (p->icmp6->icmp6_type == ND_ROUTER_ADVERT) {
		if (p->len < sizeof(struct nd_router_advert)) {
			log_warn("%s: Error parsing ICMPv6 ND_RA packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_router_advert), base64_encode_packet(p));
			return -2;
		}
		p->ra = (const struct nd_router_advert *)p->pos;
		p->pos += sizeof(struct nd_router_advert);
		p->len -= sizeof(struct nd_router_advert);
	} else if (p->icmp6->icmp6_type == ND_ROUTER_SOLICIT) {
		if (p->len < sizeof(struct nd_router_solicit)) {
			log_warn("%s: Error parsing ICMPv6 ND_RS packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_router_solicit), base64_encode_packet(p));
			return -2;
		}
		p->rs = (const struct nd_router_solicit *)p->pos;
		p->pos += sizeof(struct nd_router_solicit);
		p->len -= sizeof(struct nd_router_solicit);
	} else {
		/* parse_ipv6() should not call us with other types */
		assert(0);
		return -2;
	}

	for (;;) {
		const struct nd_opt_hdr *opt;

		if (p->len < sizeof(struct nd_opt_hdr))
			break;

		opt = (const struct nd_opt_hdr *)p->pos;

		if (opt->nd_opt_len == 0) {
			log_warn("%s: Error parsing ICMPv6 ND options. Option length is 0. Packet dump: %s", p->ifc->name,
				 base64_encode_packet(p));
			return -2;
		}

		if (p->len < opt->nd_opt_len * 8) {
			log_warn("%s: Error parsing ICMPv6 ND options. Option header is too small (%zu of %d bytes). Packet dump: %s",
				 p->ifc->name, p->len, opt->nd_opt_len * 8, base64_encode_packet(p));
			return -2;
		}

		p->pos += opt->nd_opt_len * 8;
		p->len -= (unsigned)opt->nd_opt_len * 8;

		switch (opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
			p->opt_slla = opt;
			break;
		case ND_OPT_TARGET_LINKADDR:
			p->opt_tlla = opt;
			break;
		default:
			break;
		}
	}

	return 0;
}

_nonnull_ _wur_ static int parse_ipv6(struct pkt *p)
{
	const struct ip6_hdr *ip6;
	const struct icmp6_hdr *icmp6;

	assert(p);

	if (p->len < sizeof(struct ip6_hdr)) {
		log_warn("%s: Error parsing IPv6 packet. Packet is too small (%zu of %zu bytes). Packet dump: %s", p->ifc->name, p->len,
			 sizeof(struct ip6_hdr), base64_encode_packet(p));
		return -2;
	}

	ip6 = (const struct ip6_hdr *)p->pos;
	p->ip6 = ip6;
	p->pos += sizeof(struct ip6_hdr);
	p->len -= sizeof(struct ip6_hdr);

	// Skip IPv6 extension headers
	for (uint8_t next_header = ip6->ip6_nxt; next_header != IPPROTO_ICMPV6;) {
		switch (next_header) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_DSTOPTS: {
			const struct ip6_ext *ip6e;
			size_t ext_len;

			if (p->len < sizeof(struct ip6_ext)) {
				log_warn("%s: Error parsing IPv6 packet. Extension header is too small (%zu of %zu bytes). Packet dump: %s",
					 p->ifc->name, p->len, sizeof(struct ip6_ext), base64_encode_packet(p));
				return -2;
			}
			ip6e = (const struct ip6_ext *)p->pos;
			ext_len = ((size_t)ip6e->ip6e_len + 1) * 8;
			if (p->len < ext_len) {
				log_warn(
					"%s: Error parsing IPv6 packet. Extension content is too small (%zu of %zu bytes). Packet dump: %s",
					p->ifc->name, p->len, ext_len, base64_encode_packet(p));
				return -2;
			}
			p->pos += ext_len;
			p->len -= ext_len;
			next_header = ip6e->ip6e_nxt;
			break;
		}
		default:
			log_notice("%s: Ignoring unknown IPv6 extension header with type %d", p->ifc->name, next_header);
			return -1;
		}
	}

	if (p->len < sizeof(struct icmp6_hdr)) {
		log_warn("%s: Error parsing ICMPv6 packet. Header is too small (%zu of %zu bytes). Packet dump: %s", p->ifc->name, p->len,
			 sizeof(struct icmp6_hdr), base64_encode_packet(p));
		return -2;
	}

	icmp6 = (const struct icmp6_hdr *)p->pos;
	p->icmp6 = icmp6;

	switch (icmp6->icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_ROUTER_ADVERT:
	case ND_ROUTER_SOLICIT:
		return parse_nd(p);
	case IPPROTO_ICMPV6:   // TODO: encapsulated IPv6?
	case 143:              /* Multicast Listener Discovery Version 2 (MLDv2) for IPv6 */
		return -1;
	default:
		log_notice("%s: Ignoring unknown IPv6 ICMP6 type %d with code %d. Packet dump: %s", p->ifc->name, icmp6->icmp6_type,
			   icmp6->icmp6_code, base64_encode_packet(p));
		return -1;
	}
}

/*
 * Returns:
 * 	0	packet parsed either arp, ns or na
 * 	-1	packet is of some other type
 * 	-2	packet is malformed
 */
int parse_packet(struct pkt *p)
{
	uint16_t ether_type;

	assert(p);

	if (p->len < sizeof(struct ether_header)) {
		log_warn("%s: Error parsing Ethernet packet. Packet is too small (%zu of %zu bytes). Packet dump: %s", p->ifc->name, p->len,
			 sizeof(struct ether_header), base64_encode_packet(p));
		return -2;
	}

	p->ether = (const struct ether_header *)p->pos;
	p->pos += sizeof(struct ether_header);
	p->len -= sizeof(struct ether_header);

	ether_type = be16toh(p->ether->ether_type);
	if (ether_type == ETHERTYPE_VLAN) {
		p->vlan_tag = be16toh(*(const uint16_t *)p->pos) & 0xfff;
		p->pos += 4;
		p->len -= 4;
		ether_type = be16toh(*(const uint16_t *)(p->pos - 2));
	}

	switch (ether_type) {
	case ETHERTYPE_ARP:
		return parse_arp(p);
	case ETHERTYPE_IPV6:
		return parse_ipv6(p);
	default:
		log_notice("%s: Unknown Ethernet packet type: %u", p->ifc->name, ether_type);
		return -1;
	}
}
