#include "parse.h"

#include <assert.h>

#include "arpobserver.h"
#include "base64.h"
#include "log.h"

struct vlan_header
{
	uint16_t tpid;
	uint16_t tci;
} _packed_;

_nonnull_ _wur_ static int parse_arp(struct pkt *p)
{
	assert(p);

	if (p->len < sizeof(struct ether_arp)) {
		log_warn("%s: Error parsing ARP packet. Packet is too small (%zu of %zu bytes). Packet dump: %s", p->ifc->name, p->len,
			 sizeof(struct ether_arp), base64_encode_packet(p));
		return -2;
	}

	memcpy(&p->arp, p->pos, sizeof(struct ether_arp));
	p->kind = KIND_ARP;
	p->pos += sizeof(struct ether_arp);
	p->len -= sizeof(struct ether_arp);

	if (be16toh(p->arp.arp_hrd) != ARPHRD_ETHER) {
		log_notice("%s: Ignoring ARP packet with hardware address format %d", p->ifc->name, be16toh(p->arp.arp_hrd));
		return -1;
	}

	if (be16toh(p->arp.arp_pro) != ETHERTYPE_IP) {
		log_notice("%s: Ignoring ARP packet with protocol address format %d", p->ifc->name, be16toh(p->arp.arp_pro));
		return -1;
	}

	return 0;
}

_nonnull_ _wur_ static int parse_nd(struct pkt *p)
{
	assert(p);

	if (p->icmp6.icmp6_type == ND_NEIGHBOR_SOLICIT) {
		if (p->len < sizeof(struct nd_neighbor_solicit)) {
			log_warn("%s: Error parsing ICMPv6 ND_NS packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_neighbor_solicit), base64_encode_packet(p));
			return -2;
		}
		memcpy(&p->ns, p->pos, sizeof(struct nd_neighbor_solicit));
		p->kind = KIND_NS;
		p->pos += sizeof(struct nd_neighbor_solicit);
		p->len -= sizeof(struct nd_neighbor_solicit);
	} else if (p->icmp6.icmp6_type == ND_NEIGHBOR_ADVERT) {
		if (p->len < sizeof(struct nd_neighbor_advert)) {
			log_warn("%s: Error parsing ICMPv6 ND_NA packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_neighbor_advert), base64_encode_packet(p));
			return -2;
		}
		memcpy(&p->na, p->pos, sizeof(struct nd_neighbor_advert));
		p->kind = KIND_NA;
		p->pos += sizeof(struct nd_neighbor_advert);
		p->len -= sizeof(struct nd_neighbor_advert);
	} else if (p->icmp6.icmp6_type == ND_ROUTER_ADVERT) {
		if (p->len < sizeof(struct nd_router_advert)) {
			log_warn("%s: Error parsing ICMPv6 ND_RA packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_router_advert), base64_encode_packet(p));
			return -2;
		}
		memcpy(&p->ra, p->pos, sizeof(struct nd_router_advert));
		p->kind = KIND_RA;
		p->pos += sizeof(struct nd_router_advert);
		p->len -= sizeof(struct nd_router_advert);
	} else if (p->icmp6.icmp6_type == ND_ROUTER_SOLICIT) {
		if (p->len < sizeof(struct nd_router_solicit)) {
			log_warn("%s: Error parsing ICMPv6 ND_RS packet. Packet is too small (%zu of %zu bytes). Packet dump: %s",
				 p->ifc->name, p->len, sizeof(struct nd_router_solicit), base64_encode_packet(p));
			return -2;
		}
		memcpy(&p->rs, p->pos, sizeof(struct nd_router_solicit));
		p->kind = KIND_RS;
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
			if (p->opt_slla) {
				log_warn("%s: Error parsing ICMPv6 ND options. Multiple source link addresses. Packet dump: %s",
					 p->ifc->name, base64_encode_packet(p));
				return -2;
			}
			p->opt_slla = opt;
			break;
		case ND_OPT_TARGET_LINKADDR:
			if (p->opt_tlla) {
				log_warn("%s: Error parsing ICMPv6 ND options. Multiple target link addresses. Packet dump: %s",
					 p->ifc->name, base64_encode_packet(p));
				return -2;
			}
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
	uint16_t payload_len;

	assert(p);

	if (p->len < sizeof(struct ip6_hdr)) {
		log_warn("%s: Error parsing IPv6 packet. Packet is too small (%zu of %zu bytes). Packet dump: %s", p->ifc->name, p->len,
			 sizeof(struct ip6_hdr), base64_encode_packet(p));
		return -2;
	}

	memcpy(&p->ip6, p->pos, sizeof(struct ip6_hdr));
	p->pos += sizeof(struct ip6_hdr);
	p->len -= sizeof(struct ip6_hdr);

	payload_len = be16toh(p->ip6.ip6_plen);
	if (payload_len != p->len) {
		log_warn("%s: Error parsing IPv6 packet. Payload length mismatch(%zu vs %u bytes). Packet dump: %s", p->ifc->name, p->len,
			 payload_len, base64_encode_packet(p));
		return -2;
	}

	// Skip IPv6 extension headers
	for (uint8_t next_header = p->ip6.ip6_nxt; next_header != IPPROTO_ICMPV6;) {
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

	memcpy(&p->icmp6, p->pos, sizeof(struct icmp6_hdr));

	/* Windows 10 sends ICMPv6 packets with invalid checksum and type 58. */
	if (p->icmp6.icmp6_type == IPPROTO_ICMPV6) {
		log_debug("%s: Ignoring invalid IPv6 ICMPv6 packet with type %d and code %d. Packet dump: %s", p->ifc->name,
			  p->icmp6.icmp6_type, p->icmp6.icmp6_code, base64_encode_packet(p));
		return -1;
	}

	{
		const uint16_t packet_checksum = be16toh(p->icmp6.icmp6_cksum);
		uint32_t checksum = 0;

		/* IPv6 Source Address */
		for (size_t i = 0; i < sizeof(struct in6_addr) / 2; i++)
			checksum += be16toh(*(((const uint16_t *)&p->ip6.ip6_src) + i));

		/* IPv6 Destination Address */
		for (size_t i = 0; i < sizeof(struct in6_addr) / 2; i++)
			checksum += be16toh(*(((const uint16_t *)&p->ip6.ip6_dst) + i));

		/* Upper-Layer Packet Length */
		checksum += (uint32_t)p->len;

		/* Next Header */
		checksum += 0x3a;

		/* ICMPv6 data */
		{
			const uint8_t *ptr = p->pos;
			size_t i = p->len;
			for (; i > 1; i -= 2) {
				uint16_t d;
				memcpy(&d, ptr, sizeof(uint16_t));
				ptr += sizeof(uint16_t);
				checksum += be16toh(d);
			}
			if (i > 0)
				checksum += be16toh(*ptr);
		}

		/* Checksum is set empty for calculation */
		checksum -= packet_checksum;

		while (checksum >> 16)
			checksum = (checksum & 0xffff) + (checksum >> 16);

		checksum = (uint16_t)~checksum;

		if (checksum != packet_checksum) {
			log_warn("%s: Ignoring IPv6 ICMPv6 packet with invalid checksum %#04x, should be %#04x. Packet dump: %s",
				 p->ifc->name, packet_checksum, checksum, base64_encode_packet(p));
			return -1;
		}
	}

	switch (p->icmp6.icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
	case ND_ROUTER_ADVERT:
	case ND_ROUTER_SOLICIT:
		return parse_nd(p);
	case ICMP6_TIME_EXCEEDED: /* Time exceeded */
	case ICMP6_DST_UNREACH:   /* Destination unreachable */
	case ICMP6_ECHO_REQUEST:  /* Echo Request */
	case ICMP6_ECHO_REPLY:    /* Echo Reply */
	case 143:                 /* Multicast Listener Discovery Version 2 (MLDv2) for IPv6 */
		return -1;
	default:
		log_notice("%s: Ignoring unknown IPv6 ICMP6 type %d with code %d. Packet dump: %s", p->ifc->name, p->icmp6.icmp6_type,
			   p->icmp6.icmp6_code, base64_encode_packet(p));
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

	memcpy(&p->ether, p->pos, sizeof(struct ether_header));
	p->pos += sizeof(struct ether_header);
	p->len -= sizeof(struct ether_header);

	ether_type = be16toh(p->ether.ether_type);
	if (ether_type == ETH_P_8021AD) {
		p->pos += sizeof(struct vlan_header);
		p->len -= sizeof(struct vlan_header);
		memcpy(&ether_type, p->pos - 2, sizeof(uint16_t));
		ether_type = be16toh(ether_type);
		if (ether_type != ETHERTYPE_VLAN) {
			log_warn(
				"%s: Error parsing Ethernet packet. Double tagged VLAN header followed by header with type %d (expected %d). Packet dump: %s",
				p->ifc->name, ether_type, ETHERTYPE_VLAN, base64_encode_packet(p));
			return -2;
		}
	}

	if (ether_type == ETHERTYPE_VLAN) {
		const struct vlan_header *vlanh = (const struct vlan_header *)(p->pos - 2);
		p->vlan_tag = be16toh(vlanh->tci & 0xfff);
		p->pos += sizeof(struct vlan_header);
		p->len -= sizeof(struct vlan_header);
		memcpy(&ether_type, p->pos - 2, sizeof(uint16_t));
		ether_type = be16toh(ether_type);
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
