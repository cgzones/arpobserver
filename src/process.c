#include "process.h"

#include <assert.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#include "arpobserver.h"
#include "base64.h"
#include "log.h"
#include "storage.h"

#define ARR_TO_INT32(x) (((uint32_t)(x)[0] << 24) | ((uint32_t)(x)[1] << 16) | ((uint32_t)(x)[2] << 8) | ((uint32_t)(x)[3]))

void process_arp(struct pkt *p)
{
	const struct ether_arp *arp;

	assert(p);

	arp = p->arp;

	p->ip_len = IP4_LEN;

	if (ARR_TO_INT32(arp->arp_spa) == INADDR_ANY) {
		p->l2_addr = arp->arp_sha;
		p->ip_addr = arp->arp_tpa;
		p->origin = ARP_ACD;
		save_pairing(p);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) {
		p->l2_addr = arp->arp_sha;
		p->ip_addr = arp->arp_spa;
		p->origin = ARP_REQ;
		save_pairing(p);
		return;
	}

	if (ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) {
		p->l2_addr = arp->arp_sha;
		p->ip_addr = arp->arp_spa;
		p->origin = ARP_REP;
		save_pairing(p);
		return;
	}

	log_notice("%s: Ignoring unknown ARP packet. Packet dump: %s", p->ifc->name, base64_encode_packet(p));
}

void process_ns(struct pkt *p)
{
	assert(p);

	p->ip_len = IP6_LEN;

	if (IN6_IS_ADDR_UNSPECIFIED(&p->ip6->ip6_src)) {
		p->l2_addr = p->ether->ether_shost;
		p->ip_addr = (const uint8_t *)&p->ns->nd_ns_target;
		p->origin = ND_DAD;
		save_pairing(p);
		return;
	}

	if (p->opt_slla) {
		p->l2_addr = (const uint8_t *)(p->opt_slla + 1);
		p->ip_addr = (const uint8_t *)&p->ip6->ip6_src;
		p->origin = ND_NS;
		save_pairing(p);
		return;
	}

	log_debug("%s: Ignoring unknown IPv6 NS packet. Packet dump: %s", p->ifc->name, base64_encode_packet(p));
}

void process_na(struct pkt *p)
{
	assert(p);

	p->ip_len = IP6_LEN;

	if (p->opt_tlla) {
		p->l2_addr = (const uint8_t *)(p->opt_tlla + 1);
		p->ip_addr = (const uint8_t *)&p->na->nd_na_target;
		p->origin = ND_NA;
		save_pairing(p);
		return;
	}

	log_debug("%s: Ignoring unknown IPv6 NA packet. Packet dump: %s", p->ifc->name, base64_encode_packet(p));
}

void process_ra(struct pkt *p)
{
	assert(p);

	p->ip_len = IP6_LEN;

	if (p->opt_slla) {
		p->l2_addr = (const uint8_t *)(p->opt_slla + 1);
		p->ip_addr = (const uint8_t *)&p->ip6->ip6_src;
		p->origin = ND_RA;
		save_pairing(p);
		return;
	}

	log_debug("%s: Ignoring unknown IPv6 RA packet. Packet dump: %s", p->ifc->name, base64_encode_packet(p));
}

void process_rs(struct pkt *p)
{
	assert(p);

	p->ip_len = IP6_LEN;

	if (p->opt_slla) {
		p->l2_addr = (const uint8_t *)(p->opt_slla + 1);
		p->ip_addr = (const uint8_t *)&p->ip6->ip6_src;
		p->origin = ND_RS;
		save_pairing(p);
		return;
	}

	log_debug("%s: Ignoring unknown IPv6 RS packet. Packet dump: %s", p->ifc->name, base64_encode_packet(p));
}
