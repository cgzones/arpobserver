#include "storage.h"

#include <assert.h>
#include <stdlib.h>

#include "arpobserver.h"
#include "cleanup.h"
#include "log.h"
#include "mcache.h"
#include "output_flatfile.h"
#include "output_shm.h"
#include "output_sqlite.h"


struct mac_list_node
{
	uint8_t addr[ETHER_ADDR_LEN];
	struct mac_list_node *next;
};

static struct mac_list_node *arpbridgelist;

int arpbridgelist_add(const char *mac_str)
{
	uint8_t addr[ETHER_ADDR_LEN];
	struct mac_list_node *node;
	int rc;

	assert(mac_str);

	rc = convert_mac_str_to_addr(mac_str, addr);
	if (rc < 0)
		return log_errno_warn(EINVAL, "Cannot ignore MAC '%s': not a valid address", mac_str);

	node = malloc(sizeof(struct mac_list_node));
	if (!node)
		return log_oom();

	memcpy(node->addr, addr, sizeof(node->addr));
	node->next = arpbridgelist;
	arpbridgelist = TAKE_PTR(node);
	return 0;
}

bool arpbridgelist_contains(const uint8_t addr[ETHER_ADDR_LEN])
{
	for (const struct mac_list_node *node = arpbridgelist; node; node = node->next)
		if (memcmp(node->addr, addr, sizeof(node->addr)) == 0)
			return true;

	return false;
}

void arpbridgelist_free(void)
{
	for (struct mac_list_node *n = arpbridgelist; n;) {
		struct mac_list_node *next_node = n->next;
		free(n);
		n = next_node;
	}

	arpbridgelist = NULL;
}

static struct ip_node *ignorelist;

int ignorelist_add_ip(const char *ip_str)
{
	_cleanup_ip_node_ struct ip_node *ip = NULL;
	int rc;

	assert(ip_str);

	ip = malloc(sizeof(struct ip_node));
	if (!ip)
		return log_oom();

	rc = inet_pton(AF_INET, ip_str, ip->ip_addr);
	if (rc == 1) {
		ip->addr_len = IP4_LEN;
		ip->next = ignorelist;
		ignorelist = TAKE_PTR(ip);
		return 0;
	}

	rc = inet_pton(AF_INET6, ip_str, ip->ip_addr);
	if (rc == 1) {
		ip->addr_len = IP6_LEN;
		ip->next = ignorelist;
		ignorelist = TAKE_PTR(ip);
		return 0;
	}

	return log_errno_warn(EINVAL, "Cannot ignore IP '%s': not a valid IPv4 or IPv6 address", ip_str);
}

void ignorelist_free(void)
{
	for (struct ip_node *ip = ignorelist; ip;) {
		struct ip_node *ip_next = ip->next;
		free(ip);
		ip = ip_next;
	}

	ignorelist = NULL;
}

static const struct ip_node *ignorelist_match_ip(const uint8_t *ip_addr, uint8_t addr_len)
{
	assert(ip_addr);

	for (struct ip_node *ip = ignorelist; ip; ip = ip->next) {
		if (addr_len != ip->addr_len)
			continue;

		if (memcmp(ip_addr, ip->ip_addr, addr_len) != 0)
			continue;

		return ip;
	}

	return NULL;
}

_access_ro_(1) _access_roc_(2, 3) static uint16_t pkt_hash(const uint8_t *l2_addr, const uint8_t *ip_addr, uint8_t len, uint16_t vlan_tag)
{
	uint16_t sum = 0;

	assert(l2_addr);
	assert(ip_addr);

	for (unsigned int i = 0; i < 6; i += 2)
		sum = sum ^ *(const uint16_t *)(const void *)(l2_addr + i);

	for (unsigned int i = 0; i < len; i += 2)
		sum = sum ^ *(const uint16_t *)(const void *)(ip_addr + i);

	sum = sum ^ vlan_tag;

	return sum;
}

void save_pairing(const struct pkt *p)
{
	char mac_str[MAC_STR_LEN];
	char ip_str[INET6_ADDRSTRLEN];
	time_t tstamp;
	uint16_t hash = 0;

	assert(p);

	if (ignorelist_match_ip(p->ip_addr, p->ip_len))
		return;

	tstamp = p->pcap_header->ts.tv_sec;

	if (global_cfg.ratelimit) {
		hash = pkt_hash(p->l2_addr, p->ip_addr, p->ip_len, p->vlan_tag);
		hash = hash % (uint16_t)global_cfg.hashsize;
		if (cache_lookup(p->l2_addr, p->ip_addr, p->ip_len, tstamp, p->vlan_tag, p->ifc->cache + hash))
			return;
	}

	convert_mac_addr_to_str(p->l2_addr, mac_str);

	if (convert_ip_addr_to_str(p->ip_addr, p->ip_len, ip_str) < 0) {
		log_warn("%s: Cannot convert IP address to textual form: %m", __func__);
		return;
	}

	log_debug("saving %lu %s %u %s %s %s", tstamp, p->ifc->name, p->vlan_tag, mac_str, ip_str, pkt_origin_str[p->origin]);

	(void)!output_shm_save(p, mac_str, ip_str);

	(void)!output_flatfile_save(p, mac_str, ip_str);

#ifdef HAVE_LIBSQLITE3
	if (global_cfg.sqlite_filename)
		(void)!output_sqlite_save(p, mac_str, ip_str);
#endif

	if (global_cfg.ratelimit)
		(void)!cache_add(p->l2_addr, p->ip_addr, p->ip_len, tstamp, p->vlan_tag, p->ifc->cache + hash);
}
