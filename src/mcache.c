#include "mcache.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "arpobserver.h"
#include "log.h"

// Delete dead_node and all following nodes from cache
void cache_prune(struct mcache_node *dead_node, struct mcache_node **cache)
{
	struct mcache_node *node;
	struct mcache_node *next;

	assert(cache);

	if (dead_node == *cache)
		*cache = NULL;
	else {
		for (node = *cache; node && node->next != dead_node; node = node->next) {}

		/* Assert that dead_node was found in the cache */
		assert(node->next == dead_node);
		node->next = NULL;
	}

	/* Delete remaining list */
	for (node = dead_node; node; node = next) {
		next = node->next;
		free(node);
	}
}

// Delete only deda_node from the cache
void cache_del(struct mcache_node *dead_node, struct mcache_node **cache)
{
	struct mcache_node *node;

	assert(cache);

	if (dead_node == *cache)
		*cache = dead_node->next;
	else {
		for (node = *cache; node && node->next != dead_node; node = node->next) {}

		assert(node->next == dead_node);
		node->next = dead_node->next;
	}

	free(dead_node);
}

// Add new node to the cache
int cache_add(const uint8_t *l2_addr, const uint8_t *ip_addr, uint8_t len, time_t tstamp, uint16_t vlan_tag, struct mcache_node **cache)
{
	struct mcache_node *node;

	assert(l2_addr);
	assert(ip_addr);
	assert(cache);

	node = calloc(sizeof(*node), 1);
	if (!node)
		return log_oom();

	memcpy(node->l2_addr, l2_addr, sizeof(node->l2_addr));
	memcpy(node->ip_addr, ip_addr, len);
	node->tstamp = tstamp;
	node->addr_len = len;
	node->vlan_tag = vlan_tag;

	node->next = *cache;
	*cache = node;

	return 0;
}

struct mcache_node *cache_lookup(const uint8_t *l2_addr,
				 const uint8_t *ip_addr,
				 uint8_t len,
				 time_t tstamp,
				 uint16_t vlan_tag,
				 struct mcache_node **cache)
{
	assert(l2_addr);
	assert(ip_addr);
	assert(cache);

	for (struct mcache_node *node = *cache; node != NULL; node = node->next) {
		/* New cache nodes are inserted at the beginning of the list
		 * resulting cache list ordered by timestamp.
		 *
		 * If we find old cache node we can safely delete it and all
		 * following nodes.
		 */
		if (global_cfg.ratelimit > 0 && tstamp > node->tstamp + global_cfg.ratelimit) {
			cache_prune(node, cache);
			return NULL;
		}

		if (vlan_tag != node->vlan_tag)
			continue;

		if (len != node->addr_len)
			continue;

		if (memcmp(ip_addr, node->ip_addr, len) != 0)
			continue;

		if (memcmp(l2_addr, node->l2_addr, sizeof(node->l2_addr)) != 0) {
			cache_del(node, cache);
			return NULL;
		}

		return node;
	}

	return NULL;
}
