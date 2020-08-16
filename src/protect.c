#include "protect.h"

#include <net/ethernet.h>
#include <string.h>

#include "common.h"
#include "dllist.h"
#include "log.h"

struct protect_entry {
	uint8_t ip4_address[IP4_LEN];
	uint8_t ip6_address[IP6_LEN];
	uint8_t mac_address[ETHER_ADDR_LEN];
	bool ip4_set;
	bool ip6_set;
	bool mac_set;
};

static void free_protect_entry(void *p)
{
	free(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct protect_entry *, free_protect_entry);
#define _cleanup_protect_entry_ _cleanup_(free_protect_entryp)

static struct dllist_head *protect_list = NULL;


static int init_protect_list(void)
{
	if (protect_list)
		return 0;

	protect_list = dllist_init(free_protect_entry);

	return protect_list ? 0 : -ENOMEM;
}

void free_protect_list()
{
	dllist_free(protect_list);
	protect_list = NULL;
}

int protect_ip(const char *ip_str)
{
	_cleanup_protect_entry_ struct protect_entry *new_entry = NULL;

	if (init_protect_list() < 0)
		return log_error("Cannot initialize protect list: %m");

	new_entry = malloc(sizeof(struct protect_entry));
	if (!new_entry)
		return log_oom();

	if (convert_ip4_str_to_addr(ip_str, new_entry->ip4_address) == 0) {
		new_entry->ip4_set = true;
		new_entry->ip6_set = false;
	} else if (convert_ip6_str_to_addr(ip_str, new_entry->ip6_address) == 0) {
		new_entry->ip4_set = false;
		new_entry->ip6_set = true;
	} else
		return log_errno_warn(EINVAL, "Cannot protect IP '%s': not a valid IPv4 or IPv6 address", ip_str);

	new_entry->mac_set = false;

	if (dllist_push_back(protect_list, TAKE_PTR(new_entry)) < 0)
		log_oom();

	return 0;
}

int protect_mac(const char *mac_str)
{
	_cleanup_protect_entry_ struct protect_entry *new_entry = NULL;

	if (init_protect_list() < 0)
		return log_error("Cannot initialize protect list: %m");

	new_entry = malloc(sizeof(struct protect_entry));
	if (!new_entry)
		return log_oom();

	if (convert_mac_str_to_addr(mac_str, new_entry->mac_address) < 0)
		return log_errno_warn(EINVAL, "Cannot protect MAC '%s': not a valid MAC address", mac_str);

	new_entry->mac_set = true;
	new_entry->ip4_set = new_entry->ip6_set = false;

	if (dllist_push_back(protect_list, TAKE_PTR(new_entry)) < 0)
		log_oom();

	return 0;
}

int protect_mac_ip_pairing(const char *mac_ip_str)
{
	_cleanup_protect_entry_ struct protect_entry *new_entry = NULL;
	const char *delim, *ip_str;
	_cleanup_free_ char *mac_str = NULL;

	if (init_protect_list() < 0)
		return log_error("Cannot initialize protect list: %m");

	new_entry = malloc(sizeof(struct protect_entry));
	if (!new_entry)
		return log_oom();

	delim = strchr(mac_ip_str, '@');
	if (!delim)
		return log_errno_warn(EINVAL, "Cannot protect pairing '%s': invalid format", mac_ip_str);
	ip_str = delim + 1;

	mac_str = strndup(mac_ip_str, (size_t)(delim - mac_ip_str));
	if (!mac_str)
		return log_oom();

	if (convert_mac_str_to_addr(mac_str, new_entry->mac_address) < 0)
		return log_errno_warn(EINVAL, "Cannot protect MAC '%s': not a valid MAC address", mac_str);

	new_entry->mac_set = true;

	if (convert_ip4_str_to_addr(ip_str, new_entry->ip4_address) == 0) {
		new_entry->ip4_set = true;
		new_entry->ip6_set = false;
	} else if (convert_ip6_str_to_addr(ip_str, new_entry->ip6_address) == 0) {
		new_entry->ip4_set = false;
		new_entry->ip6_set = true;
	} else
		return log_errno_warn(EINVAL, "Cannot protect IP '%s': not a valid IPv4 or IPv6 address", ip_str);

	if (dllist_push_back(protect_list, TAKE_PTR(new_entry)) < 0)
		log_oom();

	return 0;
}

bool protect_match(const uint8_t *mac_addr, const uint8_t *ip_addr, enum ip_type_len ip_addr_len)
{
	if (!protect_list)
		return false;

	for (struct dllist_entry *dentry = protect_list->first; dentry; dentry = dentry->next) {
		struct protect_entry *pentry = dentry->data;

		/* does MAC address match? */
		if (pentry->mac_set && 0 == memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address))) {
			if (ip_addr_len == IP4_LEN) {
				if (pentry->ip4_set)
					return 0 != memcmp(pentry->ip4_address, ip_addr, sizeof(pentry->ip4_address));

				memcpy(pentry->ip4_address, ip_addr, sizeof(pentry->ip4_address));
				pentry->ip4_set = true;

				return false;
			}

			if (ip_addr_len == IP6_LEN) {
				if (pentry->ip6_set)
					return 0 != memcmp(pentry->ip6_address, ip_addr, sizeof(pentry->ip6_address));

				memcpy(pentry->ip6_address, ip_addr, sizeof(pentry->ip6_address));
				pentry->ip6_set = true;

				return false;
			}

			return false;
		}

		/* does IPv4 address match? */
		if (ip_addr_len == IP4_LEN && pentry->ip4_set && 0 == memcmp(pentry->ip4_address, ip_addr, sizeof(pentry->ip4_address))) {
			if (pentry->mac_set)
				return 0 != memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address));

			memcpy(pentry->mac_address, mac_addr, sizeof(pentry->mac_address));
			pentry->mac_set = true;

			return false;
		}

		/* does IPv6 address match? */
		if (ip_addr_len == IP6_LEN && pentry->ip6_set && 0 == memcmp(pentry->ip6_address, ip_addr, sizeof(pentry->ip6_address))) {
			if (pentry->mac_set)
				return 0 != memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address));

			memcpy(pentry->mac_address, mac_addr, sizeof(pentry->mac_address));
			pentry->mac_set = true;

			return false;
		}
	}

	return false;
}
