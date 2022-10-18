#include "protect.h"

#include <string.h>

#include "common.h"
#include "dllist.h"
#include "log.h"

static void free_protect_entry(void *p)
{
	free(p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(struct protect_entry *, free_protect_entry);
#define _cleanup_protect_entry_ _cleanup_(free_protect_entryp)

static struct dllist_head *protect_list = NULL;

_wur_ static int init_protect_list(void)
{
	if (protect_list)
		return 0;

	protect_list = dllist_init(free_protect_entry);

	return protect_list ? 0 : -ENOMEM;
}

size_t protect_list_size(void)
{
	size_t count = 0;

	if (!protect_list)
		return 0;

	for (const struct dllist_entry *dentry = protect_list->first; dentry; dentry = dentry->next)
		++count;

	return count;
}

void free_protect_list(void)
{
	dllist_free(protect_list);
	protect_list = NULL;
}

_nonnull_ _wur_ static bool ip4_already_set(const uint8_t *ip4_addr)
{
	assert(protect_list);
	assert(ip4_addr);

	for (const struct dllist_entry *dentry = protect_list->first; dentry; dentry = dentry->next) {
		const struct protect_entry *pentry = dentry->data;

		if (!pentry->ip4_set)
			continue;

		if (0 == memcmp(pentry->ip4_address, ip4_addr, IP4_LEN))
			return true;
	}

	return false;
}

_nonnull_ _wur_ static bool ip6_already_set(const uint8_t *ip6_addr)
{
	assert(protect_list);
	assert(ip6_addr);

	for (const struct dllist_entry *dentry = protect_list->first; dentry; dentry = dentry->next) {
		const struct protect_entry *pentry = dentry->data;

		if (!pentry->ip6_set)
			continue;

		if (0 == memcmp(pentry->ip6_address, ip6_addr, IP6_LEN))
			return true;
	}

	return false;
}

_nonnull_ _wur_ static struct protect_entry *find_mac(const uint8_t *mac_addr)
{
	assert(protect_list);
	assert(mac_addr);

	for (const struct dllist_entry *dentry = protect_list->first; dentry; dentry = dentry->next) {
		struct protect_entry *pentry = dentry->data;

		if (!pentry->mac_set)
			continue;

		if (0 == memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address)))
			return pentry;
	}

	return NULL;
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
		if (ip4_already_set(new_entry->ip4_address))
			return log_errno_warn(EINVAL, "Cannot protect IP '%s': IPv4 address already protected", ip_str);
		new_entry->ip4_set = true;
		new_entry->ip6_set = false;
	} else if (convert_ip6_str_to_addr(ip_str, new_entry->ip6_address) == 0) {
		if (ip6_already_set(new_entry->ip6_address))
			return log_errno_warn(EINVAL, "Cannot protect IP '%s': IPv6 address already protected", ip_str);
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

	if (find_mac(new_entry->mac_address))
		return log_errno_warn(EINVAL, "Cannot protect MAC '%s': MAC address already protected", mac_str);

	new_entry->mac_set = true;
	new_entry->ip4_set = new_entry->ip6_set = false;

	if (dllist_push_back(protect_list, TAKE_PTR(new_entry)) < 0)
		log_oom();

	return 0;
}

int protect_mac_ip_pairing(const char *mac_ip_str)
{
	_cleanup_protect_entry_ struct protect_entry *new_entry = NULL;
	struct protect_entry *found_entry;
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
		return log_errno_warn(EINVAL, "Cannot protect pairing MAC '%s': not a valid MAC address", mac_str);

	new_entry->mac_set = true;

	if (convert_ip4_str_to_addr(ip_str, new_entry->ip4_address) == 0) {
		new_entry->ip4_set = true;
		new_entry->ip6_set = false;
	} else if (convert_ip6_str_to_addr(ip_str, new_entry->ip6_address) == 0) {
		new_entry->ip4_set = false;
		new_entry->ip6_set = true;
	} else
		return log_errno_warn(EINVAL, "Cannot protect pairing IP '%s': not a valid IPv4 or IPv6 address", ip_str);

	found_entry = find_mac(new_entry->mac_address);
	if (found_entry) {
		if (new_entry->ip4_set && found_entry->ip4_set)
			return log_errno_warn(EINVAL, "Cannot protect pairing '%s': MAC and IPv4 already protected", mac_ip_str);

		if (new_entry->ip6_set && found_entry->ip6_set)
			return log_errno_warn(EINVAL, "Cannot protect pairing '%s': MAC and IPv6 already protected", mac_ip_str);

		if (!found_entry->ip4_set && new_entry->ip4_set) {
			memcpy(found_entry->ip4_address, new_entry->ip4_address, sizeof(found_entry->ip4_address));
			found_entry->ip4_set = true;
		}
		if (!found_entry->ip6_set && new_entry->ip6_set) {
			memcpy(found_entry->ip6_address, new_entry->ip6_address, sizeof(found_entry->ip6_address));
			found_entry->ip6_set = true;
		}

		return 0;
	}

	if (dllist_push_back(protect_list, TAKE_PTR(new_entry)) < 0)
		log_oom();

	return 0;
}

const struct protect_entry *protect_match(const uint8_t *mac_addr, const uint8_t *ip_addr, enum ip_type_len ip_addr_len)
{
	if (!protect_list)
		return NULL;

	for (struct dllist_entry *dentry = protect_list->first; dentry; dentry = dentry->next) {
		struct protect_entry *pentry = dentry->data;

		/* does MAC address match? */
		if (pentry->mac_set && 0 == memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address))) {
			if (ip_addr_len == IP4_LEN) {
				if (pentry->ip4_set) {
					if (0 != memcmp(pentry->ip4_address, ip_addr, sizeof(pentry->ip4_address)))
						return pentry;

					continue;
				}

				memcpy(pentry->ip4_address, ip_addr, sizeof(pentry->ip4_address));
				pentry->ip4_set = true;

				return NULL;
			}

			if (ip_addr_len == IP6_LEN) {
				if (pentry->ip6_set) {
					if (0 != memcmp(pentry->ip6_address, ip_addr, sizeof(pentry->ip6_address)))
						return pentry;

					continue;
				}

				memcpy(pentry->ip6_address, ip_addr, sizeof(pentry->ip6_address));
				pentry->ip6_set = true;

				return NULL;
			}

			return NULL;
		}

		/* does IPv4 address match? */
		if (ip_addr_len == IP4_LEN && pentry->ip4_set && 0 == memcmp(pentry->ip4_address, ip_addr, sizeof(pentry->ip4_address))) {
			if (pentry->mac_set) {
				if (0 != memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address)))
					return pentry;

				continue;
			}

			memcpy(pentry->mac_address, mac_addr, sizeof(pentry->mac_address));
			pentry->mac_set = true;

			return NULL;
		}

		/* does IPv6 address match? */
		if (ip_addr_len == IP6_LEN && pentry->ip6_set && 0 == memcmp(pentry->ip6_address, ip_addr, sizeof(pentry->ip6_address))) {
			if (pentry->mac_set) {
				if (0 != memcmp(pentry->mac_address, mac_addr, sizeof(pentry->mac_address)))
					return pentry;

				continue;
			}

			memcpy(pentry->mac_address, mac_addr, sizeof(pentry->mac_address));
			pentry->mac_set = true;

			return NULL;
		}
	}

	return NULL;
}
