#include "common.h"

#include <assert.h>
#include <errno.h>

const char *const pkt_origin_str[] = {"ARP_REQ", "ARP_REP", "ARP_ACD", "ND_NS", "ND_NA", "ND_DAD", "ND_RA", "ND_RS", NULL};

const char *const pkt_origin_desc[] = {[ARP_REQ] = "ARP Request packet",
				       [ARP_REP] = "ARP Reply packet",
				       [ARP_ACD] = "ARP Address collision detection packet",
				       [ND_NS] = "Neighbor Solicitation packet",
				       [ND_NA] = "Neighbor Advertisement packet",
				       [ND_DAD] = "Duplicate Address Detection packet",
				       [ND_RA] = "Router Advertisement packet",
				       [ND_RS] = "Router Solicitation packet",
				       NULL};


void convert_mac_addr_to_str(const uint8_t addr[], char *str)
{
	assert(addr);
	assert(str);

	snprintf(str, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

int convert_mac_str_to_addr(const char *str, uint8_t addr[])
{
	int rc;

	assert(str);
	assert(addr);

	rc = sscanf(str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);

	return rc == 6 ? 0 : -EINVAL;
}

int convert_ip4_addr_to_str(const void *addr, char *str)
{
	assert(addr);
	assert(str);

	if (!inet_ntop(AF_INET, addr, str, INET_ADDRSTRLEN))
		return -errno;

	return 0;
}

int convert_ip4_str_to_addr(const char *str, void *addr)
{
	int rc;

	assert(str);
	assert(addr);

	rc = inet_pton(AF_INET, str, addr);
	if (rc < 0)
		return -errno;
	if (rc == 1)
		return 0;

	return -EINVAL;
}

int convert_ip6_addr_to_str(const void *addr, char *str)
{
	assert(addr);
	assert(str);

	if (!inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN))
		return -errno;

	return 0;
}

int convert_ip6_str_to_addr(const char *str, void *addr)
{
	int rc;

	assert(str);
	assert(addr);

	rc = inet_pton(AF_INET6, str, addr);
	if (rc < 0)
		return -errno;
	if (rc == 1)
		return 0;

	return -EINVAL;
}

int convert_ip_addr_to_str(const void *addr, int addr_len, char *str)
{
	if (addr_len == IP6_LEN)
		return convert_ip6_addr_to_str(addr, str);
	if (addr_len == IP4_LEN)
		return convert_ip4_addr_to_str(addr, str);

	return -EINVAL;
}
