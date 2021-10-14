#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"
#include "check_packet.h"
#include "cleanup.h"
#include "log.h"
#include "macro.h"
#include "parse.h"

extern bool arpbridgelist_contains(_unused_ const uint8_t addr[ETHER_ADDR_LEN]);


bool arpbridgelist_contains(_unused_ const uint8_t addr[ETHER_ADDR_LEN])
{
	return false;
}

static void parse_wrapper(const uint8_t *data, size_t length)
{
	struct pkt p;
	int rc;

	assert(data);

	memset(&p, 0, sizeof(p));

	p.raw_packet = data;

	p.pos = data;
	p.len = length;

	p.ifc = NULL;
	p.pcap_header = NULL;

	rc = parse_packet(&p);
	if (rc < 0) {
		fprintf(stderr, "parsing failed.\n");
		return;
	}

	switch (p.kind) {
	case KIND_ARP:
		rc = check_arp(&p);
		break;
	case KIND_NA:
		rc = check_na(&p);
		break;
	case KIND_NS:
		rc = check_ns(&p);
		break;
	case KIND_RA:
		rc = check_ra(&p);
		break;
	case KIND_RS:
		rc = check_rs(&p);
		break;
	default:
		rc = -1;
		fprintf(stderr, "Invalid parsed packet type: %d\n", p.kind);
		break;
	}

	if (rc)
		fprintf(stderr, "packet check failed.\n");
}

int main(int argc, char *argv[])
{
	const char *base64_pkt;
	size_t base64_pkt_len;
	_cleanup_free_ char *raw_pkt = NULL;
	size_t raw_pkt_len;
	size_t decoded_size;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <base64-packet>\n", argv[0]);
		return EXIT_FAILURE;
	}

	log_open("packet-parser");

	base64_pkt = argv[1];
	base64_pkt_len = strlen(base64_pkt);

	raw_pkt_len = (base64_pkt_len + 2) / 4 * 3;
	raw_pkt = malloc(raw_pkt_len);
	if (!raw_pkt) {
		fprintf(stderr, "Out of memory: %m\n");
		return EXIT_FAILURE;
	}

	decoded_size = base64_decode(base64_pkt, base64_pkt_len, raw_pkt, raw_pkt_len);

	printf("parsing packet of size %zu..\n", decoded_size);

	parse_wrapper((unsigned char *)raw_pkt, decoded_size);

	return EXIT_SUCCESS;
}
