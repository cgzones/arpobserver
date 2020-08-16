#include "base64.h"

#include <assert.h>
#include <string.h>
#include <strings.h>

static const char *const b64_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char pkt_buffer[SNAP_LEN * 4 / 3 + 3];

static void base64_enc_block(const uint8_t in[3], char out[4], unsigned int len)
{
	unsigned int bin;

	assert(in);
	assert(out);
	assert(len >= 1 && len <= 3);

	if (len == 3) {
		bin = (unsigned int)(in[0] << 16) + (unsigned int)(in[1] << 8) + (in[2]);
		out[3] = b64_map[(bin >> 0) & 0x3f];
		out[2] = b64_map[(bin >> 6) & 0x3f];
		out[1] = b64_map[(bin >> 12) & 0x3f];
		out[0] = b64_map[(bin >> 18) & 0x3f];
	} else if (len == 2) {
		bin = (unsigned int)(in[0] << 16) + (unsigned int)(in[1] << 8);
		out[3] = '=';
		out[2] = b64_map[(bin >> 6) & 0x3f];
		out[1] = b64_map[(bin >> 12) & 0x3f];
		out[0] = b64_map[(bin >> 18) & 0x3f];
	} else if (len == 1) {
		bin = (unsigned int)(in[0] << 16);
		out[3] = '=';
		out[2] = '=';
		out[1] = b64_map[(bin >> 12) & 0x3f];
		out[0] = b64_map[(bin >> 18) & 0x3f];
	}
}

void base64_encode(const uint8_t *src, char *dst, unsigned int ssize, unsigned int dsize)
{
	assert(src);
	assert(dst);
	assert(dsize >= (ssize + (ssize % 3)) * 4 / 3);

	for (unsigned int i = 0; i < ssize; i = i + 3) {
		unsigned int len = (ssize - i >= 3 ? 3 : ssize - i);
		base64_enc_block(src + i, dst + i * 4 / 3, len);
	}
}

char *base64_encode_packet(const struct pkt *p)
{
	assert(p);

	memset(pkt_buffer, 0, sizeof(pkt_buffer));

	base64_encode(p->raw_packet, pkt_buffer, p->pcap_header->len, sizeof(pkt_buffer));

	return pkt_buffer;
}
