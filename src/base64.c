#include "base64.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *const b64_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char pkt_buffer[SNAP_LEN * 4 / 3 + 3];

static void base64_enc_block(const unsigned char in[3], char out[4], uint8_t len)
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

size_t base64_encode(const void *src, size_t ssize, void *dst, size_t dsize)
{
	assert(src);
	assert(dst);
	assert(dsize >= (ssize + 2) / 3 * 4);

	for (size_t i = 0; i < ssize; i = i + 3) {
		uint8_t len = (ssize - i >= 3 ? 3 : (uint8_t)(ssize - i));
		base64_enc_block((const unsigned char *)src + i, (char *)dst + i * 4 / 3, len);
	}

	return (ssize + 2) / 3 * 4;
}

const char *base64_encode_packet(const struct pkt *p)
{
	assert(p);

	memset(pkt_buffer, 0, sizeof(pkt_buffer));

	base64_encode(p->raw_packet, p->pcap_header->len, pkt_buffer, sizeof(pkt_buffer));

	return pkt_buffer;
}

static const uint8_t b64_decode_map[256] = {
	0, 0, 0,  0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,
	0, 0, 0,  0, 0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0, 0,
	0, 0, 0,  0, 1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0,
	0, 0, 63, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

size_t base64_decode(const void *src, size_t ssize, void *dst, size_t dsize)
{
	const unsigned char *s;
	unsigned char *d;
	unsigned int pad;
	size_t limit;
	size_t j = 0;

	assert(src);
	assert(dst);
	assert(dsize >= (ssize + 2) / 4 * 3);

	s = src;
	d = dst;
	pad = ssize > 0 && (ssize % 4 || s[ssize - 1] == '=');
	limit = ((ssize + 3) / 4 - pad) * 4;

	for (size_t i = 0; i < limit; i += 4) {
		unsigned int n = (unsigned int)(b64_decode_map[s[i]] << 18) | (unsigned int)(b64_decode_map[s[i + 1]] << 12)
				 | (unsigned int)(b64_decode_map[s[i + 2]] << 6) | (unsigned int)(b64_decode_map[s[i + 3]]);
		d[j++] = (uint8_t)(n >> 16);
		d[j++] = (n >> 8) & 0xFF;
		d[j++] = n & 0xFF;
	}

	if (pad) {
		unsigned int n = (unsigned int)(b64_decode_map[s[limit]] << 18) | (unsigned int)(b64_decode_map[s[limit + 1]] << 12);
		d[j++] = (uint8_t)(n >> 16);

		if (ssize > limit + 2 && s[limit + 2] != '=') {
			n |= (unsigned int)(b64_decode_map[s[limit + 2]] << 6);
			d[j++] = (n >> 8) & 0xFF;
		}
	}

	return j;
}
