#pragma once

#include <string.h>

#include "common.h"

void base64_encode(const uint8_t *src, char *dst, unsigned int ssize, unsigned int dsize);
char *base64_encode_packet(const struct pkt *p) _wur_;
