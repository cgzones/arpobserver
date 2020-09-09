#pragma once

#include <string.h>

#include "common.h"

void base64_encode(const uint8_t *src, char *dst, unsigned int ssize, unsigned int dsize) _access_roc_(1, 3) _access_woc_(2, 3);
char *base64_encode_packet(const struct pkt *p) _nonnull_ _wur_;
