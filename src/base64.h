#pragma once

#include <string.h>

#include "macro.h"
#include "packet.h"

size_t base64_encode(const void *src, size_t ssize, void *dst, size_t dsize) _access_roc_(1, 2) _access_woc_(3, 4);
const char *base64_encode_packet(const struct pkt *p) _nonnull_ _wur_;

size_t base64_decode(const void *src, size_t ssize, void *dst, size_t dsize) _access_roc_(1, 2) _access_woc_(3, 4);
