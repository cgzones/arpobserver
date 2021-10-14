#pragma once

#include "macro.h"
#include "packet.h"

int output_flatfile_init(void) _wur_;
int output_flatfile_reload(void) _wur_;
int output_flatfile_save(const struct pkt *p, const char *mac_str, const char *ip_str) _nonnull_ _wur_;
void output_flatfile_close(void);
