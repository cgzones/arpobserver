#pragma once

#include "common.h"

int output_sqlite_init(void) _wur_;
int output_sqlite_reload(void) _wur_;
int output_sqlite_save(const struct pkt *p, const char *mac_str, const char *ip_str) _nonnull_ _wur_;
void output_sqlite_close(void);
