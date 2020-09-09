#pragma once

#include "common.h"

int output_shm_init(void) _wur_;
int output_shm_reload(void) _wur_;
int output_shm_save(const struct pkt *p, const char *mac_str, const char *ip_str) _nonnull_ _wur_;
int output_shm_timeout(void) _wur_;
void output_shm_close(void);
