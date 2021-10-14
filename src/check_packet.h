#pragma once

#include "macro.h"
#include "packet.h"

int check_arp(const struct pkt *p) _nonnull_ _wur_;
int check_ns(const struct pkt *p) _nonnull_ _wur_;
int check_na(const struct pkt *p) _nonnull_ _wur_;
int check_ra(const struct pkt *p) _nonnull_ _wur_;
int check_rs(const struct pkt *p) _nonnull_ _wur_;
