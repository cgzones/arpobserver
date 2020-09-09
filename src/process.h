#pragma once

#include "common.h"

void process_arp(struct pkt *p) _nonnull_;
void process_ns(struct pkt *p) _nonnull_;
void process_na(struct pkt *p) _nonnull_;
void process_ra(struct pkt *p) _nonnull_;
void process_rs(struct pkt *p) _nonnull_;
