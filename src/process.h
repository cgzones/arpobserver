#pragma once

#include "common.h"

void process_arp(struct pkt *p);
void process_ns(struct pkt *p);
void process_na(struct pkt *p);
void process_ra(struct pkt *p);
void process_rs(struct pkt *p);
