#pragma once

#include "dllist.h"

#define CHECK_DEFAULT_STATE_FILE LOCALSTATEDIR "/lib/" PACKAGE "/check.state"

int lock_state_file(const char *path) _nonnull_ _wur_;

int read_state_file(const char *path, struct dllist_head *state) _nonnull_ _wur_;

void dump_state(const struct dllist_head *state) _nonnull_;

int write_state_file(const char *path, const struct dllist_head *state) _nonnull_ _wur_;
