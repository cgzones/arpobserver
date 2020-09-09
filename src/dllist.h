#pragma once

#include <assert.h>
#include <stddef.h>

#include "cleanup.h"
#include "macro.h"

struct dllist_entry {
	void *data;
	struct dllist_entry *next;
	struct dllist_entry *prev;
};

typedef void (*entry_data_free_t)(void *data);

struct dllist_head {
	struct dllist_entry *first;
	struct dllist_entry *last;
	size_t size;
	entry_data_free_t free_func;
};


struct dllist_head *dllist_init(entry_data_free_t free_func) _wur_;

void dllist_free(struct dllist_head *h);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct dllist_head *, dllist_free);
#define _cleanup_dllist_ _cleanup_(dllist_freep)


int dllist_push_front(struct dllist_head *h, void *data) _nonnull_ _wur_;
int dllist_push_back(struct dllist_head *h, void *data) _nonnull_ _wur_;

struct dllist_entry *dllist_delete_entry(struct dllist_head *h, struct dllist_entry *e) _nonnull_;

void dllist_promote_entry(struct dllist_head *h, struct dllist_entry *e) _nonnull_;
