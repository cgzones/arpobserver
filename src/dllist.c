#include "dllist.h"

struct dllist_head *dllist_init(entry_data_free_t free_func)
{
	struct dllist_head *h = malloc(sizeof(struct dllist_head));
	if (!h)
		return NULL;

	h->first = NULL;
	h->last = NULL;
	h->size = 0;
	h->free_func = free_func;

	return h;
}

void dllist_free(struct dllist_head *h)
{
	if (!h)
		return;

	for (struct dllist_entry *e = h->first; e;) {
		struct dllist_entry *next = e->next;
		if (h->free_func)
			h->free_func(e->data);
		free(e);
		e = next;
	}

	free(h);
}

int dllist_push_back(struct dllist_head *h, void *data)
{
	struct dllist_entry *new_entry;

	assert(h);
	assert(data);

	new_entry = malloc(sizeof(struct dllist_entry));
	if (!new_entry) {
		if (h->free_func)
			h->free_func(data);
		return -ENOMEM;
	}

	new_entry->data = data;
	new_entry->next = NULL;
	new_entry->prev = h->last;
	h->last = new_entry;
	if (new_entry->prev)
		new_entry->prev->next = new_entry;
	if (!h->first)
		h->first = new_entry;
	h->size++;

	return 0;
}

int dllist_push_front(struct dllist_head *h, void *data)
{
	struct dllist_entry *new_entry;

	assert(h);
	assert(data);

	new_entry = malloc(sizeof(struct dllist_entry));
	if (!new_entry) {
		if (h->free_func)
			h->free_func(data);
		return -ENOMEM;
	}

	new_entry->data = data;
	new_entry->next = h->first;
	new_entry->prev = NULL;
	if (h->first)
		h->first->prev = new_entry;
	h->first = new_entry;
	if (!h->last)
		h->last = new_entry;
	h->size++;

	return 0;
}

struct dllist_entry *dllist_delete_entry(struct dllist_head *h, struct dllist_entry *e)
{
	struct dllist_entry *next;

	assert(h);
	assert(h->size > 0);
	assert(e);

	next = e->next;

	if (!e->prev)
		h->first = e->next;   // head entry
	else
		e->prev->next = e->next;

	if (!e->next)
		h->last = e->prev;   // tail entry
	else
		e->next->prev = e->prev;

	if (h->free_func)
		h->free_func(e->data);

	free(e);

	h->size -= 1;

	return next;
}

void dllist_promote_entry(struct dllist_head *h, struct dllist_entry *e)
{
	assert(h);
	assert(e);

	if (!e->prev)
		return;

	if (!e->prev->prev) {
		// predecessor is head entry
		h->first = e;
		if (e->next)
			e->next->prev = e->prev;
		else
			h->last = e->prev;
		e->prev->next = e->next;
		e->prev->prev = e;
		e->next = e->prev;
		e->prev = NULL;
	} else {
		e->prev->prev->next = e;
		if (e->next)
			e->next->prev = e->prev;
		else
			h->last = e->prev;
		e->prev->next = e->next;
		e->next = e->prev;
		e->prev = e->prev->prev;
		e->next->prev = e;
	}
}
