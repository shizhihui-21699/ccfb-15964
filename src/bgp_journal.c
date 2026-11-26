#include "tcp_ao.h"

#include <stdlib.h>
#include <string.h>

struct bgp_journal_message {
	uint64_t id;
	uint8_t *data;
	size_t len;
};

struct bgp_journal {
	size_t max_messages;
	uint64_t next_id;
	struct bgp_journal_message *items;
	size_t count;
	size_t cap;
};

int bgp_journal_create(size_t max_messages, bgp_journal_t **out)
{
	bgp_journal_t *j;

	if (!out)
		return AO_EINVAL;
	j = calloc(1, sizeof(*j));
	if (!j)
		return AO_ENOMEM;
	j->max_messages = max_messages;
	j->next_id = 1;
	*out = j;
	return AO_OK;
}

void bgp_journal_destroy(bgp_journal_t *j)
{
	size_t i;

	if (!j)
		return;
	for (i = 0; i < j->count; ++i)
		free(j->items[i].data);
	free(j->items);
	free(j);
}

int bgp_journal_append(bgp_journal_t *j, const uint8_t *message,
		       size_t len, uint64_t *id)
{
	struct bgp_journal_message *grown;
	uint8_t *copy;

	if (!j || !message || len == 0)
		return AO_EINVAL;
	if (j->max_messages && j->count >= j->max_messages)
		return AO_EOVERFLOW;
	if (j->count == j->cap) {
		size_t cap = j->cap ? j->cap * 2 : 16;
		grown = realloc(j->items, cap * sizeof(*grown));
		if (!grown)
			return AO_ENOMEM;
		j->items = grown;
		j->cap = cap;
	}

	copy = malloc(len);
	if (!copy)
		return AO_ENOMEM;
	memcpy(copy, message, len);
	j->items[j->count].id = j->next_id++;
	j->items[j->count].data = copy;
	j->items[j->count].len = len;
	if (id)
		*id = j->items[j->count].id;
	j->count++;
	return AO_OK;
}

size_t bgp_journal_pending(const bgp_journal_t *j)
{
	return j ? j->count : 0;
}

int bgp_writer_init(bgp_update_writer_t *w, int fd, bgp_journal_t *journal)
{
	if (!w || !journal)
		return AO_EINVAL;
	memset(w, 0, sizeof(*w));
	w->fd = fd;
	w->journal = journal;
	return AO_OK;
}

int bgp_writer_enqueue(bgp_update_writer_t *w, const uint8_t *msg,
		       size_t len, uint64_t *id)
{
	if (!w)
		return AO_EINVAL;
	return bgp_journal_append(w->journal, msg, len, id);
}

static int pop_first(bgp_journal_t *j)
{
	if (j->count == 0)
		return AO_ESTATE;
	free(j->items[0].data);
	memmove(&j->items[0], &j->items[1],
		(j->count - 1) * sizeof(j->items[0]));
	j->count--;
	return AO_OK;
}

int bgp_writer_flush(bgp_update_writer_t *w, bgp_write_fn write_fn,
		     void *user)
{
	if (!w || !write_fn)
		return AO_EINVAL;

	while (w->journal->count > 0) {
		struct bgp_journal_message *m = &w->journal->items[0];
		size_t remaining;
		ssize_t n;

		if (w->active_id != m->id) {
			w->active_id = m->id;
			w->active_offset = 0;
		}
		if (w->active_offset >= m->len) {
			pop_first(w->journal);
			w->active_id = 0;
			w->active_offset = 0;
			continue;
		}

		remaining = m->len - w->active_offset;
		n = write_fn(w->fd, m->data + w->active_offset, remaining,
			      user);
		if (n <= 0)
			return AO_EAGAIN;
		if ((size_t)n > remaining)
			return AO_EOVERFLOW;
		w->active_offset += (size_t)n;
		if (w->active_offset == m->len) {
			pop_first(w->journal);
			w->active_id = 0;
			w->active_offset = 0;
		}
	}
	return AO_OK;
}
