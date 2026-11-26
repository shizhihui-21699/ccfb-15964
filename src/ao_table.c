#include "tcp_ao.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct ao_table {
	pthread_rwlock_t lock;
	ao_mkt_t *items;
	size_t count;
	size_t cap;
	uint32_t next_id;
};

static void secure_zero(void *p, size_t n)
{
	volatile unsigned char *vp = p;
	while (n-- > 0)
		*vp++ = 0;
}

static int valid_alg(const ao_mkt_t *m)
{
	if (m->alg == AO_ALG_HMAC_SHA1_96)
		return m->mac_len == 0 || m->mac_len == AO_MAC_HMAC_SHA1_96_LEN;
	if (m->alg == AO_ALG_AES_128_CMAC_96 ||
	    m->alg == AO_ALG_HMAC_SHA256_96)
		return 1; /* accepted for kernel pass-through */
	return 0;
}

static int validate_mkt(const ao_mkt_t *m)
{
	if (!m || m->key_len == 0 || m->key_len > AO_MAX_MASTER_KEY_LEN)
		return 0;
	if (m->mac_len > AO_MAX_MAC_LEN)
		return 0;
	if (!valid_alg(m))
		return 0;
	if (m->match.local.family != AO_FAMILY_UNSPEC) {
		if (m->match.local.family != AO_FAMILY_IPV4 &&
		    m->match.local.family != AO_FAMILY_IPV6)
			return 0;
		if (m->match.local.prefix >
		    (m->match.local.family == AO_FAMILY_IPV4 ? 32 : 128))
			return 0;
	}
	if (m->match.remote.family != AO_FAMILY_UNSPEC) {
		if (m->match.remote.family != AO_FAMILY_IPV4 &&
		    m->match.remote.family != AO_FAMILY_IPV6)
			return 0;
		if (m->match.remote.prefix >
		    (m->match.remote.family == AO_FAMILY_IPV4 ? 32 : 128))
			return 0;
	}
	return 1;
}

int ao_table_create(ao_table_t **table)
{
	ao_table_t *t;

	if (!table)
		return AO_EINVAL;
	t = calloc(1, sizeof(*t));
	if (!t)
		return AO_ENOMEM;
	if (pthread_rwlock_init(&t->lock, NULL) != 0) {
		free(t);
		return AO_EIO;
	}
	t->next_id = 1;
	*table = t;
	return AO_OK;
}

void ao_table_destroy(ao_table_t *table)
{
	if (!table)
		return;
	pthread_rwlock_destroy(&table->lock);
	if (table->items)
		secure_zero(table->items, table->count * sizeof(*table->items));
	free(table->items);
	free(table);
}

static int prefix_bits_equal(const uint8_t *a, const uint8_t *b,
			     uint8_t prefix, size_t bytes)
{
	size_t full = prefix / 8;
	unsigned rem = prefix % 8;

	if (prefix > bytes * 8)
		return 0;
	if (full && memcmp(a, b, full) != 0)
		return 0;
	if (rem && full < bytes) {
		uint8_t mask = (uint8_t)(0xffU << (8 - rem));
		return (a[full] & mask) == (b[full] & mask);
	}
	return 1;
}

static int addr_matches(const ao_addr_t *sel, const ao_addr_t *a)
{
	size_t bytes;

	if (sel->family != AO_FAMILY_UNSPEC) {
		if (sel->family != a->family)
			return 0;
		bytes = sel->family == AO_FAMILY_IPV4 ? 4 : 16;
		if (!prefix_bits_equal(sel->addr, a->addr, sel->prefix, bytes))
			return 0;
	}
	/* A wildcard address can still carry a specific port selector. */
	if (sel->port != 0 && sel->port != a->port)
		return 0;
	return 1;
}

static int tuple_matches(const ao_tuple_t *sel, const ao_tuple_t *t)
{
	return addr_matches(&sel->local, &t->local) &&
	       addr_matches(&sel->remote, &t->remote);
}

static int prefixes_overlap(const ao_addr_t *a, const ao_addr_t *b)
{
	uint8_t min_prefix;
	size_t bytes;

	if (a->family == AO_FAMILY_UNSPEC || b->family == AO_FAMILY_UNSPEC)
		return 1;
	if (a->family != b->family)
		return 0;
	bytes = a->family == AO_FAMILY_IPV4 ? 4 : 16;
	min_prefix = a->prefix < b->prefix ? a->prefix : b->prefix;
	return prefix_bits_equal(a->addr, b->addr, min_prefix, bytes);
}

static int port_overlap(uint16_t a, uint16_t b)
{
	return a == 0 || b == 0 || a == b;
}

static int tuples_overlap(const ao_tuple_t *a, const ao_tuple_t *b)
{
	return prefixes_overlap(&a->local, &b->local) &&
	       prefixes_overlap(&a->remote, &b->remote) &&
	       port_overlap(a->local.port, b->local.port) &&
	       port_overlap(a->remote.port, b->remote.port);
}

int ao_table_add(ao_table_t *table, const ao_mkt_t *mkt, uint32_t *id)
{
	ao_mkt_t *grown;
	size_t i;
	int rc = AO_OK;

	if (!table || !mkt || !validate_mkt(mkt))
		return AO_EINVAL;

	pthread_rwlock_wrlock(&table->lock);
	for (i = 0; i < table->count; ++i) {
		ao_mkt_t *old = &table->items[i];
		if (tuples_overlap(&old->match, &mkt->match) &&
		    (old->send_id == mkt->send_id ||
		     old->recv_id == mkt->recv_id)) {
			rc = AO_EEXIST;
			goto out;
		}
	}

	if (table->count == table->cap) {
		size_t new_cap = table->cap ? table->cap * 2 : 8;
		if (new_cap < table->cap ||
		    new_cap > SIZE_MAX / sizeof(*grown)) {
			rc = AO_EOVERFLOW;
			goto out;
		}
		grown = realloc(table->items, new_cap * sizeof(*grown));
		if (!grown) {
			rc = AO_ENOMEM;
			goto out;
		}
		table->items = grown;
		table->cap = new_cap;
	}

	table->items[table->count] = *mkt;
	table->items[table->count].id = table->next_id++;
	if ((mkt->alg == AO_ALG_HMAC_SHA1_96 ||
	     mkt->alg == AO_ALG_AES_128_CMAC_96) &&
	    table->items[table->count].mac_len == 0)
		table->items[table->count].mac_len = AO_MAC_HMAC_SHA1_96_LEN;
	if (id)
		*id = table->items[table->count].id;
	table->count++;
out:
	pthread_rwlock_unlock(&table->lock);
	return rc;
}

int ao_table_del(ao_table_t *table, uint32_t id)
{
	size_t i;
	int rc = AO_ENOTFOUND;

	if (!table)
		return AO_EINVAL;
	pthread_rwlock_wrlock(&table->lock);
	for (i = 0; i < table->count; ++i) {
		if (table->items[i].id == id) {
			memmove(&table->items[i], &table->items[i + 1],
				(table->count - i - 1) * sizeof(*table->items));
			table->count--;
			rc = AO_OK;
			break;
		}
	}
	pthread_rwlock_unlock(&table->lock);
	return rc;
}

int ao_table_count(const ao_table_t *table, size_t *count)
{
	if (!table || !count)
		return AO_EINVAL;
	pthread_rwlock_rdlock((pthread_rwlock_t *)&table->lock);
	*count = table->count;
	pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
	return AO_OK;
}

int ao_table_get(const ao_table_t *table, uint32_t id, ao_mkt_t *out)
{
	size_t i;
	int rc = AO_ENOTFOUND;

	if (!table || !out)
		return AO_EINVAL;
	pthread_rwlock_rdlock((pthread_rwlock_t *)&table->lock);
	for (i = 0; i < table->count; ++i) {
		if (table->items[i].id == id) {
			*out = table->items[i];
			rc = AO_OK;
			break;
		}
	}
	pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
	return rc;
}

int ao_table_snapshot(const ao_table_t *table, ao_mkt_t **items,
		      size_t *count)
{
	ao_mkt_t *copy;

	if (!table || !items || !count)
		return AO_EINVAL;

	pthread_rwlock_rdlock((pthread_rwlock_t *)&table->lock);
	*count = table->count;
	if (table->count == 0) {
		*items = NULL;
		pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
		return AO_OK;
	}
	copy = calloc(table->count, sizeof(*copy));
	if (!copy) {
		pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
		return AO_ENOMEM;
	}
	memcpy(copy, table->items, table->count * sizeof(*copy));
	*items = copy;
	pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
	return AO_OK;
}

void ao_table_snapshot_free(ao_mkt_t *items, size_t count)
{
	if (items)
		secure_zero(items, count * sizeof(*items));
	free(items);
}

static int find_id(const ao_table_t *table, const ao_tuple_t *tuple,
		   uint8_t id, int recv, ao_mkt_t *out)
{
	size_t i;
	int found = 0;

	if (!table || !tuple || !out)
		return AO_EINVAL;

	pthread_rwlock_rdlock((pthread_rwlock_t *)&table->lock);
	for (i = 0; i < table->count; ++i) {
		ao_mkt_t *m = &table->items[i];
		uint8_t wanted = recv ? m->recv_id : m->send_id;

		if (wanted != id || !tuple_matches(&m->match, tuple))
			continue;
		if (found) {
			pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
			return AO_EEXIST;
		}
		*out = *m;
		found = 1;
	}
	pthread_rwlock_unlock((pthread_rwlock_t *)&table->lock);
	return found ? AO_OK : AO_ENOTFOUND;
}

int ao_table_find_recv_id(const ao_table_t *table, const ao_tuple_t *tuple,
			  uint8_t recv_id, ao_mkt_t *out)
{
	return find_id(table, tuple, recv_id, 1, out);
}

int ao_table_find_send_id(const ao_table_t *table, const ao_tuple_t *tuple,
			  uint8_t send_id, ao_mkt_t *out)
{
	return find_id(table, tuple, send_id, 0, out);
}
