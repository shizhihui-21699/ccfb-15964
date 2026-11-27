/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace MKT table. Lookups follow RFC 5925 3.1: an incoming segment
 * matches exactly one MKT by socket pair + KeyID(RecvID); we additionally
 * implement longest-prefix peer matching as the kernel does for listener
 * sockets.
 */
#include "tcpao/keystore.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int tcpao_keystore_init(struct tcpao_keystore *ks, size_t capacity)
{
	if (!capacity)
		capacity = 16;
	ks->mkt = calloc(capacity, sizeof(*ks->mkt));
	if (!ks->mkt)
		return -ENOMEM;
	ks->cap = capacity;
	ks->n = 0;
	return 0;
}

void tcpao_keystore_destroy(struct tcpao_keystore *ks)
{
	if (!ks)
		return;
	tcpao_keystore_purge(ks);
	free(ks->mkt);
	ks->mkt = NULL;
	ks->cap = ks->n = 0;
}

void tcpao_keystore_purge(struct tcpao_keystore *ks)
{
	for (size_t i = 0; i < ks->n; i++)
		tcpao_explicit_bzero(ks->mkt[i].key, sizeof(ks->mkt[i].key));
	ks->n = 0;
}

static int family_of(const struct sockaddr *sa)
{
	return sa ? sa->sa_family : AF_UNSPEC;
}

static const uint8_t *addr_bytes(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return (const uint8_t *)&((const struct sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family == AF_INET6)
		return (const uint8_t *)&((const struct sockaddr_in6 *)sa)->sin6_addr;
	return NULL;
}

static const uint8_t *mkt_addr_bytes(const struct tcpao_mkt *m)
{
	return addr_bytes((const struct sockaddr *)&m->peer);
}

static bool prefix_covers(const struct tcpao_mkt *m,
			  const struct sockaddr *peer)
{
	if (family_of((const struct sockaddr *)&m->peer) != peer->sa_family)
		return false;
	const uint8_t *a = mkt_addr_bytes(m);
	const uint8_t *b = addr_bytes(peer);
	if (!a || !b)
		return false;
	int bits = m->prefix;
	size_t nbytes = peer->sa_family == AF_INET ? 4 : 16;
	if (bits > (int)(nbytes * 8))
		return false;
	size_t full = bits / 8;
	if (memcmp(a, b, full) != 0)
		return false;
	int rem = bits % 8;
	if (rem) {
		uint8_t mask = (uint8_t)(0xFF << (8 - rem));
		if ((a[full] & mask) != (b[full] & mask))
			return false;
	}
	return true;
}

int tcpao_keystore_add(struct tcpao_keystore *ks, struct tcpao_mkt *mkt)
{
	if (!mkt || !mkt->keylen || mkt->keylen > TCPAO_MKT_MAXKEYLEN ||
	    mkt->maclen < TCPAO_MIN_MACLEN ||
	    mkt->maclen > TCPAO_MAX_MACLEN)
		return -EINVAL;

	const struct sockaddr *peer = (const struct sockaddr *)&mkt->peer;

	/* RFC 5925 3.1: IDs MUST NOT overlap where connection identifiers
	 * overlap. Reject duplicate SendID/RecvID on the same peer prefix. */
	for (size_t i = 0; i < ks->n; i++) {
		struct tcpao_mkt *m = &ks->mkt[i];
		if (family_of((const struct sockaddr *)&m->peer) !=
		    peer->sa_family)
			continue;
		if (prefix_covers(m, peer) || prefix_covers(mkt,
				(const struct sockaddr *)&m->peer)) {
			if (m->sndid == mkt->sndid ||
			    m->rcvid == mkt->rcvid)
				return -EEXIST;
		}
	}

	if (ks->n == ks->cap) {
		size_t ncap = ks->cap * 2;
		struct tcpao_mkt *nm = realloc(ks->mkt,
					       ncap * sizeof(*nm));
		if (!nm)
			return -ENOMEM;
		ks->mkt = nm;
		ks->cap = ncap;
	}

	ks->mkt[ks->n] = *mkt;
	ks->mkt[ks->n].in_use = true;
	ks->n++;
	/* Caller's copy of the secret no longer needed. */
	tcpao_explicit_bzero(mkt->key, sizeof(mkt->key));
	return 0;
}

int tcpao_keystore_del(struct tcpao_keystore *ks,
		       const struct sockaddr *peer,
		       uint8_t sndid, uint8_t rcvid)
{
	for (size_t i = 0; i < ks->n; i++) {
		struct tcpao_mkt *m = &ks->mkt[i];
		if (m->sndid == sndid && m->rcvid == rcvid &&
		    prefix_covers(m, peer)) {
			tcpao_explicit_bzero(m->key, sizeof(m->key));
			ks->mkt[i] = ks->mkt[--ks->n];
			return 0;
		}
	}
	return -ENOENT;
}

static const struct tcpao_mkt *
lookup(const struct tcpao_keystore *ks, const struct sockaddr *peer,
       uint8_t id, bool want_rcv)
{
	const struct tcpao_mkt *best = NULL;
	int best_prefix = -1;

	for (size_t i = 0; i < ks->n; i++) {
		const struct tcpao_mkt *m = &ks->mkt[i];
		uint8_t mid = want_rcv ? m->rcvid : m->sndid;
		if (mid != id || !prefix_covers(m, peer))
			continue;
		if ((int)m->prefix > best_prefix) {
			best = m;
			best_prefix = m->prefix;
		}
	}
	return best;
}

const struct tcpao_mkt *
tcpao_keystore_lookup_recv(const struct tcpao_keystore *ks,
			   const struct sockaddr *peer, uint8_t rcvid)
{
	return lookup(ks, peer, rcvid, true);
}

const struct tcpao_mkt *
tcpao_keystore_lookup_send(const struct tcpao_keystore *ks,
			   const struct sockaddr *peer, uint8_t sndid)
{
	return lookup(ks, peer, sndid, false);
}

int tcpao_keystore_foreach_peer(const struct tcpao_keystore *ks,
				const struct sockaddr *peer,
				int (*cb)(const struct tcpao_mkt *, void *),
				void *arg)
{
	for (size_t i = 0; i < ks->n; i++) {
		if (!prefix_covers(&ks->mkt[i], peer))
			continue;
		int rc = cb(&ks->mkt[i], arg);
		if (rc)
			return rc;
	}
	return 0;
}

size_t tcpao_keystore_count(const struct tcpao_keystore *ks)
{
	return ks->n;
}
