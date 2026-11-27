/* SPDX-License-Identifier: BSD-2-Clause
 *
 * In-process master key table: the userspace MKT database that backs
 * per-socket TCP_AO_ADD_KEY / TCP_AO_DEL_KEY calls. One table per
 * routing daemon process; lookups are by peer address prefix and IDs,
 * matching the kernel's per-listener key semantics.
 */
#ifndef TCPAO_KEYSTORE_H
#define TCPAO_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "tcpao/mkt.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcpao_keystore {
	struct tcpao_mkt	*mkt;
	size_t			cap;
	size_t			n;
};

int tcpao_keystore_init(struct tcpao_keystore *ks, size_t capacity);
void tcpao_keystore_destroy(struct tcpao_keystore *ks);

/* Insert an MKT. Fails on a duplicate (peer, sndid, rcvid) tuple or on
 * overlapping IDs for the same connection identifier, per RFC 5925 3.1.
 * The master key bytes are copied and then wiped from the argument. */
int tcpao_keystore_add(struct tcpao_keystore *ks, struct tcpao_mkt *mkt);

/* Remove by peer + IDs. Returns -ENOENT if absent. */
int tcpao_keystore_del(struct tcpao_keystore *ks,
		       const struct sockaddr *peer,
		       uint8_t sndid, uint8_t rcvid);

/* Find the MKT whose peer prefix covers @peer and whose RecvID matches
 * (incoming SYN/segment lookup per RFC 5925 7.5.1). Longest-prefix wins. */
const struct tcpao_mkt *
tcpao_keystore_lookup_recv(const struct tcpao_keystore *ks,
			   const struct sockaddr *peer, uint8_t rcvid);

/* Find by SendID for an outgoing connection to @peer. */
const struct tcpao_mkt *
tcpao_keystore_lookup_send(const struct tcpao_keystore *ks,
			   const struct sockaddr *peer, uint8_t sndid);

/* Iterate every MKT whose peer prefix covers @peer. */
int tcpao_keystore_foreach_peer(const struct tcpao_keystore *ks,
				const struct sockaddr *peer,
				int (*cb)(const struct tcpao_mkt *, void *),
				void *arg);

size_t tcpao_keystore_count(const struct tcpao_keystore *ks);

/* Wipe and re-initialize (e.g. after fork in a daemon). */
void tcpao_keystore_purge(struct tcpao_keystore *ks);

#ifdef __cplusplus
}
#endif
#endif
