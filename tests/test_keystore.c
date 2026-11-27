/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Key table tests: longest-prefix lookup, ID overlap rejection per
 * RFC 5925 3.1, send/recv directionality, and secret wiping on delete.
 */
#include "test_util.h"
#include "tcpao/keystore.h"

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

static struct tcpao_mkt make_mkt(const char *peer, uint8_t prefix,
				 uint8_t snd, uint8_t rcv)
{
	struct tcpao_mkt m = {0};
	struct sockaddr_in *sin = (struct sockaddr_in *)&m.peer;
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, peer, &sin->sin_addr);
	m.prefix = prefix;
	m.alg = TCPAO_ALG_HMAC_SHA1_96;
	m.maclen = 12;
	m.sndid = snd;
	m.rcvid = rcv;
	m.keylen = 16;
	memset(m.key, 0xAB, 16);
	return m;
}

bool run_keystore_tests(int *total)
{
	struct tcpao_keystore ks;
	CHECK(tcpao_keystore_init(&ks, 4) == 0);

	/* Overlapping prefixes with distinct IDs coexist. */
	struct tcpao_mkt wide = make_mkt("10.0.0.0", 8, 1, 2);
	struct tcpao_mkt narrow = make_mkt("10.1.2.0", 24, 3, 4);
	CHECK(tcpao_keystore_add(&ks, &wide) == 0);
	CHECK(tcpao_keystore_add(&ks, &narrow) == 0);
	CHECK(tcpao_keystore_count(&ks) == 2);

	/* Same RecvID on an overlapping connection identifier is illegal. */
	(*total)++;
	struct tcpao_mkt dup = make_mkt("10.1.2.0", 24, 9, 4);
	CHECK(tcpao_keystore_add(&ks, &dup) == -EEXIST);

	/* Longest-prefix wins for incoming segment lookup. */
	(*total)++;
	struct sockaddr_in q = {0};
	q.sin_family = AF_INET;
	inet_pton(AF_INET, "10.1.2.99", &q.sin_addr);
	const struct tcpao_mkt *hit =
		tcpao_keystore_lookup_recv(&ks, (struct sockaddr *)&q, 4);
	CHECK(hit && hit->sndid == 3);
	hit = tcpao_keystore_lookup_send(&ks, (struct sockaddr *)&q, 1);
	CHECK(hit && hit->sndid == 1);

	/* Outside the narrow prefix, only the wide key matches. */
	(*total)++;
	inet_pton(AF_INET, "10.9.9.9", &q.sin_addr);
	hit = tcpao_keystore_lookup_recv(&ks, (struct sockaddr *)&q, 2);
	CHECK(hit && hit->sndid == 1);
	CHECK(tcpao_keystore_lookup_recv(&ks, (struct sockaddr *)&q, 4)
	      == NULL);

	/* Delete and secret wipe. */
	(*total)++;
	struct sockaddr_in narrow_peer;
	memcpy(&narrow_peer, &narrow.peer, sizeof(narrow_peer));
	CHECK(tcpao_keystore_del(&ks, (struct sockaddr *)&narrow_peer,
				 3, 4) == 0);
	/* The storage slot may be reused by another entry, but the deleted
	 * MKT's secret must no longer be findable. */
	CHECK(tcpao_keystore_lookup_recv(&ks, (struct sockaddr *)&q, 4)
	      == NULL);
	CHECK(tcpao_keystore_del(&ks, (struct sockaddr *)&narrow_peer,
				 3, 4) == -ENOENT);

	/* Input validation. */
	(*total)++;
	struct tcpao_mkt bad = make_mkt("10.0.0.1", 32, 5, 6);
	bad.keylen = 0;
	CHECK(tcpao_keystore_add(&ks, &bad) == -EINVAL);
	bad = make_mkt("10.0.0.1", 32, 5, 6);
	bad.maclen = 3;
	CHECK(tcpao_keystore_add(&ks, &bad) == -EINVAL);

	tcpao_keystore_destroy(&ks);
	return true;
}
