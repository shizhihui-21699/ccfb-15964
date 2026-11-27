/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Example integration for a BGP daemon. This is illustrative wiring, not
 * a production daemon: it shows the order in which a routing process calls
 * the TCP-AO library to (a) protect a listener, (b) accept a session, and
 * (c) roll its key without dropping the established TCP connection.
 */
#include "tcpao/session.h"
#include "tcpao/kernel.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

static void load_mkt(struct tcpao_mkt *m, const char *peer,
		     uint8_t sndid, uint8_t rcvid, const uint8_t *secret,
		     size_t secretlen)
{
	memset(m, 0, sizeof(*m));
	struct sockaddr_in *sin = (struct sockaddr_in *)&m->peer;
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, peer, &sin->sin_addr);
	m->prefix = 32;
	m->alg = TCPAO_ALG_AES_128_CMAC_96;
	m->sndid = sndid;
	m->rcvid = rcvid;
	m->maclen = 12;			/* AES-128-CMAC-96 */
	m->keylen = (uint8_t)secretlen;
	memcpy(m->key, secret, secretlen);
}

int main(void)
{
	/* 1. Userspace master-key table (could be seeded from a key
	 *    management protocol or a protected local store). */
	struct tcpao_keystore ks;
	tcpao_keystore_init(&ks, 8);

	uint8_t secret_a[16], secret_b[16];
	memset(secret_a, 0x11, sizeof(secret_a));
	memset(secret_b, 0x22, sizeof(secret_b));

	struct tcpao_mkt mkt_a, mkt_b;
	load_mkt(&mkt_a, "198.51.100.2", 10, 11, secret_a, sizeof(secret_a));
	load_mkt(&mkt_b, "198.51.100.2", 20, 21, secret_b, sizeof(secret_b));
	tcpao_keystore_add(&ks, &mkt_a);	/* current key */
	/* mkt_b is added later, at rollover time. */

	if (!tcpao_kernel_supported()) {
		fprintf(stderr,
			"kernel lacks TCP_AO (need >=6.10 CONFIG_TCP_AO=y)\n");
		return 1;
	}

	int lfd = socket(AF_INET, SOCK_STREAM, 0);
	/* A legacy RFC 2385-only peer can share the listener with its own
	 * MD5 key prefix; the kernel forbids both types for the same peer. */
	tcpao_protect_listener(lfd, &ks, NULL, 0, /*ao_required=*/true);

	/* 2. Per-session object after accept(). */
	struct tcpao_session sess;
	struct sockaddr_in peer;
	socklen_t plen = sizeof(peer);
	int fd = accept(lfd, (struct sockaddr *)&peer, &plen);
	if (fd >= 0)
		tcpao_reconcile_accepted(fd, &ks, (struct sockaddr *)&peer,
					 &sess);

	/* 3. Hitless rollover. The daemon timer loop calls the step driver
	 *    with a monotonic timestamp until it returns 0 (done) or an
	 *    error other than -EINPROGRESS. */
	tcpao_keystore_add(&ks, &mkt_b);
	struct tcpao_roll_request req = { .new_mkt = mkt_b,
					  .now_ms = tcpao_now_ms() };
	int rc;
	while ((rc = tcpao_rollover_step(&sess, &req)) == -EINPROGRESS) {
		req.now_ms = tcpao_now_ms();
		/* Real daemon: sleep one poll interval here. The library
		 * keeps both MKTs installed the whole time, so the BGP
		 * session and every UPDATE continue to validate. */
	}
	if (rc != 0)
		fprintf(stderr, "rollover failed: %s\n",
			tcpao_kernel_strerror(rc));

	struct tcpao_ao_info inf;
	if (tcpao_session_info(&sess, &inf) == 0)
		printf("current_key=%u rnext=%u good=%llu bad=%llu\n",
		       inf.current_key, inf.rnext,
		       (unsigned long long)inf.pkt_good,
		       (unsigned long long)inf.pkt_bad);

	close(fd);
	close(lfd);
	tcpao_keystore_destroy(&ks);
	return rc == 0 ? 0 : 1;
}
