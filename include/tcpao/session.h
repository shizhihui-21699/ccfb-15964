/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Session-level orchestration: the API a routing daemon calls to
 * protect a BGP peering and to roll its keys without dropping the
 * established TCP session (and thus without a single BGP UPDATE loss).
 *
 * One tcpao_session tracks one BGP TCP connection together with its
 * rollover state machine and a monotonic observation schedule.
 */
#ifndef TCPAO_SESSION_H
#define TCPAO_SESSION_H

#include <stdint.h>
#include <stdbool.h>

#include "tcpao/mkt.h"
#include "tcpao/rollover.h"
#include "tcpao/keystore.h"

#ifdef __cplusplus
extern "C" {
#endif

enum tcpao_peer_mode {
	TCPAO_PEER_AO = 0,		/* upgraded peer, RFC 5925 */
	TCPAO_PEER_MD5_LEGACY,		/* RFC 2385-only box, coexistence */
};

struct tcpao_session {
	int			fd;		/* BGP TCP socket */
	enum tcpao_peer_mode	mode;
	struct tcpao_rollover	roll;
	uint8_t			cur_sndid;
	uint8_t			cur_rcvid;
	bool			established;
};

/* Protect a listener socket: install every MKT in the table destined
 * for @listen_addr's peers. Legacy MD5 peers are installed via the
 * RFC 2385 setsockopt instead. The two key types never share a peer
 * prefix (kernel enforced). */
int tcpao_protect_listener(int lfd, const struct tcpao_keystore *ks,
			   const struct tcpao_md5_key *legacy,
			   size_t nlegacy, bool ao_required);

/* After accept(): the kernel deliberately does not propagate key
 * changes made on the listener during the 3-way handshake (see
 * Documentation/networking/tcp_ao.html section 4). Reconcile the new
 * socket with the keystore so an in-flight rollover cannot strand it. */
int tcpao_reconcile_accepted(int fd, const struct tcpao_keystore *ks,
			     const struct sockaddr *peer,
			     struct tcpao_session *sess);

/* Attach AO to an actively opened BGP socket before connect(2): keys
 * must be installed pre-connection so the SYN carries a valid MAC. */
int tcpao_protect_active(int fd, const struct tcpao_mkt *initial,
			 struct tcpao_session *sess);

/* Full hitless rollover driver. Call repeatedly (e.g. from the daemon
 * timer loop, or driven by tests with synthetic time).
 *
 * Sequence, all failure-safe:
 *  1. add new MKT to the socket (both keys now validate incoming)
 *  2. TCP_AO_INFO rnext -> new RecvID (advertised on every segment)
 *  3. poll getsockopt until the kernel flips current_key on observing
 *     the peer's RNextKeyID (RFC 5925 7.5.2.e)
 *  4. drain for cfg.drain_ms with zero bad/not-found counters
 *  5. delete the old MKT; update session pointers
 *
 * Returns -EINPROGRESS while the rollover needs more polling, 0 on
 * completion, negative errno on fatal error (call tcpao_roll_abort()).
 */
struct tcpao_roll_request {
	struct tcpao_mkt	new_mkt;
	uint64_t		now_ms;
};

int tcpao_rollover_step(struct tcpao_session *sess,
			const struct tcpao_roll_request *req);

/* Snapshot counters for observability / SNMP TCPAO* linkage. */
int tcpao_session_info(const struct tcpao_session *sess,
		       struct tcpao_ao_info *out);

/* Graceful shutdown support: install a "goodbye" key (zero-length key,
 * kernel convention) so a signed RST can tear the session down cleanly. */
int tcpao_install_goodbye(int fd, const struct sockaddr *peer,
			  uint8_t sndid, uint8_t rcvid);

/* Monotonic millisecond clock for callers without one (clock_gettime). */
uint64_t tcpao_now_ms(void);

#ifdef __cplusplus
}
#endif
#endif
