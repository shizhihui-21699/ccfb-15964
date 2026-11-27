/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Hitless MKT rollover state machine (RFC 5925 section 6.1).
 *
 * The two peers cannot change keys at the same instant. TCP-AO solves
 * this with two ID fields carried in every segment:
 *
 *   KeyID      = sender's current outgoing MKT SendID
 *   RNextKeyID = the RecvID the sender wants future *incoming* segments
 *                to use ("receive next")
 *
 * and two per-connection pointers:
 *
 *   current_key : MKT used for outgoing segments
 *   rnext_key   : MKT preferred for incoming segments
 *
 * Rollover is a four-phase dance; at every instant both the old and the
 * new MKT are installed on the socket, so in-flight segments signed
 * with either key validate and no BGP update riding on a retransmitted
 * segment is ever dropped:
 *
 *   STABLE      : one MKT (N), current=rnext=N
 *      rollover_request(new M):
 *   PREPARED    : N and M installed; current=N (still send with N),
 *                 rnext=M (advertise M in RNextKeyID on every segment)
 *      peer's segments start arriving with KeyID=M once it sees our
 *      RNextKeyID=M AND its own rollover state flips; the Linux kernel
 *      atomically moves current_key when a segment's RNextKeyID matches
 *      a locally installed MKT (RFC 5925 7.5.2.e):
 *   SWITCHING   : kernel has switched current to M; N kept installed for
 *                 reordered/retransmitted old segments ("backing up"
 *                 per RFC 5925 6.1 is legal)
 *      all observed traffic (good/bad counters, getsockopt current_key)
 *      confirms M is bidirectionally active for a quiet interval:
 *   RETIRING    : rnext moved off N; after the reorder guard interval
 *                 N is deleted from the socket -> back to STABLE with M
 *
 * Timers use monotonic milliseconds; the policy layer (bgp-ao-keyctl or
 * the routing daemon) supplies time, making this module deterministic
 * and unit-testable.
 */
#ifndef TCPAO_ROLLOVER_H
#define TCPAO_ROLLOVER_H

#include <stdint.h>
#include <stdbool.h>

#include "tcpao/mkt.h"

#ifdef __cplusplus
extern "C" {
#endif

enum tcpao_roll_phase {
	TCPAO_PHASE_STABLE = 0,
	TCPAO_PHASE_PREPARED,		/* new MKT installed, advertising it */
	TCPAO_PHASE_SWITCHING,		/* kernel flipped current_key        */
	TCPAO_PHASE_RETIRING,		/* draining old key before delete    */
};

/* Events fed back from the kernel via getsockopt(TCP_AO_INFO). */
struct tcpao_ao_info {
	uint8_t		current_key;	/* KeyID of kernel current_key */
	uint8_t		rnext;		/* KeyID of kernel rnext_key   */
	uint64_t	pkt_good;
	uint64_t	pkt_bad;
	uint64_t	pkt_key_not_found;
	uint64_t	pkt_ao_required;
};

struct tcpao_roll_config {
	/* Reorder guard: minimum time the new key must be observed as the
	 * active current_key in both directions before the old key may be
	 * deleted. Must exceed the peer's maximum reorder/ACK delay; BGP
	 * deployments typically use 30-120s. */
	uint32_t	drain_ms;
	/* Abort rollover if the peer never engages within this window. */
	uint32_t	stall_timeout_ms;
};

struct tcpao_rollover {
	enum tcpao_roll_phase	phase;
	uint8_t			old_sndid;
	uint8_t			old_rcvid;
	uint8_t			new_sndid;
	uint8_t			new_rcvid;
	bool			have_new;
	uint64_t		switch_at_ms;	/* monotonic time of first SWITCHING */
	uint64_t		start_ms;	/* monotonic time of PREPARED entry */
	uint64_t		last_good;	/* pkt_good at last observation */
	uint64_t		last_bad;	/* pkt_bad at last observation */
	uint64_t		last_key_not_found;
	struct tcpao_roll_config cfg;
	char			last_error[128];
};

void tcpao_roll_init(struct tcpao_rollover *r,
		     const struct tcpao_roll_config *cfg);

/* Begin a rollover. Returns 0 and moves STABLE -> PREPARED. The caller
 * must (in order): install the new MKT, then set rnext to its RecvID. */
int tcpao_roll_begin(struct tcpao_rollover *r,
		     uint8_t old_sndid, uint8_t old_rcvid,
		     uint8_t new_sndid, uint8_t new_rcvid,
		     uint64_t now_ms);

/* Feed a getsockopt(TCP_AO_INFO) observation. Drives PREPARED ->
 * SWITCHING when the kernel reports the new SendID as current_key. */
int tcpao_roll_observe(struct tcpao_rollover *r,
		       const struct tcpao_ao_info *info,
		       uint64_t now_ms);

/* True once drain_ms has elapsed since the switch with no bad/missing
 * key counters increasing: caller may delete the old MKT. On success
 * the machine moves to STABLE with the new key as the only one. */
bool tcpao_roll_can_retire(const struct tcpao_rollover *r, uint64_t now_ms);

/* Caller has deleted the old key from the kernel socket. */
int tcpao_roll_confirm_retired(struct tcpao_rollover *r);

/* Tear down an in-progress rollover (stall timeout or operator abort):
 * remove the new key instead and return to STABLE on the old key.
 * Returns the phase-independent list of cleanup actions via out_*. */
int tcpao_roll_abort(struct tcpao_rollover *r,
		     uint8_t *keep_sndid, uint8_t *keep_rcvid);

const char *tcpao_roll_phase_name(enum tcpao_roll_phase p);

/* Default conservative timings for BGP sessions. */
#define TCPAO_DEFAULT_DRAIN_MS		60000u
#define TCPAO_DEFAULT_STALL_MS		300000u

#ifdef __cplusplus
}
#endif
#endif
