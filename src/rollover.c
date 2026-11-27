/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Hitless rollover state machine — see include/tcpao/rollover.h for the
 * phase semantics. This file is pure logic with no syscalls, so the
 * exact timing/feedback behaviour is exercised deterministically in
 * tests/test_rollover.c.
 */
#include "tcpao/rollover.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static void seterr(struct tcpao_rollover *r, const char *msg)
{
	snprintf(r->last_error, sizeof(r->last_error), "%s", msg);
}

const char *tcpao_roll_phase_name(enum tcpao_roll_phase p)
{
	switch (p) {
	case TCPAO_PHASE_STABLE:	return "STABLE";
	case TCPAO_PHASE_PREPARED:	return "PREPARED";
	case TCPAO_PHASE_SWITCHING:	return "SWITCHING";
	case TCPAO_PHASE_RETIRING:	return "RETIRING";
	}
	return "?";
}

void tcpao_roll_init(struct tcpao_rollover *r,
		     const struct tcpao_roll_config *cfg)
{
	memset(r, 0, sizeof(*r));
	r->phase = TCPAO_PHASE_STABLE;
	if (cfg)
		r->cfg = *cfg;
	else
		r->cfg = (struct tcpao_roll_config){
			.drain_ms = TCPAO_DEFAULT_DRAIN_MS,
			.stall_timeout_ms = TCPAO_DEFAULT_STALL_MS,
		};
}

int tcpao_roll_begin(struct tcpao_rollover *r,
		     uint8_t old_sndid, uint8_t old_rcvid,
		     uint8_t new_sndid, uint8_t new_rcvid,
		     uint64_t now_ms)
{
	if (r->phase != TCPAO_PHASE_STABLE) {
		seterr(r, "rollover already in progress");
		return -EBUSY;
	}
	if (new_sndid == old_sndid && new_rcvid == old_rcvid) {
		seterr(r, "new key IDs must differ from old");
		return -EINVAL;
	}
	r->old_sndid = old_sndid;
	r->old_rcvid = old_rcvid;
	r->new_sndid = new_sndid;
	r->new_rcvid = new_rcvid;
	r->have_new = true;
	r->start_ms = now_ms;
	r->switch_at_ms = 0;
	r->phase = TCPAO_PHASE_PREPARED;
	return 0;
}

int tcpao_roll_observe(struct tcpao_rollover *r,
		       const struct tcpao_ao_info *info,
		       uint64_t now_ms)
{
	if (!info)
		return -EINVAL;

	switch (r->phase) {
	case TCPAO_PHASE_STABLE:
		return 0;

	case TCPAO_PHASE_PREPARED:
		/* Stall detection: peer never acknowledges the new key. */
		if (r->cfg.stall_timeout_ms &&
		    now_ms - r->start_ms > r->cfg.stall_timeout_ms) {
			seterr(r, "peer did not engage new key within stall window");
			return -ETIMEDOUT;
		}
		/* The kernel moves current_key atomically when an incoming
		 * segment carries RNextKeyID matching an installed MKT
		 * (RFC 5925 7.5.2.e). That is the only authoritative
		 * switch signal: never switch on a local timer alone. */
		if (info->current_key == r->new_sndid) {
			r->phase = TCPAO_PHASE_SWITCHING;
			r->switch_at_ms = now_ms;
		}
		r->last_good = info->pkt_good;
		return 0;

	case TCPAO_PHASE_SWITCHING: {
		/* Reordered old segments can briefly flip current_key
		 * back ("backing up", RFC 5925 6.1). Treat a flip back
		 * as a reset of the drain clock rather than an error. */
		if (info->current_key != r->new_sndid) {
			r->switch_at_ms = 0;
			r->phase = TCPAO_PHASE_PREPARED;
			return 0;
		}
		if (r->switch_at_ms == 0)
			r->switch_at_ms = now_ms;
		/* Counters are cumulative: only a *new* failure since the
		 * last observation resets the drain clock. */
		if (info->pkt_bad > r->last_bad ||
		    info->pkt_key_not_found > r->last_key_not_found)
			r->switch_at_ms = now_ms;
		r->last_bad = info->pkt_bad;
		r->last_key_not_found = info->pkt_key_not_found;
		r->last_good = info->pkt_good;
		if (tcpao_roll_can_retire(r, now_ms))
			r->phase = TCPAO_PHASE_RETIRING;
		return 0;
	}

	case TCPAO_PHASE_RETIRING:
		/* Once retiring, a regression means the old key is still
		 * needed: caller must abort the delete and re-prepare. */
		if (info->current_key != r->new_sndid) {
			seterr(r, "current_key regressed while retiring");
			return -EAGAIN;
		}
		return 0;
	}
	return -EINVAL;
}

bool tcpao_roll_can_retire(const struct tcpao_rollover *r, uint64_t now_ms)
{
	if (r->phase != TCPAO_PHASE_SWITCHING || r->switch_at_ms == 0)
		return false;
	return now_ms - r->switch_at_ms >= r->cfg.drain_ms;
}

int tcpao_roll_confirm_retired(struct tcpao_rollover *r)
{
	if (r->phase != TCPAO_PHASE_RETIRING &&
	    r->phase != TCPAO_PHASE_SWITCHING)
		return -EINVAL;
	r->phase = TCPAO_PHASE_STABLE;
	r->old_sndid = r->new_sndid;
	r->old_rcvid = r->new_rcvid;
	r->have_new = false;
	r->switch_at_ms = 0;
	return 0;
}

int tcpao_roll_abort(struct tcpao_rollover *r,
		     uint8_t *keep_sndid, uint8_t *keep_rcvid)
{
	if (r->phase == TCPAO_PHASE_STABLE)
		return -EINVAL;
	if (keep_sndid)
		*keep_sndid = r->old_sndid;
	if (keep_rcvid)
		*keep_rcvid = r->old_rcvid;
	r->phase = TCPAO_PHASE_STABLE;
	r->have_new = false;
	r->switch_at_ms = 0;
	return 0;
}
