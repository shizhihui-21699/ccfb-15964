/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Rollover state machine tests. Synthetic clock + synthetic kernel
 * observations make every timing edge deterministic; the guarantees
 * under test are the ones that protect BGP updates during rekey:
 *
 *  - old MKT remains validating until a full drain after the switch
 *  - kernel current_key (driven by peer RNextKeyID), not a local timer,
 *    is the only switch trigger
 *  - reordering flips the machine back rather than deleting early
 *  - stall timeout aborts without touching the old key
 */
#include "test_util.h"
#include "tcpao/rollover.h"

#include <errno.h>
#include <string.h>

static struct tcpao_rollover make_machine(void)
{
	struct tcpao_rollover r;
	struct tcpao_roll_config cfg = {
		.drain_ms = 1000,
		.stall_timeout_ms = 5000,
	};
	tcpao_roll_init(&r, &cfg);
	return r;
}

static struct tcpao_ao_info info(uint8_t cur, uint8_t rn,
				 uint64_t good, uint64_t bad,
				 uint64_t nf)
{
	return (struct tcpao_ao_info){
		.current_key = cur, .rnext = rn,
		.pkt_good = good, .pkt_bad = bad, .pkt_key_not_found = nf,
	};
}

/* Bind a named lvalue so CHECK() and observe() can take its address. */
#define OBS(r, cur, rn, good, bad, nf, t) ({ \
	struct tcpao_ao_info _i = info(cur, rn, good, bad, nf); \
	tcpao_roll_observe((r), &_i, (t)); })

bool run_rollover_tests(int *total)
{
	/* 1. Happy path: STABLE -> PREPARED -> SWITCHING -> RETIRING ->
	 *    STABLE, old key only removable after the drain. */
	(*total)++;
	struct tcpao_rollover r = make_machine();
	CHECK(tcpao_roll_begin(&r, 10, 11, 20, 21, 1000) == 0);
	CHECK(r.phase == TCPAO_PHASE_PREPARED);

	/* Peer has not engaged: nothing switches, cannot retire. */
	CHECK(OBS(&r, 10, 21, 5, 0, 0, 1100) == 0);
	CHECK(r.phase == TCPAO_PHASE_PREPARED);
	CHECK(!tcpao_roll_can_retire(&r, 2000));

	/* Kernel flips current_key after seeing peer RNextKeyID=20. */
	CHECK(OBS(&r, 20, 21, 9, 0, 0, 1200) == 0);
	CHECK(r.phase == TCPAO_PHASE_SWITCHING);
	CHECK(!tcpao_roll_can_retire(&r, 1500));
	CHECK(tcpao_roll_can_retire(&r, 2201));

	/* One bad segment inside the drain resets the drain clock: an
	 * in-flight old-key segment must not be stranded by early delete. */
	(*total)++;
	CHECK(OBS(&r, 20, 21, 10, 1, 0, 1800) == 0);
	CHECK(!tcpao_roll_can_retire(&r, 2700));
	CHECK(tcpao_roll_can_retire(&r, 2801));
	CHECK(OBS(&r, 20, 21, 20, 1, 0, 2801) == 0);
	CHECK(r.phase == TCPAO_PHASE_RETIRING);
	CHECK(tcpao_roll_confirm_retired(&r) == 0);
	CHECK(r.phase == TCPAO_PHASE_STABLE);
	CHECK(r.old_sndid == 20 && r.old_rcvid == 21);

	/* 2. Reordering during SWITCHING: current_key flips back to the
	 *    old key; the machine returns to PREPARED and restarts drain. */
	(*total)++;
	r = make_machine();
	CHECK(tcpao_roll_begin(&r, 10, 11, 20, 21, 0) == 0);
	CHECK(OBS(&r, 20, 21, 1, 0, 0, 100) == 0);
	CHECK(r.phase == TCPAO_PHASE_SWITCHING);
	CHECK(OBS(&r, 10, 21, 2, 0, 0, 200) == 0);
	CHECK(r.phase == TCPAO_PHASE_PREPARED);
	CHECK(!tcpao_roll_can_retire(&r, 9999));
	/* Re-engage, drain cleanly. */
	CHECK(OBS(&r, 20, 21, 3, 0, 0, 300) == 0);
	CHECK(r.phase == TCPAO_PHASE_SWITCHING);
	CHECK(tcpao_roll_can_retire(&r, 1301));

	/* 3. Stall timeout: peer never advertises readiness. */
	(*total)++;
	r = make_machine();
	CHECK(tcpao_roll_begin(&r, 10, 11, 20, 21, 0) == 0);
	CHECK(OBS(&r, 10, 11, 1, 0, 0, 4000) == 0);
	CHECK(r.phase == TCPAO_PHASE_PREPARED);
	CHECK(OBS(&r, 10, 11, 1, 0, 0, 5001) ==
	      -ETIMEDOUT);
	uint8_t keep_snd = 0, keep_rcv = 0;
	CHECK(tcpao_roll_abort(&r, &keep_snd, &keep_rcv) == 0);
	CHECK(keep_snd == 10 && keep_rcv == 11);
	CHECK(r.phase == TCPAO_PHASE_STABLE);

	/* 4. Begin rejects double rollover and identical IDs. */
	(*total)++;
	r = make_machine();
	CHECK(tcpao_roll_begin(&r, 10, 11, 20, 21, 0) == 0);
	CHECK(tcpao_roll_begin(&r, 20, 21, 30, 31, 1) == -EBUSY);
	CHECK(tcpao_roll_abort(&r, NULL, NULL) == 0);
	CHECK(tcpao_roll_begin(&r, 10, 11, 10, 11, 0) == -EINVAL);

	/* 5. Regression after RETIRING is surfaced as EAGAIN, never silent. */
	(*total)++;
	r = make_machine();
	CHECK(tcpao_roll_begin(&r, 10, 11, 20, 21, 0) == 0);
	CHECK(OBS(&r, 20, 21, 1, 0, 0, 100) == 0);
	CHECK(OBS(&r, 20, 21, 2, 0, 0, 1101) == 0);
	CHECK(r.phase == TCPAO_PHASE_RETIRING);
	CHECK(OBS(&r, 10, 21, 3, 0, 0, 1200) ==
	      -EAGAIN);

	return true;
}
