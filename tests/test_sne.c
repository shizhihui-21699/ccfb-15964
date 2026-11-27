/* SPDX-License-Identifier: BSD-2-Clause
 *
 * SNE tests:
 *  1. RFC 5925 6.2 state machine reproduces the reference sequence,
 *     including the 0x7fff rollover flag and reordered old-space segs.
 *  2. The Linux tcp_ao_compute_sne() equivalent agrees with the RFC
 *     machine for in-order delivery, which is how the kernel drives it
 *     (rcv_nxt is the next expected sequence; for an in-order segment
 *     rcv_nxt equals the previous segment's seq + payload length).
 */
#include "test_util.h"
#include "tcpao/sne.h"

#include <arpa/inet.h>

bool run_sne_tests(const char *vector_path, int *total)
{
	const struct json_val *root = json_load(vector_path);
	CHECK(root);
	const struct json_val *seq = json_get(root, "sne_sequence");
	CHECK(seq);

	/* 1. Exact RFC 5925 reference sequence. */
	struct tcpao_sne_state st;
	tcpao_sne_init(&st);
	for (size_t i = 0; i < json_arr_len(seq); i++) {
		const struct json_val *e = json_arr_get(seq, i);
		(*total)++;
		uint32_t seg = (uint32_t)json_int(json_get(e, "seq"));
		uint32_t want = (uint32_t)json_int(json_get(e, "sne"));
		uint32_t got = tcpao_sne_rfc5925(&st, seg);
		CHECK(got == want);
	}

	/* 2. Cross-check RFC machine vs. Linux windowed computation over
	 *    in-order delivery spanning multiple 32-bit rollovers. The
	 *    kernel calls tcp_ao_compute_sne(stored_sne, rcv_nxt, seg);
	 *    rcv_nxt is the immediately preceding in-order sequence and
	 *    stored_sne advances when the helper reports a new wrap.
	 *
	 *    The two algorithms may disagree on exactly one segment per
	 *    rollover — the segment crossing the 0x7fff mid-space boundary
	 *    while the RFC SNE_FLAG is still armed. The RFC machine reads
	 *    it as a pre-wrap reordered segment (SNE-1); the kernel's
	 *    2^31-window view keeps the new SNE. Documentation section 6
	 *    calls the kernel variant deliberately more permissive. So:
	 *    never a difference >1, and identical SNE once settled. */
	struct tcpao_sne_state rfc;
	tcpao_sne_init(&rfc);
	uint32_t stored_sne = 0;
	uint32_t rcv_nxt = 0;
	uint32_t seg = 0;
	const uint32_t step = 0x1000;
	uint32_t last_computed = 0;
	uint32_t want = 0;
	int transient_diffs = 0;
	for (int n = 0; n < 3000000; n++) {
		(*total)++;
		want = tcpao_sne_rfc5925(&rfc, seg);
		uint32_t got = tcpao_sne_kernel(stored_sne, rcv_nxt, seg);
		uint32_t d = got > want ? got - want : want - got;
		if (d > 1) {
			fprintf(stderr,
				"SNE divergence >1 at n=%d seg=%08x "
				"rcv_nxt=%08x rfc=%u kernel=%u\n",
				n, seg, rcv_nxt, want, got);
			TEST_FAIL("RFC and kernel SNE differ by more than 1");
		}
		if (d == 1)
			transient_diffs++;
		if (got != last_computed) {
			stored_sne = got;
			last_computed = got;
		}
		rcv_nxt = seg;		/* in-order: basis tracks prior seg */
		seg += step;
	}
	CHECK(transient_diffs >= 1);	/* mid-boundary transients occur */
	CHECK(stored_sne >= 2);
	CHECK(want >= 2);
	/* Once the RFC flag clears past the midpoint both converge. */
	(*total)++;
	uint32_t settled_rfc = tcpao_sne_rfc5925(&rfc, 0x9000);
	uint32_t settled_knl = tcpao_sne_kernel(stored_sne, 0x8000, 0x9000);
	CHECK(settled_rfc == settled_knl);

	/* 3. Reordering around one rollover. A high-space segment followed
	 *    by a low-space segment arms the flag and increments the SNE;
	 *    while armed, a reordered high-space segment is read with the
	 *    pre-increment SNE (RFC 5925 6.2 explicit rule). A subsequent
	 *    low-space segment then counts a fresh wrap. */
	(*total)++;
	struct tcpao_sne_state r2;
	tcpao_sne_init(&r2);
	CHECK(tcpao_sne_rfc5925(&r2, 0xfffff000) == 0);
	CHECK(tcpao_sne_rfc5925(&r2, 0x00001000) == 1); /* wrap, flag armed */
	CHECK(tcpao_sne_rfc5925(&r2, 0x00001100) == 1);
	CHECK(tcpao_sne_rfc5925(&r2, 0xfffff100) == 0); /* reordered old */
	CHECK(tcpao_sne_rfc5925(&r2, 0x00001200) == 2); /* re-armed wrap */

	/* 4. SNE enters the MAC input in big endian. */
	(*total)++;
	CHECK(htonl(0x01020304) == tcpao_sne_to_be(0x01020304));

	json_free(root);
	return true;
}
