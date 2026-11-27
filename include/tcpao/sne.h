/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Sequence Number Extension (RFC 5925 section 6.2).
 *
 * The TCP-AO MAC is computed over (SNE || segment), where SNE is the
 * high 32 bits of an emulated 64-bit sequence space. Two variants are
 * provided:
 *
 *  - tcpao_sne_rfc5925(): the exact state machine from RFC 5925 6.2
 *    (PREV_SEQ + SNE_FLAG, 0x7fff boundaries), useful for conformance
 *    tests and for userspace packet generators.
 *  - tcpao_sne_kernel(): the equivalent of Linux tcp_ao_compute_sne(),
 *    which derives the SNE from rcv_nxt/snd_una with a 2^31 window and
 *    needs no per-segment flag state.
 *
 * Both must agree on every segment a conforming TCP peer can emit inside
 * a valid receive window; the test suite cross-checks them.
 */
#ifndef TCPAO_SNE_H
#define TCPAO_SNE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Exact RFC 5925 section 6.2 receiver-side state. */
struct tcpao_sne_state {
	uint32_t	sne;		/* current RCV/SND.SNE */
	uint32_t	prev_seq;	/* RCV/SND.PREV_SEQ */
	int		sne_flag;	/* RCV/SND.SNE_FLAG */
};

void tcpao_sne_init(struct tcpao_sne_state *st);

/* Feed the next segment's SEG.SEQ (host byte order) and return the SNE
 * (host byte order) that must be placed into the MAC input. */
uint32_t tcpao_sne_rfc5925(struct tcpao_sne_state *st, uint32_t seg_seq);

/* Linux net/ipv4/tcp_ao.c::tcp_ao_compute_sne().
 *   next_sne: SNE currently recorded for the direction
 *   next_seq: rcv_nxt (receive) or snd_una (send), host order
 *   seq:      the segment's sequence number, host order
 * before()/after() comparisons against a 2^31 window. */
uint32_t tcpao_sne_kernel(uint32_t next_sne, uint32_t next_seq, uint32_t seq);

/* Compare two TCP sequence numbers a la <linux/seqlock.h>:
 * returns true iff @a is strictly before @b in the 2^31 window. */
static inline bool tcpao_seq_before(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}

/* Byte order helper for the MAC input: SNE goes on the wire big endian. */
uint32_t tcpao_sne_to_be(uint32_t sne);

#ifdef __cplusplus
}
#endif
#endif
