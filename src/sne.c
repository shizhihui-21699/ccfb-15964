/* SPDX-License-Identifier: BSD-2-Clause
 *
 * SNE algorithms: RFC 5925 6.2 reference state machine and the Linux
 * tcp_ao_compute_sne() equivalent.
 */
#include "tcpao/sne.h"

#include <arpa/inet.h>

void tcpao_sne_init(struct tcpao_sne_state *st)
{
	st->sne = 0;
	st->prev_seq = 0;
	st->sne_flag = 0;
}

uint32_t tcpao_sne_rfc5925(struct tcpao_sne_state *st, uint32_t seg_seq)
{
	uint32_t sne;

	/* set the flag when SEG.SEQ first rolls over */
	if (st->sne_flag == 0 &&
	    st->prev_seq > 0x7fff && seg_seq < 0x7fff) {
		st->sne++;
		st->sne_flag = 1;
	}

	/* decide which SNE to use after incremented */
	if (st->sne_flag == 1 && seg_seq > 0x7fff)
		sne = st->sne - 1;	/* reordered old-space segment */
	else
		sne = st->sne;

	/* reset the flag in the middle of the window */
	if (st->prev_seq < 0x7fff && seg_seq > 0x7fff)
		st->sne_flag = 0;

	st->prev_seq = seg_seq;
	return sne;
}

/* Verbatim logic of Linux tcp_ao_compute_sne():
 *
 *   if (before(seq, next_seq)) { if (seq > next_seq) sne--; }
 *   else                        { if (seq < next_seq) sne++; }
 *
 * The unsigned comparisons look paradoxical but resolve against the
 * 2^31 modular window together with the before() test: they detect the
 * wrap point where signed comparison disagrees with modular ordering.
 */
uint32_t tcpao_sne_kernel(uint32_t next_sne, uint32_t next_seq, uint32_t seq)
{
	uint32_t sne = next_sne;

	if (tcpao_seq_before(seq, next_seq)) {
		if (seq > next_seq)
			sne--;
	} else {
		if (seq < next_seq)
			sne++;
	}
	return sne;
}

uint32_t tcpao_sne_to_be(uint32_t sne)
{
	return htonl(sne);
}
