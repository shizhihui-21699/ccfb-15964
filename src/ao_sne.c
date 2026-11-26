#include "tcp_ao.h"

void ao_sne_init(ao_sne_state_t *st)
{
	if (!st)
		return;
	st->sne = 0;
	st->prev_seq = 0;
	st->flag = 0;
	st->initialized = 0;
	st->reserved = 0;
}

/*
 * Exact RFC 5925 Section 6.2 pseudocode.  The 0x7fff constant is intentional:
 * it defines the small post-wrap window in which a reordered pre-wrap segment
 * is authenticated with SNE-1.
 */
uint32_t ao_sne_next_rfc5925(ao_sne_state_t *st, uint32_t seg_seq)
{
	uint32_t sne;

	if (!st)
		return 0;

	if (!st->initialized) {
		st->prev_seq = 0;
		st->initialized = 1;
	}

	if ((st->flag == 0) &&
	    (st->prev_seq > 0x7fffU) && (seg_seq < 0x7fffU)) {
		st->sne++;
		st->flag = 1;
	}

	if ((st->flag == 1) && (seg_seq > 0x7fffU))
		sne = st->sne - 1;
	else
		sne = st->sne;

	if ((st->prev_seq < 0x7fffU) && (seg_seq > 0x7fffU))
		st->flag = 0;

	st->prev_seq = seg_seq;
	return sne;
}
