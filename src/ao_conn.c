#include "tcp_ao.h"

#include "ao_cmac.h"
#include "ao_crypto.h"

#include <stdlib.h>
#include <string.h>

struct ao_conn_entry {
	ao_mkt_t mkt;
	ao_traffic_key_t send_syn;
	ao_traffic_key_t send_other;
	ao_traffic_key_t recv_syn;
	ao_traffic_key_t recv_other;
};

struct ao_conn {
	ao_conn_ctx_t ctx;
	ao_sne_state_t snd_sne;
	ao_sne_state_t rcv_sne;
	struct ao_conn_entry *entries;
	size_t count;
	size_t cap;
	uint8_t current_send_id;
	uint8_t rnext_recv_id;
	unsigned has_current : 1;
	unsigned has_rnext : 1;
};

static void secure_zero(void *p, size_t n)
{
	volatile unsigned char *vp = p;
	while (n-- > 0)
		*vp++ = 0;
}

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

int ao_conn_create(const ao_conn_ctx_t *ctx, ao_conn_t **conn)
{
	ao_conn_t *c;

	if (!ctx || !conn)
		return AO_EINVAL;
	c = calloc(1, sizeof(*c));
	if (!c)
		return AO_ENOMEM;
	c->ctx = *ctx;
	ao_sne_init(&c->snd_sne);
	ao_sne_init(&c->rcv_sne);
	*conn = c;
	return AO_OK;
}

void ao_conn_destroy(ao_conn_t *conn)
{
	if (!conn)
		return;
	if (conn->entries)
		secure_zero(conn->entries,
			    conn->count * sizeof(*conn->entries));
	free(conn->entries);
	free(conn);
}

static int derive_entry_keys(ao_conn_t *c, struct ao_conn_entry *e)
{
	int rc;

	rc = ao_derive_traffic_key(&e->mkt, &c->ctx, 1, 1, &e->send_syn);
	if (rc != AO_OK)
		return rc;
	rc = ao_derive_traffic_key(&e->mkt, &c->ctx, 1, 0, &e->send_other);
	if (rc != AO_OK)
		return rc;
	rc = ao_derive_traffic_key(&e->mkt, &c->ctx, 0, 1, &e->recv_syn);
	if (rc != AO_OK)
		return rc;
	return ao_derive_traffic_key(&e->mkt, &c->ctx, 0, 0, &e->recv_other);
}

int ao_conn_update_isns(ao_conn_t *conn, uint32_t local_isn,
			uint32_t remote_isn)
{
	size_t i;
	int rc;

	if (!conn)
		return AO_EINVAL;
	conn->ctx.local_isn = local_isn;
	conn->ctx.remote_isn = remote_isn;
	conn->ctx.local_isn_valid = 1;
	conn->ctx.remote_isn_valid = 1;
	for (i = 0; i < conn->count; ++i) {
		rc = derive_entry_keys(conn, &conn->entries[i]);
		if (rc != AO_OK)
			return rc;
	}
	return AO_OK;
}

static struct ao_conn_entry *find_by_send(ao_conn_t *c, uint8_t send_id)
{
	size_t i;
	for (i = 0; i < c->count; ++i)
		if (c->entries[i].mkt.send_id == send_id)
			return &c->entries[i];
	return NULL;
}

static struct ao_conn_entry *find_by_recv(ao_conn_t *c, uint8_t recv_id)
{
	size_t i;
	for (i = 0; i < c->count; ++i)
		if (c->entries[i].mkt.recv_id == recv_id)
			return &c->entries[i];
	return NULL;
}

int ao_conn_install_mkt(ao_conn_t *conn, const ao_mkt_t *mkt)
{
	struct ao_conn_entry *e, *grown;
	size_t new_cap;
	int rc;

	if (!conn || !mkt || mkt->key_len == 0)
		return AO_EINVAL;
	if (find_by_send(conn, mkt->send_id) ||
	    find_by_recv(conn, mkt->recv_id))
		return AO_EEXIST;

	if (conn->count == conn->cap) {
		new_cap = conn->cap ? conn->cap * 2 : 4;
		grown = realloc(conn->entries, new_cap * sizeof(*grown));
		if (!grown)
			return AO_ENOMEM;
		conn->entries = grown;
		conn->cap = new_cap;
	}

	e = &conn->entries[conn->count];
	memset(e, 0, sizeof(*e));
	e->mkt = *mkt;
	if ((e->mkt.alg == AO_ALG_HMAC_SHA1_96 ||
	     e->mkt.alg == AO_ALG_AES_128_CMAC_96) &&
	    e->mkt.mac_len == 0)
		e->mkt.mac_len = AO_MAC_HMAC_SHA1_96_LEN;

	rc = derive_entry_keys(conn, e);
	if (rc != AO_OK)
		return rc;

	conn->count++;
	if (!conn->has_current) {
		conn->current_send_id = mkt->send_id;
		conn->has_current = 1;
	}
	if (!conn->has_rnext) {
		conn->rnext_recv_id = mkt->recv_id;
		conn->has_rnext = 1;
	}
	return AO_OK;
}

int ao_conn_set_rnext_recv_id(ao_conn_t *conn, uint8_t recv_id)
{
	if (!conn || !find_by_recv(conn, recv_id))
		return AO_ENOTFOUND;
	conn->rnext_recv_id = recv_id;
	conn->has_rnext = 1;
	return AO_OK;
}

int ao_conn_current_send_id(const ao_conn_t *conn, uint8_t *send_id)
{
	if (!conn || !send_id || !conn->has_current)
		return AO_ESTATE;
	*send_id = conn->current_send_id;
	return AO_OK;
}

int ao_conn_rnext_recv_id(const ao_conn_t *conn, uint8_t *recv_id)
{
	if (!conn || !recv_id || !conn->has_rnext)
		return AO_ESTATE;
	*recv_id = conn->rnext_recv_id;
	return AO_OK;
}

int ao_conn_get_traffic_key(ao_conn_t *conn, uint8_t key_id,
			    int outgoing, int pure_syn,
			    ao_traffic_key_t *key)
{
	struct ao_conn_entry *e;

	if (!conn || !key)
		return AO_EINVAL;
	e = outgoing ? find_by_send(conn, key_id) : find_by_recv(conn, key_id);
	if (!e)
		return AO_ENOTFOUND;
	if (outgoing)
		*key = pure_syn ? e->send_syn : e->send_other;
	else
		*key = pure_syn ? e->recv_syn : e->recv_other;
	return AO_OK;
}

static int build_pseudo(const ao_conn_t *conn, int outgoing,
			uint32_t tcp_len, uint8_t *out, size_t cap,
			size_t *out_len)
{
	const ao_addr_t *src, *dst;
	size_t addr_len, need;

	if (conn->ctx.tuple.local.family == AO_FAMILY_IPV4)
		addr_len = 4;
	else if (conn->ctx.tuple.local.family == AO_FAMILY_IPV6)
		addr_len = 16;
	else
		return AO_EINVAL;

	src = outgoing ? &conn->ctx.tuple.local : &conn->ctx.tuple.remote;
	dst = outgoing ? &conn->ctx.tuple.remote : &conn->ctx.tuple.local;
	need = addr_len == 4 ? 12 : 40;
	if (cap < need)
		return AO_EOVERFLOW;

	memcpy(out, src->addr, addr_len);
	memcpy(out + addr_len, dst->addr, addr_len);
	if (addr_len == 4) {
		out[8] = 0;
		out[9] = 6;
		put_be16(out + 10, (uint16_t)tcp_len);
	} else {
		put_be32(out + 32, tcp_len);
		out[36] = 0;
		out[37] = 0;
		out[38] = 0;
		out[39] = 6;
	}
	*out_len = need;
	return AO_OK;
}

struct mac_state {
	int is_aes;
	ao_hmac_sha1_ctx_t hmac;
	ao_cmac_ctx_t cmac;
};

static int mac_state_init(struct mac_state *m, enum ao_alg alg,
			  const ao_traffic_key_t *key)
{
	memset(m, 0, sizeof(*m));
	if (alg == AO_ALG_AES_128_CMAC_96) {
		if (key->len != 16)
			return AO_EINVAL;
		m->is_aes = 1;
		return ao_cmac_init(&m->cmac, key->bytes);
	}
	if (alg == AO_ALG_HMAC_SHA1_96) {
		if (key->len != AO_SHA1_DIGEST_SIZE)
			return AO_EINVAL;
		ao_hmac_sha1_init(&m->hmac, key->bytes, key->len);
		return AO_OK;
	}
	return AO_EUNSUPPORTED;
}

static void mac_state_update(struct mac_state *m, const void *data, size_t len)
{
	if (m->is_aes)
		ao_cmac_update(&m->cmac, data, len);
	else
		ao_hmac_sha1_update(&m->hmac, data, len);
}

static int mac_state_final(struct mac_state *m, uint8_t *out, size_t cap)
{
	if (m->is_aes) {
		if (cap < 16)
			return AO_EOVERFLOW;
		return ao_cmac_final(&m->cmac, out);
	}
	if (cap < AO_SHA1_DIGEST_SIZE)
		return AO_EOVERFLOW;
	ao_hmac_sha1_final(&m->hmac, out);
	return AO_OK;
}

static int compute_segment_mac(const ao_conn_t *conn,
			      enum ao_alg alg,
			      const ao_traffic_key_t *key,
			      uint32_t sne, int outgoing,
			      int include_other_options,
			      const uint8_t *tcp_segment, size_t tcp_len,
			      uint8_t *mac_out, uint8_t mac_len)
{
	uint8_t pseudo[40];
	uint8_t zeros[AO_MAX_MAC_LEN];
	uint8_t full_mac[AO_SHA1_DIGEST_SIZE];
	size_t pseudo_len = 0, header_len, pos;
	uint8_t sne_be[4];
	struct mac_state mac;
	int rc;

	if (mac_len == 0 || mac_len > AO_SHA1_DIGEST_SIZE)
		return AO_EINVAL;
	rc = mac_state_init(&mac, alg, key);
	if (rc != AO_OK)
		return rc;
	rc = ao_tcp_header_len(tcp_segment, tcp_len, &header_len);
	if (rc != AO_OK)
		return rc;
	rc = build_pseudo(conn, outgoing, (uint32_t)tcp_len, pseudo,
			  sizeof(pseudo), &pseudo_len);
	if (rc != AO_OK)
		return rc;

	memset(zeros, 0, mac_len);
	put_be32(sne_be, sne);
	mac_state_update(&mac, sne_be, sizeof(sne_be));
	mac_state_update(&mac, pseudo, pseudo_len);

	/* Base TCP header, checksum zeroed. */
	mac_state_update(&mac, tcp_segment, 16);
	mac_state_update(&mac, zeros, 2);
	mac_state_update(&mac, tcp_segment + 18, 2);

	/*
	 * Reconstruct the option portion covered by the MAC.  TCP-AO itself
	 * is always covered with its MAC field zeroed.  Other options are
	 * included by default and omitted (not zeroed) in EXCLUDE_OPT mode.
	 */
	pos = 20;
	while (pos < header_len) {
		uint8_t kind = tcp_segment[pos];
		uint8_t optlen;

		if (kind == 0 || kind == 1) {
			if (include_other_options)
				mac_state_update(&mac, tcp_segment + pos, 1);
			pos++;
			continue;
		}
		if (pos + 2 > header_len)
			return AO_EINVAL;
		optlen = tcp_segment[pos + 1];
		if (optlen < 2 || pos + optlen > header_len)
			return AO_EINVAL;

		if (kind == AO_OPTION_KIND) {
			if (optlen < AO_OPTION_FIXED_LEN ||
			    pos + AO_OPTION_FIXED_LEN > header_len)
				return AO_EINVAL;
			mac_state_update(&mac, tcp_segment + pos,
					 AO_OPTION_FIXED_LEN);
			mac_state_update(&mac, zeros, optlen - 4);
		} else if (include_other_options) {
			mac_state_update(&mac, tcp_segment + pos, optlen);
		}
		pos += optlen;
	}

	if (tcp_len > header_len)
		mac_state_update(&mac, tcp_segment + header_len,
				 tcp_len - header_len);
	rc = mac_state_final(&mac, full_mac, sizeof(full_mac));
	if (rc != AO_OK)
		return rc;
	memcpy(mac_out, full_mac, mac_len);
	return AO_OK;
}

int ao_conn_sign(ao_conn_t *conn, uint32_t seq, int pure_syn,
		 uint8_t *tcp_segment, size_t tcp_len)
{
	ao_option_t opt;
	struct ao_conn_entry *cur, *rnext;
	ao_traffic_key_t key;
	uint32_t sne;
	ao_sne_state_t sne_try;
	uint8_t digest[AO_SHA1_DIGEST_SIZE];
	int rc;

	if (!conn || !tcp_segment)
		return AO_EINVAL;
	if (!conn->has_current || !conn->has_rnext)
		return AO_ESTATE;

	rc = ao_option_parse(tcp_segment, tcp_len, &opt);
	if (rc != AO_OK)
		return rc;

	cur = find_by_send(conn, conn->current_send_id);
	rnext = find_by_recv(conn, conn->rnext_recv_id);
	if (!cur || !rnext)
		return AO_ESTATE;
	if (opt.mac_len != cur->mkt.mac_len)
		return AO_EINVAL;

	tcp_segment[opt.option_offset + 2] = cur->mkt.send_id;
	tcp_segment[opt.option_offset + 3] = rnext->mkt.recv_id;
	memset(tcp_segment + opt.option_offset + AO_OPTION_FIXED_LEN, 0,
	       opt.mac_len);
	opt.key_id = cur->mkt.send_id;
	opt.rnext_id = rnext->mkt.recv_id;

	sne_try = conn->snd_sne;
	sne = ao_sne_next_rfc5925(&sne_try, seq);
	rc = ao_conn_get_traffic_key(conn, cur->mkt.send_id, 1, pure_syn, &key);
	if (rc != AO_OK)
		return rc;
	rc = compute_segment_mac(conn, cur->mkt.alg, &key, sne, 1,
				 !cur->mkt.exclude_options,
				 tcp_segment, tcp_len,
				 digest, cur->mkt.mac_len);
	if (rc != AO_OK)
		return rc;
	conn->snd_sne = sne_try;
	memcpy(tcp_segment + opt.option_offset + AO_OPTION_FIXED_LEN,
	       digest, cur->mkt.mac_len);
	return AO_OK;
}

int ao_conn_verify(ao_conn_t *conn, uint32_t seq, int pure_syn,
		   const uint8_t *tcp_segment, size_t tcp_len,
		   ao_verify_result_t *result)
{
	ao_option_t opt;
	struct ao_conn_entry *entry, *requested;
	ao_traffic_key_t key;
	uint32_t sne;
	ao_sne_state_t sne_try;
	uint8_t digest[AO_SHA1_DIGEST_SIZE];
	uint8_t previous_current;
	int rc;

	if (!conn || !tcp_segment)
		return AO_EINVAL;
	rc = ao_option_parse(tcp_segment, tcp_len, &opt);
	if (rc != AO_OK)
		return rc;

	entry = find_by_recv(conn, opt.key_id);
	if (!entry)
		return AO_ENOTFOUND;
	if (opt.mac_len != entry->mkt.mac_len)
		return AO_EVERIFY;

	/*
	 * Do not let an unauthenticated segment advance persistent SNE state.
	 * Compute against a copy and commit only after the MAC is valid.
	 */
	sne_try = conn->rcv_sne;
	sne = ao_sne_next_rfc5925(&sne_try, seq);
	rc = ao_conn_get_traffic_key(conn, opt.key_id, 0, pure_syn, &key);
	if (rc != AO_OK)
		return rc;
	rc = compute_segment_mac(conn, entry->mkt.alg, &key, sne, 0,
				 !entry->mkt.exclude_options,
				 tcp_segment, tcp_len,
				 digest, entry->mkt.mac_len);
	if (rc != AO_OK)
		return rc;
	if (ao_const_time_equal(digest, opt.mac, entry->mkt.mac_len) != 0)
		return AO_EVERIFY;
	conn->rcv_sne = sne_try;

	previous_current = conn->current_send_id;
	if (conn->has_current && opt.rnext_id != conn->current_send_id) {
		requested = find_by_send(conn, opt.rnext_id);
		if (requested) {
			conn->current_send_id = requested->mkt.send_id;
			conn->has_current = 1;
		}
	}

	if (result) {
		memset(result, 0, sizeof(*result));
		result->option = opt;
		/* opt.mac points into the caller's segment; that is intentional. */
		result->sne = sne;
		result->mkt_table_id = entry->mkt.id;
		result->peer_key_id = opt.key_id;
		result->peer_rnext_id = opt.rnext_id;
		result->previous_current_send_id = previous_current;
		result->current_send_id = conn->current_send_id;
		result->current_key_changed =
			conn->has_current &&
			previous_current != conn->current_send_id;
	}
	return AO_OK;
}
