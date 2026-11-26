#include "tcp_ao.h"
#include "tcp_ao_linux.h"
#include "ao_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond) do { \
	checks++; \
	if (!(cond)) { \
		failures++; \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

#define CHECK_RC(rc, expected) do { \
	int rc_ = (rc); \
	checks++; \
	if (rc_ != (expected)) { \
		failures++; \
		printf("FAIL %s:%d: %s returned %d (%s), expected %d (%s)\n", \
		       __FILE__, __LINE__, #rc, rc_, ao_strerror(rc_), \
		       (expected), ao_strerror(expected)); \
	} \
} while (0)

static void test_sha1_hmac(void)
{
	uint8_t d[20];
	static const uint8_t key[20] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
					 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
					 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
	static const char *want_sha = "a9993e364706816aba3e25717850c26c9cd0d89d";
	static const char *want_hmac = "b617318655057264e28bc0b6fb378c8ef146be00";
	char hex[41];
	int i;

	ao_sha1((const uint8_t *)"abc", 3, d);
	for (i = 0; i < 20; ++i)
		snprintf(hex + i * 2, 3, "%02x", d[i]);
	CHECK(strcmp(hex, want_sha) == 0);

	ao_hmac_sha1(key, sizeof(key), (const uint8_t *)"Hi There", 8, d);
	for (i = 0; i < 20; ++i)
		snprintf(hex + i * 2, 3, "%02x", d[i]);
	CHECK(strcmp(hex, want_hmac) == 0);
}

static void test_kdf_context_golden(void)
{
	ao_conn_ctx_t ctx;
	ao_mkt_t mkt;
	ao_traffic_key_t tk;
	uint8_t context[64];
	size_t context_len;
	static const uint8_t want_ctx[] =
		"c0000201c6336402c35000b30102030405060708";
	static const uint8_t want_tk[] =
		"7e6ee8557be5e056a09b8444fed131b0dc2f1fcb";
	char hex[64];
	int i;

	memset(&ctx, 0, sizeof(ctx));
	ao_addr_ipv4(&ctx.tuple.local, (uint8_t[]){192,0,2,1}, 50000);
	ao_addr_ipv4(&ctx.tuple.remote, (uint8_t[]){198,51,100,2}, 179);
	ctx.local_isn = 0x01020304;
	ctx.remote_isn = 0x05060708;

	CHECK_RC(ao_build_kdf_context(&ctx, 1, 0, context, sizeof(context),
				       &context_len), AO_OK);
	for (i = 0; i < (int)context_len; ++i)
		snprintf(hex + i * 2, 3, "%02x", context[i]);
	hex[context_len * 2] = 0;
	CHECK(context_len == 20);
	CHECK(strcmp(hex, (const char *)want_ctx) == 0);

	memset(&mkt, 0, sizeof(mkt));
	mkt.alg = AO_ALG_HMAC_SHA1_96;
	mkt.key_len = 16;
	memcpy(mkt.master_key, "0123456789abcdef", 16);
	CHECK_RC(ao_derive_hmac_sha1_key(&mkt, &ctx, 1, 0, &tk), AO_OK);
	for (i = 0; i < tk.len; ++i)
		snprintf(hex + i * 2, 3, "%02x", tk.bytes[i]);
	hex[tk.len * 2] = 0;
	CHECK(strcmp(hex, (const char *)want_tk) == 0);

	/* SYN uses zero destination ISN. */
	CHECK_RC(ao_build_kdf_context(&ctx, 1, 1, context, sizeof(context),
				       &context_len), AO_OK);
	CHECK(context[16] == 0 && context[17] == 0 &&
	      context[18] == 0 && context[19] == 0);
}

static void test_sne_wrap_and_reorder(void)
{
	ao_sne_state_t st;

	ao_sne_init(&st);
	CHECK(ao_sne_next_rfc5925(&st, 0xffff0000) == 0);
	/* Full 32-bit sequence wrap enters the low post-wrap window. */
	CHECK(ao_sne_next_rfc5925(&st, 0x00001000) == 1);
	/* Reordered high segment is verified with pre-increment SNE. */
	CHECK(ao_sne_next_rfc5925(&st, 0x00010000) == 0);
	/* Flag has reset; ordinary forward traffic uses SNE 1. */
	CHECK(ao_sne_next_rfc5925(&st, 0x00012000) == 1);

	/* Next wrap increments the high 32 bits that are prepended to MAC. */
	st.prev_seq = 0xffff0000;
	st.flag = 0;
	CHECK(ao_sne_next_rfc5925(&st, 0x00002000) == 2);
}

static void make_tuple(ao_tuple_t *t)
{
	ao_addr_ipv4(&t->local, (uint8_t[]){192,0,2,10}, 51000);
	ao_addr_ipv4(&t->remote, (uint8_t[]){198,51,100,20}, 179);
}

static ao_mkt_t make_mkt(uint8_t send_id, uint8_t recv_id, uint8_t key_seed)
{
	ao_mkt_t m;
	size_t i;

	memset(&m, 0, sizeof(m));
	m.alg = AO_ALG_HMAC_SHA1_96;
	m.mac_len = 12;
	m.key_len = 20;
	for (i = 0; i < m.key_len; ++i)
		m.master_key[i] = (uint8_t)(key_seed + i * 7 + 1);
	m.send_id = send_id;
	m.recv_id = recv_id;
	m.match.local.family = AO_FAMILY_IPV4;
	m.match.remote.family = AO_FAMILY_IPV4;
	return m;
}

static void make_ctx_pair(ao_conn_ctx_t *a, ao_conn_ctx_t *b)
{
	memset(a, 0, sizeof(*a));
	memset(b, 0, sizeof(*b));
	ao_addr_ipv4(&a->tuple.local, (uint8_t[]){192,0,2,10}, 51000);
	ao_addr_ipv4(&a->tuple.remote, (uint8_t[]){198,51,100,20}, 179);
	a->local_isn = 0xa1a2a3a4;
	a->remote_isn = 0xb5b6b7b8;
	a->local_isn_valid = a->remote_isn_valid = 1;
	*b = *a;
	ao_addr_ipv4(&b->tuple.local, (uint8_t[]){198,51,100,20}, 179);
	ao_addr_ipv4(&b->tuple.remote, (uint8_t[]){192,0,2,10}, 51000);
	b->local_isn = 0xb5b6b7b8;
	b->remote_isn = 0xa1a2a3a4;
}

static size_t build_packet(uint8_t *pkt, size_t cap, const char *payload)
{
	size_t plen = strlen(payload);
	size_t total = 20 + AO_OPTION_FIXED_LEN + 12 + plen;

	if (cap < total)
		return 0;
	memset(pkt, 0, total);
	pkt[12] = (9 << 4); /* data offset = 36 bytes */
	CHECK(ao_option_build(pkt + 20, AO_MAX_OPTION_LEN, 0, 0, NULL, 12)
	      == 16);
	memcpy(pkt + 36, payload, plen);
	return total;
}

static void test_sign_verify_tamper(void)
{
	ao_conn_ctx_t ca, cb;
	ao_conn_t *a, *b;
	ao_mkt_t ma, mb;
	uint8_t pkt[256];
	size_t len;
	ao_verify_result_t vr;

	make_ctx_pair(&ca, &cb);
	CHECK_RC(ao_conn_create(&ca, &a), AO_OK);
	CHECK_RC(ao_conn_create(&cb, &b), AO_OK);
	ma = make_mkt(100, 200, 11);
	mb = ma;
	mb.send_id = 200;
	mb.recv_id = 100;
	CHECK_RC(ao_conn_install_mkt(a, &ma), AO_OK);
	CHECK_RC(ao_conn_install_mkt(b, &mb), AO_OK);

	len = build_packet(pkt, sizeof(pkt), "UPDATE next-hop reachable");
	CHECK(len > 0);
	CHECK_RC(ao_conn_sign(a, 1000, 0, pkt, len), AO_OK);
	CHECK_RC(ao_conn_verify(b, 1000, 0, pkt, len, &vr), AO_OK);
	CHECK(vr.peer_key_id == 100);
	CHECK(vr.peer_rnext_id == 200);
	CHECK(vr.sne == 0);

	pkt[len - 1] ^= 0x01;
	CHECK_RC(ao_conn_verify(b, 1000, 0, pkt, len, &vr), AO_EVERIFY);

	ao_conn_destroy(a);
	ao_conn_destroy(b);
}

static int exchange(ao_conn_t *sender, ao_conn_t *receiver, uint32_t seq,
		    const char *payload, ao_verify_result_t *vr);

static void test_wrapped_sne_mac(void)
{
	ao_conn_ctx_t ca, cb;
	ao_conn_t *a, *b;
	ao_mkt_t ma, mb;
	ao_verify_result_t vr;

	make_ctx_pair(&ca, &cb);
	CHECK_RC(ao_conn_create(&ca, &a), AO_OK);
	CHECK_RC(ao_conn_create(&cb, &b), AO_OK);
	ma = make_mkt(100, 200, 31);
	mb = ma;
	mb.send_id = 200;
	mb.recv_id = 100;
	CHECK_RC(ao_conn_install_mkt(a, &ma), AO_OK);
	CHECK_RC(ao_conn_install_mkt(b, &mb), AO_OK);

	CHECK_RC(exchange(a, b, 0xffff0000, "before-wrap", &vr), AO_OK);
	CHECK(vr.sne == 0);
	CHECK_RC(exchange(a, b, 0x00001000, "just-after-wrap", &vr), AO_OK);
	CHECK(vr.sne == 1);
	/* Reordered high sequence is covered by the pre-increment SNE. */
	CHECK_RC(exchange(a, b, 0x00010000, "reordered-high", &vr), AO_OK);
	CHECK(vr.sne == 0);
	CHECK_RC(exchange(a, b, 0x00012000, "middle-window-forward", &vr),
		 AO_OK);
	CHECK(vr.sne == 1);

	ao_conn_destroy(a);
	ao_conn_destroy(b);
}

static void test_table_selectors(void)
{
	ao_table_t *t;
	ao_mkt_t old, new, out;
	uint32_t id1, id2;
	ao_tuple_t tuple;

	make_tuple(&tuple);
	CHECK_RC(ao_table_create(&t), AO_OK);
	old = make_mkt(10, 20, 1);
	old.match = tuple;
	new = make_mkt(11, 21, 2);
	new.match = tuple;
	CHECK_RC(ao_table_add(t, &old, &id1), AO_OK);
	CHECK_RC(ao_table_add(t, &new, &id2), AO_OK);
	CHECK(id1 != id2);
	{
		ao_mkt_t *snapshot = NULL;
		size_t snapshot_count = 0;
		CHECK_RC(ao_table_snapshot(t, &snapshot, &snapshot_count),
			 AO_OK);
		CHECK(snapshot_count == 2);
		ao_table_snapshot_free(snapshot, snapshot_count);
	}
	CHECK_RC(ao_table_find_recv_id(t, &tuple, 20, &out), AO_OK);
	CHECK(out.send_id == 10);
	CHECK_RC(ao_table_find_send_id(t, &tuple, 11, &out), AO_OK);
	CHECK(out.recv_id == 21);

	/* Overlapping MKTs cannot reuse the same incoming RecvID. */
	new.recv_id = 20;
	CHECK_RC(ao_table_add(t, &new, NULL), AO_EEXIST);
	{
		ao_mkt_t bad_prefix = new;
		bad_prefix.recv_id = 220;
		bad_prefix.match.remote.prefix = 200;
		CHECK_RC(ao_table_add(t, &bad_prefix, NULL), AO_EINVAL);
	}
	CHECK_RC(ao_table_del(t, id1), AO_OK);
	CHECK_RC(ao_table_find_recv_id(t, &tuple, 20, &out), AO_ENOTFOUND);
	ao_table_destroy(t);
}

static int exchange(ao_conn_t *sender, ao_conn_t *receiver, uint32_t seq,
		    const char *payload, ao_verify_result_t *vr)
{
	uint8_t pkt[512];
	size_t len = build_packet(pkt, sizeof(pkt), payload);
	int rc;

	if (len == 0)
		return AO_EOVERFLOW;
	rc = ao_conn_sign(sender, seq, 0, pkt, len);
	if (rc != AO_OK)
		return rc;
	return ao_conn_verify(receiver, seq, 0, pkt, len, vr);
}

static void test_hitless_rotation_and_backup(void)
{
	ao_conn_ctx_t ca, cb;
	ao_conn_t *a, *b, *legacy_b;
	ao_mkt_t old_a, new_a, old_b, new_b;
	ao_roll_state_t ra, rb;
	ao_roll_config_t cfg_a = {10, 20, 11, 21, 4};
	ao_roll_config_t cfg_b = {20, 10, 21, 11, 4};
	ao_verify_result_t vr;
	uint8_t id;

	make_ctx_pair(&ca, &cb);
	CHECK_RC(ao_conn_create(&ca, &a), AO_OK);
	CHECK_RC(ao_conn_create(&cb, &b), AO_OK);
	CHECK_RC(ao_conn_create(&cb, &legacy_b), AO_OK);

	old_a = make_mkt(10, 20, 1);
	new_a = make_mkt(11, 21, 2);
	old_b = old_a; old_b.send_id = 20; old_b.recv_id = 10;
	new_b = new_a; new_b.send_id = 21; new_b.recv_id = 11;
	CHECK_RC(ao_conn_install_mkt(a, &old_a), AO_OK);
	CHECK_RC(ao_conn_install_mkt(a, &new_a), AO_OK);
	CHECK_RC(ao_conn_install_mkt(b, &old_b), AO_OK);
	CHECK_RC(ao_conn_install_mkt(b, &new_b), AO_OK);
	CHECK_RC(ao_conn_install_mkt(legacy_b, &old_b), AO_OK);

	CHECK_RC(ao_roll_init(&ra, &cfg_a), AO_OK);
	CHECK_RC(ao_roll_init(&rb, &cfg_b), AO_OK);
	CHECK_RC(ao_roll_stage_new(&ra), AO_OK);
	CHECK_RC(ao_roll_stage_new(&rb), AO_OK);

	/* A asks B to use new SendID 21, while A still sends old KeyID 10. */
	CHECK_RC(ao_conn_set_rnext_recv_id(a, 21), AO_OK);
	CHECK_RC(ao_roll_advertise_new(&ra), AO_OK);
	CHECK_RC(exchange(a, b, 1000, "update-1", &vr), AO_OK);
	CHECK(vr.current_key_changed);
	CHECK(vr.current_send_id == 21);
	ao_roll_observe_verified(&rb, &vr);
	CHECK(rb.phase == AO_ROLL_LOCAL_CURRENT_NEW);

	/* B has switched sending key but is not yet asking A to switch. */
	CHECK_RC(exchange(b, a, 2000, "update-2", &vr), AO_OK);
	CHECK(vr.peer_key_id == 21);
	CHECK(!vr.current_key_changed);
	ao_roll_observe_verified(&ra, &vr);
	CHECK(ra.peer_sends_new);

	/* B's independent switch time arrives. */
	CHECK_RC(ao_conn_set_rnext_recv_id(b, 11), AO_OK);
	CHECK_RC(ao_roll_advertise_new(&rb), AO_OK);
	CHECK_RC(exchange(b, a, 2001, "update-3", &vr), AO_OK);
	CHECK(vr.current_key_changed);
	CHECK(vr.current_send_id == 11);
	ao_roll_observe_verified(&ra, &vr);
	CHECK(ra.phase == AO_ROLL_DRAIN);

	/* A now sends with new current key; B accepts it. */
	CHECK_RC(ao_conn_current_send_id(a, &id), AO_OK);
	CHECK(id == 11);
	CHECK_RC(exchange(a, b, 1001, "update-4", &vr), AO_OK);
	ao_roll_observe_sent(&ra, 11, 21);
	ao_roll_observe_verified(&rb, &vr);
	ao_roll_observe_sent(&rb, 21, 11);
	CHECK_RC(ao_roll_note_messages_flushed(&ra, 4), AO_OK);
	CHECK_RC(ao_roll_note_messages_flushed(&rb, 4), AO_OK);
	CHECK(ao_roll_can_retire_old(&ra));
	CHECK(ao_roll_can_retire_old(&rb));
	CHECK_RC(ao_roll_retire_old(&ra), AO_OK);
	CHECK_RC(ao_roll_retire_old(&rb), AO_OK);

	/*
	 * A reordered/old B segment can move A's current_key back to old.
	 * The old MKT is still installed, so it authenticates instead of
	 * dropping a routing update.
	 */
	CHECK_RC(exchange(legacy_b, a, 2002, "delayed-update", &vr), AO_OK);
	CHECK(vr.current_key_changed);
	CHECK(vr.current_send_id == 10);

	/* A fresh new-key request moves it forward again. */
	CHECK_RC(exchange(b, a, 2003, "new-update-again", &vr), AO_OK);
	CHECK(vr.current_send_id == 11);

	ao_conn_destroy(a);
	ao_conn_destroy(b);
	ao_conn_destroy(legacy_b);
}

struct fake_sink {
	uint8_t data[8192];
	size_t len;
	size_t budget;
};

static ssize_t fake_write(int fd, const uint8_t *buf, size_t len, void *user)
{
	struct fake_sink *s = user;
	size_t n;
	(void)fd;

	if (s->budget == 0)
		return 0; /* equivalent to EAGAIN for the writer state */
	n = len < s->budget ? len : s->budget;
	if (s->len + n > sizeof(s->data))
		return -7;
	memcpy(s->data + s->len, buf, n);
	s->len += n;
	s->budget -= n;
	return (ssize_t)n;
}

static void test_journal_partial_writes(void)
{
	bgp_journal_t *j;
	bgp_update_writer_t w;
	struct fake_sink sink;
	static const char *msgs[] = {
		"BGP UPDATE one",
		"BGP UPDATE two, longer",
		"third route update"
	};
	uint8_t expected[4096];
	size_t expected_len = 0;
	int rc, i;

	memset(&sink, 0, sizeof(sink));
	CHECK_RC(bgp_journal_create(16, &j), AO_OK);
	CHECK_RC(bgp_writer_init(&w, -1, j), AO_OK);
	for (i = 0; i < 3; ++i) {
		uint64_t id;
		CHECK_RC(bgp_writer_enqueue(&w, (const uint8_t *)msgs[i],
					     strlen(msgs[i]), &id), AO_OK);
		memcpy(expected + expected_len, msgs[i], strlen(msgs[i]));
		expected_len += strlen(msgs[i]);
	}

	sink.budget = 7;
	rc = bgp_writer_flush(&w, fake_write, &sink);
	CHECK_RC(rc, AO_EAGAIN);
	CHECK(bgp_journal_pending(j) >= 1);
	CHECK(sink.len == 7);

	sink.budget = 4096;
	CHECK_RC(bgp_writer_flush(&w, fake_write, &sink), AO_OK);
	CHECK(bgp_journal_pending(j) == 0);
	CHECK(sink.len == expected_len);
	CHECK(memcmp(sink.data, expected, expected_len) == 0);
	bgp_journal_destroy(j);

	/* Backpressure, not silent discard, when the bounded journal is full. */
	CHECK_RC(bgp_journal_create(1, &j), AO_OK);
	CHECK_RC(bgp_journal_append(j, (const uint8_t *)"x", 1, NULL), AO_OK);
	CHECK_RC(bgp_journal_append(j, (const uint8_t *)"y", 1, NULL),
		 AO_EOVERFLOW);
	bgp_journal_destroy(j);
}

static int hex_value(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static size_t hex_decode(const char *s, uint8_t *out, size_t cap)
{
	size_t n = 0;
	int high = -1;

	for (; *s; ++s) {
		int v;
		if (*s == ' ' || *s == '\n' || *s == '\t' || *s == '\r')
			continue;
		v = hex_value(*s);
		if (v < 0)
			return 0;
		if (high < 0) {
			high = v;
		} else {
			if (n >= cap)
				return 0;
			out[n++] = (uint8_t)((high << 4) | v);
			high = -1;
		}
	}
	return high == -1 ? n : 0;
}

static void test_official_rfc_test_vectors(void)
{
	/* draft-touch-tcpm-ao-test-vectors / Scapy tcpao.uts 4.1.1. */
	static const char syn_packet[] =
		"45 e0 00 4c dd 0f 40 00 ff 06 bf 6b 0a 0b 0c 0d"
		"ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5a 00 00 00 00"
		"e0 02 ff ff ca c4 00 00 02 04 05 b4 01 03 03 08"
		"04 02 08 0a 00 15 5a b7 00 00 00 00 1d 10 3d 54"
		"2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7";
	static const char syn_key[] =
		"6d63ef1b02fe1509d4b1402707fd7b0416abb74f";

	/* Vector 4.1.3: established segment with TCP options and BGP data. */
	static const char other_packet[] =
		"45 e0 00 87 36 a1 40 00 ff 06 65 9f 0a 0b 0c 0d"
		"ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5b 11 c1 42 62"
		"c0 18 01 04 a1 62 00 00 01 01 08 0a 00 15 5a c1"
		"84 a5 0b eb 1d 10 3d 54 70 64 cf 99 8c c6 c3 15"
		"c2 c2 e2 bf ff ff ff ff ff ff ff ff ff ff ff ff"
		"ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d"
		"26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02"
		"00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40"
		"06 00 64 00 01 01 00";
	static const char other_key[] =
		"d2e59c65ffc7b1a39347656463b70edc24a13d71";

	/* Vector 4.2.3: EXCLUDE_OPT omits other TCP options from the MAC. */
	static const char excluded_packet[] =
		"45 e0 00 87 a8 f5 40 00 ff 06 f3 4a 0a 0b 0c 0d"
		"ac 1b 1c 1d ff 12 00 b3 cb 0e fb ef ac d5 b5 e2"
		"c0 18 01 04 6c 45 00 00 01 01 08 0a 00 02 4c ce"
		"57 67 72 f3 1d 10 3d 54 71 06 08 cc 69 6c 03 a2"
		"71 c9 3a a5 ff ff ff ff ff ff ff ff ff ff ff ff"
		"ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d"
		"26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02"
		"00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40"
		"06 00 64 00 01 01 00";

	/* Vector 5.1.1: KDF_AES_128_CMAC and AES-128-CMAC-96. */
	static const char aes_packet[] =
		"45 e0 00 4c 7b 9f 40 00 ff 06 20 dc 0a 0b 0c 0d"
		"ac 1b 1c 1d c4 fa 00 b3 78 7a 1d df 00 00 00 00"
		"e0 02 ff ff 5a 0f 00 00 02 04 05 b4 01 03 03 08"
		"04 02 08 0a 00 01 7e d0 00 00 00 00 1d 10 3d 54"
		"e4 77 e9 9c 80 40 76 54 98 e5 50 91";
	static const char aes_key[] =
		"f5b8b3d5f34fdbb6eb8d4ab9660e60e3";

	uint8_t pkt[512], want[20];
	size_t pkt_len, want_len;
	const uint8_t *tcp;
	size_t tcp_len;
	ao_conn_ctx_t ctx;
	ao_conn_t *conn;
	ao_mkt_t mkt;
	ao_traffic_key_t tk;
	ao_verify_result_t vr;
	uint32_t seq;

	memset(&ctx, 0, sizeof(ctx));
	ao_addr_ipv4(&ctx.tuple.local, (uint8_t[]){172,27,28,29}, 179);
	ao_addr_ipv4(&ctx.tuple.remote, (uint8_t[]){10,11,12,13}, 59863);
	ctx.local_isn = 0x11c14261;
	ctx.remote_isn = 0xfbfbab5a;
	ctx.local_isn_valid = ctx.remote_isn_valid = 1;
	CHECK_RC(ao_conn_create(&ctx, &conn), AO_OK);

	memset(&mkt, 0, sizeof(mkt));
	mkt.alg = AO_ALG_HMAC_SHA1_96;
	mkt.mac_len = 12;
	mkt.key_len = 10;
	memcpy(mkt.master_key, "testvector", 10);
	mkt.send_id = 84;
	mkt.recv_id = 61;
	CHECK_RC(ao_conn_install_mkt(conn, &mkt), AO_OK);

	/* Incoming pure SYN: destination ISN is zero in the KDF context. */
	pkt_len = hex_decode(syn_packet, pkt, sizeof(pkt));
	CHECK(pkt_len == 76);
	tcp = pkt + 20;
	tcp_len = pkt_len - 20;
	seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
	      ((uint32_t)tcp[6] << 8) | tcp[7];
	CHECK_RC(ao_conn_get_traffic_key(conn, 61, 0, 1, &tk), AO_OK);
	want_len = hex_decode(syn_key, want, sizeof(want));
	CHECK(want_len == 20 && tk.len == 20);
	CHECK(memcmp(tk.bytes, want, 20) == 0);
	CHECK_RC(ao_conn_verify(conn, seq, 1, tcp, tcp_len, &vr), AO_OK);
	CHECK(memcmp(vr.option.mac,
		     (uint8_t[]){0x2e,0xe4,0x37,0xc6,0xf8,0xed,0xe6,0xd7,
				 0xc4,0xd6,0x02,0xe7}, 12) == 0);

	/* Established segment uses both ISNs and the full option/payload. */
	pkt_len = hex_decode(other_packet, pkt, sizeof(pkt));
	CHECK(pkt_len == 135);
	tcp = pkt + 20;
	tcp_len = pkt_len - 20;
	seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
	      ((uint32_t)tcp[6] << 8) | tcp[7];
	CHECK_RC(ao_conn_get_traffic_key(conn, 61, 0, 0, &tk), AO_OK);
	want_len = hex_decode(other_key, want, sizeof(want));
	CHECK(want_len == 20);
	CHECK(memcmp(tk.bytes, want, 20) == 0);
	CHECK_RC(ao_conn_verify(conn, seq, 0, tcp, tcp_len, &vr), AO_OK);
	CHECK(vr.sne == 0);

	{
		ao_conn_ctx_t ctx_ex;
		ao_conn_t *conn_ex;
		ao_mkt_t mkt_ex;

		memset(&ctx_ex, 0, sizeof(ctx_ex));
		ao_addr_ipv4(&ctx_ex.tuple.local,
			     (uint8_t[]){172,27,28,29}, 179);
		ao_addr_ipv4(&ctx_ex.tuple.remote,
			     (uint8_t[]){10,11,12,13}, 0xff12);
		ctx_ex.local_isn = 0xacd5b5e1;
		ctx_ex.remote_isn = 0xcb0efbee;
		ctx_ex.local_isn_valid = ctx_ex.remote_isn_valid = 1;
		CHECK_RC(ao_conn_create(&ctx_ex, &conn_ex), AO_OK);

		memset(&mkt_ex, 0, sizeof(mkt_ex));
		mkt_ex.alg = AO_ALG_HMAC_SHA1_96;
		mkt_ex.mac_len = 12;
		mkt_ex.key_len = 10;
		mkt_ex.exclude_options = 1;
		memcpy(mkt_ex.master_key, "testvector", 10);
		mkt_ex.send_id = 84;
		mkt_ex.recv_id = 61;
		CHECK_RC(ao_conn_install_mkt(conn_ex, &mkt_ex), AO_OK);

		pkt_len = hex_decode(excluded_packet, pkt, sizeof(pkt));
		CHECK(pkt_len == 135);
		tcp = pkt + 20;
		tcp_len = pkt_len - 20;
		seq = ((uint32_t)tcp[4] << 24) |
		      ((uint32_t)tcp[5] << 16) |
		      ((uint32_t)tcp[6] << 8) | tcp[7];
		CHECK_RC(ao_conn_verify(conn_ex, seq, 0, tcp, tcp_len, &vr),
			 AO_OK);
		ao_conn_destroy(conn_ex);
	}

	{
		ao_conn_ctx_t ctx_aes;
		ao_conn_t *conn_aes;
		ao_mkt_t mkt_aes;

		memset(&ctx_aes, 0, sizeof(ctx_aes));
		ao_addr_ipv4(&ctx_aes.tuple.local,
			     (uint8_t[]){172,27,28,29}, 179);
		ao_addr_ipv4(&ctx_aes.tuple.remote,
			     (uint8_t[]){10,11,12,13}, 0xc4fa);
		ctx_aes.remote_isn = 0x787a1ddf;
		ctx_aes.remote_isn_valid = 1;
		CHECK_RC(ao_conn_create(&ctx_aes, &conn_aes), AO_OK);

		memset(&mkt_aes, 0, sizeof(mkt_aes));
		mkt_aes.alg = AO_ALG_AES_128_CMAC_96;
		mkt_aes.mac_len = 12;
		mkt_aes.key_len = 10;
		memcpy(mkt_aes.master_key, "testvector", 10);
		mkt_aes.send_id = 84;
		mkt_aes.recv_id = 61;
		CHECK_RC(ao_conn_install_mkt(conn_aes, &mkt_aes), AO_OK);

		pkt_len = hex_decode(aes_packet, pkt, sizeof(pkt));
		CHECK(pkt_len == 76);
		tcp = pkt + 20;
		tcp_len = pkt_len - 20;
		seq = ((uint32_t)tcp[4] << 24) |
		      ((uint32_t)tcp[5] << 16) |
		      ((uint32_t)tcp[6] << 8) | tcp[7];
		CHECK_RC(ao_conn_get_traffic_key(conn_aes, 61, 0, 1, &tk),
			 AO_OK);
		want_len = hex_decode(aes_key, want, sizeof(want));
		CHECK(want_len == 16 && tk.len == 16);
		CHECK(memcmp(tk.bytes, want, 16) == 0);
		CHECK_RC(ao_conn_verify(conn_aes, seq, 1, tcp, tcp_len, &vr),
			 AO_OK);
		CHECK(memcmp(vr.option.mac,
			     (uint8_t[]){0xe4,0x77,0xe9,0x9c,0x80,0x40,
					 0x76,0x54,0x98,0xe5,0x50,0x91},
			     12) == 0);
		ao_conn_destroy(conn_aes);
	}

	ao_conn_destroy(conn);
}

struct loss_link {
	ao_conn_t *a;
	ao_conn_t *b;
	uint32_t seq;
	uint8_t received[4096];
	size_t received_len;
	size_t messages;
	int last_rc;
};

static ssize_t loss_link_write(int fd, const uint8_t *buf, size_t len,
			       void *user)
{
	struct loss_link *link = user;
	uint8_t pkt[1024];
	ao_verify_result_t vr;
	size_t total = AO_OPTION_FIXED_LEN + 12 + len + 20;
	uint32_t seq;
	int rc;

	(void)fd;
	if (total > sizeof(pkt) || len > 512) {
		link->last_rc = AO_EOVERFLOW;
		return -1;
	}
	memset(pkt, 0, total);
	pkt[12] = 9 << 4;
	rc = ao_option_build(pkt + 20, AO_MAX_OPTION_LEN, 0, 0, NULL, 12);
	if (rc < 0) {
		link->last_rc = rc;
		return -1;
	}
	memcpy(pkt + 36, buf, len);
	seq = link->seq++;
	link->last_rc = ao_conn_sign(link->a, seq, 0, pkt, total);
	if (link->last_rc != AO_OK)
		return -1;
	link->last_rc = ao_conn_verify(link->b, seq, 0, pkt, total, &vr);
	if (link->last_rc != AO_OK)
		return -1;
	if (link->received_len + len <= sizeof(link->received)) {
		memcpy(link->received + link->received_len, buf, len);
		link->received_len += len;
	}
	link->messages++;
	return (ssize_t)len;
}

static void test_no_update_loss_during_rotation(void)
{
	ao_conn_ctx_t ca, cb;
	ao_conn_t *a, *b, *legacy_b;
	ao_mkt_t old_a, new_a, old_b, new_b;
	bgp_journal_t *journal;
	bgp_update_writer_t writer;
	struct loss_link link;
	uint8_t expected[2048];
	size_t expected_len = 0;
	unsigned i;

	make_ctx_pair(&ca, &cb);
	CHECK_RC(ao_conn_create(&ca, &a), AO_OK);
	CHECK_RC(ao_conn_create(&cb, &b), AO_OK);
	CHECK_RC(ao_conn_create(&cb, &legacy_b), AO_OK);
	old_a = make_mkt(10, 20, 41);
	new_a = make_mkt(11, 21, 42);
	old_b = old_a; old_b.send_id = 20; old_b.recv_id = 10;
	new_b = new_a; new_b.send_id = 21; new_b.recv_id = 11;
	CHECK_RC(ao_conn_install_mkt(a, &old_a), AO_OK);
	CHECK_RC(ao_conn_install_mkt(a, &new_a), AO_OK);
	CHECK_RC(ao_conn_install_mkt(b, &old_b), AO_OK);
	CHECK_RC(ao_conn_install_mkt(b, &new_b), AO_OK);
	CHECK_RC(ao_conn_install_mkt(legacy_b, &old_b), AO_OK);
	CHECK_RC(ao_conn_set_rnext_recv_id(a, 21), AO_OK);

	CHECK_RC(bgp_journal_create(32, &journal), AO_OK);
	CHECK_RC(bgp_writer_init(&writer, -1, journal), AO_OK);
	memset(&link, 0, sizeof(link));
	link.a = a;
	link.b = b;
	link.seq = 3000;

	for (i = 0; i < 10; ++i) {
		char msg[32];
		ao_verify_result_t vr;
		int n = snprintf(msg, sizeof(msg), "route-%u", i);

		CHECK(n > 0 && (size_t)n < sizeof(msg));
		memcpy(expected + expected_len, msg, (size_t)n);
		expected_len += (size_t)n;

		if (i == 4) {
			/* A valid delayed old-key segment backs A up. */
			CHECK_RC(exchange(legacy_b, a, 6000, "old", &vr),
				 AO_OK);
			CHECK(vr.current_send_id == 10);
		}

		CHECK_RC(bgp_writer_enqueue(&writer, (uint8_t *)msg,
					     (size_t)n, NULL), AO_OK);
		link.last_rc = AO_OK;
		CHECK_RC(bgp_writer_flush(&writer, loss_link_write, &link),
			 AO_OK);
		CHECK_RC(link.last_rc, AO_OK);

		if (i == 0) {
			/* B's independent switch time arrives after message 1. */
			CHECK_RC(ao_conn_set_rnext_recv_id(b, 11), AO_OK);
			CHECK_RC(exchange(b, a, 5000, "rnext-new", &vr),
				 AO_OK);
			CHECK(vr.current_send_id == 11);
		}
		if (i == 4) {
			/* A fresh RNext moves A forward again. */
			CHECK_RC(exchange(b, a, 6001, "rnext-restore", &vr),
				 AO_OK);
			CHECK(vr.current_send_id == 11);
		}
	}

	CHECK(link.messages == 10);
	CHECK(bgp_journal_pending(journal) == 0);
	CHECK(link.received_len == expected_len);
	CHECK(memcmp(link.received, expected, expected_len) == 0);

	bgp_journal_destroy(journal);
	ao_conn_destroy(legacy_b);
	ao_conn_destroy(b);
	ao_conn_destroy(a);
}

static void test_policy_and_platform_stub(void)
{
	ao_peer_policy_t p;

	memset(&p, 0, sizeof(p));
	p.mode = AO_MODE_DUAL_LISTENER;
	CHECK_RC(ao_policy_validate(&p), AO_OK);
	CHECK(ao_policy_use_ao_for_syn(&p, 1, 0) == 1);
	CHECK(ao_policy_use_ao_for_syn(&p, 0, 1) == 0);
	CHECK(ao_policy_use_ao_for_syn(&p, 0, 0) == AO_EAGAIN);

	p.mode = AO_MODE_AO_ONLY;
	CHECK(ao_policy_use_ao_for_syn(&p, 0, 0) == AO_EVERIFY);
	p.mode = AO_MODE_MD5_ONLY;
	CHECK(ao_policy_use_ao_for_syn(&p, 0, 1) == 0);

#ifndef __linux__
	CHECK_RC(ao_linux_probe(-1), AO_EUNSUPPORTED);
#endif
}

int main(void)
{
	test_sha1_hmac();
	test_kdf_context_golden();
	test_sne_wrap_and_reorder();
	test_wrapped_sne_mac();
	test_sign_verify_tamper();
	test_table_selectors();
	test_official_rfc_test_vectors();
	test_hitless_rotation_and_backup();
	test_journal_partial_writes();
	test_no_update_loss_during_rotation();
	test_policy_and_platform_stub();

	printf("tcp-ao tests: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
