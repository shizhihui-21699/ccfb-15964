/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Segment MAC conformance: reassemble the pseudoheader + TCP segment
 * described in vectors.json and verify the C MAC path reproduces the
 * independent Python reference tag, including SNE participation.
 */
#include "test_util.h"
#include "tcpao/mac.h"
#include "tcpao/kdf.h"

#include <string.h>
#include <arpa/inet.h>

static enum tcpao_alg alg_of(const char *name)
{
	if (!strcmp(name, "hmac-sha1"))	return TCPAO_ALG_HMAC_SHA1_96;
	if (!strcmp(name, "aes128-cmac")) return TCPAO_ALG_AES_128_CMAC_96;
	if (!strcmp(name, "hmac-sha256")) return TCPAO_ALG_HMAC_SHA256;
	return -1;
}

bool run_mac_tests(const char *vector_path, int *total)
{
	const struct json_val *root = json_load(vector_path);
	CHECK(root);
	const struct json_val *cases = json_get(root, "cases");

	for (size_t i = 0; i < json_arr_len(cases); i++) {
		const struct json_val *c = json_arr_get(cases, i);
		const char *name = json_str(json_get(c, "name"));
		if (strncmp(name, "mac-", 4) != 0)
			continue;
		(*total)++;

		uint8_t master[80], ctx[64], tkey[32], seg[256], want[32];
		int mklen = json_hex(json_get(c, "master_hex"),
				     master, sizeof(master));
		int ctxlen = json_hex(json_get(c, "context_hex"),
				      ctx, sizeof(ctx));
		int seglen = json_hex(json_get(c, "segment_zeroed_hex"),
				      seg, sizeof(seg));
		int wantlen = json_hex(json_get(c, "expected_mac_hex"),
				       want, sizeof(want));
		CHECK(mklen > 0 && ctxlen > 0 && seglen > 0 && wantlen > 0);

		enum tcpao_alg alg = alg_of(json_str(json_get(c, "alg")));
		size_t digest = tcpao_alg_digest_size(alg);
		CHECK(digest <= sizeof(tkey));
		CHECK(tcpao_kdf_derive(alg, master, mklen, ctx, ctxlen,
				       tkey, digest) == 0);

		struct tcpao_mkt mkt = {0};
		mkt.alg = alg;
		mkt.maclen = (uint8_t)json_int(json_get(c, "maclen"));
		mkt.exclude_options = false;

		struct tcpao_segment_v4 s = {
			.src = { .s_addr = inet_addr("192.0.2.1") },
			.dst = { .s_addr = inet_addr("198.51.100.2") },
			.tcp = seg,
			.tcp_len = seglen,
			.sne = (uint32_t)json_int(json_get(c, "sne")),
		};
		uint8_t got[16];
		CHECK(tcpao_mac_v4(&mkt, tkey, digest, &s, got) == 0);
		if (!tcpao_mac_equal(got, want, mkt.maclen)) {
			fprintf(stderr, "MAC mismatch in %s\n", name);
			TEST_FAIL("segment tag differs from reference");
		}

		/* Tamper detection: flip a payload byte, tag must change. */
		uint8_t saved = seg[seglen - 1];
		seg[seglen - 1] ^= 0x01;
		uint8_t tag2[16];
		CHECK(tcpao_mac_v4(&mkt, tkey, digest, &s, tag2) == 0);
		CHECK(!tcpao_mac_equal(got, tag2, mkt.maclen));
		seg[seglen - 1] = saved;

		/* SNE participation: bumping SNE changes the tag. */
		s.sne++;
		uint8_t tag3[16];
		CHECK(tcpao_mac_v4(&mkt, tkey, digest, &s, tag3) == 0);
		CHECK(!tcpao_mac_equal(got, tag3, mkt.maclen));
	}
	json_free(root);
	return true;
}
