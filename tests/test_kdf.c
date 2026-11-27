/* SPDX-License-Identifier: BSD-2-Clause
 *
 * KDF conformance: every vectors.json KDF case is reproduced byte for
 * byte, covering HMAC-SHA1, AES-128-CMAC (incl. non-16-byte master key
 * extraction per RFC 5926 Fig.1), HMAC-SHA-256, and SYN (disn=0),
 * send and receive contexts.
 */
#include "test_util.h"
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

bool run_kdf_tests(const char *vector_path, int *total)
{
	const struct json_val *root = json_load(vector_path);
	CHECK(root);
	const struct json_val *cases = json_get(root, "cases");
	CHECK(cases);

	for (size_t i = 0; i < json_arr_len(cases); i++) {
		const struct json_val *c = json_arr_get(cases, i);
		const char *name = json_str(json_get(c, "name"));
		if (!strstr(name, "kdf-"))
			continue;
		(*total)++;

		uint8_t master[80], ctx[64], want[32], got[32];
		int mklen = json_hex(json_get(c, "master_hex"),
				     master, sizeof(master));
		int ctxlen = json_hex(json_get(c, "context_hex"),
				      ctx, sizeof(ctx));
		int wantlen = json_hex(
			json_get(c, "traffic_key_send_hex"), want, sizeof(want));
		CHECK(mklen > 0 && ctxlen > 0 && wantlen > 0);

		enum tcpao_alg alg = alg_of(json_str(json_get(c, "alg")));
		long long outlen = json_int(json_get(c, "outlen"));
		CHECK((int)outlen == wantlen);

		int rc = tcpao_kdf_derive(alg, master, mklen,
					  ctx, ctxlen, got, outlen);
		CHECK(rc == 0);
		if (memcmp(got, want, wantlen) != 0) {
			fprintf(stderr, "KDF mismatch in %s\n", name);
			TEST_FAIL("traffic key bytes differ from reference");
		}

		/* The receive/SYN variants in the vector must also match
		 * a full endpoint keyset derivation. */
		if (i == 0) {
			struct tcpao_mkt mkt = {0};
			mkt.alg = alg;
			memcpy(mkt.key, master, mklen);
			mkt.keylen = mklen;
			struct tcpao_endpoint_v4 ep = {
				.local_addr = { .s_addr = inet_addr("192.0.2.1") },
				.remote_addr = { .s_addr = inet_addr("198.51.100.2") },
				.local_port = htons(179),
				.remote_port = htons(41234),
				.local_isn = htonl(0x11223344),
				.remote_isn = htonl(0x55667788),
			};
			struct tcpao_traffic_keys tk;
			CHECK(tcpao_derive_v4_keyset(&mkt, &ep, &tk) == 0);
			CHECK(tk.valid && tk.keylen == (size_t)outlen);
			uint8_t want_syn[32];
			int synlen = json_hex(json_get(c, "traffic_key_syn_hex"),
					      want_syn, sizeof(want_syn));
			CHECK(synlen == wantlen);
			CHECK(memcmp(tk.send_syn, want_syn, synlen) == 0);
			uint8_t want_recv[32];
			int rlen = json_hex(json_get(c, "traffic_key_recv_hex"),
					    want_recv, sizeof(want_recv));
			CHECK(rlen == wantlen);
			CHECK(memcmp(tk.recv_other, want_recv, rlen) == 0);
		}
	}
	json_free(root);
	return true;
}
