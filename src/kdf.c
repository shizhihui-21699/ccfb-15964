/* SPDX-License-Identifier: BSD-2-Clause
 *
 * RFC 5926 KDF implementation and RFC 5925 traffic-key context builder.
 *
 * Counter mode (RFC 5926 3.1.1):
 *   block_i = (i || "TCP-AO\0" || Context || OutputLength_BE16)
 *   stream  = PRF(MK, block_1) || PRF(MK, block_2) || ...
 *   traffic_key = first OutputLength bytes of stream
 *
 * AES-128-CMAC special case (RFC 5926 Figure 1): if the master key is
 * not exactly 16 bytes it is first reduced with AES-CMAC(0^128, MK);
 * HMAC-based KDFs use the master key directly (no extraction step).
 */
#include "tcpao/kdf.h"
#include "tcpao/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

const char *tcpao_alg_name(enum tcpao_alg alg)
{
	switch (alg) {
	case TCPAO_ALG_HMAC_SHA1_96:	return TCPAO_ALGNAME_SHA1;
	case TCPAO_ALG_AES_128_CMAC_96:	return TCPAO_ALGNAME_CMAC;
	case TCPAO_ALG_HMAC_SHA256:	return TCPAO_ALGNAME_SHA256;
	}
	return "unknown";
}

size_t tcpao_alg_digest_size(enum tcpao_alg alg)
{
	switch (alg) {
	case TCPAO_ALG_HMAC_SHA1_96:	return 20;	/* 160 bits */
	case TCPAO_ALG_AES_128_CMAC_96:	return 16;	/* 128 bits */
	case TCPAO_ALG_HMAC_SHA256:	return 32;	/* 256 bits */
	}
	return 0;
}

int tcpao_alg_from_name(const char *name, enum tcpao_alg *out)
{
	if (!name || !out)
		return -1;
	if (!strcmp(name, TCPAO_ALGNAME_SHA1) ||
	    !strcasecmp(name, "hmac-sha1-96") ||
	    !strcasecmp(name, "sha1")) {
		*out = TCPAO_ALG_HMAC_SHA1_96;
		return 0;
	}
	if (!strcmp(name, TCPAO_ALGNAME_CMAC) ||
	    !strcasecmp(name, "aes-128-cmac-96") ||
	    !strcasecmp(name, "cmac(aes128)")) {
		*out = TCPAO_ALG_AES_128_CMAC_96;
		return 0;
	}
	if (!strcmp(name, TCPAO_ALGNAME_SHA256) ||
	    !strcasecmp(name, "hmac-sha256") ||
	    !strcasecmp(name, "sha256")) {
		*out = TCPAO_ALG_HMAC_SHA256;
		return 0;
	}
	return -1;
}

/* One PRF invocation on a fully assembled input block. */
static int prf_block(enum tcpao_alg alg,
		     const uint8_t *master, size_t masterlen,
		     const uint8_t *block, size_t blocklen,
		     uint8_t *out, size_t outcap)
{
	switch (alg) {
	case TCPAO_ALG_HMAC_SHA1_96:
		if (outcap < 20)
			return -1;
		return tcpao_hmac_sha1(master, masterlen,
				       block, blocklen, out);
	case TCPAO_ALG_HMAC_SHA256:
		if (outcap < 32)
			return -1;
		return tcpao_hmac_sha256(master, masterlen,
					 block, blocklen, out);
	case TCPAO_ALG_AES_128_CMAC_96: {
		uint8_t zero16[16] = { 0 };
		uint8_t k[16];
		if (outcap < 16)
			return -1;
		/* RFC 5926 Fig.1 step 1: extract unless MK is 128-bit. */
		if (masterlen == 16) {
			memcpy(k, master, 16);
		} else {
			if (tcpao_aes128_cmac(zero16, master, masterlen, k))
				return -1;
		}
		int rc = tcpao_aes128_cmac(k, block, blocklen, out);
		tcpao_explicit_bzero(k, sizeof(k));
		return rc;
	} }
	return -1;
}

/* Assemble block i into a scratch buffer. Layout is fixed prefix
 * (counter + label) || context || 2-octet output length. */
static int build_block(uint8_t *buf, size_t buflen, uint8_t counter,
		       const void *context, size_t contextlen,
		       uint16_t outlen_bits)
{
	size_t need = 1 + 6 + contextlen + 2;
	if (buflen < need)
		return -1;
	buf[0] = counter;
	/* RFC 5926 label: exactly the 6 ASCII characters "TCP-AO", no NUL. */
	memcpy(buf + 1, TCPAO_LABEL, 6);
	memcpy(buf + 7, context, contextlen);
	uint16_t be = htons(outlen_bits);
	memcpy(buf + 7 + contextlen, &be, 2);
	return (int)need;
}

int tcpao_kdf_derive(enum tcpao_alg alg,
		     const uint8_t *master, size_t masterlen,
		     const void *context, size_t contextlen,
		     uint8_t *out, size_t outlen)
{
	size_t prf_size = tcpao_alg_digest_size(alg);
	uint16_t outlen_bits = (uint16_t)(outlen * 8);
	size_t produced = 0;
	uint8_t counter = 1;
	int rc = -1;

	if (!master || !masterlen || !context || !out || !outlen ||
	    outlen > prf_size + 32 || prf_size == 0)
		return -1;

	/* A single block is always enough for the RFC 5926 key sizes
	 * (16/20/32 <= 32), but implement full counter mode anyway. */
	size_t blocklen = 1 + 6 + contextlen + 2;
	uint8_t *block = malloc(blocklen);
	uint8_t chunk[32];
	if (!block)
		return -1;

	while (produced < outlen) {
		size_t n = build_block(block, blocklen, counter,
				       context, contextlen, outlen_bits);
		if ((size_t)n != blocklen)
			goto out;
		if (prf_block(alg, master, masterlen, block, blocklen,
			      chunk, sizeof(chunk)))
			goto out;
		size_t take = outlen - produced;
		if (take > prf_size)
			take = prf_size;
		memcpy(out + produced, chunk, take);
		produced += take;
		if (counter == 255)
			goto out;	/* counter is one octet */
		counter++;
	}
	rc = 0;
out:
	tcpao_explicit_bzero(block, blocklen);
	tcpao_explicit_bzero(chunk, sizeof(chunk));
	free(block);
	return rc;
}

int tcpao_derive_v4_keyset(const struct tcpao_mkt *mkt,
			   const struct tcpao_endpoint_v4 *ep,
			   struct tcpao_traffic_keys *tk)
{
	struct tcpao_v4_context ctx;
	size_t klen = tcpao_alg_digest_size(mkt->alg);

	if (!mkt || !ep || !tk || klen == 0 || klen > sizeof(tk->send_syn))
		return -1;

	memset(tk, 0, sizeof(*tk));

	/* Send_other: local -> remote, both ISNs known. */
	ctx.saddr = ep->local_addr;
	ctx.daddr = ep->remote_addr;
	ctx.sport = ep->local_port;
	ctx.dport = ep->remote_port;
	ctx.sisn = ep->local_isn;
	ctx.disn = ep->remote_isn;
	if (tcpao_kdf_derive(mkt->alg, mkt->key, mkt->keylen,
			     &ctx, sizeof(ctx), tk->send_other, klen))
		goto fail;

	/* Receive_other: swap source/destination (RFC 5925 5.2 table). */
	ctx.saddr = ep->remote_addr;
	ctx.daddr = ep->local_addr;
	ctx.sport = ep->remote_port;
	ctx.dport = ep->local_port;
	ctx.sisn = ep->remote_isn;
	ctx.disn = ep->local_isn;
	if (tcpao_kdf_derive(mkt->alg, mkt->key, mkt->keylen,
			     &ctx, sizeof(ctx), tk->recv_other, klen))
		goto fail;

	/* SYN variants: destination ISN = 0. */
	ctx = (struct tcpao_v4_context){
		.saddr = ep->local_addr, .daddr = ep->remote_addr,
		.sport = ep->local_port, .dport = ep->remote_port,
		.sisn = ep->local_isn, .disn = 0,
	};
	if (tcpao_kdf_derive(mkt->alg, mkt->key, mkt->keylen,
			     &ctx, sizeof(ctx), tk->send_syn, klen))
		goto fail;

	ctx = (struct tcpao_v4_context){
		.saddr = ep->remote_addr, .daddr = ep->local_addr,
		.sport = ep->remote_port, .dport = ep->local_port,
		.sisn = ep->remote_isn, .disn = 0,
	};
	if (tcpao_kdf_derive(mkt->alg, mkt->key, mkt->keylen,
			     &ctx, sizeof(ctx), tk->recv_syn, klen))
		goto fail;

	tk->keylen = klen;
	tk->valid = true;
	return 0;
fail:
	tcpao_explicit_bzero(tk, sizeof(*tk));
	return -1;
}
