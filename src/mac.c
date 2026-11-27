/* SPDX-License-Identifier: BSD-2-Clause
 *
 * RFC 5925 5.1 segment MAC, matching Linux tcp_ao_hash_skb() byte for
 * byte: SNE(BE32) || pseudoheader || TCP header (zeroed checksum/MAC)
 * || payload.
 */
#include "tcpao/mac.h"
#include "tcpao/crypto.h"
#include "tcpao/tcphdr.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/* Streaming MAC accumulator so callers never allocate a full
 * pseudoheader+segment linear buffer. */
struct mac_ctx {
	enum tcpao_alg	alg;
	uint8_t		key[32];
	size_t		keylen;
	/* HMAC path */
	void		*hctx;
	/* CMAC path: OpenSSL 1.x CMAC is streaming too, but keeping the
	 * code portable across 1.1/3.x is simpler with linear assembly. */
	uint8_t		*linear;
	size_t		linear_len;
	size_t		linear_cap;
};

int tcpao_mac_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0;
	for (size_t i = 0; i < len; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

/* ---- HMAC streaming path ------------------------------------------------ */

#include <openssl/hmac.h>
#include <openssl/evp.h>

static int hmac_ctx_init(struct mac_ctx *c)
{
	const EVP_MD *md = c->alg == TCPAO_ALG_HMAC_SHA1_96 ?
		EVP_sha1() : EVP_sha256();
	HMAC_CTX *h = HMAC_CTX_new();
	if (!h)
		return -1;
	if (HMAC_Init_ex(h, c->key, (int)c->keylen, md, NULL) != 1) {
		HMAC_CTX_free(h);
		return -1;
	}
	c->hctx = h;
	return 0;
}

static int hmac_update(struct mac_ctx *c, const void *p, size_t len)
{
	return HMAC_Update(c->hctx, p, len) == 1 ? 0 : -1;
}

static int hmac_final(struct mac_ctx *c, uint8_t *out, unsigned *outlen)
{
	return HMAC_Final(c->hctx, out, outlen) == 1 ? 0 : -1;
}

/* ---- linear assembly (used for CMAC, shared logic) ---------------------- */

static int linear_append(struct mac_ctx *c, const void *p, size_t len)
{
	if (c->linear_len + len > c->linear_cap) {
		size_t ncap = c->linear_cap ? c->linear_cap * 2 : 256;
		while (ncap < c->linear_len + len)
			ncap *= 2;
		uint8_t *nb = realloc(c->linear, ncap);
		if (!nb)
			return -1;
		c->linear = nb;
		c->linear_cap = ncap;
	}
	memcpy(c->linear + c->linear_len, p, len);
	c->linear_len += len;
	return 0;
}

struct v4_pseudohdr {
	uint32_t	saddr;
	uint32_t	daddr;
	uint8_t		pad;
	uint8_t		protocol;
	uint16_t	tcp_len;
} __attribute__((packed));

int tcpao_find_option(const uint8_t *tcp, size_t tcp_len,
		      size_t *mac_off, size_t *mac_len)
{
	if (tcp_len < TCPAO_TH_BASE)
		return -1;
	size_t doff = tcpao_th_doff(tcp);
	if (doff < TCPAO_TH_BASE || doff > tcp_len)
		return -1;

	size_t i = TCPAO_TH_BASE;
	while (i < doff) {
		uint8_t kind = tcp[i];
		if (kind == 0)			/* End of options */
			break;
		if (kind == 1) {		/* NOP */
			i++;
			continue;
		}
		if (i + 1 >= doff)
			return -1;
		uint8_t olen = tcp[i + 1];
		if (olen < 2 || i + olen > doff)
			return -1;
		if (kind == TCPAO_OPT_KIND) {
			if (olen < 4)
				return -1;
			if (mac_off)
				*mac_off = i + 4;	/* after Kind/Len/IDs */
			if (mac_len)
				*mac_len = olen - 4;
			return (int)i;
		}
		i += olen;
	}
	return -1;
}

int tcpao_build_option(uint8_t *optbuf, size_t buflen,
		       uint8_t keyid, uint8_t rnextid,
		       const uint8_t *mac, uint8_t maclen)
{
	size_t total = 4 + maclen;
	if (buflen < total || maclen == 0)
		return -1;
	optbuf[0] = TCPAO_OPT_KIND;
	optbuf[1] = (uint8_t)total;
	optbuf[2] = keyid;
	optbuf[3] = rnextid;
	memcpy(optbuf + 4, mac, maclen);
	return (int)total;
}

int tcpao_mac_v4(const struct tcpao_mkt *mkt,
		 const uint8_t *traffic_key, size_t tkeylen,
		 const struct tcpao_segment_v4 *seg,
		 uint8_t *mac_out)
{
	int rc = -1;
	size_t doff = tcpao_th_doff(seg->tcp);
	size_t mac_off, mlen;
	struct mac_ctx ctx;

	if (doff > seg->tcp_len || doff < TCPAO_TH_BASE ||
	    mkt->maclen < TCPAO_MIN_MACLEN || mkt->maclen > TCPAO_MAX_MACLEN)
		return -1;
	if (tcpao_find_option(seg->tcp, seg->tcp_len, &mac_off, &mlen) < 0)
		return -1;
	if (mlen != mkt->maclen || mac_off + mlen > doff)
		return -1;
	if (tkeylen > sizeof(ctx.key))
		return -1;

	memset(&ctx, 0, sizeof(ctx));
	ctx.alg = mkt->alg;
	memcpy(ctx.key, traffic_key, tkeylen);
	ctx.keylen = tkeylen;

	bool use_hmac = (mkt->alg != TCPAO_ALG_AES_128_CMAC_96);
	if (use_hmac) {
		if (hmac_ctx_init(&ctx))
			goto out;
	}

	/* 1. SNE, big endian (kernel tcp_ao_hash_sne). */
	uint32_t sne_be = htonl(seg->sne);
	/* 2. IPv4 pseudo-header (kernel tcp4_pseudohdr): note the kernel
	 *    names the fields daddr/saddr in that order but feeds them
	 *    (daddr, saddr); the on-wire order remains src then dst per
	 *    RFC 793, which is what tcp_ao_hash_skb passes via iph. */
	struct v4_pseudohdr ph = {
		.saddr	= seg->src.s_addr,
		.daddr	= seg->dst.s_addr,
		.pad	= 0,
		.protocol = IPPROTO_TCP,
		.tcp_len = htons((uint16_t)seg->tcp_len),
	};

	/* 3. TCP header on a private copy: checksum and MAC zeroed.
	 *    Checksum is the 16-bit field at wire offset 16. */
	uint8_t *hdr = malloc(doff);
	if (!hdr)
		goto out;
	memcpy(hdr, seg->tcp, doff);
	hdr[TCPAO_TH_CHECKSUM_OFF] = 0;
	hdr[TCPAO_TH_CHECKSUM_OFF + 1] = 0;
	memset(hdr + mac_off, 0, mlen);

	size_t hdr_used = doff;
	uint8_t *ex_hdr = NULL;
	if (mkt->exclude_options) {
		/* Kernel rule: base header + bare AO option only. */
		hdr_used = TCPAO_TH_BASE + 4 + mlen;
		ex_hdr = malloc(hdr_used);
		if (!ex_hdr) {
			free(hdr);
			goto out;
		}
		memcpy(ex_hdr, hdr, TCPAO_TH_BASE);
		memcpy(ex_hdr + TCPAO_TH_BASE,
		       hdr + mac_off - 4, 4 + mlen);
		tcpao_explicit_bzero(hdr, doff);
		free(hdr);
		hdr = ex_hdr;
	}

	/* 4. payload. */
	const uint8_t *payload = seg->tcp + doff;
	size_t payload_len = seg->tcp_len - doff;

	if (use_hmac) {
		unsigned outlen = 0;
		uint8_t digest[32];
		if (hmac_update(&ctx, &sne_be, 4) ||
		    hmac_update(&ctx, &ph, sizeof(ph)) ||
		    hmac_update(&ctx, hdr, hdr_used) ||
		    (payload_len && hmac_update(&ctx, payload, payload_len)) ||
		    hmac_final(&ctx, digest, &outlen))
			goto out_hdr;
		if (outlen < mkt->maclen)
			goto out_hdr;
		memcpy(mac_out, digest, mkt->maclen);
		tcpao_explicit_bzero(digest, sizeof(digest));
	} else {
		/* CMAC: single linear message. */
		size_t total = 4 + sizeof(ph) + hdr_used + payload_len;
		if (linear_append(&ctx, &sne_be, 4) ||
		    linear_append(&ctx, &ph, sizeof(ph)) ||
		    linear_append(&ctx, hdr, hdr_used) ||
		    (payload_len && linear_append(&ctx, payload, payload_len)))
			goto out_hdr;
		uint8_t mac16[16];
		if (ctx.linear_len != total ||
		    tcpao_aes128_cmac(ctx.key, ctx.linear, ctx.linear_len,
				      mac16))
			goto out_hdr;
		memcpy(mac_out, mac16, mkt->maclen);
		tcpao_explicit_bzero(mac16, sizeof(mac16));
	}
	rc = 0;

out_hdr:
	tcpao_explicit_bzero(hdr, hdr_used);
	free(hdr);
out:
	if (use_hmac && ctx.hctx)
		HMAC_CTX_free(ctx.hctx);
	free(ctx.linear);
	tcpao_explicit_bzero(&ctx, sizeof(ctx));
	return rc;
}
