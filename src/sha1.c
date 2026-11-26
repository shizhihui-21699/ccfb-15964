#include "ao_crypto.h"

#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_block(ao_sha1_ctx_t *ctx, const uint8_t block[64])
{
	uint32_t w[80];
	uint32_t a, b, c, d, e;
	int i;

	for (i = 0; i < 16; ++i) {
		w[i] = ((uint32_t)block[i * 4] << 24) |
		       ((uint32_t)block[i * 4 + 1] << 16) |
		       ((uint32_t)block[i * 4 + 2] << 8) |
		       ((uint32_t)block[i * 4 + 3]);
	}
	for (; i < 80; ++i) {
		w[i] = ROTL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 80; ++i) {
		uint32_t f, k, temp;

		if (i < 20) {
			f = (b & c) | ((~b) & d);
			k = 0x5a827999U;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ed9eba1U;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8f1bbcdcU;
		} else {
			f = b ^ c ^ d;
			k = 0xca62c1d6U;
		}
		temp = ROTL32(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = ROTL32(b, 30);
		b = a;
		a = temp;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

void ao_sha1_init(ao_sha1_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->state[0] = 0x67452301U;
	ctx->state[1] = 0xefcdab89U;
	ctx->state[2] = 0x98badcfeU;
	ctx->state[3] = 0x10325476U;
	ctx->state[4] = 0xc3d2e1f0U;
}

void ao_sha1_update(ao_sha1_ctx_t *ctx, const void *data, size_t len)
{
	const uint8_t *p = data;

	ctx->bitlen += (uint64_t)len * 8U;
	while (len > 0) {
		size_t n = AO_SHA1_BLOCK_SIZE - ctx->buflen;

		if (n > len)
			n = len;
		memcpy(ctx->buffer + ctx->buflen, p, n);
		ctx->buflen += n;
		p += n;
		len -= n;
		if (ctx->buflen == AO_SHA1_BLOCK_SIZE) {
			sha1_block(ctx, ctx->buffer);
			ctx->buflen = 0;
		}
	}
}

void ao_sha1_final(ao_sha1_ctx_t *ctx, uint8_t digest[AO_SHA1_DIGEST_SIZE])
{
	static const uint8_t pad = 0x80;
	uint8_t length_be[8];
	size_t i;
	uint64_t bits = ctx->bitlen;

	ao_sha1_update(ctx, &pad, 1);
	while (ctx->buflen != 56) {
		uint8_t zero = 0;
		ao_sha1_update(ctx, &zero, 1);
	}
	for (i = 0; i < 8; ++i)
		length_be[i] = (uint8_t)(bits >> (56 - i * 8));
	ao_sha1_update(ctx, length_be, sizeof(length_be));

	for (i = 0; i < 5; ++i) {
		digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (uint8_t)ctx->state[i];
	}
}

void ao_sha1(const uint8_t *data, size_t len,
	     uint8_t digest[AO_SHA1_DIGEST_SIZE])
{
	ao_sha1_ctx_t ctx;

	ao_sha1_init(&ctx);
	ao_sha1_update(&ctx, data, len);
	ao_sha1_final(&ctx, digest);
}

void ao_hmac_sha1_init(ao_hmac_sha1_ctx_t *ctx, const uint8_t *key,
		       size_t key_len)
{
	uint8_t k[AO_SHA1_BLOCK_SIZE];
	uint8_t ipad[AO_SHA1_BLOCK_SIZE];
	size_t i;

	memset(k, 0, sizeof(k));
	if (key_len > AO_SHA1_BLOCK_SIZE)
		ao_sha1(key, key_len, k);
	else if (key_len != 0)
		memcpy(k, key, key_len);

	memcpy(ctx->key, k, sizeof(k));
	for (i = 0; i < AO_SHA1_BLOCK_SIZE; ++i)
		ipad[i] = k[i] ^ 0x36;

	ao_sha1_init(&ctx->sha);
	ao_sha1_update(&ctx->sha, ipad, sizeof(ipad));
}

void ao_hmac_sha1_update(ao_hmac_sha1_ctx_t *ctx, const void *data,
			 size_t len)
{
	ao_sha1_update(&ctx->sha, data, len);
}

void ao_hmac_sha1_final(ao_hmac_sha1_ctx_t *ctx,
			uint8_t mac[AO_SHA1_DIGEST_SIZE])
{
	uint8_t inner[AO_SHA1_DIGEST_SIZE];
	uint8_t opad[AO_SHA1_BLOCK_SIZE];
	ao_sha1_ctx_t outer;
	size_t i;

	ao_sha1_final(&ctx->sha, inner);
	for (i = 0; i < AO_SHA1_BLOCK_SIZE; ++i)
		opad[i] = ctx->key[i] ^ 0x5c;

	ao_sha1_init(&outer);
	ao_sha1_update(&outer, opad, sizeof(opad));
	ao_sha1_update(&outer, inner, sizeof(inner));
	ao_sha1_final(&outer, mac);
}

void ao_hmac_sha1(const uint8_t *key, size_t key_len,
		  const uint8_t *data, size_t data_len,
		  uint8_t mac[AO_SHA1_DIGEST_SIZE])
{
	ao_hmac_sha1_ctx_t ctx;

	ao_hmac_sha1_init(&ctx, key, key_len);
	ao_hmac_sha1_update(&ctx, data, data_len);
	ao_hmac_sha1_final(&ctx, mac);
}

int ao_const_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < len; ++i)
		diff |= (uint8_t)(a[i] ^ b[i]);
	return diff == 0 ? 0 : -1;
}
