#include "tcp_ao.h"

#include "ao_cmac.h"
#include "ao_crypto.h"

#include <arpa/inet.h>
#include <string.h>

#define AO_KDF_LABEL "TCP-AO"
#define AO_KDF_LABEL_LEN 6

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

int ao_build_kdf_context(const ao_conn_ctx_t *ctx, int outgoing, int pure_syn,
			 uint8_t *out, size_t out_cap, size_t *out_len)
{
	const ao_addr_t *src, *dst;
	uint32_t src_isn, dst_isn;
	size_t addr_len, need;
	uint8_t *p;

	if (!ctx || !out)
		return AO_EINVAL;
	if (ctx->tuple.local.family != ctx->tuple.remote.family)
		return AO_EINVAL;
	if (ctx->tuple.local.family == AO_FAMILY_IPV4)
		addr_len = 4;
	else if (ctx->tuple.local.family == AO_FAMILY_IPV6)
		addr_len = 16;
	else
		return AO_EINVAL;

	if (outgoing) {
		src = &ctx->tuple.local;
		dst = &ctx->tuple.remote;
		src_isn = ctx->local_isn;
		dst_isn = ctx->remote_isn;
	} else {
		src = &ctx->tuple.remote;
		dst = &ctx->tuple.local;
		src_isn = ctx->remote_isn;
		dst_isn = ctx->local_isn;
	}
	if (pure_syn)
		dst_isn = 0;

	need = 2 * addr_len + 4 + 8;
	if (out_cap < need)
		return AO_EOVERFLOW;

	p = out;
	memcpy(p, src->addr, addr_len);
	p += addr_len;
	memcpy(p, dst->addr, addr_len);
	p += addr_len;
	put_be16(p, src->port);
	p += 2;
	put_be16(p, dst->port);
	p += 2;
	put_be32(p, src_isn);
	p += 4;
	put_be32(p, dst_isn);
	p += 4;

	if (out_len)
		*out_len = need;
	return AO_OK;
}

int ao_kdf_hmac_sha1(const uint8_t *master, size_t master_len,
		     const uint8_t *context, size_t context_len,
		     uint16_t output_bits, uint8_t *out, size_t out_cap)
{
	size_t output_bytes, generated = 0;
	uint8_t counter;

	if ((master_len == 0 && master != NULL) || !out || output_bits == 0)
		return AO_EINVAL;
	if (output_bits % 8 != 0)
		return AO_EINVAL;
	output_bytes = output_bits / 8;
	if (out_cap < output_bytes)
		return AO_EOVERFLOW;

	for (counter = 1; generated < output_bytes; ++counter) {
		uint8_t block[1 + AO_KDF_LABEL_LEN + 255 + 2];
		size_t block_len = 0;
		uint8_t digest[AO_SHA1_DIGEST_SIZE];
		size_t take;

		if (context_len > 255 || counter == 0)
			return AO_EOVERFLOW;
		block[block_len++] = counter;
		memcpy(block + block_len, AO_KDF_LABEL, AO_KDF_LABEL_LEN);
		block_len += AO_KDF_LABEL_LEN;
		if (context_len)
			memcpy(block + block_len, context, context_len);
		block_len += context_len;
		put_be16(block + block_len, output_bits);
		block_len += 2;

		ao_hmac_sha1(master, master_len, block, block_len, digest);
		take = output_bytes - generated;
		if (take > sizeof(digest))
			take = sizeof(digest);
		memcpy(out + generated, digest, take);
		generated += take;
	}
	return AO_OK;
}

int ao_derive_hmac_sha1_key(const ao_mkt_t *mkt,
			    const ao_conn_ctx_t *ctx,
			    int outgoing, int pure_syn,
			    ao_traffic_key_t *key)
{
	uint8_t context[48];
	size_t context_len = 0;
	int rc;

	if (!mkt || !ctx || !key)
		return AO_EINVAL;
	if (mkt->alg != AO_ALG_HMAC_SHA1_96)
		return AO_EUNSUPPORTED;

	rc = ao_build_kdf_context(ctx, outgoing, pure_syn, context,
				  sizeof(context), &context_len);
	if (rc != AO_OK)
		return rc;

	memset(key, 0, sizeof(*key));
	key->len = AO_TRAFFIC_KEY_SHA1_LEN;
	return ao_kdf_hmac_sha1(mkt->master_key, mkt->key_len,
				context, context_len,
				AO_TRAFFIC_KEY_SHA1_LEN * 8,
				key->bytes, sizeof(key->bytes));
}

int ao_derive_traffic_key(const ao_mkt_t *mkt,
			  const ao_conn_ctx_t *ctx,
			  int outgoing, int pure_syn,
			  ao_traffic_key_t *key)
{
	uint8_t context[48];
	size_t context_len = 0;
	int rc;

	if (!mkt || !ctx || !key)
		return AO_EINVAL;

	rc = ao_build_kdf_context(ctx, outgoing, pure_syn, context,
				  sizeof(context), &context_len);
	if (rc != AO_OK)
		return rc;

	memset(key, 0, sizeof(*key));
	if (mkt->alg == AO_ALG_HMAC_SHA1_96) {
		key->len = AO_TRAFFIC_KEY_SHA1_LEN;
		return ao_kdf_hmac_sha1(mkt->master_key, mkt->key_len,
					context, context_len, 160,
					key->bytes, sizeof(key->bytes));
	}
	if (mkt->alg == AO_ALG_AES_128_CMAC_96) {
		key->len = 16;
		return ao_kdf_aes_cmac(mkt->master_key, mkt->key_len,
				       context, context_len, 128,
				       key->bytes, sizeof(key->bytes));
	}
	return AO_EUNSUPPORTED;
}
