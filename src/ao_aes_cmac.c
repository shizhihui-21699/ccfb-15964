#include "ao_cmac.h"
#include "tcp_ao.h"

#include <string.h>

static const uint8_t aes_sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t rot_word(uint32_t w)
{
	return (w << 8) | (w >> 24);
}

static uint32_t sub_word(uint32_t w)
{
	return ((uint32_t)aes_sbox[(w >> 24) & 0xff] << 24) |
	       ((uint32_t)aes_sbox[(w >> 16) & 0xff] << 16) |
	       ((uint32_t)aes_sbox[(w >> 8) & 0xff] << 8) |
	       (uint32_t)aes_sbox[w & 0xff];
}

void ao_aes128_set_key(ao_aes128_key_t *key, const uint8_t user_key[16])
{
	static const uint8_t rcon[11] = {
		0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
	};
	uint32_t *rk;
	int i;

	if (!key || !user_key)
		return;
	rk = key->round_keys;
	for (i = 0; i < 4; ++i) {
		rk[i] = ((uint32_t)user_key[4 * i] << 24) |
			((uint32_t)user_key[4 * i + 1] << 16) |
			((uint32_t)user_key[4 * i + 2] << 8) |
			user_key[4 * i + 3];
	}
	for (i = 4; i < 44; ++i) {
		uint32_t t = rk[i - 1];
		if (i % 4 == 0)
			t = sub_word(rot_word(t)) ^
			     ((uint32_t)rcon[i / 4] << 24);
		rk[i] = rk[i - 4] ^ t;
	}
}

static void add_round_key(uint8_t state[16], const uint32_t *rk)
{
	int c;

	for (c = 0; c < 4; ++c) {
		uint32_t w = rk[c];
		state[4 * c] ^= (uint8_t)(w >> 24);
		state[4 * c + 1] ^= (uint8_t)(w >> 16);
		state[4 * c + 2] ^= (uint8_t)(w >> 8);
		state[4 * c + 3] ^= (uint8_t)w;
	}
}

static uint8_t xtime(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

void ao_aes128_encrypt_block(const ao_aes128_key_t *key,
			     const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16], tmp[16];
	int round, i;

	if (!key || !in || !out)
		return;
	memcpy(s, in, sizeof(s));
	add_round_key(s, key->round_keys);

	for (round = 1; round < 10; ++round) {
		for (i = 0; i < 16; ++i)
			s[i] = aes_sbox[s[i]];

		for (i = 0; i < 4; ++i) {
			int r = i;
			int c;
			for (c = 0; c < 4; ++c)
				tmp[r + 4 * c] = s[r + 4 * ((c + i) % 4)];
		}
		memcpy(s, tmp, sizeof(s));

		for (i = 0; i < 4; ++i) {
			uint8_t *col = s + 4 * i;
			uint8_t a0 = col[0], a1 = col[1];
			uint8_t a2 = col[2], a3 = col[3];
			uint8_t t = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
			tmp[4 * i] = (uint8_t)(a0 ^ t ^ xtime(a0 ^ a1));
			tmp[4 * i + 1] = (uint8_t)(a1 ^ t ^ xtime(a1 ^ a2));
			tmp[4 * i + 2] = (uint8_t)(a2 ^ t ^ xtime(a2 ^ a3));
			tmp[4 * i + 3] = (uint8_t)(a3 ^ t ^ xtime(a3 ^ a0));
		}
		memcpy(s, tmp, sizeof(s));
		add_round_key(s, key->round_keys + round * 4);
	}

	for (i = 0; i < 16; ++i)
		s[i] = aes_sbox[s[i]];
	for (i = 0; i < 4; ++i) {
		int r = i, c;
		for (c = 0; c < 4; ++c)
			tmp[r + 4 * c] = s[r + 4 * ((c + i) % 4)];
	}
	memcpy(s, tmp, sizeof(s));
	add_round_key(s, key->round_keys + 40);
	memcpy(out, s, 16);
}

static void cmac_left_shift(uint8_t block[16])
{
	uint8_t carry = 0;
	uint8_t msb = (uint8_t)(block[0] >> 7);
	int i;

	for (i = 15; i >= 0; --i) {
		uint8_t top = (uint8_t)(block[i] >> 7);
		block[i] = (uint8_t)((block[i] << 1) | carry);
		carry = top;
	}
	if (msb)
		block[15] ^= 0x87;
}

static void cmac_process_block(ao_cmac_ctx_t *ctx, const uint8_t block[16])
{
	uint8_t i;

	for (i = 0; i < 16; ++i)
		ctx->x[i] ^= block[i];
	ao_aes128_encrypt_block(&ctx->aes, ctx->x, ctx->x);
}

int ao_cmac_init(ao_cmac_ctx_t *ctx, const uint8_t key[16])
{
	uint8_t zero[16] = {0};

	if (!ctx || !key)
		return AO_EINVAL;
	memset(ctx, 0, sizeof(*ctx));
	ao_aes128_set_key(&ctx->aes, key);
	ao_aes128_encrypt_block(&ctx->aes, zero, ctx->k1);
	cmac_left_shift(ctx->k1);
	memcpy(ctx->k2, ctx->k1, 16);
	cmac_left_shift(ctx->k2);
	return AO_OK;
}

int ao_cmac_update(ao_cmac_ctx_t *ctx, const void *data, size_t len)
{
	const uint8_t *p = data;

	if (!ctx || (!data && len))
		return AO_EINVAL;

	while (len > 0) {
		size_t n;

		if (ctx->pending_len == AO_AES_BLOCK_SIZE) {
			cmac_process_block(ctx, ctx->pending);
			ctx->pending_len = 0;
		}
		n = AO_AES_BLOCK_SIZE - ctx->pending_len;
		if (n > len)
			n = len;
		memcpy(ctx->pending + ctx->pending_len, p, n);
		ctx->pending_len += n;
		p += n;
		len -= n;

		if (ctx->pending_len == AO_AES_BLOCK_SIZE && len > 0) {
			cmac_process_block(ctx, ctx->pending);
			ctx->pending_len = 0;
		}
	}
	return AO_OK;
}

int ao_cmac_final(ao_cmac_ctx_t *ctx, uint8_t mac[16])
{
	if (!ctx || !mac)
		return AO_EINVAL;

	if (ctx->pending_len == AO_AES_BLOCK_SIZE) {
		int i;
		for (i = 0; i < 16; ++i)
			ctx->pending[i] ^= ctx->k1[i];
		cmac_process_block(ctx, ctx->pending);
	} else {
		size_t pos = ctx->pending_len;
		int i;

		ctx->pending[pos++] = 0x80;
		while (pos < 16)
			ctx->pending[pos++] = 0;
		for (i = 0; i < 16; ++i)
			ctx->pending[i] ^= ctx->k2[i];
		cmac_process_block(ctx, ctx->pending);
	}
	memcpy(mac, ctx->x, 16);
	return AO_OK;
}

int ao_aes_cmac(const uint8_t key[16], const uint8_t *data, size_t len,
		uint8_t mac[16])
{
	ao_cmac_ctx_t ctx;
	int rc;

	rc = ao_cmac_init(&ctx, key);
	if (rc != AO_OK)
		return rc;
	rc = ao_cmac_update(&ctx, data, len);
	if (rc != AO_OK)
		return rc;
	return ao_cmac_final(&ctx, mac);
}

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

int ao_kdf_aes_cmac(const uint8_t *master, size_t master_len,
		    const uint8_t *context, size_t context_len,
		    uint16_t output_bits, uint8_t *out, size_t out_cap)
{
	static const uint8_t zero_key[16] = {0};
	uint8_t derived_master[16];
	const uint8_t *k;
	size_t output_bytes, generated = 0;
	unsigned counter;

	if (!out || output_bits == 0 || output_bits % 8 != 0)
		return AO_EINVAL;
	if ((master_len == 0 && master != NULL) || master_len > 80)
		return AO_EINVAL;
	if (context_len > 255)
		return AO_EOVERFLOW;
	output_bytes = output_bits / 8;
	if (out_cap < output_bytes)
		return AO_EOVERFLOW;

	if (master_len == 16) {
		k = master;
	} else {
		int rc = ao_aes_cmac(zero_key, master, master_len,
				     derived_master);
		if (rc != AO_OK)
			return rc;
		k = derived_master;
	}

	for (counter = 1; generated < output_bytes; ++counter) {
		uint8_t block[1 + 6 + 255 + 2];
		size_t block_len = 0;
		uint8_t digest[16];
		size_t take;
		int rc;

		if (counter > 255)
			return AO_EOVERFLOW;
		block[block_len++] = (uint8_t)counter;
		memcpy(block + block_len, "TCP-AO", 6);
		block_len += 6;
		if (context_len)
			memcpy(block + block_len, context, context_len);
		block_len += context_len;
		put_be16(block + block_len, output_bits);
		block_len += 2;

		rc = ao_aes_cmac(k, block, block_len, digest);
		if (rc != AO_OK)
			return rc;
		take = output_bytes - generated;
		if (take > sizeof(digest))
			take = sizeof(digest);
		memcpy(out + generated, digest, take);
		generated += take;
	}
	return AO_OK;
}
