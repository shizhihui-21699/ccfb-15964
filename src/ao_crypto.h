#ifndef AO_CRYPTO_H
#define AO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AO_SHA1_BLOCK_SIZE 64
#define AO_SHA1_DIGEST_SIZE 20

typedef struct ao_sha1_ctx {
	uint32_t state[5];
	uint64_t bitlen;
	uint8_t buffer[AO_SHA1_BLOCK_SIZE];
	size_t buflen;
} ao_sha1_ctx_t;

void ao_sha1_init(ao_sha1_ctx_t *ctx);
void ao_sha1_update(ao_sha1_ctx_t *ctx, const void *data, size_t len);
void ao_sha1_final(ao_sha1_ctx_t *ctx, uint8_t digest[AO_SHA1_DIGEST_SIZE]);
void ao_sha1(const uint8_t *data, size_t len,
	     uint8_t digest[AO_SHA1_DIGEST_SIZE]);

typedef struct ao_hmac_sha1_ctx {
	ao_sha1_ctx_t sha;
	uint8_t key[AO_SHA1_BLOCK_SIZE];
} ao_hmac_sha1_ctx_t;

void ao_hmac_sha1_init(ao_hmac_sha1_ctx_t *ctx, const uint8_t *key,
		       size_t key_len);
void ao_hmac_sha1_update(ao_hmac_sha1_ctx_t *ctx, const void *data,
			 size_t len);
void ao_hmac_sha1_final(ao_hmac_sha1_ctx_t *ctx,
			uint8_t mac[AO_SHA1_DIGEST_SIZE]);
void ao_hmac_sha1(const uint8_t *key, size_t key_len,
		  const uint8_t *data, size_t data_len,
		  uint8_t mac[AO_SHA1_DIGEST_SIZE]);

/* Constant-time comparison; returns AO_OK only when lengths and bits match. */
int ao_const_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif
