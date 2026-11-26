#ifndef AO_CMAC_H
#define AO_CMAC_H

#include <stddef.h>
#include <stdint.h>

#define AO_AES_BLOCK_SIZE 16

typedef struct ao_aes128_key {
	uint32_t round_keys[44];
} ao_aes128_key_t;

void ao_aes128_set_key(ao_aes128_key_t *key, const uint8_t user_key[16]);
void ao_aes128_encrypt_block(const ao_aes128_key_t *key,
			     const uint8_t in[16], uint8_t out[16]);

typedef struct ao_cmac_ctx {
	ao_aes128_key_t aes;
	uint8_t x[16];
	uint8_t k1[16];
	uint8_t k2[16];
	uint8_t pending[16];
	size_t pending_len;
} ao_cmac_ctx_t;

int ao_cmac_init(ao_cmac_ctx_t *ctx, const uint8_t key[16]);
int ao_cmac_update(ao_cmac_ctx_t *ctx, const void *data, size_t len);
int ao_cmac_final(ao_cmac_ctx_t *ctx, uint8_t mac[16]);
int ao_aes_cmac(const uint8_t key[16], const uint8_t *data, size_t len,
		uint8_t mac[16]);

/* RFC 5926 KDF_AES_128_CMAC counter-mode PRF. */
int ao_kdf_aes_cmac(const uint8_t *master, size_t master_len,
		    const uint8_t *context, size_t context_len,
		    uint16_t output_bits, uint8_t *out, size_t out_cap);

#endif
