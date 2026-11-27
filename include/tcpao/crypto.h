/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Portable crypto backend abstraction.
 *
 * Two primitives are needed for RFC 5926:
 *   - HMAC-SHA-1 / HMAC-SHA-256 (used both as PRF in the KDF and as MAC)
 *   - AES-128-CMAC (PRF in the KDF with RFC 4615 key extraction, and MAC)
 *
 * The Linux kernel performs exactly these operations via its crypto API
 * (net/ipv4/tcp_ao.c); userspace reproduces them via OpenSSL EVP so the
 * same code path is unit-testable off-box.
 */
#ifndef TCPAO_CRYPTO_H
#define TCPAO_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One-shot HMAC. md_out must hold at least the digest size
 * (20 for SHA-1, 32 for SHA-256). Returns 0 on success. */
int tcpao_hmac_sha1(const uint8_t *key, size_t keylen,
		    const uint8_t *data, size_t datalen,
		    uint8_t md_out[20]);

int tcpao_hmac_sha256(const uint8_t *key, size_t keylen,
		      const uint8_t *data, size_t datalen,
		      uint8_t md_out[32]);

/* One-shot AES-128-CMAC. key is always exactly 16 bytes at this layer;
 * variable-length master-key extraction (RFC 5926 Fig.1 step 1b) lives
 * in the KDF. Output is 16 bytes. */
int tcpao_aes128_cmac(const uint8_t key16[16],
		      const uint8_t *data, size_t datalen,
		      uint8_t mac16[16]);

#ifdef __cplusplus
}
#endif
#endif
