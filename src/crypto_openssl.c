/* SPDX-License-Identifier: BSD-2-Clause
 *
 * OpenSSL EVP backend for RFC 5926 primitives.
 * Works with OpenSSL >= 1.1 (EVP_MAC / EVP_PKEY and legacy HMAC_CTX).
 * On the target router this same code links against the system OpenSSL
 * or BoringSSL; the kernel side uses its internal crypto API with the
 * identical algorithm wiring.
 */
#include "tcpao/crypto.h"
#include "tcpao/mkt.h"

#include <string.h>

#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>

void tcpao_explicit_bzero(void *p, size_t len)
{
#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
	OPENSSL_cleanse(p, len);
#else
	volatile unsigned char *vp = p;
	while (len--)
		*vp++ = 0;
#endif
}

static int hmac_one(const EVP_MD *md,
		    const uint8_t *key, size_t keylen,
		    const uint8_t *data, size_t datalen,
		    uint8_t *out, unsigned int *outlen)
{
	unsigned int len = 0;
	uint8_t *rc;

	rc = HMAC(md, key, (int)keylen, data, datalen, out, &len);
	if (!rc)
		return -1;
	*outlen = len;
	return 0;
}

int tcpao_hmac_sha1(const uint8_t *key, size_t keylen,
		    const uint8_t *data, size_t datalen,
		    uint8_t md_out[20])
{
	unsigned int len = 0;
	int rc = hmac_one(EVP_sha1(), key, keylen, data, datalen,
			  md_out, &len);
	if (rc || len != 20)
		return -1;
	return 0;
}

int tcpao_hmac_sha256(const uint8_t *key, size_t keylen,
		      const uint8_t *data, size_t datalen,
		      uint8_t md_out[32])
{
	unsigned int len = 0;
	int rc = hmac_one(EVP_sha256(), key, keylen, data, datalen,
			  md_out, &len);
	if (rc || len != 32)
		return -1;
	return 0;
}

int tcpao_aes128_cmac(const uint8_t key16[16],
		      const uint8_t *data, size_t datalen,
		      uint8_t mac16[16])
{
	int rc = -1;
	size_t outlen = 16;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
	if (!mac)
		return -1;
	EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
	EVP_MAC_free(mac);
	if (!ctx)
		return -1;

	char cipher_name[] = "AES-128-CBC";
	OSSL_PARAM params[2];
	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
						     cipher_name, 0);
	params[1] = OSSL_PARAM_construct_end();

	if (EVP_MAC_init(ctx, key16, 16, params) == 1 &&
	    EVP_MAC_update(ctx, data, datalen) == 1 &&
	    EVP_MAC_final(ctx, mac16, &outlen, 16) == 1 &&
	    outlen == 16)
		rc = 0;
	EVP_MAC_CTX_free(ctx);
#else
	CMAC_CTX *ctx = CMAC_CTX_new();
	if (!ctx)
		return -1;
	if (CMAC_Init(ctx, key16, 16, EVP_aes_128_cbc(), NULL) == 1 &&
	    CMAC_Update(ctx, data, datalen) == 1 &&
	    CMAC_Final(ctx, mac16, &outlen) == 1 && outlen == 16)
		rc = 0;
	CMAC_CTX_free(ctx);
#endif
	return rc;
}
