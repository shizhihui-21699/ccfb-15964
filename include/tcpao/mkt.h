/* SPDX-License-Identifier: BSD-2-Clause
 *
 * TCP-AO (RFC 5925 / RFC 5926) Master Key Tuple and per-connection
 * data structures.
 *
 * Field semantics follow RFC 5925 section 4 and the Linux uAPI
 * (include/uapi/linux/tcp.h, struct tcp_ao_add).
 */
#ifndef TCPAO_MKT_H
#define TCPAO_MKT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TCPAO_MKT_MAXKEYLEN	80	/* matches TCP_AO_MAXKEYLEN */
#define TCPAO_MAX_KEYID		255
#define TCPAO_MIN_MACLEN	4	/* kernel enforces >= 4 bytes */
#define TCPAO_MAX_MACLEN	16	/* option space cap for default MACs */
#define TCPAO_LABEL		"TCP-AO"

/* RFC 5926 mandatory-to-implement pair, plus the Linux HMAC-SHA-256
 * extension (see Documentation/networking/tcp_ao.html).
 */
enum tcpao_alg {
	TCPAO_ALG_HMAC_SHA1_96 = 0,	/* KDF_HMAC_SHA1   / HMAC-SHA-1-96  */
	TCPAO_ALG_AES_128_CMAC_96,	/* KDF_AES_128_CMAC / AES-128-CMAC-96 */
	TCPAO_ALG_HMAC_SHA256,		/* Linux extension, variable maclen  */
};

/* alg_name strings accepted by the kernel crypto API (TCP_AO_ADD_KEY). */
#define TCPAO_ALGNAME_SHA1	"hmac(sha1)"
#define TCPAO_ALGNAME_CMAC	"cmac(aes)"
#define TCPAO_ALGNAME_SHA256	"hmac(sha256)"

struct tcpao_mkt {
	/* Connection identifier: peer address (network order) + prefix. */
	struct sockaddr_storage	peer;
	uint8_t			prefix;
	int			ifindex;	/* VRF, 0 = none */

	enum tcpao_alg		alg;
	uint8_t			sndid;		/* KeyID on outgoing segments */
	uint8_t			rcvid;		/* matched against incoming KeyID */
	uint8_t			maclen;		/* truncated MAC length in bytes */
	bool			exclude_options;/* TCP_AO_KEYF_EXCLUDE_OPT */

	uint8_t			key[TCPAO_MKT_MAXKEYLEN];
	uint8_t			keylen;

	/* Bookkeeping, not wire data. */
	bool			in_use;
};

/* Directional traffic keys, RFC 5925 section 5.2: up to four per MKT. */
struct tcpao_traffic_keys {
	uint8_t	send_syn[TCPAO_MAX_MACLEN + 16];
	uint8_t	recv_syn[TCPAO_MAX_MACLEN + 16];
	uint8_t	send_other[TCPAO_MAX_MACLEN + 16];
	uint8_t	recv_other[TCPAO_MAX_MACLEN + 16];
	size_t	keylen;
	bool	valid;
};

const char *tcpao_alg_name(enum tcpao_alg alg);
size_t tcpao_alg_digest_size(enum tcpao_alg alg);	/* full PRF/MAC output */
int tcpao_alg_from_name(const char *name, enum tcpao_alg *out);

/* Zero secret material; never optimized away. */
void tcpao_explicit_bzero(void *p, size_t len);

/* RFC 2385 legacy key carried on a listener for mixed peer fleets.
 * Defined here so session.h can reference the complete type. */
struct tcpao_md5_key {
	struct sockaddr_storage	peer;
	uint8_t			prefix;
	uint8_t			key[80];
	uint8_t			keylen;
};

#ifdef __cplusplus
}
#endif
#endif
