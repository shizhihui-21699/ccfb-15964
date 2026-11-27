/* SPDX-License-Identifier: BSD-2-Clause
 *
 * RFC 5926 section 3.1 Key Derivation Functions and RFC 5925 section 5.2
 * per-connection KDF context construction.
 */
#ifndef TCPAO_KDF_H
#define TCPAO_KDF_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#include "tcpao/mkt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 5925 Figure 7 / Figure 8, all fields in network byte order.
 * Packed so the on-the-wire-equivalent context can be hashed directly,
 * mirroring struct tcp4_ao_context / tcp6_ao_context in the kernel. */
struct tcpao_v4_context {
	struct in_addr	saddr;
	struct in_addr	daddr;
	uint16_t	sport;	/* network order */
	uint16_t	dport;	/* network order */
	uint32_t	sisn;	/* network order */
	uint32_t	disn;	/* network order; 0 for SYN */
} __attribute__((packed));

struct tcpao_v6_context {
	struct in6_addr	saddr;
	struct in6_addr	daddr;
	uint16_t	sport;
	uint16_t	dport;
	uint32_t	sisn;
	uint32_t	disn;
} __attribute__((packed));

/* RFC 5926 section 3.1.1 counter-mode input block:
 * (i || Label || Context || Output_Length), i one octet starting at 1,
 * Label = "TCP-AO" (6 octets incl. NUL per kernel kdf_input_block),
 * Output_Length in bits as a 2-octet big-endian integer.
 *
 * The kernel's struct kdf_input_block reserves label[6] and copies 6
 * bytes ("TCP-AO\0"); we do the same for byte-identical results. */
struct tcpao_kdf_block_v4 {
	uint8_t			counter;
	uint8_t			label[6];
	struct tcpao_v4_context	ctx;
	uint16_t		outlen_be;	/* bits, big endian */
} __attribute__((packed));

struct tcpao_kdf_block_v6 {
	uint8_t			counter;
	uint8_t			label[6];
	struct tcpao_v6_context	ctx;
	uint16_t		outlen_be;
} __attribute__((packed));

/* Derive one traffic key of outlen bytes for a fully formed context.
 * outlen is the MAC/PRF key size (RFC 5926: 20 for HMAC-SHA1,
 * 16 for AES-128-CMAC; SHA-256 Linux ext: 32). */
int tcpao_kdf_derive(enum tcpao_alg alg,
		     const uint8_t *master, size_t masterlen,
		     const void *context, size_t contextlen,
		     uint8_t *out, size_t outlen);

/* Convenience: derive the four directional keys of RFC 5925 5.2 for a
 * connected socket (local/remote addresses, ports, both ISNs known).
 * All address/port/ISN arguments are in network byte order. */
struct tcpao_endpoint_v4 {
	struct in_addr	local_addr;
	struct in_addr	remote_addr;
	uint16_t	local_port;
	uint16_t	remote_port;
	uint32_t	local_isn;
	uint32_t	remote_isn;
};

int tcpao_derive_v4_keyset(const struct tcpao_mkt *mkt,
			   const struct tcpao_endpoint_v4 *ep,
			   struct tcpao_traffic_keys *tk);

#ifdef __cplusplus
}
#endif
#endif
