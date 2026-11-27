/* SPDX-License-Identifier: BSD-2-Clause
 *
 * RFC 5925 section 5.1 MAC computation over whole TCP segments,
 * byte-compatible with Linux net/ipv4/tcp_ao.c::tcp_ao_hash_skb().
 *
 * MAC input order (confirmed from the kernel implementation):
 *
 *   1. SNE            : 32-bit big-endian Sequence Number Extension
 *   2. IP pseudoheader: src/dst addr, zero, IPPROTO_TCP, TCP length (BE)
 *   3. TCP header     : checksum zeroed; TCP-AO MAC field zeroed;
 *                       with EXCLUDE_OPT, only base header + AO option
 *   4. TCP payload
 */
#ifndef TCPAO_MAC_H
#define TCPAO_MAC_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "tcpao/mkt.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tcpao_segment_v4 {
	struct in_addr	src;
	struct in_addr	dst;
	const uint8_t	*tcp;		/* full TCP header + options + payload */
	size_t		tcp_len;	/* bytes from TCP header to segment end */
	uint32_t	sne;		/* host order; converted to BE internally */
};

/* Compute the (possibly truncated) MAC for one segment using an
 * already-derived traffic key. The buffer pointed to by seg->tcp is
 * never modified; zeroing of checksum/MAC happens on a private copy.
 * mac_out must provide at least mkt->maclen bytes. */
int tcpao_mac_v4(const struct tcpao_mkt *mkt,
		 const uint8_t *traffic_key, size_t tkeylen,
		 const struct tcpao_segment_v4 *seg,
		 uint8_t *mac_out);

/* Constant-time compare of two MACs of equal length. */
int tcpao_mac_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* Locate the TCP-AO option (kind 29) in a TCP header.
 * Returns offset from segment start of the Kind byte, or -1.
 * Sets *mac_off to the offset of the MAC field and *mac_len. */
#define TCPAO_OPT_KIND	29
int tcpao_find_option(const uint8_t *tcp, size_t tcp_len,
		      size_t *mac_off, size_t *mac_len);

/* Build a TCP-AO option (Kind=29, Length, KeyID, RNextKeyID, MAC).
 * Returns total option length (4 + maclen), or -1 on error. */
int tcpao_build_option(uint8_t *optbuf, size_t buflen,
		       uint8_t keyid, uint8_t rnextid,
		       const uint8_t *mac, uint8_t maclen);

#ifdef __cplusplus
}
#endif
#endif
