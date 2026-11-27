/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Wire-format TCP header access. Linux and macOS name the fields of
 * struct tcphdr differently and disagree on host-vs-network order; the
 * MAC code must always operate on the on-the-wire big-endian image, so
 * everything goes through these helpers.
 */
#ifndef TCPAO_TCPHDR_H
#define TCPAO_TCPHDR_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/tcp.h>

#ifdef __linux__
#include <linux/tcp.h>
#endif

/* Data offset in bytes (header + options). */
static inline size_t tcpao_th_doff(const void *tcp)
{
	const uint8_t *p = tcp;
	/* doff is the high nibble of byte 12 on both platforms' wire image. */
	return (size_t)(p[12] >> 4) * 4;
}

/* Checksum field sits at bytes 16-17 (network order). The MAC code
 * zeroes it on a private copy via byte offsets, never struct fields. */
#define TCPAO_TH_CHECKSUM_OFF	16

/* Base TCP header size. */
#define TCPAO_TH_BASE		20

#endif
