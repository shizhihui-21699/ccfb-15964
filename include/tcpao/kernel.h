/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Linux TCP_AO setsockopt(2) adapter.
 *
 * Thin, strictly typed wrappers around the uAPI described in
 * Documentation/networking/tcp_ao.html and include/uapi/linux/tcp.h.
 * Everything that touches <linux/tcp.h> lives here so the rest of the
 * codebase compiles on development machines (macOS) for unit testing.
 *
 * Requires kernel >= 6.10 with CONFIG_TCP_AO=y (and CONFIG_CRYPTO_CMAC,
 * CONFIG_CRYPTO_HMAC, CONFIG_CRYPTO_SHA1, CONFIG_CRYPTO_SHA256).
 */
#ifndef TCPAO_KERNEL_H
#define TCPAO_KERNEL_H

#include <stdint.h>
#include <stdbool.h>

#include "tcpao/mkt.h"
#include "tcpao/rollover.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True if the running kernel supports TCP_AO_* setsockopts. */
bool tcpao_kernel_supported(void);

/* Install an MKT on a socket (listener or established).
 *   set_current: make it current_key immediately
 *   set_rnext  : advertise its RecvID as RNextKeyID immediately
 * Mirrors struct tcp_ao_add. */
int tcpao_kernel_add_key(int fd, const struct tcpao_mkt *mkt,
			 bool set_current, bool set_rnext);

/* Remove an MKT identified by peer + sndid/rcvid.
 * Normal delete fails (-EBUSY) while the key is current/rnext; use the
 * forced variant (TCP_AO_DEL_KEY set_current/set_rnext + replacement
 * IDs) only in rollover abort paths. */
int tcpao_kernel_del_key(int fd, const struct tcpao_mkt *mkt);

int tcpao_kernel_force_del_key(int fd, const struct tcpao_mkt *victim,
			       uint8_t replacement_current,
			       uint8_t replacement_rnext,
			       bool set_current, bool set_rnext);

/* Move the per-socket current_key / rnext_key pointers via TCP_AO_INFO.
 * A -1 for either pointer leaves it unchanged. */
int tcpao_kernel_set_pointers(int fd, int current_keyid, int rnext_keyid);

/* Read counters and current pointers via getsockopt(TCP_AO_INFO). */
int tcpao_kernel_get_info(int fd, struct tcpao_ao_info *out);

/* Require TCP-AO: reject non-AO incoming connections/segments. */
int tcpao_kernel_set_required(int fd, bool required);

/* Dump installed keys for a peer into @out (caller-sized array). */
int tcpao_kernel_get_keys(int fd, const struct sockaddr *peer,
			  struct tcpao_mkt *out, size_t cap, size_t *n);

/* ---- TCP MD5 (RFC 2385) coexistence for legacy peers ----------------
 *
 * A listener may carry both key *types* (never for the same peer):
 * install an MD5 key on a per-peer prefix while all upgraded peers use
 * TCP-AO. Established connections cannot mix the two — the kernel
 * rejects adding the other type once a connection is signed.
 * (struct tcpao_md5_key is declared in tcpao/mkt.h.) */

int tcpao_md5_listener_add(int fd, const struct tcpao_md5_key *k);
int tcpao_md5_listener_del(int fd, const struct sockaddr *peer,
			   uint8_t prefix);

/* Checkpoint/restore helpers (TCP_AO_REPAIR): SNE/ISN must survive a
 * daemon restart without invalidating the long-lived BGP session. */
struct tcpao_repair_state {
	uint32_t	snt_isn;	/* network order */
	uint32_t	rcv_isn;
	uint32_t	snd_sne;	/* host order */
	uint32_t	rcv_sne;
};

int tcpao_repair_get(int fd, struct tcpao_repair_state *out);
int tcpao_repair_set(int fd, const struct tcpao_repair_state *in);

/* Human-readable errno-style string for the common TCP_AO errors. */
const char *tcpao_kernel_strerror(int err);

#ifdef __cplusplus
}
#endif
#endif
