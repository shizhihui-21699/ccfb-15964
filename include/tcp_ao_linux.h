/*
 * tcp_ao_linux.h - Linux TCP_AO_* setsockopt adapter and TCP-MD5 coexistence.
 *
 * The portable core deliberately does not require Linux headers.  This
 * adapter uses binary-compatible copies of the current Linux UAPI structures
 * so it can still be compiled against older system headers.
 */
#ifndef TCP_AO_LINUX_H
#define TCP_AO_LINUX_H

#include "tcp_ao.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return AO_OK when this build is running on a Linux kernel with TCP-AO. */
int ao_linux_probe(int fd);

/* Add an MKT to a TCP listener or established BGP socket. */
int ao_linux_add_mkt(int fd, const ao_mkt_t *mkt,
		     int set_current, int set_rnext);

/* Stage every MKT in a userspace master table on a Linux socket. */
int ao_linux_apply_table(int fd, const ao_table_t *table);

/* Normal delete. Do not force unless the peer ignores RNextKeyID. */
int ao_linux_del_mkt(int fd, const ao_mkt_t *mkt);

/* Atomically replace a used key; may break a non-cooperating session. */
int ao_linux_force_del_mkt(int fd, const ao_mkt_t *old_mkt,
			   uint8_t replacement_current_send_id,
			   uint8_t replacement_rnext_recv_id);

int ao_linux_set_rnext(int fd, uint8_t rnext_recv_id);
int ao_linux_set_current(int fd, uint8_t current_send_id);

typedef struct ao_linux_info {
	uint8_t current_send_id;
	uint8_t rnext_recv_id;
	uint64_t pkt_good;
	uint64_t pkt_bad;
	uint64_t pkt_key_not_found;
	uint64_t pkt_ao_required;
} ao_linux_info_t;

int ao_linux_get_info(int fd, ao_linux_info_t *info);

/* RFC 2385 legacy peer. Use a separate peer selector; Linux cannot migrate. */
int ao_linux_add_md5(int fd, const ao_addr_t *peer,
		     const uint8_t *key, size_t key_len);

/*
 * Best-effort query of bytes still in the local TCP send queue.  When zero,
 * all bytes have at least left the queue; TCP still provides retransmission
 * and the overlapping MKTs protect unACKed segments.
 */
int ao_linux_send_queue_bytes(int fd, size_t *bytes);

#ifdef __cplusplus
}
#endif

#endif
