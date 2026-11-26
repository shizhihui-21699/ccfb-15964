/*
 * tcp_ao.h - RFC 5925/5926 TCP Authentication Option key management core.
 *
 * This is the portable, kernel-independent part used by a C routing daemon.
 * It owns:
 *   - the Master Key Table (MKT),
 *   - connection-specific traffic-key derivation,
 *   - SendID/RecvID key selection,
 *   - Sequence Number Extension (SNE) handling,
 *   - TCP-AO option/MAC construction and verification,
 *   - hitless key-rollover state,
 *   - a retryable BGP update journal.
 *
 * The Linux setsockopt adapter lives in ao_linux.h / ao_linux.c.
 */
#ifndef TCP_AO_H
#define TCP_AO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AO_MAX_MASTER_KEY_LEN 80
#define AO_TRAFFIC_KEY_SHA1_LEN 20
#define AO_OPTION_KIND 29
#define AO_OPTION_FIXED_LEN 4
#define AO_MAC_HMAC_SHA1_96_LEN 12
#define AO_MAX_MAC_LEN 36
#define AO_MAX_OPTION_LEN (AO_OPTION_FIXED_LEN + AO_MAX_MAC_LEN)

/* Positive values are length/boolean success helpers; zero is success. */
enum ao_status {
	AO_OK = 0,
	AO_EINVAL = -1,
	AO_ENOMEM = -2,
	AO_ENOTFOUND = -3,
	AO_EEXIST = -4,
	AO_EVERIFY = -5,
	AO_EUNSUPPORTED = -6,
	AO_EAGAIN = -7,
	AO_ESTATE = -8,
	AO_EOVERFLOW = -9,
	AO_EIO = -10
};

enum ao_family {
	AO_FAMILY_UNSPEC = 0,
	AO_FAMILY_IPV4 = 4,
	AO_FAMILY_IPV6 = 6
};

enum ao_alg {
	/* RFC 5926 mandatory-to-implement pair. */
	AO_ALG_HMAC_SHA1_96 = 1,
	/* Pass-through algorithm identifiers for the Linux kernel adapter. */
	AO_ALG_AES_128_CMAC_96 = 2,
	AO_ALG_HMAC_SHA256_96 = 3
};

enum ao_security_mode {
	/* Listen with AO and TCP-MD5 entries; classify each new peer by SYN. */
	AO_MODE_DUAL_LISTENER = 0,
	/* Use TCP-AO only. */
	AO_MODE_AO_ONLY = 1,
	/* Existing legacy peer: keep RFC 2385 TCP-MD5 on a separate socket. */
	AO_MODE_MD5_ONLY = 2,
	/* For outbound connections, use configured capability information. */
	AO_MODE_AUTO = 3
};

typedef struct ao_addr {
	enum ao_family family;
	/* IPv4 is stored in the first four bytes. IPv6 uses all 16 bytes. */
	uint8_t addr[16];
	/* Host byte order. Zero in an MKT selector is a wildcard. */
	uint16_t port;
	/* Address prefix length; use 32/128 for an exact host. */
	uint8_t prefix;
	uint8_t reserved;
	uint32_t ifindex;
} ao_addr_t;

typedef struct ao_tuple {
	ao_addr_t local;
	ao_addr_t remote;
} ao_tuple_t;

typedef struct ao_mkt {
	uint32_t id;                 /* local table id, not a TCP-AO ID */
	ao_tuple_t match;
	uint8_t send_id;             /* inserted as outgoing KeyID */
	uint8_t recv_id;             /* matched against incoming KeyID */
	enum ao_alg alg;
	uint8_t mac_len;
	uint8_t key_len;
	uint8_t exclude_options;     /* TCP_AO_KEYF_EXCLUDE_OPT */
	uint8_t ao_required;
	uint8_t master_key[AO_MAX_MASTER_KEY_LEN];
} ao_mkt_t;

/* Connection instance and Initial Sequence Numbers used by the KDF. */
typedef struct ao_conn_ctx {
	ao_tuple_t tuple;
	uint32_t local_isn;
	uint32_t remote_isn;
	unsigned local_isn_valid : 1;
	unsigned remote_isn_valid : 1;
} ao_conn_ctx_t;

typedef struct ao_traffic_key {
	uint8_t len;
	uint8_t bytes[AO_TRAFFIC_KEY_SHA1_LEN];
} ao_traffic_key_t;

typedef struct ao_table ao_table_t;
typedef struct ao_conn ao_conn_t;

const char *ao_strerror(int status);

/* Address helpers. */
int ao_addr_ipv4(ao_addr_t *a, const uint8_t bytes[4], uint16_t port);
int ao_addr_ipv6(ao_addr_t *a, const uint8_t bytes[16], uint16_t port);
int ao_addr_set_prefix(ao_addr_t *a, uint8_t prefix);
int ao_addr_equal(const ao_addr_t *a, const ao_addr_t *b);
int ao_tuple_equal(const ao_tuple_t *a, const ao_tuple_t *b);

/*
 * Master Key Table.  A table is safe for concurrent readers/writers when the
 * platform lock is enabled; lookups copy the selected MKT to avoid use-after-
 * free while a rollover deletes an old entry.
 */
int ao_table_create(ao_table_t **table);
void ao_table_destroy(ao_table_t *table);
int ao_table_add(ao_table_t *table, const ao_mkt_t *mkt, uint32_t *id);
int ao_table_del(ao_table_t *table, uint32_t id);
int ao_table_count(const ao_table_t *table, size_t *count);
int ao_table_get(const ao_table_t *table, uint32_t id, ao_mkt_t *out);
/* Returns a malloc'd consistent copy of all MKTs; release with free(). */
int ao_table_snapshot(const ao_table_t *table, ao_mkt_t **items,
		      size_t *count);
void ao_table_snapshot_free(ao_mkt_t *items, size_t count);
int ao_table_find_recv_id(const ao_table_t *table,
			  const ao_tuple_t *tuple,
			  uint8_t recv_id,
			  ao_mkt_t *out);
int ao_table_find_send_id(const ao_table_t *table,
			  const ao_tuple_t *tuple,
			  uint8_t send_id,
			  ao_mkt_t *out);

/* RFC 5926 KDF and context. Most callers use ao_conn_install_mkt(). */
int ao_kdf_hmac_sha1(const uint8_t *master, size_t master_len,
		     const uint8_t *context, size_t context_len,
		     uint16_t output_bits, uint8_t *out, size_t out_cap);
int ao_build_kdf_context(const ao_conn_ctx_t *ctx, int outgoing, int pure_syn,
			 uint8_t *out, size_t out_cap, size_t *out_len);
int ao_derive_hmac_sha1_key(const ao_mkt_t *mkt,
			    const ao_conn_ctx_t *ctx,
			    int outgoing, int pure_syn,
			    ao_traffic_key_t *key);
/* Dispatches to RFC 5926 KDF_HMAC_SHA1 or KDF_AES_128_CMAC. */
int ao_derive_traffic_key(const ao_mkt_t *mkt,
			  const ao_conn_ctx_t *ctx,
			  int outgoing, int pure_syn,
			  ao_traffic_key_t *key);

/*
 * RFC 5925 Section 6.2 receiver/Sender SNE state.  Feed TCP SEG.SEQ in host
 * byte order.  The returned value is the high 32 bits to prepend to the MAC.
 */
typedef struct ao_sne_state {
	uint32_t sne;
	uint32_t prev_seq;
	uint8_t flag;
	uint8_t initialized;
	uint16_t reserved;
} ao_sne_state_t;

void ao_sne_init(ao_sne_state_t *st);
uint32_t ao_sne_next_rfc5925(ao_sne_state_t *st, uint32_t seg_seq);

/* TCP-AO option codec. */
typedef struct ao_option {
	uint8_t key_id;
	uint8_t rnext_id;
	uint8_t mac_len;
	const uint8_t *mac;
	size_t option_offset;
} ao_option_t;

size_t ao_option_total_len(uint8_t mac_len);
int ao_option_build(uint8_t *buf, size_t cap, uint8_t key_id,
		    uint8_t rnext_id, const uint8_t *mac, uint8_t mac_len);
int ao_option_parse(const uint8_t *tcp_segment, size_t tcp_len,
		    ao_option_t *opt);
int ao_tcp_header_len(const uint8_t *tcp_segment, size_t tcp_len,
		      size_t *header_len);

/* Per-connection key ring and current/rnext pointers. */
int ao_conn_create(const ao_conn_ctx_t *ctx, ao_conn_t **conn);
void ao_conn_destroy(ao_conn_t *conn);
int ao_conn_update_isns(ao_conn_t *conn, uint32_t local_isn,
			uint32_t remote_isn);
int ao_conn_install_mkt(ao_conn_t *conn, const ao_mkt_t *mkt);
int ao_conn_set_rnext_recv_id(ao_conn_t *conn, uint8_t recv_id);
int ao_conn_current_send_id(const ao_conn_t *conn, uint8_t *send_id);
int ao_conn_rnext_recv_id(const ao_conn_t *conn, uint8_t *recv_id);
int ao_conn_get_traffic_key(ao_conn_t *conn, uint8_t key_id,
			    int outgoing, int pure_syn,
			    ao_traffic_key_t *key);

/*
 * Sign/verify a complete mutable TCP segment.  The TCP-AO option must already
 * be present in tcp_segment and its MAC bytes may be zero; ao_conn_sign()
 * locates and fills them.
 */
int ao_conn_sign(ao_conn_t *conn, uint32_t seq, int pure_syn,
		 uint8_t *tcp_segment, size_t tcp_len);

typedef struct ao_verify_result {
	ao_option_t option;
	uint32_t sne;
	uint8_t mkt_table_id_padding[4];
	uint32_t mkt_table_id;
	int current_key_changed;
	uint8_t previous_current_send_id;
	uint8_t current_send_id;
	uint8_t peer_key_id;
	uint8_t peer_rnext_id;
} ao_verify_result_t;

int ao_conn_verify(ao_conn_t *conn, uint32_t seq, int pure_syn,
		   const uint8_t *tcp_segment, size_t tcp_len,
		   ao_verify_result_t *result);

/*
 * Hitless rollover coordinator.  It is deliberately driven by observations:
 * one endpoint cannot know the peer's precise switch time.  Retaining both
 * MKTs and allowing current_key to move forward or "back up" is what prevents
 * reordered segments from being dropped.
 */
enum ao_roll_phase {
	AO_ROLL_STABLE = 0,
	AO_ROLL_NEW_STAGED = 1,       /* new MKT installed, not requested */
	AO_ROLL_LOCAL_RNEXT_NEW = 2,  /* this host announces new RNextKeyID */
	AO_ROLL_PEER_SWITCHED = 3,    /* valid segment had peer's new KeyID */
	AO_ROLL_LOCAL_CURRENT_NEW = 4,/* peer requested our new SendID */
	AO_ROLL_CONVERGED = 5,        /* both directions observed on new key */
	AO_ROLL_DRAIN = 6,            /* wait for old segments/updates to drain */
	AO_ROLL_DONE = 7,
	AO_ROLL_ROLLED_BACK = 8
};

typedef struct ao_roll_config {
	uint8_t old_send_id;
	uint8_t old_recv_id;
	uint8_t new_send_id;
	uint8_t new_recv_id;
	/* Number of update bytes/messages that must be flushed before DONE. */
	uint64_t drain_messages;
} ao_roll_config_t;

typedef struct ao_roll_state {
	ao_roll_config_t cfg;
	enum ao_roll_phase phase;
	unsigned local_rnext_is_new : 1;
	unsigned local_current_is_new : 1;
	unsigned peer_sends_new : 1;
	unsigned peer_requests_new : 1;
	unsigned old_key_retired : 1;
	uint64_t verified_new_segments;
	uint64_t verified_old_segments;
	uint64_t drain_remaining;
} ao_roll_state_t;

int ao_roll_init(ao_roll_state_t *roll, const ao_roll_config_t *cfg);
int ao_roll_stage_new(ao_roll_state_t *roll);
int ao_roll_advertise_new(ao_roll_state_t *roll);
int ao_roll_observe_sent(ao_roll_state_t *roll, uint8_t key_id,
			  uint8_t rnext_id);
int ao_roll_observe_verified(ao_roll_state_t *roll,
			     const ao_verify_result_t *result);
int ao_roll_note_messages_flushed(ao_roll_state_t *roll, uint64_t count);
int ao_roll_can_retire_old(const ao_roll_state_t *roll);
int ao_roll_retire_old(ao_roll_state_t *roll);
int ao_roll_cancel_to_old(ao_roll_state_t *roll);

/*
 * Reliable BGP update journal.  A real integration writes complete BGP
 * messages (the 16-byte BGP marker + length framing is preserved) through
 * bgp_update_writer_flush().  Partial writes and EAGAIN retain the unsent
 * suffix so no route update is lost or interleaved.
 */
typedef struct bgp_journal bgp_journal_t;

int bgp_journal_create(size_t max_messages, bgp_journal_t **out);
void bgp_journal_destroy(bgp_journal_t *j);
int bgp_journal_append(bgp_journal_t *j, const uint8_t *message,
		       size_t len, uint64_t *id);
size_t bgp_journal_pending(const bgp_journal_t *j);

typedef ssize_t (*bgp_write_fn)(int fd, const uint8_t *buf, size_t len,
				void *user);

typedef struct bgp_update_writer {
	int fd;
	bgp_journal_t *journal;
	uint64_t next_id;
	/* Current partially written message and byte offset. */
	uint64_t active_id;
	size_t active_offset;
} bgp_update_writer_t;

int bgp_writer_init(bgp_update_writer_t *w, int fd,
		    bgp_journal_t *journal);
int bgp_writer_enqueue(bgp_update_writer_t *w, const uint8_t *msg,
		       size_t len, uint64_t *id);
/* AO_OK: everything queued has been fully written. AO_EAGAIN: retry later. */
int bgp_writer_flush(bgp_update_writer_t *w, bgp_write_fn write_fn,
		     void *user);

/* Security mode / legacy coexistence policy. */
typedef struct ao_peer_policy {
	ao_addr_t peer;
	enum ao_security_mode mode;
	ao_mkt_t ao;
	uint8_t md5_key[AO_MAX_MASTER_KEY_LEN];
	uint8_t md5_key_len;
} ao_peer_policy_t;

int ao_policy_validate(const ao_peer_policy_t *policy);
int ao_policy_use_ao_for_syn(const ao_peer_policy_t *policy,
			     int received_ao_option,
			     int received_md5_option);

#ifdef __cplusplus
}
#endif

#endif /* TCP_AO_H */
