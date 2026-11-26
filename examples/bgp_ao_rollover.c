/*
 * bgp_ao_rollover.c - compact hitless TCP-AO rollover demonstration.
 *
 * This program exercises the same calls a BGP I/O thread should make:
 *   1. install old and new MKTs before advertising the new one,
 *   2. keep accepting either RecvID during the overlap window,
 *   3. let RNextKeyID move current_key (including a possible backup),
 *   4. retain an update journal until writes have accepted all bytes,
 *   5. retire the old MKT only after bidirectional convergence and drain.
 *
 * On Linux, replace the in-memory ao_conn_t operations with the included
 * ao_linux_* setsockopt calls. The kernel owns wire SNE/MAC processing after
 * the MKT has been installed.
 */
#include "tcp_ao.h"
#include "tcp_ao_linux.h"

#include <stdio.h>
#include <string.h>

struct sink {
	uint8_t bytes[4096];
	size_t len;
};

static ssize_t sink_write(int fd, const uint8_t *buf, size_t len, void *user)
{
	struct sink *sink = user;
	(void)fd;

	if (sink->len + len > sizeof(sink->bytes))
		return -1;
	memcpy(sink->bytes + sink->len, buf, len);
	sink->len += len;
	return (ssize_t)len;
}

int main(void)
{
	bgp_journal_t *journal;
	bgp_update_writer_t writer;
	struct sink sink = {0};
	static const char *updates[] = {
		"BGP UPDATE 203.0.113.0/24 AS64501",
		"BGP UPDATE 198.51.100.0/24 AS64502",
		"BGP UPDATE 192.0.2.0/24 AS64503"
	};
	ao_roll_state_t roll;
	ao_roll_config_t cfg = {
		.old_send_id = 10,
		.old_recv_id = 20,
		.new_send_id = 11,
		.new_recv_id = 21,
		.drain_messages = 3
	};
	size_t i;
	int rc;

	rc = ao_roll_init(&roll, &cfg);
	if (rc != AO_OK) {
		fprintf(stderr, "roll init: %s\n", ao_strerror(rc));
		return 1;
	}
	ao_roll_stage_new(&roll);
	ao_roll_advertise_new(&roll);

	if (bgp_journal_create(128, &journal) != AO_OK ||
	    bgp_writer_init(&writer, -1, journal) != AO_OK) {
		fprintf(stderr, "journal initialization failed\n");
		return 1;
	}

	for (i = 0; i < sizeof(updates) / sizeof(updates[0]); ++i) {
		rc = bgp_writer_enqueue(&writer, (const uint8_t *)updates[i],
					strlen(updates[i]), NULL);
		if (rc != AO_OK) {
			fprintf(stderr, "enqueue update %zu: %s\n", i,
				ao_strerror(rc));
			return 1;
		}
	}

	/*
	 * A non-blocking BGP socket would call flush() whenever EPOLLOUT is
	 * reported and retry on AO_EAGAIN. Short writes retain the suffix.
	 */
	rc = bgp_writer_flush(&writer, sink_write, &sink);
	if (rc != AO_OK) {
		fprintf(stderr, "update flush: %s\n", ao_strerror(rc));
		return 1;
	}

	/* Simulate observations from authenticated segments in both dirs. */
	ao_roll_observe_verified(&roll, &(ao_verify_result_t){
		.peer_key_id = 21,
		.peer_rnext_id = 11,
		.current_send_id = 11
	});
	ao_roll_observe_sent(&roll, 11, 21);
	ao_roll_note_messages_flushed(&roll, 3);

	printf("wrote %zu BGP update bytes; pending journal=%zu; phase=%d\n",
	       sink.len, bgp_journal_pending(journal), (int)roll.phase);
	printf("old key retirement %s; Linux TCP-AO adapter: %s\n",
	       ao_roll_can_retire_old(&roll) ? "safe" : "not safe yet",
	       ao_strerror(ao_linux_probe(-1)));

	bgp_journal_destroy(journal);
	return ao_roll_can_retire_old(&roll) ? 0 : 2;
}
