/* SPDX-License-Identifier: BSD-2-Clause
 *
 * Session orchestration over the kernel TCP_AO adapter and the pure
 * rollover state machine.
 */
#include "tcpao/session.h"
#include "tcpao/kernel.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

uint64_t tcpao_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + ts.tv_nsec / 1000000u;
}

int tcpao_protect_listener(int lfd, const struct tcpao_keystore *ks,
			   const struct tcpao_md5_key *legacy,
			   size_t nlegacy, bool ao_required)
{
	for (size_t i = 0; i < ks->n; i++) {
		const struct tcpao_mkt *m = &ks->mkt[i];
		int rc = tcpao_kernel_add_key(lfd, m, false, false);
		if (rc)
			return rc;
	}
	for (size_t i = 0; i < nlegacy; i++) {
		int rc = tcpao_md5_listener_add(lfd, &legacy[i]);
		if (rc)
			return rc;
	}
	if (ao_required) {
		int rc = tcpao_kernel_set_required(lfd, true);
		if (rc)
			return rc;
	}
	return 0;
}

int tcpao_reconcile_accepted(int fd, const struct tcpao_keystore *ks,
			     const struct sockaddr *peer,
			     struct tcpao_session *sess)
{
	memset(sess, 0, sizeof(*sess));
	sess->fd = fd;
	sess->mode = TCPAO_PEER_AO;
	tcpao_roll_init(&sess->roll, NULL);

	/* Ensure every MKT covering this peer exists on the child socket.
	 * The kernel resolves lookups against the listener while a
	 * connection is in the accept queue, so a key added mid-handshake
	 * may be missing here; adding an existing key again fails with
	 * EEXIST, which we tolerate. */
	for (size_t i = 0; i < ks->n; i++) {
		const struct tcpao_mkt *m = &ks->mkt[i];
		int rc = tcpao_kernel_add_key(fd, m, false, false);
		if (rc && rc != -EEXIST)
			return rc;
	}

	struct tcpao_ao_info info;
	int rc = tcpao_kernel_get_info(fd, &info);
	if (rc)
		return rc;
	sess->cur_sndid = info.current_key;
	sess->cur_rcvid = info.rnext;
	sess->established = true;
	return 0;
}

int tcpao_protect_active(int fd, const struct tcpao_mkt *initial,
			 struct tcpao_session *sess)
{
	int rc = tcpao_kernel_add_key(fd, initial, true, true);
	if (rc)
		return rc;
	memset(sess, 0, sizeof(*sess));
	sess->fd = fd;
	sess->mode = TCPAO_PEER_AO;
	sess->cur_sndid = initial->sndid;
	sess->cur_rcvid = initial->rcvid;
	sess->established = false;
	tcpao_roll_init(&sess->roll, NULL);
	return 0;
}

int tcpao_rollover_step(struct tcpao_session *sess,
			const struct tcpao_roll_request *req)
{
	struct tcpao_rollover *r = &sess->roll;

	switch (r->phase) {
	case TCPAO_PHASE_STABLE: {
		int rc = tcpao_roll_begin(r, sess->cur_sndid, sess->cur_rcvid,
					  req->new_mkt.sndid,
					  req->new_mkt.rcvid, req->now_ms);
		if (rc)
			return rc;
		/* Step 1: install new MKT while old stays current. Incoming
		 * segments signed with either key now validate. */
		rc = tcpao_kernel_add_key(sess->fd, &req->new_mkt,
					  false, false);
		if (rc)
			goto abort_roll;
		/* Step 2: ask peer to switch its outgoing key. */
		rc = tcpao_kernel_set_pointers(sess->fd, -1,
					       req->new_mkt.rcvid);
		if (rc)
			goto abort_roll;
		return -EINPROGRESS;
	}

	case TCPAO_PHASE_PREPARED:
	case TCPAO_PHASE_SWITCHING:
	case TCPAO_PHASE_RETIRING: {
		struct tcpao_ao_info info;
		int rc = tcpao_kernel_get_info(sess->fd, &info);
		if (rc)
			return rc;
		rc = tcpao_roll_observe(r, &info, req->now_ms);
		if (rc == -ETIMEDOUT)
			goto abort_roll;
		if (rc)
			return rc;

		if (r->phase == TCPAO_PHASE_RETIRING) {
			/* Drain completed without a single failed segment:
			 * the old MKT can now leave the socket. Normal
			 * delete, not force-delete — kernel EBUSY would
			 * mean our state machine misjudged the drain. */
			struct tcpao_mkt victim = req->new_mkt;
			victim.sndid = r->old_sndid;
			victim.rcvid = r->old_rcvid;
			rc = tcpao_kernel_del_key(sess->fd, &victim);
			if (rc)
				return rc;
			rc = tcpao_roll_confirm_retired(r);
			if (rc)
				return rc;
			sess->cur_sndid = r->new_sndid;
			sess->cur_rcvid = r->new_rcvid;
			return 0;
		}
		return -EINPROGRESS;
	}
	}
	return -EINVAL;

abort_roll: {
	uint8_t keep_snd, keep_rcv;
	tcpao_roll_abort(r, &keep_snd, &keep_rcv);
	/* Best-effort cleanup of the half-installed new MKT. */
	struct tcpao_mkt victim = req->new_mkt;
	tcpao_kernel_del_key(sess->fd, &victim);
	tcpao_kernel_set_pointers(sess->fd, keep_snd, keep_rcv);
	return -ECONNABORTED;
}
}

int tcpao_session_info(const struct tcpao_session *sess,
		       struct tcpao_ao_info *out)
{
	return tcpao_kernel_get_info(sess->fd, out);
}

int tcpao_install_goodbye(int fd, const struct sockaddr *peer,
			  uint8_t sndid, uint8_t rcvid)
{
	struct tcpao_mkt mkt;
	memset(&mkt, 0, sizeof(mkt));
	size_t addrlen = peer->sa_family == AF_INET6 ?
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	memcpy(&mkt.peer, peer, addrlen);
	mkt.prefix = peer->sa_family == AF_INET6 ? 128 : 32;
	mkt.alg = TCPAO_ALG_HMAC_SHA1_96;
	mkt.sndid = sndid;
	mkt.rcvid = rcvid;
	mkt.maclen = 12;
	mkt.keylen = 0;	/* kernel: zero-length key == goodbye key */
	return tcpao_kernel_add_key(fd, &mkt, false, false);
}
