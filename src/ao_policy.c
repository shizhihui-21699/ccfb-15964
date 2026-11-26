#include "tcp_ao.h"

int ao_policy_validate(const ao_peer_policy_t *p)
{
	if (!p)
		return AO_EINVAL;
	if (p->mode == AO_MODE_MD5_ONLY || p->mode == AO_MODE_DUAL_LISTENER) {
		if (p->md5_key_len > AO_MAX_MASTER_KEY_LEN)
			return AO_EINVAL;
	}
	if (p->mode == AO_MODE_AO_ONLY || p->mode == AO_MODE_AUTO ||
	    p->mode == AO_MODE_DUAL_LISTENER) {
		if (p->ao.key_len != 0 &&
		    (p->ao.key_len > AO_MAX_MASTER_KEY_LEN ||
		     p->ao.send_id == p->ao.recv_id)) {
			/*
			 * SendID and RecvID may be equal by policy; only reject
			 * an actually invalid key length. Keep this explicit
			 * branch readable for integrators.
			 */
			if (p->ao.key_len > AO_MAX_MASTER_KEY_LEN)
				return AO_EINVAL;
		}
	}
	return AO_OK;
}

int ao_policy_use_ao_for_syn(const ao_peer_policy_t *policy,
			     int received_ao_option,
			     int received_md5_option)
{
	if (!policy)
		return AO_EINVAL;

	switch (policy->mode) {
	case AO_MODE_AO_ONLY:
		return received_ao_option ? 1 : AO_EVERIFY;
	case AO_MODE_MD5_ONLY:
		return received_md5_option ? 0 : AO_EVERIFY;
	case AO_MODE_AUTO:
	case AO_MODE_DUAL_LISTENER:
		/* Prefer AO when the peer proves it knows the KeyID. */
		if (received_ao_option)
			return 1;
		if (received_md5_option)
			return 0;
		/*
		 * Bare SYNs are normal on a listener before kernel option
		 * classification. The caller should keep the dual socket and
		 * let the first authenticated segment classify the peer.
		 */
		return AO_EAGAIN;
	}
	return AO_EINVAL;
}
