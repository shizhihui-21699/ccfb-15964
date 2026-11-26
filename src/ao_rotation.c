#include "tcp_ao.h"

#include <string.h>

static void update_phase(ao_roll_state_t *r);

int ao_roll_init(ao_roll_state_t *roll, const ao_roll_config_t *cfg)
{
	if (!roll || !cfg)
		return AO_EINVAL;
	if (cfg->old_send_id == cfg->new_send_id ||
	    cfg->old_recv_id == cfg->new_recv_id)
		return AO_EINVAL;
	memset(roll, 0, sizeof(*roll));
	roll->cfg = *cfg;
	roll->phase = AO_ROLL_STABLE;
	roll->drain_remaining = cfg->drain_messages;
	return AO_OK;
}

int ao_roll_stage_new(ao_roll_state_t *roll)
{
	if (!roll)
		return AO_EINVAL;
	if (roll->phase != AO_ROLL_STABLE &&
	    roll->phase != AO_ROLL_ROLLED_BACK)
		return AO_ESTATE;
	roll->phase = AO_ROLL_NEW_STAGED;
	return AO_OK;
}

int ao_roll_advertise_new(ao_roll_state_t *roll)
{
	if (!roll)
		return AO_EINVAL;
	if (roll->phase != AO_ROLL_NEW_STAGED &&
	    roll->phase != AO_ROLL_LOCAL_RNEXT_NEW &&
	    roll->phase != AO_ROLL_PEER_SWITCHED &&
	    roll->phase != AO_ROLL_LOCAL_CURRENT_NEW &&
	    roll->phase != AO_ROLL_ROLLED_BACK)
		return AO_ESTATE;
	roll->local_rnext_is_new = 1;
	update_phase(roll);
	return AO_OK;
}

static void update_phase(ao_roll_state_t *r)
{
	if (r->old_key_retired) {
		r->phase = AO_ROLL_DONE;
		return;
	}
	if (r->local_rnext_is_new && r->local_current_is_new &&
	    r->peer_sends_new && r->peer_requests_new) {
		if (r->phase < AO_ROLL_CONVERGED) {
			r->phase = AO_ROLL_DRAIN;
			r->drain_remaining = r->cfg.drain_messages;
		}
		if (r->drain_remaining == 0)
			r->phase = AO_ROLL_CONVERGED;
		else
			r->phase = AO_ROLL_DRAIN;
	} else if (r->local_current_is_new || r->peer_requests_new) {
		r->phase = AO_ROLL_LOCAL_CURRENT_NEW;
	} else if (r->peer_sends_new) {
		r->phase = AO_ROLL_PEER_SWITCHED;
	} else if (r->local_rnext_is_new) {
		r->phase = AO_ROLL_LOCAL_RNEXT_NEW;
	}
}

int ao_roll_observe_sent(ao_roll_state_t *roll, uint8_t key_id,
			  uint8_t rnext_id)
{
	if (!roll)
		return AO_EINVAL;
	roll->local_current_is_new = (key_id == roll->cfg.new_send_id);
	roll->local_rnext_is_new = (rnext_id == roll->cfg.new_recv_id);
	update_phase(roll);
	return AO_OK;
}

int ao_roll_observe_verified(ao_roll_state_t *roll,
			     const ao_verify_result_t *v)
{
	if (!roll || !v)
		return AO_EINVAL;

	if (v->peer_key_id == roll->cfg.new_recv_id) {
		roll->peer_sends_new = 1;
		roll->verified_new_segments++;
	} else if (v->peer_key_id == roll->cfg.old_recv_id) {
		roll->verified_old_segments++;
	}

	roll->peer_requests_new =
		(v->peer_rnext_id == roll->cfg.new_send_id);
	roll->local_current_is_new =
		(v->current_send_id == roll->cfg.new_send_id);
	update_phase(roll);
	return AO_OK;
}

int ao_roll_note_messages_flushed(ao_roll_state_t *roll, uint64_t count)
{
	if (!roll)
		return AO_EINVAL;
	if (count >= roll->drain_remaining)
		roll->drain_remaining = 0;
	else
		roll->drain_remaining -= count;
	update_phase(roll);
	return AO_OK;
}

int ao_roll_can_retire_old(const ao_roll_state_t *roll)
{
	if (!roll || roll->old_key_retired)
		return 0;
	return roll->local_rnext_is_new &&
	       roll->local_current_is_new &&
	       roll->peer_sends_new &&
	       roll->peer_requests_new &&
	       roll->drain_remaining == 0;
}

int ao_roll_retire_old(ao_roll_state_t *roll)
{
	if (!roll)
		return AO_EINVAL;
	if (!ao_roll_can_retire_old(roll))
		return AO_ESTATE;
	roll->old_key_retired = 1;
	roll->phase = AO_ROLL_DONE;
	return AO_OK;
}

int ao_roll_cancel_to_old(ao_roll_state_t *roll)
{
	if (!roll)
		return AO_EINVAL;
	roll->local_rnext_is_new = 0;
	roll->local_current_is_new = 0;
	roll->peer_requests_new = 0;
	/* peer_sends_new remains observational history but phase rolls back. */
	roll->phase = AO_ROLL_ROLLED_BACK;
	return AO_OK;
}
