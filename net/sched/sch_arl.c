// SPDX-License-Identifier: GPL-2.0
/* Adaptive Rate Limiting Qdisc (ARL) is designed for home routers to eliminate
 * bufferbloat at upstream CPE (Cable/DSL) modem. It prevents bloated queue
 * from forming at upstream CPE modem by rate shaping the throughput to match
 * the available bandwidth. Instead of using a preconfigured static rate limit,
 * it automatically figures out the available bandwidth and adjust rate limit
 * in real time, by continuously monitoring latency passively.
 * The latency measurement come from two sources: one is the RTT from kernel’s
 * TCP/IP stacks, another is the half path RTT measured from routed TCP
 * streams. The minimum latency from all flows is used as the indication of
 * bufferbloat at upstream CPE modem, because that’s the common path for all
 * flows. ARL adjusts the rate limit dynamically based on the minimum latency.
 * If the throughput is less than available bandwidth, there will be no queue
 * buildup at CPE device, hence the minimum latency should stay flat. On the
 * other hand, a spike of minimum latency suggests there is bloated queue in
 * upstream CPE modem, indicating the current rate limit is over the available
 * bandwidth. In the case, ARL drains the queue and reduces rate limit.
 * ARL can be applied as root qdisc for WAN interface to prevent upstream
 * bufferbloat at the CPE modem. Queue is then managed locally at the
 * router, by applying another qdisc such as fq_codel as child qdisc.
 * In order to use ARL for downstream (ingress), an IFB device needs be created
 * and setup filter rule to redirect ingress traffic to the IFB device, then
 * apply ARL in ingress mode as the root qdisc for the IFB device
 *
 * The passive latency measurement method for routed TCP stream is inspired by:
 * Kathleen Nichols, "Listening to Networks",
 * http://netseminar.stanford.edu/seminars/02_02_17.pdf
 *
 * The rate shaping and some utility functions are from:
 * net/sched/sch_tbf.c
 * Author:	Kan Yan	<kyan@google.com>
 */

#include <linux/average.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/win_minmax.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/tcp.h>

#include "sch_arl.h"

#define ARL_SCALE	7	/* 128 Byte per second, approximately 1kbps */
#define ARL_BW_UNIT	BIT(7) /* 128 Byte per second, approximately 1kbps */

/* High gain to exponentially increase bw. Double the BW in 20 cycles */
static const int ARL_HIGH_GAIN = ARL_BW_UNIT * 1035 / 1000;
/* Drain gain: half the rate in two cycles */
static const int ARL_DRAIN_GAIN = ARL_BW_UNIT * 707 / 1000;

static bool arl_latency_sampling_enabled;
static int arl_dev_index = -1;

/* The rate for each phase is:
 * base_rate + rate_delta * arl_rate_tbl[state][phase]
 */
static const int arl_rate_tbl[][ARL_CYCLE_LEN] = {
			{0, 0, 0, 0},		/* STABLE */
			{-1, -1, -1, 0},	/* DRAIN */
			{1, 0, 1, 0},		/* BW_PROBE */
			{-1, -1, -1, 0},	/* LATENCY_PROBE */
			{0, 0, 0, 0},		/* UNTHROTTLED */
			};

static void arl_bw_estimate_reset(struct arl_sched_data *q)
{
	q->vars.bw_est_start_t = jiffies;
	q->vars.bw_est_bytes_sent = 0;
}

static void arl_update_bw_estimate(struct arl_sched_data *q)
{
	struct	arl_vars *vars = &q->vars;
	unsigned long now = jiffies, bw_avg;

	if (!time_after(now, (vars->bw_est_start_t
			+ msecs_to_jiffies(q->vars.phase_dur) - 1)))
		return;

	vars->last_bw_est = vars->bw_est;
	vars->bw_est = div_u64(vars->bw_est_bytes_sent * HZ,
			       (now - vars->bw_est_start_t)*1000);

	ewma_add(&vars->bw_avg, vars->bw_est);
	bw_avg = ewma_read(&vars->bw_avg);

	minmax_running_max(&vars->max_bw, msecs_to_jiffies(ARL_LT_WIN), now,
			   bw_avg);
	if (bw_avg > q->stats.max_bw)
		q->stats.max_bw = bw_avg;
	arl_bw_estimate_reset(q);
}

static bool arl_is_latency_high(struct arl_sched_data *q)
{
	u32 lt_min_hrtt, st_min_hrtt;

	/* return true only when there is recent latency measurement */
	if (time_after(jiffies, q->vars.last_latency_upd_t +
		       msecs_to_jiffies(q->vars.phase_dur * ARL_CYCLE_LEN * 2)))
		return false;

	lt_min_hrtt = minmax_get(&q->vars.lt_min_hrtt);
	st_min_hrtt = minmax_get(&q->vars.st_min_hrtt);

	/* consider latency is high if the short term smoothed latency is
	 * significantly (>latency_hysteresis) higher than
	 * max(ARL_LOW_LATENCY, lt_min_hrtt) or higher than the ARL parameter
	 * "max_latency".
	 */
	if ((st_min_hrtt < q->params.latency_hysteresis +
	    max_t(u32, ARL_LOW_LATENCY, lt_min_hrtt)) &&
	    minmax_get(&q->vars.min_hrtt) < q->params.max_latency)
		return false;
	else
		return true;
}

/* Check if the bandwidth is fully used.
 * Return true if the measured throughput is above ~92% or within 400 Kbits of
 * the configured rate.
 */
static bool arl_is_under_load(struct arl_sched_data *q)
{
	u32 rate = q->vars.current_rate;

	if (q->vars.bw_est > (rate - ((rate * 10) >> ARL_SCALE)) ||
	    q->vars.bw_est + 400 / 8 > rate)
		return true;
	else
		return false;
}

static bool arl_is_throttling(struct arl_sched_data *q)
{
	if (!q->qdisc)
		return false;

	/* consider ARL is throttling the traffic if it causes significant
	 * backlog (sojourn time > 1/2 CoDel target).
	 */
	return psched_l2t_ns(&q->vars.rate, q->qdisc->qstats.backlog) >
			     q->params.target * NSEC_PER_USEC / 2 ? 1 : 0;
}

/* Check if ARL should enter DRAIN state. Periodically DRAIN the queue helps
 * find the true minmium latency.
 */
static bool arl_check_drain(struct arl_sched_data *q)
{
	if (q->vars.state != ARL_LATENCY_PROBE && q->vars.state != ARL_STABLE)
		return false;

	/* No need to DRAIN if the latency is low */
	if (minmax_get(&q->vars.st_min_hrtt) < ARL_LOW_LATENCY)
		return false;

	/* No need to DRAIN unless it is under load */
	if (!arl_is_under_load(q))
		return false;

	/* For INGRESS mode, if ARL is throttling the traffic, it is already
	 * draining the queue, so no need to enter the DRAIN mode.
	 */
	if (q->params.mode == ARL_INGRESS && arl_is_throttling(q) &&
	    !arl_is_latency_high(q))
		return false;

	if (minmax_get(&q->vars.min_hrtt) > q->params.max_latency)
		return true;

	/* periodically enter DRAIN state for Egress mode if it is under load */
	if (ktime_ms_delta(q->vars.phase_start_t, q->vars.last_drain_t)
	     > ARL_DRAIN_INTERVAL)
		return true;
	else
		return false;
}

static void arl_apply_new_rate(struct arl_sched_data *q, u64 next_rate)
{
	u32	buffer;

	next_rate *= 1000;
	psched_ratecfg_precompute(&q->vars.rate, &q->vars.cfg_rate, next_rate);
	/* The buffer is burst size in ns, ensure it is large enough to
	 * transmit a max_size packet.
	 */
	buffer = psched_l2t_ns(&q->vars.rate, q->params.max_size);
	q->vars.buffer = max(buffer, q->params.buffer);
}

static void arl_change_state(struct arl_sched_data *q, int new_state)
{
	struct arl_vars *vars = &q->vars;
	u64	next_rate;
	u32	bw, dur_min, dur_max;

	vars->phase = 0;
	vars->cycle_cnt = 0;
	vars->phase_start_t = ktime_get();
	vars->state_start_t = jiffies;
	vars->latency_trend = 0;
	vars->rate_factor = ARL_BW_UNIT;

	if (q->params.mode == ARL_INGRESS) {
		dur_min = ARL_INGRESS_PHASE_DUR_MIN;
		dur_max = ARL_INGRESS_PHASE_DUR_MAX;
	} else {
		dur_min = ARL_PHASE_DUR_MIN;
		dur_max = ARL_PHASE_DUR_MAX;
	}

	vars->phase_dur = clamp((u32)(2 * minmax_get(&vars->st_min_hrtt)
				/ USEC_PER_MSEC), dur_min, dur_max);

	if (vars->state == new_state)
		return;

	/* observed available bandwidth at the end of previous state */
	bw = max_t(u32, ewma_read(&vars->bw_avg), vars->bw_est);

	if (vars->state == ARL_DRAIN || new_state == ARL_LATENCY_PROBE) {
		/* Leaving drain state or enter LATENCY_PROBE, restore bw to
		 * the last stable measurement of bw.
		 */
		bw = vars->last_stable_base_rate;
		if (arl_is_latency_high(q))
			vars->next_bw_probe_t = jiffies +
						msecs_to_jiffies(120 *
								 MSEC_PER_SEC);
	} else if (vars->state == ARL_BW_PROBE) {
		/* Use the bw from previous cycle to avoid overshot */
		bw = max_t(u32, ewma_read(&vars->bw_avg),
			   vars->last_bw_est);
	} else if (q->params.mode == ARL_EGRESS) {
		/* For egress mode, reduce BW to offset the overshot due to
		 * increased BW when exit UNTHROTTLED state.
		 * It is not needed for ingress mode as the measured BW should
		 * be the actual available bandwidth.
		 */
		if (vars->state == ARL_UNTHROTTLED) {
			bw -= (bw >> ARL_SCALE) * 5;
			bw = min_t(u32, bw, vars->base_rate * 2);
		} else {
			bw = min_t(u32, bw, vars->base_rate);
			if (arl_is_latency_high(q) ||
			    time_after(jiffies, vars->last_latency_upd_t +
				       msecs_to_jiffies(ARL_MT_WIN)))
				bw -= (bw >> ARL_SCALE) * 2;
		}
	}
	/* adjust for overshot */
	bw -= (2 * bw >> ARL_SCALE);

	/* New base rate for next state */
	if (new_state != ARL_DRAIN && new_state != ARL_LATENCY_PROBE)
		vars->base_rate = max(bw, vars->base_rate);
	vars->last_stable_base_rate = bw;

	/* set rate for next cycle */
	vars->target_rate = vars->base_rate;
	switch (new_state) {
	case  ARL_DRAIN:
		vars->last_drain_t = ktime_get();
		vars->phase_dur = minmax_get(&vars->st_min_hrtt) /
					     USEC_PER_MSEC;
		vars->phase_dur = clamp(vars->phase_dur, ARL_DRAIN_DUR_MIN,
					ARL_DRAIN_DUR_MAX);

		vars->target_rate -= 5 * (vars->base_rate >> ARL_SCALE);
		if (arl_is_latency_high(q)) {
			/* If latency is high, reduce the base rate to ~70%. so
			 * a [-1, -1, -1, 0] cycle could eliminate ~90% of RTT
			 * worth of queueing latency.
			 */
			vars->target_rate = (vars->base_rate *
					     ARL_DRAIN_GAIN >> ARL_SCALE);
			vars->base_rate -= 3 * (vars->base_rate >> ARL_SCALE);
		}
		break;

	case ARL_BW_PROBE:
		vars->target_rate = (vars->base_rate * ARL_HIGH_GAIN
				     >> ARL_SCALE);
		break;

	case ARL_LATENCY_PROBE:
		vars->base_rate -= (vars->base_rate >> ARL_SCALE);
		vars->target_rate -= 5 * (vars->base_rate  >> ARL_SCALE);
		break;

	default:
		break;
	}

	vars->base_rate = max_t(u32, vars->base_rate, q->params.min_rate);
	vars->current_rate = vars->base_rate;
	vars->rate_delta = abs(vars->target_rate - vars->base_rate);

	vars->last_min_hrtt = minmax_get(&vars->st_min_hrtt);
	vars->min_hrtt_last_cycle = vars->last_min_hrtt;
	vars->state = new_state;

	next_rate = vars->rate_delta * arl_rate_tbl[vars->state][vars->phase]
		    + vars->current_rate;
	arl_apply_new_rate(q, next_rate);
	arl_bw_estimate_reset(q);
}

static void arl_update_phase(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct arl_vars *vars = &q->vars;
	u64	next_rate;
	int	latency;
	u32	bw_avg;
	bool	is_under_load, is_latency_high, is_latency_current,
		is_throttling;

	is_under_load = arl_is_under_load(q);
	is_throttling = arl_is_throttling(q);

	/* Is latency high compared to long term minimum? */
	is_latency_high = arl_is_latency_high(q);

	is_latency_current = !time_after(jiffies, vars->last_latency_upd_t +
					 msecs_to_jiffies(vars->phase_dur *
					 ARL_CYCLE_LEN * 2));

	if (arl_check_drain(q)) {
		arl_change_state(q, ARL_DRAIN);
		return;
	}

	vars->phase = (vars->phase == (ARL_CYCLE_LEN - 1)) ? 0 :
		       vars->phase + 1;
	vars->phase_start_t = ktime_get();

	next_rate = vars->rate_delta * arl_rate_tbl[vars->state][vars->phase]
		    + vars->current_rate;
	arl_apply_new_rate(q, next_rate);

	latency = minmax_get(&vars->st_min_hrtt);

	/* Update the latency_trend at the end of each phase for egress mode */
	if (q->params.mode == ARL_EGRESS) {
		if (!time_after(jiffies, vars->last_latency_upd_t +
				msecs_to_jiffies(q->vars.phase_dur))) {
			if (latency + q->params.latency_hysteresis / 2 <
			    min(vars->min_hrtt_last_cycle, vars->last_min_hrtt))
				vars->latency_trend--;
			else if (latency > q->params.latency_hysteresis / 2 +
			    min(vars->min_hrtt_last_cycle, vars->last_min_hrtt))
				vars->latency_trend++;
		}
	} else if (vars->phase == 0) {
		/* For ingress mode latency_trend indicates latency has been
		 * high for how many consective cycles.
		 */
		if (is_latency_high)
			vars->latency_trend++;
		else
			vars->latency_trend--;
	}

	if (latency < ARL_LOW_LATENCY || vars->latency_trend < 0)
		vars->latency_trend = 0;

	/* Update state for next cycle */
	if (vars->phase != 0)
		return;

	arl_update_bw_estimate(q);
	bw_avg = ewma_read(&vars->bw_avg);

	/* If there is no recent latency, stop adjusting rates for Egress mode.
	 * For ingress mode, the BW is still get updated based on the current
	 * measurement of incoming data rate.
	 */
	if ((time_after(jiffies, vars->last_latency_upd_t +
			msecs_to_jiffies(ARL_MT_WIN))) &&
	    q->params.mode == ARL_EGRESS) {
		if (vars->state != ARL_STABLE)
			arl_change_state(q, ARL_STABLE);
		return;
	}

	if ((minmax_get(&q->vars.max_bw) > q->params.max_bw) &&
	    !is_latency_high) {
		/* The available BW is too high to worry about bufferbloat.
		 * so detach the rate limiter to avoid overhead.
		 */
		arl_change_state(q, ARL_UNTHROTTLED);
		return;
	}

	switch (vars->state) {
	case ARL_STABLE:
		if (vars->bw_est < q->params.min_rate && !is_under_load) {
			arl_change_state(q, ARL_IDLE);
			return;
		}

		if (q->params.mode == ARL_EGRESS) {
			/* Exit stable state if latency increases under load */
			if (is_latency_high) {
				/* Defer a few cycles before trying to reduce
				 * the rate. It may be just a short glitch or
				 * the bloated queue happened in the other
				 * direction.
				 */
				if (is_under_load || vars->cycle_cnt > 3) {
					arl_change_state(q, ARL_LATENCY_PROBE);
					return;
				}
			} else if (is_under_load) {
				if (vars->latency_trend == 0 &&
				    vars->cycle_cnt > 5 &&
				    time_after(jiffies,
					       vars->next_bw_probe_t)) {
					arl_change_state(q, ARL_BW_PROBE);
					return;
				}
			} else {
				vars->cycle_cnt = 0;
			}
			break;
		}

		// INGRESS mode
		if (is_latency_high) {
			if (vars->latency_trend > 1) {
				arl_change_state(q, ARL_LATENCY_PROBE);
				return;
			}
			break;
		}

		/* If the ingress queue is building up when the latency
		 * increases, then it operates in the right direction. CoDel
		 * will do its work to shrink the queue. Otherwise, the current
		 * rate is too high and need be reduced.
		 */
		if (!is_throttling) {
			vars->last_drain_t = ktime_get();
			vars->cycle_cnt = 0;
			break;
		}
		if (vars->latency_trend > 0 || !is_latency_current)
			break;
		/* Latency is low and the ingress queue is building up, the rate
		 * can be increased to the bw observed.
		 */
		if (vars->cycle_cnt > 5 && bw_avg > vars->base_rate -
		    2 * (vars->base_rate >> ARL_SCALE) &&
		    time_after(jiffies, vars->next_bw_probe_t)) {
			arl_change_state(q, ARL_BW_PROBE);
			return;
		}
		bw_avg -= 2 * (bw_avg >> ARL_SCALE);
		vars->current_rate = max_t(u32, vars->current_rate, bw_avg);
		break;

	case ARL_BW_PROBE:
		if (q->params.mode == ARL_EGRESS) {
			/* Exit BW probe state if latency is increasing */
			if (is_latency_high || vars->latency_trend > 2) {
				arl_change_state(q, ARL_LATENCY_PROBE);
				return;
			}

			/* Exit to stable state if the traffic is light */
			if (!is_throttling || vars->latency_trend >= 1) {
				arl_change_state(q, ARL_STABLE);
				return;
			}

			/* If BW has increased signficantly (>30%)
			 * without latency increase, switch to UNTHROTTLED state
			 * to figure out the available BW quickly.
			 */
			if (vars->cycle_cnt > 9) {
				if (vars->bw_est >
				    vars->base_rate * 130 / 100) {
					arl_change_state(q, ARL_UNTHROTTLED);
					return;
				}
			}
		} else {
			if (vars->latency_trend > 0) {
				arl_change_state(q, ARL_LATENCY_PROBE);
				return;
			}

			if (!is_throttling || !is_latency_current) {
				/* For ingress, exit to stable state if not
				 * throttling the traffic and lost latency
				 * measurement.
				 */
				arl_change_state(q, ARL_STABLE);
				return;
			}
		}

		/* Update probe rate every 3 cycles */
		if (vars->cycle_cnt % 3 == 2) {
			/* Go to stable state if the measured bw stops
			 * increasing
			 */
			if (vars->bw_est < vars->base_rate) {
				arl_change_state(q, ARL_STABLE);
				return;
			}
			vars->current_rate = max_t(u32, vars->current_rate,
						   bw_avg);
			vars->target_rate = vars->current_rate;

			/* Pause the rate_delta increase for one in every 3
			 * cycles to observe the latency change. There could
			 * be some lags between rate change and latency change.
			 */
			vars->rate_factor = ARL_BW_UNIT;
			/* For ingress mode, stop increase rate for every cycles
			 * and only increase rate based on observed bandwidth
			 * increase.
			 */
			vars->rate_delta = 0;
		} else {
			/* Switch to high gain if latency is stable. */
			vars->rate_factor = ARL_HIGH_GAIN;
		}

		/* Ingress Mode, the rate is updated every cycle to the
		 * observed bandwidth.
		 */
		if (q->params.mode == ARL_INGRESS) {
			vars->current_rate = max(vars->current_rate,
						 vars->bw_est);
		} else {
			/* update rate for next cycle */
			vars->target_rate = max_t(u32, vars->target_rate,
						  vars->current_rate);
			vars->target_rate = vars->target_rate *
						vars->rate_factor >> ARL_SCALE;
			vars->rate_delta = vars->target_rate + 1 -
					   vars->current_rate;
			vars->rate_delta = min_t(u32, vars->rate_delta,
						 vars->base_rate / 10);
		}
		break;

	case ARL_LATENCY_PROBE:
		if (!is_latency_high || vars->bw_est < q->params.min_rate) {
			/* If latency is no longer high or cannot be further
			 * reduced, go back to stable state.
			 */
			if (is_under_load)
				vars->base_rate -= (vars->base_rate >>
						    ARL_SCALE);
			arl_change_state(q, ARL_STABLE);
			return;
		}

		/* If it is not just short term minor latency increases,
		 * then the pervious minor adjustment of rate is not sufficient.
		 * The base_rate is likely exceed the available bandwidth, goto
		 * DRAIN state.
		 */
		if (vars->bw_est > q->params.min_rate && is_latency_current &&
		    (minmax_get(&q->vars.st_min_hrtt) > q->params.max_latency &&
		     vars->cycle_cnt > 2)) {
			vars->base_rate -= 3 * (vars->base_rate >> ARL_SCALE);
			arl_change_state(q, ARL_DRAIN);
			return;
		}

		/* update rate for next cycle */
		if (vars->latency_trend >= 0 || is_latency_high)
			vars->rate_factor = ARL_DRAIN_GAIN;
		else
			vars->rate_factor = ARL_BW_UNIT;

		vars->target_rate = vars->target_rate *
					vars->rate_factor >> ARL_SCALE;
		vars->current_rate = clamp(vars->last_stable_base_rate,
					   vars->target_rate, vars->base_rate);
		break;

	case ARL_DRAIN:
		if (!is_latency_high) {
			arl_change_state(q, ARL_STABLE);
			return;
		}
		vars->current_rate -= 5 * (vars->base_rate >> ARL_SCALE);
		if (vars->last_stable_base_rate < vars->base_rate)
			vars->base_rate = max(vars->last_stable_base_rate,
					      vars->current_rate);
		arl_change_state(q, ARL_LATENCY_PROBE);
		return;

	case ARL_UNTHROTTLED:
		if (minmax_get(&vars->max_bw) > q->params.max_bw ||
		    vars->bw_est < q->params.min_rate)
			break;

		if (is_latency_high || vars->latency_trend > 1 ||
		    !is_latency_current || vars->cycle_cnt > 10 ||
		    vars->bw_est > vars->base_rate * 2) {
			arl_change_state(q, ARL_STABLE);
			return;
		}
		break;

	case ARL_IDLE:
		if (vars->bw_est > q->params.min_rate || is_under_load) {
			arl_change_state(q, ARL_STABLE);
			return;
		}
		/* Restore the default rate when it has been idle for 20
		 * minutes.
		 */
		if (time_after(jiffies, vars->state_start_t + 20 * 60 * HZ)) {
			if (vars->base_rate < q->params.rate)
				vars->base_rate = q->params.rate;
			arl_change_state(q, ARL_IDLE);
		}
		break;
	}

	/* state unchanged */
	vars->cycle_cnt++;
	vars->min_hrtt_last_cycle = minmax_get(&vars->st_min_hrtt);
	if (q->params.mode == ARL_EGRESS)
		vars->latency_trend = 0;
	if (vars->base_rate < q->stats.min_rate || q->stats.min_rate == 0)
		q->stats.min_rate = vars->base_rate;
	next_rate = vars->rate_delta * arl_rate_tbl[vars->state][vars->phase]
		    + vars->current_rate;
	arl_apply_new_rate(q, next_rate);
}

static void arl_update(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	if (ktime_ms_delta(ktime_get(), q->vars.phase_start_t) <
	    q->vars.phase_dur)
		return;

	arl_update_phase(sch);
}

static void arl_params_init(struct arl_params *params)
{
	params->max_size = 1600;
	params->buffer = ARL_BUFFER_SIZE_DEFAULT * NSEC_PER_USEC;
	params->max_bw = ARL_MAX_BW_DEFAULT;
	params->min_rate = ARL_MIN_RATE_DEFAULT;
	params->limit = 1000;
	params->max_latency = ARL_MAX_LATENCY_DEFAULT;
	params->latency_hysteresis = ARL_LAT_HYSTERESIS_DEFAULT;
	params->mode = ARL_EGRESS;
	params->target = 10000;
}

static void arl_vars_init(struct arl_sched_data *q)
{
	struct arl_vars *vars = &q->vars;

	vars->ts = ktime_get_ns();
	vars->last_drain_t = ktime_get();
	minmax_reset(&vars->lt_min_hrtt, jiffies, 5 * MSEC_PER_SEC);
	minmax_reset(&vars->st_min_hrtt, jiffies, 5 * MSEC_PER_SEC);
	minmax_reset(&vars->max_bw, jiffies, 0);
	ewma_init(&vars->bw_avg, 8, 8);
	vars->cfg_rate.linklayer = TC_LINKLAYER_ETHERNET;
	vars->base_rate = q->params.rate;
	vars->current_rate = vars->base_rate;
	vars->target_rate = vars->base_rate;
	vars->tokens = q->params.buffer;
	vars->buffer = q->params.buffer;
	vars->next_bw_probe_t = jiffies;
	vars->last_latency_upd_t = jiffies;
	arl_bw_estimate_reset(q);
	arl_change_state(q, ARL_BW_PROBE);
}

static void arl_update_latency_ct(struct arl_sched_data *q,
				  struct  tcp_latency_sample *lat, u32 latency)
{
	u32 s_hrtt, duration, s_hrtt_last = lat->s_hrtt_us;

	if (latency > ARL_LATENCY_SAMPLE_TIMEOUT_US)
		return;

	if (s_hrtt_last > ARL_LATENCY_SAMPLE_TIMEOUT_US)
		s_hrtt_last = latency;

	/* s_hrtt_us = 3/4 old s_hrtt_us + 1/4 new sample */
	if (s_hrtt_last)
		s_hrtt = s_hrtt_last * 4 + latency - s_hrtt_last;
	else
		s_hrtt = latency * 4;

	s_hrtt = s_hrtt / 4;
	if (s_hrtt > ARL_LATENCY_SAMPLE_TIMEOUT_US)
		s_hrtt = latency;
	lat->s_hrtt_us = s_hrtt;

	/* Ingess mode (downstream traffic) has fewer latency samples */
	if (q->params.mode == ARL_INGRESS)
		duration = q->vars.phase_dur * 4;
	else
		duration = q->vars.phase_dur;

	minmax_running_min(&q->vars.st_min_hrtt, msecs_to_jiffies(duration),
			   jiffies, latency);
	minmax_running_min(&q->vars.min_hrtt, msecs_to_jiffies(ARL_MT_WIN),
			   jiffies, s_hrtt);
	minmax_running_min(&q->vars.lt_min_hrtt, msecs_to_jiffies(ARL_LT_WIN),
			   jiffies, s_hrtt);
	q->vars.last_latency_upd_t = jiffies;
}

static void arl_update_latency(struct arl_sched_data *q, u32 latency)
{
	u32 duration;

	/* Ingess mode (downstream traffic) has fewer latency samples */
	if (q->params.mode == ARL_INGRESS)
		duration = q->vars.phase_dur * 4;
	else
		duration = q->vars.phase_dur;

	minmax_running_min(&q->vars.st_min_hrtt,
			   (msecs_to_jiffies(duration)), jiffies,
			   latency);
	minmax_running_min(&q->vars.min_hrtt, msecs_to_jiffies(ARL_MT_WIN),
			   jiffies, latency);
	minmax_running_min(&q->vars.lt_min_hrtt, msecs_to_jiffies(ARL_LT_WIN),
			   jiffies, latency);
	q->vars.last_latency_upd_t = jiffies;
}

/* Latency measurement related utilities.
 * There are two sources of the latency measurement:
 * 1) Kernel's RTT measurement for TCP sockets bound to the qdisc's interface.
 * 2) The half path RTT measured by ARL for routed TCP sessions. The half path
 * measured is from router-> internet -> ACKs back to the router.
 *
 * To measure the half path RTT for routed TCP sessions:
 * For each routed TCP flow, one egress packet is sampled for latency
 * measurement. The sequence number extracted from the TCP header and the
 * dequeue time are stored in the TCP stream's conntrack entry. The latency is
 * measured as from the time of the packet is dequeued at egress path to the
 * time the TCP ACK for that segment is received at ingress path.
 */
static void arl_egress_mark_pkt(struct sk_buff *skb, u32 seq,
				struct nf_conn *ct)
{
	struct tcp_latency_sample *tcp_lat;
	ktime_t	now;

	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);

	tcp_lat = &ct->proto.tcp.latency_sample;

	now = ktime_get();
	tcp_lat->send_ts = now.tv64;
	tcp_lat->last_seq = seq;
	tcp_lat->last_hrtt = 0;
}

static struct tcphdr *arl_get_tcp_header_ipv4(struct sk_buff *skb,
					      void *buffer)
{
	const struct iphdr *iph;
	struct tcphdr *tcph;
	u32 tcph_offset;

	if (unlikely(!pskb_may_pull(skb, sizeof(*iph))))
		return NULL;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NULL;

	tcph_offset = skb_network_offset(skb) + iph->ihl * 4;
	if (tcph_offset > skb->len)
		return NULL;

	tcph = skb_header_pointer(skb, tcph_offset, sizeof(struct tcphdr),
				  buffer);
	return tcph;
}

static struct tcphdr *arl_get_tcp_header_ipv6(struct sk_buff *skb,
					      void *buffer)
{
	const struct ipv6hdr *ipv6h;
	struct tcphdr *tcphdr;
	u8 proto;
	__be16 frag_off;
	int tcphoff;

	if (unlikely(!pskb_may_pull(skb, sizeof(*ipv6h))))
		return NULL;

	ipv6h = ipv6_hdr(skb);
	if (ipv6h->version != 6)
		return NULL;

	if (ipv6_addr_is_multicast(&ipv6h->daddr) ||
	    ipv6_addr_is_multicast(&ipv6h->saddr))
		return NULL;

	proto = ipv6h->nexthdr;
	tcphoff = ipv6_skip_exthdr(skb, skb_network_offset(skb) +
				   sizeof(*ipv6h), &proto, &frag_off);

	if (tcphoff < 0 || proto != IPPROTO_TCP ||
	    ((tcphoff + sizeof(struct tcphdr)) > skb->len))
		return NULL;

	tcphdr = skb_header_pointer(skb, tcphoff, sizeof(struct tcphdr),
				    buffer);
	return tcphdr;
}

/* Find the conntrack entry for packet that takes the shortcut path and has no
 * ct entry set in its skb.
 */
static struct nf_conn *arl_egress_find_ct_v4(struct sk_buff *skb,
					     struct tcphdr *tcph)
{
	struct iphdr *iph;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct = NULL;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));

	iph = ip_hdr(skb);
	tuple.dst.protonum = iph->protocol;

	/* The routed packet is transfromed by NAPT, so use the CT entry from
	 * the reverse direction.
	 */
	tuple.dst.dir = IP_CT_DIR_REPLY;
	tuple.src.u3.ip = iph->daddr;
	tuple.dst.u3.ip = iph->saddr;
	tuple.src.l3num = AF_INET;

	tuple.src.u.tcp.port = tcph->dest;
	tuple.dst.u.tcp.port = tcph->source;

	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h))
		return ct;

	ct = nf_ct_tuplehash_to_ctrack(h);
	return ct;
}

static struct nf_conn *arl_egress_find_ct_v6(struct sk_buff *skb,
					     struct tcphdr *tcph)
{
	struct ipv6hdr *ipv6h;
	struct nf_conntrack_tuple_hash *h;
	struct nf_conntrack_tuple tuple;
	struct nf_conn *ct = NULL;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));
	tuple.dst.dir = IP_CT_DIR_REPLY;
	tuple.dst.protonum = IPPROTO_TCP;

	ipv6h = ipv6_hdr(skb);
	tuple.src.u3.in6 = ipv6h->daddr;
	tuple.dst.u3.in6 = ipv6h->saddr;
	tuple.src.l3num = AF_INET6;

	tuple.dst.u.tcp.port = tcph->source;
	tuple.src.u.tcp.port = tcph->dest;

	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h))
		return ct;

	ct = nf_ct_tuplehash_to_ctrack(h);
	return ct;
}

static void arl_sample_latency_egress(struct arl_sched_data *q,
				      struct sk_buff *skb)
{
	struct tcphdr *tcph, tcphdr;
	struct nf_conn *ct;
	struct tcp_latency_sample *tcp_lat;
	u32 latency_sampling;
	u32 latency = 0;

	if (!arl_latency_sampling_enabled)
		return;

	/* skip small packets */
	if (!skb || skb->len < 54)
		return;

	/* Skip bc/mc packets. */
	if (unlikely(skb->pkt_type == PACKET_BROADCAST ||
		     skb->pkt_type == PACKET_MULTICAST))
		return;

	/* Only process TCP packets */
	if (likely(htons(ETH_P_IP) == skb->protocol)) {
		tcph = arl_get_tcp_header_ipv4(skb, &tcphdr);
		if (!tcph)
			return;
		ct = arl_egress_find_ct_v4(skb, tcph);
	} else if (likely(htons(ETH_P_IPV6) == skb->protocol)) {
		tcph = arl_get_tcp_header_ipv6(skb, &tcphdr);
		if (!tcph)
			return;
		ct = arl_egress_find_ct_v6(skb, tcph);
	} else {
		return;
	}

	if (unlikely(!ct))
		return;

	/* Skip untracked connections. */
	if (unlikely(nf_ct_is_untracked(ct)))
		goto exit;

	if (!nf_ct_is_confirmed(ct))
		goto exit;

	tcp_lat = &ct->proto.tcp.latency_sample;
	latency_sampling = atomic_read(&tcp_lat->sampling_state);

	if (unlikely(latency_sampling == ARL_SAMPLE_STATE_DONE)) {
		latency = tcp_lat->last_hrtt;

		if (atomic_cmpxchg(&tcp_lat->sampling_state,
				   ARL_SAMPLE_STATE_DONE,
				   ARL_SAMPLE_STATE_UPDATING)
		    != ARL_SAMPLE_STATE_DONE)
			goto exit;
		if (latency) {
			tcp_lat->last_hrtt = 0;
			arl_update_latency_ct(q, tcp_lat, latency);
		}
		atomic_set(&tcp_lat->sampling_state,
			   ARL_SAMPLE_STATE_IDLE);
	} else if (latency_sampling == ARL_SAMPLE_STATE_SAMPLING) {
		ktime_t	send_ts;

		send_ts.tv64 = tcp_lat->send_ts;
		if (ktime_us_delta(ktime_get(), send_ts) <
		    ARL_LATENCY_SAMPLE_TIMEOUT_US)
			goto exit;

		if (atomic_cmpxchg(&tcp_lat->sampling_state,
				   ARL_SAMPLE_STATE_SAMPLING,
				   ARL_SAMPLE_STATE_IDLE) !=
		    ARL_SAMPLE_STATE_SAMPLING)
			goto exit;
	} else if (latency_sampling > ARL_SAMPLE_STATE_IDLE) {
		goto exit;
	}

	/* Check if it should start sampling for latency again */
	if (ntohl(tcph->seq) == tcp_lat->last_seq)
		goto exit;

	if (atomic_cmpxchg(&tcp_lat->sampling_state, ARL_SAMPLE_STATE_IDLE,
			   ARL_SAMPLE_STATE_UPDATING) != ARL_SAMPLE_STATE_IDLE)
		goto exit;

	arl_egress_mark_pkt(skb, ntohl(tcph->seq), ct);
	atomic_set(&tcp_lat->sampling_state,
		   ARL_SAMPLE_STATE_SAMPLING);

exit:
	nf_ct_put(ct);
}

/* Extract half path round trip time measured from routed TCP packets.
 * Return 0 if successful, return -1 otherwise.
 */
static int arl_update_hrtt(struct arl_sched_data *q, struct sk_buff *skb,
			   u32 ack_seq,
			   struct tcp_latency_sample *tcp_lat)
{
	s64	time_delta;
	ktime_t	sent_ts;

	if (ack_seq < tcp_lat->last_seq)
		return -1;

	sent_ts.tv64 = tcp_lat->send_ts;
	time_delta = ktime_us_delta(ktime_get(), sent_ts);
	if (time_delta > ARL_LATENCY_SAMPLE_TIMEOUT_US) {
		atomic_set(&tcp_lat->sampling_state,
			   ARL_SAMPLE_STATE_IDLE);
		return -1;
	}

	if (atomic_cmpxchg(&tcp_lat->sampling_state,
			   ARL_SAMPLE_STATE_SAMPLING,
			   ARL_SAMPLE_STATE_UPDATING) !=
	    ARL_SAMPLE_STATE_SAMPLING)
		return -1;

	tcp_lat->last_hrtt = time_delta;
	arl_update_latency_ct(q, tcp_lat, time_delta);
	atomic_set(&tcp_lat->sampling_state,
		   ARL_SAMPLE_STATE_DONE);
	return 0;
}

static void arl_sample_latency_ingress_v4(struct arl_sched_data *q,
					  struct sk_buff *skb,
					  struct tcphdr *tcph)
{
	struct nf_conn *ct;
	struct nf_conntrack_tuple tuple;
	struct iphdr *iph;
	struct nf_conntrack_tuple_hash *h;
	struct tcp_latency_sample *tcp_lat;

	if (!skb || !skb->dev)
		return;

	if (!arl_latency_sampling_enabled)
		return;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));
	tuple.dst.dir = IP_CT_DIR_REPLY;
	tuple.dst.protonum = IPPROTO_TCP;

	iph = ip_hdr(skb);
	tuple.src.u3.ip = iph->saddr;
	tuple.dst.u3.ip = iph->daddr;
	tuple.src.l3num = AF_INET;

	tuple.dst.u.tcp.port = tcph->dest;
	tuple.src.u.tcp.port = tcph->source;
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h))
		return;

	ct = nf_ct_tuplehash_to_ctrack(h);
	if (!ct)
		goto exit;

	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);

	tcp_lat = &ct->proto.tcp.latency_sample;
	if (atomic_read(&tcp_lat->sampling_state) != ARL_SAMPLE_STATE_SAMPLING)
		goto exit;

	if (arl_update_hrtt(q, skb, ntohl(tcph->ack_seq), tcp_lat))
		goto exit;

exit:
	nf_ct_put(ct);
}

static void arl_sample_latency_ingress_v6(struct arl_sched_data *q,
					  struct sk_buff *skb,
					  struct tcphdr *tcph)
{
	struct nf_conn *ct;
	struct nf_conntrack_tuple tuple;
	struct ipv6hdr *ipv6h;
	struct nf_conntrack_tuple_hash *h;
	struct tcp_latency_sample *tcp_lat;

	if (!skb || !skb->dev)
		return;

	if (!arl_latency_sampling_enabled)
		return;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));
	tuple.dst.dir = IP_CT_DIR_REPLY;
	tuple.dst.protonum = IPPROTO_TCP;

	ipv6h = ipv6_hdr(skb);
	tuple.src.u3.in6 = ipv6h->saddr;
	tuple.dst.u3.in6 = ipv6h->daddr;
	tuple.src.l3num = AF_INET6;

	tuple.dst.u.tcp.port = tcph->dest;
	tuple.src.u.tcp.port = tcph->source;
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
	if (unlikely(!h))
		return;

	ct = nf_ct_tuplehash_to_ctrack(h);
	if (!ct)
		goto exit;

	NF_CT_ASSERT(ct->timeout.data == (unsigned long)ct);

	tcp_lat = &ct->proto.tcp.latency_sample;
	if (atomic_read(&tcp_lat->sampling_state) != ARL_SAMPLE_STATE_SAMPLING)
		goto exit;

	if (arl_update_hrtt(q, skb, ntohl(tcph->ack_seq), tcp_lat))
		goto exit;

exit:
	nf_ct_put(ct);
}

static void arl_sample_latency_ingress(struct arl_sched_data *q,
				       struct sk_buff *skb)
{
	struct tcphdr *tcph, tcphdr;

	if (htons(ETH_P_IP) == skb->protocol) {
		tcph = arl_get_tcp_header_ipv4(skb, &tcphdr);
		if (!tcph)
			return;
		arl_sample_latency_ingress_v4(q, skb, tcph);
	} else if (htons(ETH_P_IPV6) == skb->protocol) {
		tcph = arl_get_tcp_header_ipv6(skb, &tcphdr);
		if (!tcph)
			return;
		arl_sample_latency_ingress_v6(q, skb, tcph);
	}
}

static void arl_dequeue_update(struct Qdisc *sch, struct sk_buff *skb)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	qdisc_qstats_backlog_dec(sch, skb);
	if (WARN_ONCE(sch->qstats.backlog > INT_MAX,
		      "backlog underflow %d %d\n", sch->qstats.backlog,
		      qdisc_pkt_len(skb)))
		sch->qstats.backlog = 0;
	sch->q.qlen--;
	qdisc_bstats_update(sch, skb);

	if (q->params.mode != ARL_EGRESS)
		return;

	q->vars.bw_est_bytes_sent += qdisc_pkt_len(skb);
	arl_sample_latency_egress(q, skb);
}

static void arl_enqueue_update(struct Qdisc *sch, unsigned int len)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	sch->qstats.backlog += len;
	sch->q.qlen++;

	if (q->params.mode != ARL_INGRESS)
		return;

	q->vars.bw_est_bytes_sent += len;
}

/* GSO packets maybe too big and takes more than maxmium tokens to transmit.
 * Segment the GSO packets that is larger than max_size.
 */

static int gso_segment(struct sk_buff *skb, struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct sk_buff *segs, *nskb;
	netdev_features_t features = netif_skb_features(skb);
	unsigned int len = 0;
	int ret, nb;

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs))
		return qdisc_reshape_fail(skb, sch);

	nb = 0;
	while (segs) {
		nskb = segs->next;
		segs->next = NULL;
		qdisc_skb_cb(segs)->pkt_len = segs->len;
		len += segs->len;
		ret = qdisc_enqueue(segs, q->qdisc);
		if (ret != NET_XMIT_SUCCESS) {
			if (net_xmit_drop_count(ret))
				qdisc_qstats_drop(sch);
		} else {
			nb++;
		}
		segs = nskb;
	}
	sch->q.qlen += nb;
	if (nb > 1)
		qdisc_tree_decrease_qlen(sch, 1 - nb);
	sch->qstats.backlog += len;
	consume_skb(skb);

	return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static int arl_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	unsigned int len = qdisc_pkt_len(skb);
	int ret;

	if (qdisc_pkt_len(skb) > q->params.max_size) {
		if (skb_is_gso(skb))
			return gso_segment(skb, sch);
		return qdisc_reshape_fail(skb, sch);
	}

	ret = qdisc_enqueue(skb, q->qdisc);
	if (unlikely(ret != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(ret))
			qdisc_qstats_drop(sch);
		return ret;
	}
	if (q->params.mode == ARL_INGRESS)
		arl_sample_latency_ingress(q, skb);
	arl_enqueue_update(sch, len);
	return NET_XMIT_SUCCESS;
}

static unsigned int arl_drop(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	int len = 0;

	if (q->qdisc->ops->drop) {
		len = q->qdisc->ops->drop(q->qdisc);
		if (len != 0) {
			sch->q.qlen--;
			qdisc_qstats_drop(sch);
		}
	}
	return len;
}

static struct sk_buff *arl_dequeue(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	arl_update(sch);
	skb = q->qdisc->ops->peek(q->qdisc);

	if (skb) {
		s64 now;
		s64 toks;
		unsigned int len = qdisc_pkt_len(skb);

		if (WARN_ONCE(len > q->params.max_size,
			      "Oversized pkt! %u Bytes, max:%u\n", len,
			      q->params.max_size))
			len = q->params.max_size - 1;

		if (q->vars.state == ARL_UNTHROTTLED) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;
			arl_dequeue_update(sch, skb);
			return skb;
		}

		now = ktime_get_ns();
		toks = min_t(s64, now - q->vars.ts, q->vars.buffer);

		toks += q->vars.tokens;
		if (toks > q->vars.buffer)
			toks = q->vars.buffer;
		toks -= (s64)psched_l2t_ns(&q->vars.rate, len);

		if (toks >= 0) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;

			q->vars.ts = now;
			q->vars.tokens = toks;
			arl_dequeue_update(sch, skb);
			return skb;
		}
		qdisc_watchdog_schedule_ns(&q->wtd, now +
					   min_t(u32, (-toks), q->vars.buffer),
					   true);

		qdisc_qstats_overlimit(sch);
	}
	return NULL;
}

static void arl_reset(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	qdisc_reset(q->qdisc);
	q->vars.ts = ktime_get_ns();
	q->vars.tokens = q->vars.buffer;
	qdisc_watchdog_cancel(&q->wtd);
}

static const struct nla_policy arl_policy[TCA_ARL_MAX + 1] = {
	[TCA_ARL_BUFFER]	= { .type = NLA_U32 },
	[TCA_ARL_MIN_RATE]	= { .type = NLA_U64 },
	[TCA_ARL_MAX_BW]	= { .type = NLA_U64 },
	[TCA_ARL_LIMIT]		= { .type = NLA_U32 },
	[TCA_ARL_MAX_LATENCY]	= { .type = NLA_U32 },
	[TCA_ARL_LATENCY_HYSTERESIS]	= { .type = NLA_U32 },
	[TCA_ARL_MODE]		= { .type = NLA_U32 },
	[TCA_ARL_CODEL_TARGET]	= { .type = NLA_U32 },
};

static int arl_change(struct Qdisc *sch, struct nlattr *opt)
{
	int err;
	struct arl_sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_ARL_MAX + 1];
	struct Qdisc *child = NULL;
	struct psched_ratecfg rate;
	struct tc_ratespec rate_conf;

	err = nla_parse_nested(tb, TCA_ARL_MAX, opt, arl_policy);
	if (err < 0)
		return err;

	if (tb[TCA_ARL_BUFFER])
		q->params.buffer = nla_get_u32(tb[TCA_ARL_BUFFER])
				   * NSEC_PER_USEC;

	/* Convert max_bw from Bps to KBps */
	if (tb[TCA_ARL_MAX_BW])
		q->params.max_bw = div_u64(nla_get_u64(tb[TCA_ARL_MAX_BW]),
					   1000);

	if (tb[TCA_ARL_MIN_RATE])
		q->params.min_rate = div_u64(nla_get_u64(tb[TCA_ARL_MIN_RATE]),
					     1000);

	if (tb[TCA_ARL_MODE])
		q->params.mode = nla_get_u32(tb[TCA_ARL_MODE]);

	/* The default config set the minimum rate to 70% of connection speed */
	q->params.rate = div_u64(q->params.min_rate * 100, 70);

	if (tb[TCA_ARL_LIMIT])
		q->params.limit = nla_get_u32(tb[TCA_ARL_LIMIT]);

	if (tb[TCA_ARL_MAX_LATENCY])
		q->params.max_latency = nla_get_u32(tb[TCA_ARL_MAX_LATENCY]);
	if (tb[TCA_ARL_LATENCY_HYSTERESIS])
		q->params.latency_hysteresis =
			nla_get_u32(tb[TCA_ARL_LATENCY_HYSTERESIS]);
	if (q->params.max_latency < ARL_MAX_LATENCY_DEFAULT / 2)
		q->params.max_latency = ARL_MAX_LATENCY_DEFAULT;

	if (tb[TCA_ARL_CODEL_TARGET])
		q->params.target = nla_get_u32(tb[TCA_ARL_CODEL_TARGET]);

	arl_vars_init(q);
	memset(&rate_conf, 0, sizeof(rate_conf));
	rate_conf.linklayer = TC_LINKLAYER_ETHERNET;

	psched_ratecfg_precompute(&rate, &rate_conf, q->params.rate * 1000);
	memcpy(&q->vars.rate, &rate, sizeof(struct psched_ratecfg));

	if (q->qdisc != &noop_qdisc) {
		err = fifo_set_limit(q->qdisc, q->params.limit);
		if (err)
			goto done;
	} else if (q->params.limit > 0) {
		child = fifo_create_dflt(sch, &bfifo_qdisc_ops,
					 q->params.limit);
		if (IS_ERR(child)) {
			err = PTR_ERR(child);
			goto done;
		}
	}

	sch_tree_lock(sch);
	if (child) {
		qdisc_tree_decrease_qlen(q->qdisc, q->qdisc->q.qlen);
		qdisc_destroy(q->qdisc);
		q->qdisc = child;
	}

	sch_tree_unlock(sch);
done:
	return err;
}

static u32 arl_get_rtt_from_sk(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 rtt = U32_MAX, last_ack;

	if (sk->sk_state != TCP_ESTABLISHED)
		return rtt;

	last_ack = jiffies_to_msecs(jiffies - tp->rcv_tstamp);
	if (last_ack > ARL_ST_WIN) /* Discard stale data */
		return rtt;

	rtt = tp->srtt_us >> 3;
	return rtt;
}

static u32 arl_get_rtt(struct Qdisc *sch)
{
	int i;
	struct inet_hashinfo *hashinfo = &tcp_hashinfo;
	u32 rtt, rtt_min = U32_MAX;

	for (i = 0; i <= hashinfo->ehash_mask; i++) {
		struct inet_ehash_bucket *head = &hashinfo->ehash[i];
		struct sock *sk;
		struct hlist_nulls_node *node;

		rcu_read_lock();
		sk_nulls_for_each_rcu(sk, node, &head->chain) {
			if (sk->sk_family != AF_INET && sk->sk_family !=
			    AF_INET6)
				continue;
			if (inet_sk(sk)->rx_dst_ifindex != arl_dev_index)
				continue;
			rtt = arl_get_rtt_from_sk(sk);
			if (rtt == U32_MAX)
				continue;

			if (rtt < rtt_min)
				rtt_min = rtt;
		}
		rcu_read_unlock();
	}
	return rtt_min;
}

static void arl_timer_func(unsigned long data)
{
	struct Qdisc *sch = (struct Qdisc *)data;
	struct arl_sched_data *q = qdisc_priv(sch);
	u32 rtt;

	mod_timer(&q->arl_timer, jiffies + ARL_TIMER_INTERVAL);
	rtt = arl_get_rtt(sch);

	if (rtt != U32_MAX)
		arl_update_latency(q, rtt);
}

static int arl_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	arl_params_init(&q->params);
	qdisc_watchdog_init(&q->wtd, sch);
	q->qdisc = &noop_qdisc;

	init_timer(&q->arl_timer);
	q->arl_timer.expires = jiffies + ARL_TIMER_INTERVAL;
	q->arl_timer.data = (unsigned long)sch;
	q->arl_timer.function = arl_timer_func;
	add_timer(&q->arl_timer);

	if (opt) {
		int err = arl_change(sch, opt);

		if (err)
			return err;
	}
	arl_latency_sampling_enabled = true;
	if (q->params.mode == ARL_EGRESS)
		arl_dev_index = dev->ifindex;

	return 0;
}

static void arl_destroy(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	if (q->params.mode == ARL_EGRESS)
		arl_dev_index = -1;
	qdisc_watchdog_cancel(&q->wtd);
	del_timer_sync(&q->arl_timer);
	qdisc_destroy(q->qdisc);
}

static int arl_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct nlattr *nest;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (!nest)
		goto nla_put_failure;

	if ((nla_put_u32(skb, TCA_ARL_BUFFER,
			 q->params.buffer / NSEC_PER_USEC)) ||
	    (nla_put_u64(skb, TCA_ARL_MIN_RATE, q->params.min_rate * 1000)) ||
	    (nla_put_u32(skb, TCA_ARL_LIMIT, q->params.limit)) ||
	    (nla_put_u64(skb, TCA_ARL_MAX_BW, q->params.max_bw)) * 1000 ||
	    (nla_put_u32(skb, TCA_ARL_MODE, q->params.mode)) ||
	    (nla_put_u32(skb, TCA_ARL_LATENCY_HYSTERESIS,
			 q->params.latency_hysteresis)) ||
	    (nla_put_u32(skb, TCA_ARL_CODEL_TARGET,
			 q->params.target)) ||
	    (nla_put_u32(skb, TCA_ARL_MAX_LATENCY, q->params.max_latency)))
		goto nla_put_failure;

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static int arl_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(1);
	tcm->tcm_info = q->qdisc->handle;

	return 0;
}

static int arl_dump_stats(struct Qdisc *sch, struct gnet_dump *d)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct tc_arl_xstats st = { 0 };

	/* convert bw and rate from KBps to Kbits */
	st.max_bw = q->stats.max_bw * 8;
	st.min_rate = q->stats.min_rate * 8;
	st.base_rate = q->vars.base_rate * 8;
	st.current_rate = q->vars.current_rate * 8;
	st.latency = minmax_get(&q->vars.min_hrtt);
	st.state = q->vars.state;
	st.current_bw = q->vars.bw_est * 8;

	return gnet_stats_copy_app(d, &st, sizeof(st));
}

static int arl_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		     struct Qdisc **old)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	if (!new)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = q->qdisc;
	q->qdisc = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	return 0;
}

static struct Qdisc *arl_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	return q->qdisc;
}

static unsigned long arl_get(struct Qdisc *sch, u32 classid)
{
	return 1;
}

static void arl_put(struct Qdisc *sch, unsigned long arg)
{
}

static void arl_walk(struct Qdisc *sch, struct qdisc_walker *walker)
{
	if (!walker->stop) {
		if (walker->count >= walker->skip)
			if (walker->fn(sch, 1, walker) < 0) {
				walker->stop = 1;
				return;
			}
		walker->count++;
	}
}

static const struct Qdisc_class_ops arl_class_ops = {
	.graft		=	arl_graft,
	.leaf		=	arl_leaf,
	.get		=	arl_get,
	.put		=	arl_put,
	.walk		=	arl_walk,
	.dump		=	arl_dump_class,
};

static struct Qdisc_ops arl_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	&arl_class_ops,
	.id		=	"arl",
	.priv_size	=	sizeof(struct arl_sched_data),
	.enqueue	=	arl_enqueue,
	.dequeue	=	arl_dequeue,
	.peek		=	qdisc_peek_dequeued,
	.drop		=	arl_drop,
	.init		=	arl_init,
	.reset		=	arl_reset,
	.destroy	=	arl_destroy,
	.change		=	arl_change,
	.dump		=	arl_dump,
	.dump_stats	=	arl_dump_stats,
	.owner		=	THIS_MODULE,
};

static int __init arl_module_init(void)
{
	return register_qdisc(&arl_qdisc_ops);
}

static void __exit arl_module_exit(void)
{
	unregister_qdisc(&arl_qdisc_ops);
}

module_init(arl_module_init)
module_exit(arl_module_exit)

MODULE_DESCRIPTION("Adaptive Rate Limiting(ARL) queue discipline");
MODULE_AUTHOR("Kan Yan <kyan@google.com>");
MODULE_LICENSE("GPL");
