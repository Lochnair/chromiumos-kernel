// SPDX-License-Identifier: GPL-2.0
/* Adaptive Rate Limiting Qdisc (ARL) is designed for home routers to eliminate
 * bufferbloat at upstream CPE (Cable/DSL) modem. It prevents bloated queue
 * from forming at upstream CPE modem by rate limit egress throughput to match
 * the available bandwidth. Instead of using a preconfigured static rate limit.
 * It automatically figures out the available upstream bandwidth and adjust
 * rate limit in real time, by continuously monitoring latency passively.
 * There are two sources of latency measurement, one is the RTT from kernel’s
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
 *
 * The passive latency measurement method for routed TCP stream is inspired by:
 * Kathleen Nichols, "Listening to Networks",
 * http://netseminar.stanford.edu/seminars/02_02_17.pdf
 *
 * The rate shaping and some utility functions are copied from:
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

#define ARL_SCALE	7	/* 128B per sec, approximatly 1kbps */
#define ARL_BW_UNIT	BIT(7) /* 128B per sec, approximatly 1kbps */

/* High gain to exponentially increase bw. Double the BW in 20 cycles */
static const int ARL_HIGH_GAIN = ARL_BW_UNIT *  1035 / 1000;
/* Drain gain: half the rate in two cycles */
static const int ARL_DRAIN_GAIN = ARL_BW_UNIT * 707 / 1000;

static bool arl_latency_sampling_enanbled;
static int arl_dev_index = -1;

/* The rate for each phase is:
 * base_rate + rate_delta * arl_rate_tbl[mode][phase]
 */
static const int arl_rate_tbl[][ARL_CYCLE_LEN] = {
			{0, 0, 0, 0},		/* STABLE */
			{-1, -1, -1, 0},	/* DRAIN */
			{1, 0, 1, 0},		/* BW_PROBE */
			{-1, -1, -1, 0},	/* LATENCY_PROBE */
			{0, 0, 0, 0},		/* UNTHROTTLED */
			};

static void arl_bw_est_reset(struct arl_sched_data *q)
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
	arl_bw_est_reset(q);
}

static bool arl_is_latency_high(struct arl_sched_data *q)
{
	u32 lt_min_hrtt = minmax_get(&q->vars.lt_min_hrtt);

	if ((minmax_get(&q->vars.st_min_hrtt) < (lt_min_hrtt +
	   q->params.latency_hysteresis)) &&
	   (minmax_get(&q->vars.min_hrtt) < q->params.max_latency))
		return false;
	else
		return true;
}

/* Check if the bandwidth is fully used.
 * Return true if the measured throughput is above ~92% of the configured rate.
 */
static bool arl_is_bw_full(struct arl_sched_data *q)
{
	u32 rate = q->vars.base_rate;

	return (q->vars.bw_est > (rate - ((rate * 10) >> ARL_SCALE))) ? true :
		false;
}

static bool arl_check_drain(struct arl_sched_data *q)
{
	if (q->vars.mode != ARL_LATENCY_PROBE)
		return false;

	if (minmax_get(&q->vars.st_min_hrtt) < ARL_LOW_LATENCY)
		return false;

	if (!arl_is_bw_full(q))
		return false;

	if (minmax_get(&q->vars.min_hrtt) > q->params.max_latency)
		return true;

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
	 * transmit max_size packet.
	 */
	buffer = psched_l2t_ns(&q->vars.rate, q->params.max_size);
	q->vars.buffer = max(buffer, q->params.buffer);
}

static void arl_change_mode(struct arl_sched_data *q, int mode)
{
	struct	arl_vars *vars = &q->vars;
	u64	next_rate;
	u32	bw;

	vars->phase = 0;
	vars->cycle_cnt = 0;
	vars->phase_start_t = ktime_get();
	vars->latency_trend = 0;
	vars->phase_dur = ARL_PHASE_DUR_MAX;
	vars->rate_factor = ARL_BW_UNIT;

	if (vars->mode == mode)
		return;

	vars->phase_dur = clamp((2 * minmax_get(&vars->st_min_hrtt)
				/ USEC_PER_MSEC), ARL_PHASE_DUR_MIN,
				ARL_PHASE_DUR_MAX);

	if (mode == ARL_UNTHROTTLED && vars->bw_est > q->params.max_bw)
		arl_latency_sampling_enanbled = false;
	else if (vars->mode == ARL_UNTHROTTLED)
		arl_latency_sampling_enanbled = true;

	/* Setup new base rate for next state. In general, the base rate should
	 * set to the available bandwidth measured, if the link is fully used.
	 * Use instand BW value when enter DRAIN mode, or exit UNTHROTTLED.
	 * Use the moving average of bw for the other states.
	 */
	if (mode == ARL_DRAIN || vars->mode == ARL_UNTHROTTLED)
		bw = vars->bw_est;
	else
		bw = ewma_read(&vars->bw_avg);

	/* Reduce BW to offset the overshot due to increase BW when exit
	 * UNTHROTTLED or BW_PROBE mode
	 */
	if (vars->mode == ARL_UNTHROTTLED)
		bw -= (bw >> ARL_SCALE) * 12;
	else if (vars->mode == ARL_BW_PROBE)
		bw -= (bw >> ARL_SCALE);

	/* Cap bw to previous base_rate when exit LATENCY_PROBE or enter DRAIN
	 * mode
	 */
	if (vars->mode == ARL_LATENCY_PROBE || mode == ARL_DRAIN)
		bw = min(bw, vars->base_rate);

	/* New base rate for next mode */
	vars->base_rate = max(bw, vars->base_rate);
	/* rate adjustment for next cycle */
	vars->probe_rate = ((vars->base_rate * ARL_HIGH_GAIN) >> ARL_SCALE);
	vars->rate_delta = vars->probe_rate - vars->base_rate;

	/* entering DRAIN mode */
	if (mode == ARL_DRAIN) {
		vars->last_drain_t = ktime_get();
		vars->phase_dur = minmax_get(&vars->st_min_hrtt) /
					     USEC_PER_MSEC;
		vars->phase_dur = clamp(vars->phase_dur, ARL_DRAIN_DUR_MIN,
					ARL_DRAIN_DUR_MAX);

		/* If latency is high, reduce the base rate to ~70%. */
		if (arl_is_latency_high(q)) {
			vars->base_rate = (vars->base_rate >> ARL_SCALE)
					* ARL_DRAIN_GAIN;
		} else if (arl_is_bw_full(q)) {
			vars->base_rate -= vars->rate_delta;
		}
		vars->base_rate = max(bw, vars->base_rate);
		/* set rate_delta to ~33% of base_rate, so a [-1, -1, -1, 0]
		 * cycle could eliminate RTT worth of queue if the base rate
		 * is approximately equals to BW.
		 */
		vars->rate_delta = vars->base_rate / 3;
	}

	vars->last_min_hrtt = minmax_get(&vars->st_min_hrtt);
	vars->min_hrtt_last_cycle = vars->last_min_hrtt;

	vars->mode = mode;
	vars->base_rate = max_t(u32, vars->base_rate, q->params.min_rate);

	next_rate = vars->rate_delta * arl_rate_tbl[vars->mode][vars->phase]
		    + vars->base_rate;
	arl_apply_new_rate(q, next_rate);
	arl_bw_est_reset(q);
}

static void arl_update_phase(struct arl_sched_data *q)
{
	struct	arl_vars *vars = &q->vars;
	u64	next_rate;
	int	latency;
	bool	is_bw_full, is_latency_high;

	if (time_after(jiffies, vars->last_latency_upd +
	    msecs_to_jiffies(ARL_LT_WIN * 2)) &&
	    vars->mode != ARL_STABLE) {
		arl_change_mode(q, ARL_UNTHROTTLED);
		return;
	}

	if (arl_check_drain(q)) {
		arl_change_mode(q, ARL_DRAIN);
		return;
	}

	/* update the latency_trend at the end of each phase */
	latency = minmax_get(&vars->st_min_hrtt);
	if ((latency + q->params.latency_hysteresis / 2) <
	    vars->min_hrtt_last_cycle)
		vars->latency_trend--;
	else if (latency > (vars->min_hrtt_last_cycle +
		 q->params.latency_hysteresis / 2))
		vars->latency_trend++;

	if (latency < ARL_LOW_LATENCY)
		vars->latency_trend = 0;

	vars->phase = (vars->phase == (ARL_CYCLE_LEN - 1)) ? 0 :
		       vars->phase + 1;
	vars->phase_start_t = ktime_get();

	next_rate = vars->rate_delta * arl_rate_tbl[vars->mode][vars->phase]
		    + vars->base_rate;

	arl_apply_new_rate(q, next_rate);

	if (vars->phase != 0)
		return;

	/* If there is no updated latency measurement, skip state update */
	if (time_after(jiffies, vars->last_latency_upd + vars->phase_dur * 4))
		return;

	arl_update_bw_estimate(q);
	is_bw_full = arl_is_bw_full(q);

	/* Is latency high compared to long term minimum? */
	is_latency_high = arl_is_latency_high(q);

	if ((minmax_get(&q->vars.max_bw) > q->params.max_bw) &&
	    !is_latency_high) {
		/* The available BW is too high to worry about bufferbloat.
		 * so disengage the rate limiter to avoid overhead.
		 */
		arl_change_mode(q, ARL_UNTHROTTLED);
		return;
	}

	switch (vars->mode) {
	case ARL_STABLE:
		if (is_latency_high && vars->bw_est > q->params.min_rate) {
			arl_change_mode(q, ARL_LATENCY_PROBE);
			return;
		}
		if (is_bw_full) {
			if (vars->latency_trend > 1) {
				arl_change_mode(q, ARL_LATENCY_PROBE);
				return;
			} else if (vars->cycle_cnt > 3) {
			/* If there is sufficient traffic load, go to BW_PROBE
			 * after delay for a few cycles.
			 */
				arl_change_mode(q, ARL_BW_PROBE);
				return;
			}
		} else {
			vars->last_drain_t = ktime_get();
		}
		break;

	case ARL_BW_PROBE:
		if (is_latency_high) {
			arl_change_mode(q, ARL_LATENCY_PROBE);
			return;
		}
		if (!is_bw_full && vars->cycle_cnt > 3) {
			arl_change_mode(q, ARL_STABLE);
			return;
		} else if (vars->latency_trend >= 2) {
			arl_change_mode(q, ARL_LATENCY_PROBE);
			return;
		}

		/* Switch to high gain if latency is stable. Pause the
		 * rate_delta increase for one in every 4 phases to observe
		 * the latecency change. The could be some lag between rate
		 * change and latency change.
		 */
		if (vars->latency_trend == 0 && vars->cycle_cnt % 4)
			vars->rate_factor = ARL_HIGH_GAIN;
		else
			vars->rate_factor = ARL_BW_UNIT;

		vars->probe_rate = ((vars->probe_rate * vars->rate_factor) >>
				    ARL_SCALE);
		vars->rate_delta = vars->probe_rate - vars->base_rate;
		/* If BW has increased signficantly(>15%) without latency
		 * increase, switch to UNTHROTTLED mode to quickly figure out
		 * the available BW.
		 */
		if (vars->rate_delta >= vars->base_rate / 4) {
			vars->rate_delta = max_t(u32, vars->rate_delta,
						 vars->base_rate / 2);
			if (vars->bw_est > vars->base_rate * 115 / 100) {
				arl_change_mode(q, ARL_UNTHROTTLED);
				return;
			}
		}
		if (vars->cycle_cnt > 20) {
			arl_change_mode(q, ARL_STABLE);
			return;
		}
		break;

	case ARL_LATENCY_PROBE:
		if (!is_latency_high || vars->bw_est < q->params.min_rate) {
		/* If latency is no longer high or cannot be further reduced,
		 * go back to stable mode.
		 */
			if (is_bw_full)
				vars->base_rate -= vars->rate_delta / 4;
			arl_change_mode(q, ARL_STABLE);
			return;
		}

		/* If it is not just short minor term latency increases,
		 * then the pervious minor adjustment of rate is not sufficient.
		 * The base_rate is likely exceed the available bandwidth, goto
		 * DRAIN state.
		 */
		if (vars->bw_est > q->params.min_rate &&
		    ((minmax_get(&q->vars.min_hrtt) > q->params.max_latency) ||
		    ((minmax_get(&q->vars.st_min_hrtt) >
		    q->params.max_latency) && vars->cycle_cnt > 2))) {
			arl_change_mode(q, ARL_DRAIN);
			return;
		}

		if (vars->latency_trend >= 0)
			vars->rate_factor = ARL_HIGH_GAIN;
		else
			vars->rate_factor = ARL_BW_UNIT;

		vars->rate_delta = ((vars->rate_delta * vars->rate_factor)
					>> ARL_SCALE);
		if (vars->rate_delta > vars->base_rate / 4)
			vars->rate_delta = vars->base_rate / 4;
		break;

	case ARL_DRAIN:
		if (!is_latency_high || vars->bw_est < q->params.min_rate) {
			arl_change_mode(q, ARL_STABLE);
			return;
		}
		arl_change_mode(q, ARL_LATENCY_PROBE);
		return;

	case ARL_UNTHROTTLED:
		if (is_latency_high) {
			arl_change_mode(q, ARL_LATENCY_PROBE);
			return;
		} else if ((vars->latency_trend > 1) ||
			   ((minmax_get(&vars->max_bw) < q->params.max_bw) &&
			   (vars->cycle_cnt > 10)))  {
			if (vars->latency_trend >= 2 && is_bw_full)
				arl_change_mode(q, ARL_LATENCY_PROBE);
			else
				arl_change_mode(q, ARL_STABLE);
			return;
		}
		break;
	}

	/* state unchanged */
	vars->cycle_cnt++;
	vars->min_hrtt_last_cycle = minmax_get(&vars->st_min_hrtt);
	vars->latency_trend = 0;
	if (vars->base_rate < q->stats.min_rate || q->stats.min_rate == 0)
		q->stats.min_rate = vars->base_rate;
	next_rate = vars->rate_delta * arl_rate_tbl[vars->mode][vars->phase]
		    + vars->base_rate;

	arl_apply_new_rate(q, next_rate);
}

static void arl_update(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);

	if (ktime_ms_delta(ktime_get(), q->vars.phase_start_t) <
	    q->vars.phase_dur)
		return;

	arl_update_phase(q);
}

static void arl_params_init(struct arl_params *params)
{
	params->max_size = 5000;
	params->buffer = ARL_BUFFER_SIZE_DEFAULT * NSEC_PER_USEC;
	params->max_bw = ARL_MAX_BW_DEFAULT;
	params->min_rate = ARL_MIN_RATE_DEFAULT;
	params->limit = 1000;
	params->max_latency = ARL_MAX_LATENCY_DEFAULT;
	params->latency_hysteresis = ARL_LAT_HYSTERESIS_DEFAULT;
}

static	void arl_vars_init(struct arl_sched_data *q)
{
	struct arl_vars *vars = &q->vars;

	vars->ts = ktime_get_ns();
	q->vars.last_drain_t = ktime_get();
	minmax_reset(&vars->lt_min_hrtt, jiffies, 5 * 1000);
	minmax_reset(&vars->st_min_hrtt, jiffies, 5 * 1000);
	minmax_reset(&vars->max_bw, jiffies, 0);
	ewma_init(&vars->bw_avg, 8, 8);
	vars->cfg_rate.linklayer = TC_LINKLAYER_ETHERNET;
	vars->base_rate = q->params.rate;
	vars->tokens = q->vars.buffer;
	vars->buffer = q->params.buffer;
	arl_bw_est_reset(q);
	arl_change_mode(q, ARL_STABLE);
}

static void arl_update_latency_ct(struct arl_sched_data *q,
				  struct  tcp_latency_sample *lat, u32 latency)
{
	u32	s_hrtt, hrtt_last = lat->s_hrtt_us;

	if (hrtt_last > ARL_LATENCY_SAMPLE_TIMEOUT_US ||
	    latency > ARL_LATENCY_SAMPLE_TIMEOUT_US)
		hrtt_last = latency;

	/* s_hrtt_us = 3/4 old s_hrtt_us + 1/4 new sample */
	if (hrtt_last)
		s_hrtt = hrtt_last * 4 + latency - hrtt_last;
	else
		s_hrtt = latency * 4;

	s_hrtt = s_hrtt / 4;
	if (s_hrtt > ARL_LATENCY_SAMPLE_TIMEOUT_US)
		s_hrtt = latency;
	lat->s_hrtt_us = s_hrtt;

	minmax_running_min(&q->vars.st_min_hrtt,
			   (msecs_to_jiffies(q->vars.phase_dur)), jiffies,
			   latency);
	minmax_running_min(&q->vars.min_hrtt, msecs_to_jiffies(ARL_MT_WIN),
			   jiffies, s_hrtt);
	minmax_running_min(&q->vars.lt_min_hrtt, msecs_to_jiffies(ARL_LT_WIN),
			   jiffies, s_hrtt);
	q->vars.last_latency_upd = jiffies;
}

static void arl_update_latency(struct arl_sched_data *q, u32 latency)
{
	minmax_running_min(&q->vars.st_min_hrtt,
			   (msecs_to_jiffies(q->vars.phase_dur)), jiffies,
			   latency);
	minmax_running_min(&q->vars.min_hrtt, msecs_to_jiffies(ARL_MT_WIN),
			   jiffies, latency);
	minmax_running_min(&q->vars.lt_min_hrtt, msecs_to_jiffies(ARL_LT_WIN),
			   jiffies, latency);
	q->vars.last_latency_upd = jiffies;
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
	struct	tcp_latency_sample *tcp_lat;
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
struct  nf_conn *arl_egress_find_ct_v4(struct sk_buff *skb, struct iphdr *iph,
				       struct tcphdr *tcph)
{
	struct	nf_conntrack_tuple_hash *h;
	struct	nf_conntrack_tuple tuple;
	struct	nf_conn *ct = NULL;

	if (!arl_latency_sampling_enanbled)
		return ct;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));
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

struct  nf_conn *arl_egress_find_ct_v6(struct sk_buff *skb,
				       struct ipv6hdr *ipv6h,
				       struct tcphdr *tcph)
{
	struct	nf_conntrack_tuple_hash *h;
	struct	nf_conntrack_tuple tuple;
	struct	nf_conn *ct = NULL;

	if (!arl_latency_sampling_enanbled)
		return ct;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));

	tuple.dst.dir = IP_CT_DIR_REPLY;
	tuple.dst.protonum = IPPROTO_TCP;

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

static void arl_latency_sample_egress(struct arl_sched_data *q,
				      struct sk_buff *skb)
{
	struct	tcphdr *tcph, tcphdr;
	struct	nf_conn *ct;
	struct	tcp_latency_sample *tcp_lat;
	u32	latency_sampling;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;

	if (!arl_latency_sampling_enanbled)
		return;

	/* skip small packets */
	if (!skb || skb->len < 256)
		return;

	/* Skip bc/mc packets. */
	if (unlikely(skb->pkt_type == PACKET_BROADCAST ||
		     skb->pkt_type == PACKET_MULTICAST))
		return;

	/* Only process TCP packets */
	if (likely(htons(ETH_P_IP) == skb->protocol)) {
		iph = ip_hdr(skb);
		tcph = arl_get_tcp_header_ipv4(skb, &tcphdr);
		if (!tcph)
			return;
		ct = arl_egress_find_ct_v4(skb, iph, tcph);
	} else if (likely(htons(ETH_P_IPV6) == skb->protocol)) {
		ipv6h = ipv6_hdr(skb);
		tcph = arl_get_tcp_header_ipv6(skb, &tcphdr);
		if (!tcph)
			return;
		ct = arl_egress_find_ct_v6(skb, ipv6h, tcph);
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
		u32 latency = tcp_lat->last_hrtt;

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
	} else if (latency_sampling > ARL_SAMPLE_STATE_IDLE) {
		goto exit;
	}

	if (atomic_cmpxchg(&tcp_lat->sampling_state, ARL_SAMPLE_STATE_IDLE,
			   ARL_SAMPLE_STATE_UPDATING) != ARL_SAMPLE_STATE_IDLE)
		goto exit;

	atomic_set(&tcp_lat->sampling_state,
		   ARL_SAMPLE_STATE_SAMPLING);
	arl_egress_mark_pkt(skb, ntohl(tcph->seq), ct);

exit:
	nf_ct_put(ct);
}

/* Extract half round trip time from routed TCP packets
 * Return hrtt in us if successful, return -1 otherwise.
 */
static int  arl_get_hrtt(struct sk_buff *skb, u32 ack_seq,
			 struct  tcp_latency_sample *tcp_lat)
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
	atomic_set(&tcp_lat->sampling_state,
		   ARL_SAMPLE_STATE_DONE);
	return 0;
}

void arl_latency_sample_ingress_v4(struct sk_buff *skb,
				   struct iphdr *iph,
				   struct tcphdr *tcph)
{
	struct	nf_conn *ct;
	struct  nf_conntrack_tuple tuple;
	struct  nf_conntrack_tuple_hash *h;
	struct  tcp_latency_sample *tcp_lat;

	if (!skb || !skb->dev || skb->dev->ifindex != arl_dev_index)
		return;

	if (!arl_latency_sampling_enanbled)
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

	if (arl_get_hrtt(skb, ntohl(tcph->ack_seq), tcp_lat))
		goto exit;

exit:
	nf_ct_put(ct);
}
EXPORT_SYMBOL(arl_latency_sample_ingress_v4);

void arl_latency_sample_ingress_v6(struct sk_buff *skb, struct ipv6hdr *ipv6h,
				   struct tcphdr *tcph)

{
	struct	nf_conn *ct;
	struct  nf_conntrack_tuple tuple;
	struct  nf_conntrack_tuple_hash *h;
	struct  tcp_latency_sample *tcp_lat;

	if (!skb || !skb->dev || skb->dev->ifindex != arl_dev_index)
		return;

	if (!arl_latency_sampling_enanbled)
		return;

	/* construct a tuple to lookup nf_conn. */
	memset(&tuple, 0, sizeof(tuple));
	tuple.dst.dir = IP_CT_DIR_REPLY;
	tuple.dst.protonum = IPPROTO_TCP;

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

	if (arl_get_hrtt(skb, ntohl(tcph->ack_seq), tcp_lat))
		goto exit;

exit:
	nf_ct_put(ct);
}
EXPORT_SYMBOL(arl_latency_sample_ingress_v6);

void arl_latency_sample_ingress(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph, tcphdr;

	if (htons(ETH_P_IP) == skb->protocol) {
		tcph = arl_get_tcp_header_ipv4(skb, &tcphdr);
		if (!tcph)
			return;
		arl_latency_sample_ingress_v4(skb, iph, tcph);
	} else if (htons(ETH_P_IPV6) == skb->protocol) {
		tcph = arl_get_tcp_header_ipv6(skb, &tcphdr);
		if (!tcph)
			return;
		arl_latency_sample_ingress_v6(skb, ipv6h, tcph);
	}
}
EXPORT_SYMBOL(arl_latency_sample_ingress);

/* GSO packets maybe too big and takes more than maxmium tokens to transmit.
 * Segment the GSO packets that is larger than max_size.
 */

static int gso_segment(struct sk_buff *skb, struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
	struct sk_buff *segs, *nskb;
	netdev_features_t features = netif_skb_features(skb);
	int ret, nb;

	segs = skb_gso_segment(skb, features & ~NETIF_F_GSO_MASK);

	if (IS_ERR_OR_NULL(segs))
		return qdisc_reshape_fail(skb, sch);

	nb = 0;
	while (segs) {
		nskb = segs->next;
		segs->next = NULL;
		qdisc_skb_cb(segs)->pkt_len = segs->len;
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
	consume_skb(skb);

	return nb > 0 ? NET_XMIT_SUCCESS : NET_XMIT_DROP;
}

static int arl_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);
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

		if (len > q->params.max_size) {
			pr_err("%s: Oversized pkt! %u Bytes, max:%u\n",
			       __func__, len, q->params.max_size);
			len = q->params.max_size - 1;
		}

		if (q->vars.mode == ARL_UNTHROTTLED) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;
			qdisc_bstats_update(sch, skb);
			q->vars.bw_est_bytes_sent += len;
			arl_latency_sample_egress(q, skb);
			return skb;
		}

		now = ktime_get_ns();
		toks = min(now - q->vars.ts, q->vars.buffer);

		toks += q->vars.tokens;
		if (toks > q->vars.buffer)
			toks = q->vars.buffer;
		toks -= psched_l2t_ns(&q->vars.rate, len);

		if (toks >= 0) {
			skb = qdisc_dequeue_peeked(q->qdisc);
			if (unlikely(!skb))
				return NULL;

			q->vars.ts = now;
			q->vars.tokens = toks;
			qdisc_unthrottled(sch);
			qdisc_bstats_update(sch, skb);
			q->vars.bw_est_bytes_sent += len;
			arl_latency_sample_egress(q, skb);
			return skb;
		}
		qdisc_watchdog_schedule_ns(&q->wtd, now + (-toks), true);

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

	if (tb[TCA_ARL_MAX_BW])
		q->params.max_bw = nla_get_u64(tb[TCA_ARL_MAX_BW]);

	if (tb[TCA_ARL_MIN_RATE])
		q->params.min_rate = div_u64(nla_get_u64(tb[TCA_ARL_MIN_RATE]),
					     1000);

	/* Start ARL with min_rate * 2 */
	q->params.rate = q->params.min_rate * 2;

	if (tb[TCA_ARL_LIMIT])
		q->params.limit = nla_get_u32(tb[TCA_ARL_LIMIT]);

	if (tb[TCA_ARL_MAX_LATENCY])
		q->params.max_latency = nla_get_u32(tb[TCA_ARL_MAX_LATENCY]);
	if (tb[TCA_ARL_LATENCY_HYSTERESIS])
		q->params.latency_hysteresis =
			nla_get_u32(tb[TCA_ARL_LATENCY_HYSTERESIS]);
	if (q->params.max_latency < ARL_MAX_LATENCY_DEFAULT / 2)
		q->params.max_latency = ARL_MAX_LATENCY_DEFAULT;

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

u32 arl_get_rtt(struct Qdisc *sch)
{
	int i;
	struct inet_hashinfo *hashinfo = &tcp_hashinfo;
	u32 rtt, rtt_min = U32_MAX;
	struct net_device *dev = qdisc_dev(sch);

	for (i = 0; i <= hashinfo->ehash_mask; i++) {
		struct inet_ehash_bucket *head = &hashinfo->ehash[i];
		spinlock_t *lock = inet_ehash_lockp(hashinfo, i);
		struct sock *sk;
		struct hlist_nulls_node *node;

		if (hlist_nulls_empty(&head->chain))
			continue;

		spin_lock_bh(lock);
		sk_nulls_for_each(sk, node, &head->chain) {
			if (sk->sk_family != AF_INET && sk->sk_family !=
			    AF_INET6)
				continue;
			if (inet_sk(sk)->rx_dst_ifindex !=  dev->ifindex)
				continue;
			rtt = arl_get_rtt_from_sk(sk);
			if (rtt == U32_MAX)
				continue;

			if (rtt < rtt_min)
				rtt_min = rtt;
		}
		spin_unlock_bh(lock);
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

	arl_dev_index = dev->ifindex;

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
	arl_latency_sampling_enanbled = true;

	return 0;
}

static void arl_destroy(struct Qdisc *sch)
{
	struct arl_sched_data *q = qdisc_priv(sch);

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
	    (nla_put_u64(skb, TCA_ARL_MAX_BW, q->params.max_bw)) ||
	    (nla_put_u32(skb, TCA_ARL_LATENCY_HYSTERESIS,
			 q->params.latency_hysteresis)) ||
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

	/* convert bw and rate from KBps to Kbps */
	st.max_bw = q->stats.max_bw * 8;
	st.min_rate = q->stats.min_rate * 8;
	st.current_rate = q->vars.base_rate * 8;
	st.latency = minmax_get(&q->vars.min_hrtt);

	/* clear max_bw and min_rate after each stats dump */
	q->stats.max_bw = 0;
	q->stats.min_rate = 0;

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
