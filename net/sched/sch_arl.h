/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SCH_ARL
#define _SCH_ARL

enum arl_state {
	/* STABLE: Maintaining current rate */
	ARL_STABLE = 0,
	/* DRAIN: Decrease rate sharply to drain the packets in the queue in
	 * the upstream devices
	 */
	ARL_DRAIN,
	/* BW_PROBE: Increase rate gradually to probe if more BW is available */
	ARL_BW_PROBE,
	/* LATENCY_PROBE: Decrease rate gradually to probe if latency can be
	 * further reduced.
	 */
	ARL_LATENCY_PROBE,
	/* UNTHROTTLED: Not enforceing rate shaping */
	ARL_UNTHROTTLED,
	/* IDLE: under light load and do nothing */
	ARL_IDLE
};

enum arl_mode {
	ARL_EGRESS = 0,
	ARL_INGRESS
};

enum arl_latency_sampling_state {
	ARL_SAMPLE_STATE_IDLE = 0,
	ARL_SAMPLE_STATE_UPDATING,
	ARL_SAMPLE_STATE_SAMPLING,
	ARL_SAMPLE_STATE_DONE
};

struct arl_params {
	u64	min_rate;	/* The lowest rate for the rate limiter */
	u64	rate;		/* Initial rate */
	u32	buffer;		/* Burst size, in ns */
	/* The maximum rate that rate limiting will be enforced. Above max_bw
	 * ARL enters UNTHROTTLED state and bypasses the rate shaper to avoid
	 * CPU overhead.
	 */
	u64	max_bw;
	u32	limit;		/* Maxmium number of packets allowed in queue */
	u32	max_latency;	/* The upper limit for latency */
	u32	max_size;	/* Max packet size */
	u32	latency_hysteresis;
	u32	target;		/* CoDel's latency target in us */
	enum arl_mode	mode;
};

struct arl_vars {
	s64	tokens;	/* token count*/
	s64	buffer;	/* Token bucket depth/rate */
	s64	ts;	/* Last de-queue time */
	ktime_t	phase_start_t;		/* phase start time */
	unsigned long state_start_t;	/* state start time */
	ktime_t	last_drain_t;		/* Timestamp of last DRAIN */
	struct psched_ratecfg rate;	/* The current rate limit */
	struct tc_ratespec cfg_rate;
	u64	bw_est_bytes_sent;
	u32	bw_est;	/* Current estimate of throughput. in Kbps */
	u32	last_bw_est; /* bw_est from previous cycle, in Kbps */
	u32	last_stable_base_rate; /* Previous base_rate with low latency */
	/* Exponentially Weighted Moving Avg. of bw */
	struct ewma	bw_avg;
	unsigned long	bw_est_start_t;	/* Timestamp of the start */
	struct minmax	max_bw;		/* windowed max of the bw measured */
	/* Short term(last cycle) windowed min of halfpath RTT */
	struct minmax	st_min_hrtt;
	struct minmax	min_hrtt;	/* Medium term(~3s) windowed min HRTT */
	struct minmax	lt_min_hrtt;	/* Longer term(~10s) win. min HRTT */
	u32	min_hrtt_last_cycle;	/* min_hrtt at the end of prev. cycle */
	u32	last_min_hrtt;		/* min_hrtt at the end of prev. state */
	u32	state;		/* Current state */
	u32	phase;		/* Current phase */
	u32	phase_dur;	/* In ms */
	u32	cycle_cnt;	/* Cycles stays in current states */
	u32	base_rate;	/* The base rate derived from the bw estimate */
	u32	target_rate;	/* Adjusted base rate for next state */
	u32	current_rate;	/* The base rate for current cycle */
	s32	rate_factor;	/* Factor for increase/decrease rate */
	s32	rate_delta;	/* The adjust of rate from base_rate */
	/* Compare to prev. cycle, is latency increasing or decreasing */
	s32	latency_trend;
	ulong	last_latency_upd_t; /* Timestamp of last latency measurement */
	ulong	next_bw_probe_t;	/* When next bw probe is allowed */
};

#define ARL_TIMER_INTERVAL		(150 * HZ / MSEC_PER_SEC) /* 150 ms */
#define ARL_LAT_HYSTERESIS_DEFAULT	(40 * USEC_PER_MSEC) /* 40 ms in us */

#define ARL_CYCLE_LEN		4	/* # of phases in a cycle */
#define ARL_PHASE_DUR_MAX	250UL	/* in ms */
#define ARL_PHASE_DUR_MIN	150UL	/* in ms */
#define ARL_DRAIN_DUR_MAX	250U	/* in ms */
#define ARL_DRAIN_DUR_MIN	20U	/* in ms */

#define ARL_INGRESS_PHASE_DUR_MAX	250UL	/* in ms */
#define ARL_INGRESS_PHASE_DUR_MIN	150UL	/* in ms */

#define ARL_DRAIN_INTERVAL	10177	/* A prime number for ~10s */
/* Longer term window size in ms, for the windowed min/max of bandwidth
 * and latency measurement. Should include a DRAIN cycle.
 */
#define ARL_LT_WIN	(11 * MSEC_PER_SEC)
#define ARL_MT_WIN	(3 * MSEC_PER_SEC) /* Medium term window size */
#define ARL_ST_WIN	400	/* Short term window size in ms */

#define ARL_LATENCY_SAMPLE_TIMEOUT_US	(2 * USEC_PER_SEC)
/* Low latency threshold to skip DRAIN cycle */
#define ARL_LOW_LATENCY	(35 * USEC_PER_MSEC)

/* The maximum BW/throughput, above it ARL will not enforce rate limit */
#define ARL_MAX_BW_DEFAULT	(300 * 1000 / 8) /* In KBytes per sec */
/* The minimun rate limit. ARL will not go below this limit */
#define ARL_MIN_RATE_DEFAULT	(2 * 1000 / 8) /* In KBytes per sec */
/* The default burst size for the Token Buffer rate limiter */
#define ARL_BUFFER_SIZE_DEFAULT	(5 * USEC_PER_MSEC) /* in us */
#define ARL_MAX_LATENCY_DEFAULT	(150 * USEC_PER_MSEC) /* in us */

struct arl_stats {
	u32	max_bw;		/* max bw detected */
	u32	min_rate;		/* the min. of base rate */
};

struct arl_sched_data {
	struct arl_params	params;
	struct arl_vars		vars;
	struct arl_stats	stats;
	struct qdisc_watchdog	wtd;
	struct Qdisc		*qdisc;
	struct timer_list	arl_timer;
};
#endif /* _NET_SCH_ARL */
