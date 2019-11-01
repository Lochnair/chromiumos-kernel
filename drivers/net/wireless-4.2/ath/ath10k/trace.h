/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2013 Qualcomm Atheros, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#if !defined(_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>
#include "core.h"

#if !defined(_TRACE_H_)
static inline u32 ath10k_frm_hdr_len(const void *buf, size_t len)
{
	const struct ieee80211_hdr *hdr = buf;

	/* In some rare cases (e.g. fcs error) device reports frame buffer
	 * shorter than what frame header implies (e.g. len = 0). The buffer
	 * can still be accessed so do a simple min() to guarantee caller
	 * doesn't get value greater than len.
	 */
	return min_t(u32, len, ieee80211_hdrlen(hdr->frame_control));
}
#endif

#define _TRACE_H_

/* create empty functions when tracing is disabled */
#if !defined(CONFIG_ATH10K_TRACING)
#undef TRACE_EVENT
#define TRACE_EVENT(name, proto, ...) \
static inline void trace_ ## name(proto) {}
#undef DECLARE_EVENT_CLASS
#define DECLARE_EVENT_CLASS(...)
#undef DEFINE_EVENT
#define DEFINE_EVENT(evt_class, name, proto, ...) \
static inline void trace_ ## name(proto) {}
#endif /* !CONFIG_ATH10K_TRACING || __CHECKER__ */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ath10k

#define ATH10K_MSG_MAX 400

DECLARE_EVENT_CLASS(ath10k_log_event,
	TP_PROTO(struct ath10k *ar, struct va_format *vaf),
	TP_ARGS(ar, vaf),
	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__dynamic_array(char, msg, ATH10K_MSG_MAX)
	),
	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		WARN_ON_ONCE(vsnprintf(__get_dynamic_array(msg),
				       ATH10K_MSG_MAX,
				       vaf->fmt,
				       *vaf->va) >= ATH10K_MSG_MAX);
	),
	TP_printk(
		"%s %s %s",
		__get_str(driver),
		__get_str(device),
		__get_str(msg)
	)
);

DEFINE_EVENT(ath10k_log_event, ath10k_log_err,
	     TP_PROTO(struct ath10k *ar, struct va_format *vaf),
	     TP_ARGS(ar, vaf)
);

DEFINE_EVENT(ath10k_log_event, ath10k_log_warn,
	     TP_PROTO(struct ath10k *ar, struct va_format *vaf),
	     TP_ARGS(ar, vaf)
);

DEFINE_EVENT(ath10k_log_event, ath10k_log_info,
	     TP_PROTO(struct ath10k *ar, struct va_format *vaf),
	     TP_ARGS(ar, vaf)
);

TRACE_EVENT(ath10k_log_dbg,
	TP_PROTO(struct ath10k *ar, unsigned int level, struct va_format *vaf),
	TP_ARGS(ar, level, vaf),
	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(unsigned int, level)
		__dynamic_array(char, msg, ATH10K_MSG_MAX)
	),
	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->level = level;
		WARN_ON_ONCE(vsnprintf(__get_dynamic_array(msg),
				       ATH10K_MSG_MAX,
				       vaf->fmt,
				       *vaf->va) >= ATH10K_MSG_MAX);
	),
	TP_printk(
		"%s %s %s",
		__get_str(driver),
		__get_str(device),
		__get_str(msg)
	)
);

TRACE_EVENT(ath10k_log_dbg_dump,
	TP_PROTO(struct ath10k *ar, const char *msg, const char *prefix,
		 const void *buf, size_t buf_len),

	TP_ARGS(ar, msg, prefix, buf, buf_len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__string(msg, msg)
		__string(prefix, prefix)
		__field(size_t, buf_len)
		__dynamic_array(u8, buf, buf_len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__assign_str(msg, msg);
		__assign_str(prefix, prefix);
		__entry->buf_len = buf_len;
		memcpy(__get_dynamic_array(buf), buf, buf_len);
	),

	TP_printk(
		"%s %s %s/%s\n",
		__get_str(driver),
		__get_str(device),
		__get_str(prefix),
		__get_str(msg)
	)
);

TRACE_EVENT(ath10k_wmi_cmd,
	TP_PROTO(struct ath10k *ar, int id, const void *buf, size_t buf_len,
		 int ret),

	TP_ARGS(ar, id, buf, buf_len, ret),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(unsigned int, id)
		__field(size_t, buf_len)
		__dynamic_array(u8, buf, buf_len)
		__field(int, ret)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->id = id;
		__entry->buf_len = buf_len;
		__entry->ret = ret;
		memcpy(__get_dynamic_array(buf), buf, buf_len);
	),

	TP_printk(
		"%s %s id %d len %zu ret %d",
		__get_str(driver),
		__get_str(device),
		__entry->id,
		__entry->buf_len,
		__entry->ret
	)
);

TRACE_EVENT(ath10k_wmi_event,
	TP_PROTO(struct ath10k *ar, int id, const void *buf, size_t buf_len),

	TP_ARGS(ar, id, buf, buf_len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(unsigned int, id)
		__field(size_t, buf_len)
		__dynamic_array(u8, buf, buf_len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->id = id;
		__entry->buf_len = buf_len;
		memcpy(__get_dynamic_array(buf), buf, buf_len);
	),

	TP_printk(
		"%s %s id %d len %zu",
		__get_str(driver),
		__get_str(device),
		__entry->id,
		__entry->buf_len
	)
);

TRACE_EVENT(ath10k_htt_stats,
	TP_PROTO(struct ath10k *ar, const void *buf, size_t buf_len),

	TP_ARGS(ar, buf, buf_len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(size_t, buf_len)
		__dynamic_array(u8, buf, buf_len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->buf_len = buf_len;
		memcpy(__get_dynamic_array(buf), buf, buf_len);
	),

	TP_printk(
		"%s %s len %zu",
		__get_str(driver),
		__get_str(device),
		__entry->buf_len
	)
);

TRACE_EVENT(ath10k_wmi_dbglog,
	TP_PROTO(struct ath10k *ar, const void *buf, size_t buf_len),

	TP_ARGS(ar, buf, buf_len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u8, hw_type);
		__field(size_t, buf_len)
		__dynamic_array(u8, buf, buf_len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->hw_type = ar->hw_rev;
		__entry->buf_len = buf_len;
		memcpy(__get_dynamic_array(buf), buf, buf_len);
	),

	TP_printk(
		"%s %s %d len %zu",
		__get_str(driver),
		__get_str(device),
		__entry->hw_type,
		__entry->buf_len
	)
);

TRACE_EVENT(ath10k_htt_pktlog,
	    TP_PROTO(struct ath10k *ar, const void *buf, u16 buf_len),

	TP_ARGS(ar, buf, buf_len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u8, hw_type);
		__field(u16, buf_len)
		__dynamic_array(u8, pktlog, buf_len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->hw_type = ar->hw_rev;
		__entry->buf_len = buf_len;
		memcpy(__get_dynamic_array(pktlog), buf, buf_len);
	),

	TP_printk(
		"%s %s %d size %hu",
		__get_str(driver),
		__get_str(device),
		__entry->hw_type,
		__entry->buf_len
	 )
);

TRACE_EVENT(ath10k_htt_tx,
	    TP_PROTO(struct ath10k *ar, u16 msdu_id, u16 msdu_len,
		     u8 vdev_id, u8 tid),

	TP_ARGS(ar, msdu_id, msdu_len, vdev_id, tid),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u16, msdu_id)
		__field(u16, msdu_len)
		__field(u8, vdev_id)
		__field(u8, tid)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->msdu_id = msdu_id;
		__entry->msdu_len = msdu_len;
		__entry->vdev_id = vdev_id;
		__entry->tid = tid;
	),

	TP_printk(
		"%s %s msdu_id %d msdu_len %d vdev_id %d tid %d",
		__get_str(driver),
		__get_str(device),
		__entry->msdu_id,
		__entry->msdu_len,
		__entry->vdev_id,
		__entry->tid
	 )
);

TRACE_EVENT(ath10k_txrx_tx_unref,
	    TP_PROTO(struct ath10k *ar, u16 msdu_id),

	TP_ARGS(ar, msdu_id),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u16, msdu_id)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->msdu_id = msdu_id;
	),

	TP_printk(
		"%s %s msdu_id %d",
		__get_str(driver),
		__get_str(device),
		__entry->msdu_id
	 )
);

DECLARE_EVENT_CLASS(ath10k_hdr_event,
		    TP_PROTO(struct ath10k *ar, const void *data, size_t len),

	TP_ARGS(ar, data, len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(size_t, len)
		__dynamic_array(u8, data, ath10k_frm_hdr_len(data, len))
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->len = ath10k_frm_hdr_len(data, len);
		memcpy(__get_dynamic_array(data), data, __entry->len);
	),

	TP_printk(
		"%s %s len %zu\n",
		__get_str(driver),
		__get_str(device),
		__entry->len
	)
);

DECLARE_EVENT_CLASS(ath10k_payload_event,
		    TP_PROTO(struct ath10k *ar, const void *data, size_t len),

	TP_ARGS(ar, data, len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(size_t, len)
		__dynamic_array(u8, payload, (len -
					      ath10k_frm_hdr_len(data, len)))
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->len = len - ath10k_frm_hdr_len(data, len);
		memcpy(__get_dynamic_array(payload),
		       data + ath10k_frm_hdr_len(data, len), __entry->len);
	),

	TP_printk(
		"%s %s len %zu\n",
		__get_str(driver),
		__get_str(device),
		__entry->len
	)
);

DEFINE_EVENT(ath10k_hdr_event, ath10k_tx_hdr,
	     TP_PROTO(struct ath10k *ar, const void *data, size_t len),
	     TP_ARGS(ar, data, len)
);

DEFINE_EVENT(ath10k_payload_event, ath10k_tx_payload,
	     TP_PROTO(struct ath10k *ar, const void *data, size_t len),
	     TP_ARGS(ar, data, len)
);

DEFINE_EVENT(ath10k_hdr_event, ath10k_rx_hdr,
	     TP_PROTO(struct ath10k *ar, const void *data, size_t len),
	     TP_ARGS(ar, data, len)
);

DEFINE_EVENT(ath10k_payload_event, ath10k_rx_payload,
	     TP_PROTO(struct ath10k *ar, const void *data, size_t len),
	     TP_ARGS(ar, data, len)
);

TRACE_EVENT(ath10k_htt_rx_desc,
	    TP_PROTO(struct ath10k *ar, const void *data, size_t len),

	TP_ARGS(ar, data, len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u8, hw_type);
		__field(u16, len)
		__dynamic_array(u8, rxdesc, len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->hw_type = ar->hw_rev;
		__entry->len = len;
		memcpy(__get_dynamic_array(rxdesc), data, len);
	),

	TP_printk(
		"%s %s %d rxdesc len %d",
		__get_str(driver),
		__get_str(device),
		__entry->hw_type,
		__entry->len
	 )
);

TRACE_EVENT(ath10k_wmi_diag_container,
	    TP_PROTO(struct ath10k *ar,
		     u8 type,
		     u32 timestamp,
		     u32 code,
		     u16 len,
		     const void *data),

	TP_ARGS(ar, type, timestamp, code, len, data),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u8, type)
		__field(u32, timestamp)
		__field(u32, code)
		__field(u16, len)
		__dynamic_array(u8, data, len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->type = type;
		__entry->timestamp = timestamp;
		__entry->code = code;
		__entry->len = len;
		memcpy(__get_dynamic_array(data), data, len);
	),

	TP_printk(
		"%s %s diag container type %hhu timestamp %u code %u len %d",
		__get_str(driver),
		__get_str(device),
		__entry->type,
		__entry->timestamp,
		__entry->code,
		__entry->len
	)
);

TRACE_EVENT(ath10k_wmi_diag,
	    TP_PROTO(struct ath10k *ar, const void *data, size_t len),

	TP_ARGS(ar, data, len),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__string(driver, dev_driver_string(ar->dev))
		__field(u16, len)
		__dynamic_array(u8, data, len)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__assign_str(driver, dev_driver_string(ar->dev));
		__entry->len = len;
		memcpy(__get_dynamic_array(data), data, len);
	),

	TP_printk(
		"%s %s tlv diag len %d",
		__get_str(driver),
		__get_str(device),
		__entry->len
	)
);

TRACE_EVENT(ath10k_update_delay_stats,
	    TP_PROTO(struct ath10k *ar, struct sk_buff *skb, u32 now,
		     u32 enqueue_time, u32 delay, u8 ac),

	TP_ARGS(ar, skb, now, enqueue_time, delay, ac),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		__field(void *, skb)
		__field(u32, now)
		__field(u32, enqueue_time)
		__field(u32, delay)
		__field(u8, ac)
	),

	TP_fast_assign(
		__assign_str(device, dev_name(ar->dev));
		__entry->skb = skb;
		__entry->now = now;
		__entry->enqueue_time = enqueue_time;
		__entry->delay = delay;
		__entry->ac = ac;
	),

	TP_printk(
		"%s: skb:%p enq:%u tx_done:%u, delay:%u ms ac:%d",
		__get_str(device),
		__entry->skb,
		__entry->enqueue_time,
		__entry->now,
		__entry->delay,
		__entry->ac
	)
);

#define MAC_ENTRY(entry_mac) __array(u8, entry_mac, ETH_ALEN)
#define MAC_ASSIGN(entry_mac, given_mac) do {			     \
	if (given_mac)						     \
		memcpy(__entry->entry_mac, given_mac, ETH_ALEN);     \
	else							     \
		eth_zero_addr(__entry->entry_mac);		     \
	} while (0)
#define MAC_PR_FMT "%pMF"
#define MAC_PR_ARG(entry_mac) (__entry->entry_mac)

TRACE_EVENT(ath10k_atf_upd,
	    TP_PROTO(struct ath10k *ar, u32 airtime, struct sk_buff *skb,
		     struct ieee80211_txq *txq),

	TP_ARGS(ar, airtime, skb, txq),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		MAC_ENTRY(mac_addr)
		__field(u32, len)
		__field(u32, airtime)
		__field(u32, bitrate)
		__field(int, deficit)
		__field(int, total_airtime_pending)
		__field(int, total_frames)
		__field(void *, skb)
		__field(int, txq_airtime)
		__field(int, txq_frames)
		__field(u8, tid)
	),

	TP_fast_assign(
		struct atf_scheduler *atf;
		struct ath10k_txq *artxq;

		artxq = (void *)txq->drv_priv;
		atf = &artxq->atf;
		__assign_str(device, dev_name(ar->dev));
		__entry->len = skb->len;
		__entry->airtime = airtime;

		__entry->deficit = atf->deficit;
		__entry->tid = txq->tid;
		__entry->txq_airtime = atf->airtime_inflight;
		__entry->txq_frames = atf->frames_inflight;
		__entry->total_airtime_pending  = ar->airtime_inflight;
		__entry->total_frames = ar->htt.num_pending_tx;

		__entry->skb = skb;
		if (txq->sta) {
			__entry->bitrate = txq->sta->last_tx_bitrate;
			MAC_ASSIGN(mac_addr, txq->sta->addr);
		} else {
			__entry->bitrate = 60;
			MAC_ASSIGN(mac_addr, txq->sta);
		}
	),

	TP_printk(
		"%s: sta mac: " MAC_PR_FMT " tid:%d skb:%p len:%d AT:%u rate:%u"
		" deficit:%d TOT:%d %d TXQ:%d %d",
		__get_str(device),
		MAC_PR_ARG(mac_addr),
		__entry->tid,
		__entry->skb,
		__entry->len,
		__entry->airtime,
		__entry->bitrate,
		__entry->deficit,
		__entry->total_airtime_pending,
		__entry->total_frames,
		__entry->txq_airtime,
		__entry->txq_frames
	)
);

TRACE_EVENT(ath10k_atf_tx_complete,
	    TP_PROTO(struct ath10k *ar, struct sk_buff *skb, u32 airtime,
		     struct ieee80211_txq *txq),

	TP_ARGS(ar, skb, airtime, txq),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		MAC_ENTRY(mac_addr)
		__field(u32, airtime)
		__field(u32, len)
		__field(int, deficit)
		__field(int, total_airtime_pending)
		__field(int, total_frames)
		__field(void *, skb)
		__field(int, txq_airtime)
		__field(int, txq_frames)
		__field(u8, tid)
	),

	TP_fast_assign(
		struct atf_scheduler *atf;
		struct ath10k_txq *artxq;

		artxq = (void *)txq->drv_priv;
		atf = &artxq->atf;
		__assign_str(device, dev_name(ar->dev));
		__entry->airtime = airtime;

		__entry->deficit = atf->deficit;
		__entry->tid = txq->tid;
		__entry->txq_airtime = atf->airtime_inflight;
		__entry->txq_frames = atf->frames_inflight;

		__entry->total_airtime_pending  = ar->airtime_inflight;
		__entry->total_frames = ar->htt.num_pending_tx;
		__entry->skb = skb;
		if (skb)
			__entry->len = skb->len;

		if (txq->sta)
			MAC_ASSIGN(mac_addr, txq->sta->addr);
		else
			MAC_ASSIGN(mac_addr, txq->sta);
	),

	TP_printk(
		"%s: sta mac: " MAC_PR_FMT " tid:%d skb:%p len:%d AT:%u"
		" deficit:%d TOT:%d %d  TXQ:%d %d",
		__get_str(device),
		MAC_PR_ARG(mac_addr),
		__entry->tid,
		__entry->skb,
		__entry->len,
		__entry->airtime,
		__entry->deficit,
		__entry->total_airtime_pending,
		__entry->total_frames,
		__entry->txq_airtime,
		__entry->txq_frames
	)
);

TRACE_EVENT(ath10k_atf_refill_deficit,
	    TP_PROTO(struct ath10k *ar, struct ieee80211_txq *txq, bool reset),

	TP_ARGS(ar, txq, reset),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		MAC_ENTRY(mac_addr)
		__field(int, deficit)
		__field(int, total_airtime_pending)
		__field(u32, total_frames)
		__field(int, txq_airtime)
		__field(u32, txq_frames)
		__field(u32, txq_bytes_send)
		__field(u32, total_bytes_send)
		__field(u8, tid)
		__field(bool, reset)
	),
	TP_fast_assign(
		struct atf_scheduler *atf;
		struct ath10k_txq *artxq;

		artxq = (void *)txq->drv_priv;
		atf = &artxq->atf;
		__assign_str(device, dev_name(ar->dev));
		__entry->deficit = atf->deficit;
		__entry->tid = txq->tid;
		__entry->txq_airtime = atf->airtime_inflight;
		__entry->txq_frames = atf->frames_inflight;
		__entry->txq_bytes_send = atf->bytes_send_last_interval;
		__entry->total_bytes_send = ar->atf_bytes_send_last_interval;
		__entry->reset = reset;

		__entry->total_airtime_pending  = ar->airtime_inflight;
		__entry->total_frames = ar->htt.num_pending_tx;
		if (txq->sta)
			MAC_ASSIGN(mac_addr, txq->sta->addr);
		else
			MAC_ASSIGN(mac_addr, txq->sta);
	),

	TP_printk(
		"%s: sta mac: " MAC_PR_FMT " tid:%d deficit:%d TOT:%d %d"
		" TXQ:%d %d reset:%d bytes_send:%u %u",
		__get_str(device),
		MAC_PR_ARG(mac_addr),
		__entry->tid,
		__entry->deficit,
		__entry->total_airtime_pending,
		__entry->total_frames,
		__entry->txq_airtime,
		__entry->txq_frames,
		__entry->reset,
		__entry->total_bytes_send,
		__entry->txq_bytes_send
	)
);

TRACE_EVENT(ath10k_htt_rx_tx_fetch_ind,
	    TP_PROTO(struct ath10k *ar, int i, u16 peer_id, u32 max_num_msdus,
		     u32 max_bytes, u32 num_msdus, u32 bytes,
		     struct ieee80211_txq *txq),

	TP_ARGS(ar, i, peer_id, max_num_msdus, max_bytes, num_msdus, bytes,
		txq),

	TP_STRUCT__entry(
		__string(device, dev_name(ar->dev))
		MAC_ENTRY(mac_addr)
		__field(int, i)
		__field(u16, peer_id)
		__field(u8, tid)
		__field(u32, max_num_msdus)
		__field(u32, max_bytes)
		__field(u32, num_msdus)
		__field(u32, bytes)
		__field(int, deficit)
		__field(int, total_airtime_pending)
		__field(int, total_frames)
		__field(int, txq_airtime)
		__field(int, txq_frames)
		__field(u32, txq_bytes_send)
		__field(u32, total_bytes_send)
	),

	TP_fast_assign(
		struct atf_scheduler *atf;
		struct ath10k_txq *artxq;

		artxq = (void *)txq->drv_priv;
		atf = &artxq->atf;
		__assign_str(device, dev_name(ar->dev));
		__entry->i = i;
		__entry->peer_id = peer_id;
		__entry->tid = txq->tid;
		__entry->max_num_msdus  = max_num_msdus;
		__entry->max_bytes  = max_bytes;
		__entry->num_msdus  = num_msdus;
		__entry->bytes  = bytes;
		__entry->deficit = atf->deficit;
		__entry->txq_frames = atf->frames_inflight;
		__entry->txq_airtime = atf->airtime_inflight;
		__entry->txq_bytes_send = atf->bytes_send_last_interval;
		__entry->total_bytes_send = ar->atf_bytes_send_last_interval;
		__entry->total_airtime_pending  = ar->airtime_inflight;
		__entry->total_frames = ar->htt.num_pending_tx;
		if (txq->sta)
			MAC_ASSIGN(mac_addr, txq->sta->addr);
		else
			MAC_ASSIGN(mac_addr, txq->sta);
	),

	TP_printk(
		"%s record %d sta mac: " MAC_PR_FMT "peer_id %hu tid %hhu "
		"max_msdus %zu max_bytes %zu msdus %zu bytes %zu deficit:%d "
		"TOT:%d %d TXQ:%d %d bytes_send:%u %u\n",
		__get_str(device),
		__entry->i,
		MAC_PR_ARG(mac_addr),
		__entry->peer_id,
		__entry->tid,
		__entry->max_num_msdus,
		__entry->max_bytes,
		__entry->num_msdus,
		__entry->bytes,
		__entry->deficit,
		__entry->total_airtime_pending,
		__entry->total_frames,
		__entry->txq_airtime,
		__entry->txq_frames,
		__entry->total_bytes_send,
		__entry->txq_bytes_send
	)
);
#endif /* _TRACE_H_ || TRACE_HEADER_MULTI_READ*/

/* we don't want to use include/trace/events */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
