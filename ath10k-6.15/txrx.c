// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2016 Qualcomm Atheros, Inc.
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 */

#include "core.h"
#include "txrx.h"
#include "htt.h"
#include "mac.h"
#include "debug.h"

static void ath10k_report_offchan_tx(struct ath10k *ar, struct sk_buff *skb)
{
	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(skb);

	if (likely(!(info->flags & IEEE80211_TX_CTL_TX_OFFCHAN)))
		return;

	if (ath10k_mac_tx_frm_has_freq(ar))
		return;

	/* If the original wait_for_completion() timed out before
	 * {data,mgmt}_tx_completed() was called then we could complete
	 * offchan_tx_completed for a different skb. Prevent this by using
	 * offchan_tx_skb.
	 */
	spin_lock_bh(&ar->data_lock);
	if (ar->offchan_tx_skb != skb) {
		ath10k_warn(ar, "completed old offchannel frame\n");
		goto out;
	}

	complete(&ar->offchan_tx_completed);
	ar->offchan_tx_skb = NULL; /* just for sanity */

	ath10k_dbg(ar, ATH10K_DBG_HTT, "completed offchannel skb %pK\n", skb);
out:
	spin_unlock_bh(&ar->data_lock);
}

static u8 cck_rateidx[] = {
	3, 2 , 1, 0
};
#define cck_rateidx_size (ARRAY_SIZE(cck_rateidx))

static u8 ofdm_rateidx[] = {
	10, 8 , 6, 4, 11, 9, 7, 5
};
#define ofdm_rateidx_size (ARRAY_SIZE(ofdm_rateidx))

static void ath10k_set_tx_rate_status(struct ath10k *ar,
				      struct ieee80211_tx_rate *rate,
				      const struct htt_tx_done *tx_done)
{
	struct ieee80211_channel *ch = ar->scan_channel;
	u8 nss = (tx_done->tx_rate_code >> 4) & 0x3;
	u8 hw_rate = tx_done->tx_rate_code & 0xF;

	if (!ch)
		ch = ar->rx_channel;

	if (tx_done->mpdus_failed) {
		if (tx_done->status == HTT_TX_COMPL_STATE_ACK) {
			/* We failed some, but then succeeded (+1) */
			rate->count = tx_done->mpdus_failed + 1;
		}
		else {
			/* We failed all of them */
			rate->count = tx_done->mpdus_failed;
		}
	}
	else {
		rate->count = 1;
	}
	rate->idx = -1; /* Will set it properly below if rate-code is sane. */

	/* NOTE:  We see reports of '24Mbps 40Mhz' tx rates often reported when we force
	 * OFDM (24Mbps, etc) legacy tx rate when station is configured for (V)HT 40 on channel
	 * 11.  One possibility is that the rate-flags are not reported correctly,
	 * but also maybe it is a real issue on the air somehow?  Evidently, it is
	 * possible to transmit an OFDM frame at 40Mhz when RTS/CTS is being used.
	 */

	switch ((tx_done->tx_rate_code >> 6) & 0x3) {
	case WMI_RATE_PREAMBLE_CCK:
		if (likely(hw_rate < cck_rateidx_size))
			rate->idx = cck_rateidx[hw_rate];
		else
			rate->idx = cck_rateidx[0];

		if (ch && (ch->band == NL80211_BAND_5GHZ)) {
			/* Not expecting CCK rates here at all, and rate->idx will be related
			 * to OFDM, so print warning and continue.  At least kernel logs will show
			 * indication of true rate.
			 */
			static unsigned long next_jiffies = 0;
			if (next_jiffies == 0 || time_after(jiffies, next_jiffies)) {
				ath10k_warn(ar, "CCK rate reported on 5Ghz, hw_rate: %d  rate-idx: %d  Speed: %s\n",
					    hw_rate, rate->idx, cck_speed_by_idx[rate->idx]);
				next_jiffies = jiffies + HZ;
			}
		}
		break;

        case WMI_RATE_PREAMBLE_OFDM:
		if (likely(hw_rate < ofdm_rateidx_size))
			rate->idx = ofdm_rateidx[hw_rate];
		else
			rate->idx = ofdm_rateidx[4];

		/* If we are on 5Ghz, then idx must be decreased by
		 * 4 since the CCK rates are not available on 5Ghz.
		 */
		if (ch && (ch->band == NL80211_BAND_5GHZ))
			rate->idx -= 4;
		break;
	}/* switch OFDM/CCK */

	if ((tx_done->tx_rate_code & 0xcc) == 0x44)
		rate->flags |= IEEE80211_TX_RC_USE_SHORT_PREAMBLE;

	if ((tx_done->tx_rate_code & 0xc0) == 0x80) {
		rate->flags |= IEEE80211_TX_RC_MCS;
		rate->idx = hw_rate + (nss * 8);
	}

	if ((tx_done->tx_rate_code & 0xc0) == 0xc0) {
		rate->flags |= IEEE80211_TX_RC_VHT_MCS;
		/* TODO-BEN:  Not sure this is correct. */
		rate->idx = (nss << 4) | hw_rate;
		WARN_ONCE(((hw_rate > 9) || (nss > 3)), "Invalid VHT rate, nss: %d  hw_rate: %d ratecode: %d\n",
			  nss, hw_rate, tx_done->tx_rate_code);
	}

	if (tx_done->tx_rate_flags & ATH10K_RC_FLAG_40MHZ)
		rate->flags |= IEEE80211_TX_RC_40_MHZ_WIDTH;
	if (tx_done->tx_rate_flags & ATH10K_RC_FLAG_80MHZ)
		rate->flags |= IEEE80211_TX_RC_80_MHZ_WIDTH;
	if (tx_done->tx_rate_flags & ATH10K_RC_FLAG_160MHZ)
		rate->flags |= IEEE80211_TX_RC_160_MHZ_WIDTH;
	if (tx_done->tx_rate_flags & ATH10K_RC_FLAG_SGI)
		rate->flags |= IEEE80211_TX_RC_SHORT_GI;
}

#if 0
static const char* tx_done_state_str(int i) {
	switch (i) {
	case HTT_TX_COMPL_STATE_NONE: return "NONE";
	case HTT_TX_COMPL_STATE_ACK: return "ACK";
	case HTT_TX_COMPL_STATE_NOACK: return "NOACK";
	case HTT_TX_COMPL_STATE_DISCARD: return "DISCARD";
	default: return "UNKNOWN";
	}
}
#endif

int ath10k_txrx_tx_unref(struct ath10k_htt *htt,
			 const struct htt_tx_done *tx_done)
{
	struct ieee80211_tx_status status;
	struct ath10k *ar = htt->ar;
	struct device *dev = ar->dev;
	struct ieee80211_tx_info *info;
	struct ieee80211_txq *txq;
	struct ath10k_skb_cb *skb_cb;
	struct ath10k_txq *artxq;
	struct sk_buff *msdu;
	u8 flags;
	bool tx_failed = false;

	ath10k_dbg(ar, ATH10K_DBG_HTT,
		   "htt tx completion msdu_id %u status %d\n",
		   tx_done->msdu_id, tx_done->status);

	if (tx_done->msdu_id >= htt->max_num_pending_tx) {
		ath10k_warn(ar, "warning: msdu_id %d too big, ignoring\n",
			    tx_done->msdu_id);
		return -EINVAL;
	}

	spin_lock_bh(&htt->tx_lock);
	msdu = idr_find(&htt->pending_tx, tx_done->msdu_id);
	if (!msdu) {
		ath10k_warn(ar, "received tx completion for invalid msdu_id: %d\n",
			    tx_done->msdu_id);
		spin_unlock_bh(&htt->tx_lock);
		return -ENOENT;
	}

	/*ath10k_warn(ar,
		    "tx_unref, msdu_id: %d len: %d  tx-rate-code: 0x%x tx-rate-flags: 0x%x  tried: %d  failed: %d ack-rssi: %d status: %d (%s)\n",
		    tx_done->msdu_id,
		    msdu->len,
		    tx_done->tx_rate_code,
		    tx_done->tx_rate_flags,
		    tx_done->mpdus_tried,
		    tx_done->mpdus_failed,
		    tx_done->ack_rssi,
		    tx_done->status, tx_done_state_str(tx_done->status));*/

	skb_cb = ATH10K_SKB_CB(msdu);
	txq = skb_cb->txq;

	if (txq) {
		artxq = (void *)txq->drv_priv;
		artxq->num_fw_queued--;
	}

	flags = skb_cb->flags;
	ath10k_htt_tx_free_msdu_id(htt, tx_done->msdu_id);
	ath10k_htt_tx_dec_pending(htt);
	spin_unlock_bh(&htt->tx_lock);

	rcu_read_lock();
	if (txq && txq->sta && skb_cb->airtime_est)
		ieee80211_sta_register_airtime(txq->sta, txq->tid,
					       skb_cb->airtime_est, 0);
	rcu_read_unlock();

	if (ar->bus_param.dev_type != ATH10K_DEV_TYPE_HL)
		dma_unmap_single(dev, skb_cb->paddr, msdu->len, DMA_TO_DEVICE);

	ath10k_report_offchan_tx(htt->ar, msdu);

	info = IEEE80211_SKB_CB(msdu);
	memset(&info->status, 0, sizeof(info->status));
	info->status.rates[0].idx = -1;

	trace_ath10k_txrx_tx_unref(ar, tx_done->msdu_id);

	if (!(info->flags & IEEE80211_TX_CTL_NO_ACK) &&
	    !(flags & ATH10K_SKB_F_NOACK_TID))
		info->flags |= IEEE80211_TX_STAT_ACK;

	if (tx_done->status == HTT_TX_COMPL_STATE_NOACK)
		tx_failed = true;

	if ((tx_done->status == HTT_TX_COMPL_STATE_ACK) &&
	    ((info->flags & IEEE80211_TX_CTL_NO_ACK) ||
	    (flags & ATH10K_SKB_F_NOACK_TID)))
		info->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;

	if (tx_done->status == HTT_TX_COMPL_STATE_DISCARD) {
		if ((info->flags & IEEE80211_TX_CTL_NO_ACK) ||
		    (flags & ATH10K_SKB_F_NOACK_TID))
			info->flags &= ~IEEE80211_TX_STAT_NOACK_TRANSMITTED;
#ifdef CONFIG_ATH10K_DEBUG
		ar->debug.tx_discard++;
		ar->debug.tx_discard_bytes += msdu->len;
#endif
		tx_failed = true;
	}

	if (tx_done->status == HTT_TX_COMPL_STATE_ACK &&
	    tx_done->ack_rssi != ATH10K_INVALID_RSSI) {
		int nf = ATH10K_DEFAULT_NOISE_FLOOR;
		int adjust = 0;
#ifdef CONFIG_ATH10K_DEBUGFS
		struct ieee80211_channel *ch = ar->scan_channel;
		if (!ch)
			ch = ar->rx_channel;

		if (ar->debug.nf_sum[0] != 0x80)
			nf = ar->debug.nf_sum[0];
		if (ar->debug.use_ofdm_peak_power && ch) {
			if (ch->band == NL80211_BAND_5GHZ)
				adjust = adjust_5[0];
			else
				adjust = adjust_24[0];
		}
#endif
		info->status.ack_signal = nf + tx_done->ack_rssi + adjust;
		info->status.flags |= IEEE80211_TX_STATUS_ACK_SIGNAL_VALID;
	}

	if (tx_done->tx_rate_code || tx_done->tx_rate_flags || ar->ok_tx_rate_status) {
		/* rate-code for 48Mbps is 0, with no flags, so we need to remember
		 * any other valid rates we might have seen and use that to know if
		 * firmware is sending tx rates.
		 */

		/* We have a better check for this in wave-1 firmware now */
		if ((!tx_done->mpdus_tried) && (!tx_done->tx_rate_code) && (!tx_done->tx_rate_flags)) {
			if (likely(test_bit(ATH10K_FW_FEATURE_TXRATE2_CT,
					    ar->running_fw->fw_file.fw_features))) {
				/* This firmware does not report rates for other than the first frame of
				 * an ampdu chain, so this check allows us to skip those (which previously
				 * resulting in a rate of 48Mbps reported.
				 */
				goto skip_reporting;
			}
		}

		ar->ok_tx_rate_status = true;
		ath10k_set_tx_rate_status(ar, &info->status.rates[0], tx_done);

		/* Only in version 14 and higher of CT firmware */
		if (test_bit(ATH10K_FW_FEATURE_HAS_TXSTATUS_NOACK,
			     ar->running_fw->fw_file.fw_features)) {
			/* Deal with tx-completion status */
			if ((tx_done->tx_rate_flags & 0x3) == ATH10K_RC_FLAG_XRETRY) {
#ifdef CONFIG_ATH10K_DEBUG
				ar->debug.tx_noack++;
				ar->debug.tx_noack_bytes += msdu->len;
#endif
				tx_failed = true;
			}
			/* TODO:  Report drops differently. */
			if ((tx_done->tx_rate_flags & 0x3) == ATH10K_RC_FLAG_DROP)
				tx_failed = true;
		}
	} else {
	skip_reporting:
		info->status.rates[0].idx = -1;
	}

	if (tx_failed) {
		info->flags &= ~IEEE80211_TX_STAT_ACK;
	}
#ifdef CONFIG_ATH10K_DEBUG
	else {
		ar->debug.tx_ok++;
		ar->debug.tx_ok_bytes += msdu->len;
	}
#endif

	memset(&status, 0, sizeof(status));
	status.skb = msdu;
	status.info = info;

	rcu_read_lock();

	if (txq)
		status.sta = txq->sta;

	ieee80211_tx_status_ext(htt->ar->hw, &status);

	rcu_read_unlock();

	/* we do not own the msdu anymore */

	return 0;
}

struct ath10k_peer *ath10k_peer_find(struct ath10k *ar, int vdev_id,
				     const u8 *addr)
{
	struct ath10k_peer *peer;

	lockdep_assert_held(&ar->data_lock);

	list_for_each_entry(peer, &ar->peers, list) {
		if (peer->vdev_id != vdev_id)
			continue;
		if (!ether_addr_equal(peer->addr, addr))
			continue;

		return peer;
	}

	return NULL;
}

struct ath10k_peer *ath10k_peer_find_by_id(struct ath10k *ar, int peer_id)
{
	struct ath10k_peer *peer;

	if (peer_id >= BITS_PER_TYPE(peer->peer_ids))
		return NULL;

	lockdep_assert_held(&ar->data_lock);

	list_for_each_entry(peer, &ar->peers, list)
		if (test_bit(peer_id, peer->peer_ids))
			return peer;

	return NULL;
}

static int ath10k_wait_for_peer_common(struct ath10k *ar, int vdev_id,
				       const u8 *addr, bool expect_mapped)
{
	long time_left;

	time_left = wait_event_timeout(ar->peer_mapping_wq, ({
			bool mapped;

			spin_lock_bh(&ar->data_lock);
			mapped = !!ath10k_peer_find(ar, vdev_id, addr);
			spin_unlock_bh(&ar->data_lock);

			(mapped == expect_mapped ||
			 test_bit(ATH10K_FLAG_CRASH_FLUSH, &ar->dev_flags));
		}), 1 * HZ);

	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

int ath10k_wait_for_peer_created(struct ath10k *ar, int vdev_id, const u8 *addr)
{
	return ath10k_wait_for_peer_common(ar, vdev_id, addr, true);
}

int ath10k_wait_for_peer_deleted(struct ath10k *ar, int vdev_id, const u8 *addr)
{
	return ath10k_wait_for_peer_common(ar, vdev_id, addr, false);
}

void ath10k_peer_map_event(struct ath10k_htt *htt,
			   struct htt_peer_map_event *ev)
{
	struct ath10k *ar = htt->ar;
	struct ath10k_peer *peer;

	if (ev->peer_id >= ATH10K_MAX_NUM_PEER_IDS) {
		ath10k_warn(ar,
			    "received htt peer map event with idx out of bounds: %u\n",
			    ev->peer_id);
		return;
	}

	spin_lock_bh(&ar->data_lock);
	peer = ath10k_peer_find(ar, ev->vdev_id, ev->addr);
	if (!peer) {
		peer = kzalloc(sizeof(*peer), GFP_ATOMIC);
		if (!peer)
			goto exit;

		peer->vdev_id = ev->vdev_id;
		ether_addr_copy(peer->addr, ev->addr);
		list_add(&peer->list, &ar->peers);
		wake_up(&ar->peer_mapping_wq);
	}

	ath10k_dbg(ar, ATH10K_DBG_HTT, "htt peer map vdev %d peer %pM id %d\n",
		   ev->vdev_id, ev->addr, ev->peer_id);

	WARN_ON(ar->peer_map[ev->peer_id] && (ar->peer_map[ev->peer_id] != peer));
	ar->peer_map[ev->peer_id] = peer;
	set_bit(ev->peer_id, peer->peer_ids);
exit:
	spin_unlock_bh(&ar->data_lock);
}

void ath10k_peer_unmap_event(struct ath10k_htt *htt,
			     struct htt_peer_unmap_event *ev)
{
	struct ath10k *ar = htt->ar;
	struct ath10k_peer *peer;

	if (ev->peer_id >= ATH10K_MAX_NUM_PEER_IDS) {
		ath10k_warn(ar,
			    "received htt peer unmap event with idx out of bounds: %u\n",
			    ev->peer_id);
		return;
	}

	spin_lock_bh(&ar->data_lock);
	peer = ath10k_peer_find_by_id(ar, ev->peer_id);
	if (!peer) {
		ath10k_warn(ar, "peer-unmap-event: unknown peer id %d\n",
			    ev->peer_id);
		/* ath10k_dump_peer_info(ar); */
		goto exit;
	}

	ath10k_dbg(ar, ATH10K_DBG_HTT, "removing peer, htt peer unmap vdev %d peer %pM id %d\n",
		   peer->vdev_id, peer->addr, ev->peer_id);

	ar->peer_map[ev->peer_id] = NULL;
	clear_bit(ev->peer_id, peer->peer_ids);

	if (bitmap_empty(peer->peer_ids, ATH10K_MAX_NUM_PEER_IDS)) {
		list_del(&peer->list);
		kfree(peer);
		wake_up(&ar->peer_mapping_wq);
	}

exit:
	spin_unlock_bh(&ar->data_lock);
}
