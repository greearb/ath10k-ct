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

#ifndef _CORE_H_
#define _CORE_H_

#include <linux/completion.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/uuid.h>
#include <linux/time.h>

#include "htt.h"
#include "htc.h"
#include "hw.h"
#include "targaddrs.h"
#include "wmi.h"
#include "../ath.h"
#include "../regd.h"
#include "../dfs_pattern_detector.h"
#include "spectral.h"
#include "thermal.h"
#include "wow.h"
#include "swap.h"

#define MS(_v, _f) (((_v) & _f##_MASK) >> _f##_LSB)
#define SM(_v, _f) (((_v) << _f##_LSB) & _f##_MASK)
#define WO(_f)      ((_f##_OFFSET) >> 2)

#define ATH10K_SCAN_ID 0
#define WMI_READY_TIMEOUT (5 * HZ)
#define ATH10K_FLUSH_TIMEOUT_HZ (5 * HZ)
#define ATH10K_CONNECTION_LOSS_HZ (3 * HZ)
#define ATH10K_NUM_CHANS 39

/* Antenna noise floor */
#define ATH10K_DEFAULT_NOISE_FLOOR -95

#define ATH10K_MAX_NUM_MGMT_PENDING 128

/* number of failed packets (20 packets with 16 sw reties each) */
#define DEFAULT_ATH10K_KICKOUT_THRESHOLD (20 * 16)

/*
 * Use insanely high numbers to make sure that the firmware implementation
 * won't start, we have the same functionality already in hostapd. Unit
 * is seconds.
 */
#define ATH10K_KEEPALIVE_MIN_IDLE 3747
#define ATH10K_KEEPALIVE_MAX_IDLE 3895
#define ATH10K_KEEPALIVE_MAX_UNRESPONSIVE 3900

/* Backports related crap */
#ifdef STANDALONE_CT_CHAOS_CALMER
/* So, maybe 4.4 era or so...  This will give compile warnings,
 * but it should work fine.
 */
#define NUM_NL80211_BANDS IEEE80211_NUM_BANDS
#define CT_PRE_NUM_NL80211_BANDS
#endif


struct ath10k;

enum ath10k_bus {
	ATH10K_BUS_PCI,
	ATH10K_BUS_AHB,
};

static inline const char *ath10k_bus_str(enum ath10k_bus bus)
{
	switch (bus) {
	case ATH10K_BUS_PCI:
		return "pci";
	case ATH10K_BUS_AHB:
		return "ahb";
	}

	return "unknown";
}

enum ath10k_skb_flags {
	ATH10K_SKB_F_NO_HWCRYPT = BIT(0),
	ATH10K_SKB_F_DTIM_ZERO = BIT(1),
	ATH10K_SKB_F_DELIVER_CAB = BIT(2),
	ATH10K_SKB_F_MGMT = BIT(3),
	ATH10K_SKB_F_QOS = BIT(4),
};

struct ath10k_skb_cb {
	dma_addr_t paddr;
	u8 flags;
	u8 eid;
	u16 msdu_id;
	struct ieee80211_vif *vif;
	struct ieee80211_txq *txq;
} __packed;

struct ath10k_skb_rxcb {
	dma_addr_t paddr;
	struct hlist_node hlist;
};

static inline struct ath10k_skb_cb *ATH10K_SKB_CB(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ath10k_skb_cb) >
		     IEEE80211_TX_INFO_DRIVER_DATA_SIZE);
	return (struct ath10k_skb_cb *)&IEEE80211_SKB_CB(skb)->driver_data;
}

static inline struct ath10k_skb_rxcb *ATH10K_SKB_RXCB(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ath10k_skb_rxcb) > sizeof(skb->cb));
	return (struct ath10k_skb_rxcb *)skb->cb;
}

#define ATH10K_RXCB_SKB(rxcb) \
		container_of((void *)rxcb, struct sk_buff, cb)

static inline u32 host_interest_item_address(u32 item_offset)
{
	return QCA988X_HOST_INTEREST_ADDRESS + item_offset;
}

struct ath10k_bmi {
	bool done_sent;
};

struct ath10k_mem_chunk {
	void *vaddr;
	dma_addr_t paddr;
	u32 len;
	u32 req_id;
};

struct ath10k_wmi {
	enum ath10k_htc_ep_id eid;
	struct completion service_ready;
	struct completion unified_ready;
	struct completion barrier;
	wait_queue_head_t tx_credits_wq;
	DECLARE_BITMAP(svc_map, WMI_SERVICE_MAX);
	struct wmi_cmd_map *cmd;
	struct wmi_vdev_param_map *vdev_param;
	struct wmi_pdev_param_map *pdev_param;
	const struct wmi_ops *ops;
	const struct wmi_peer_flags_map *peer_flags;

	u32 num_mem_chunks;
	u32 rx_decap_mode;
	struct ath10k_mem_chunk mem_chunks[WMI_MAX_MEM_REQS];
};

struct ath10k_fw_stats_peer {
	struct list_head list;

	u8 peer_macaddr[ETH_ALEN];
	u32 peer_rssi;
	u32 peer_tx_rate;
	u32 peer_rx_rate; /* 10x only */
	u32 rx_duration;
};

struct ath10k_fw_stats_vdev {
	struct list_head list;

	u32 vdev_id;
	u32 beacon_snr;
	u32 data_snr;
	u32 num_tx_frames[4];
	u32 num_rx_frames;
	u32 num_tx_frames_retries[4];
	u32 num_tx_frames_failures[4];
	u32 num_rts_fail;
	u32 num_rts_success;
	u32 num_rx_err;
	u32 num_rx_discard;
	u32 num_tx_not_acked;
	u32 tx_rate_history[10];
	u32 beacon_rssi_history[10];
};

struct ath10k_fw_stats_pdev {
	struct list_head list;

	/* PDEV stats */
	s32 ch_noise_floor;
	u32 tx_frame_count; /* cycles spent transmitting frames */
	u32 rx_frame_count; /* cycles spent receiving frames */
	u32 rx_clear_count; /* Total channel busy time, evidently */
	u32 cycle_count; /* Total on-channel time */
	u32 phy_err_count;
	u32 chan_tx_power;
	u32 ack_rx_bad;
	u32 rts_bad;
	u32 rts_good;
	u32 fcs_bad;
	u32 no_beacons;
	u32 mib_int_count;

	/* PDEV TX stats */
	s32 comp_queued;
	s32 comp_delivered;
	s32 msdu_enqued;
	s32 mpdu_enqued;
	s32 wmm_drop;
	s32 local_enqued;
	s32 local_freed;
	s32 hw_queued;
	s32 hw_reaped;
	s32 underrun;
	u32 hw_paused;
	s32 tx_abort;
	s32 mpdus_requed;
	u32 tx_ko;
	u32 data_rc;
	u32 self_triggers;
	u32 sw_retry_failure;
	u32 illgl_rate_phy_err;
	u32 pdev_cont_xretry;
	u32 pdev_tx_timeout;
	u32 pdev_resets;
	u32 phy_underrun;
	u32 txop_ovf;
	u32 seq_posted;
	u32 seq_failed_queueing;
	u32 seq_completed;
	u32 seq_restarted;
	u32 mu_seq_posted;
	u32 mpdus_sw_flush;
	u32 mpdus_hw_filter;
	u32 mpdus_truncated;
	u32 mpdus_ack_failed;
	u32 mpdus_expired;

	/* PDEV RX stats */
	s32 mid_ppdu_route_change;
	s32 status_rcvd;
	s32 r0_frags;
	s32 r1_frags;
	s32 r2_frags;
	s32 r3_frags;
	s32 htt_msdus;
	s32 htt_mpdus;
	s32 loc_msdus;
	s32 loc_mpdus;
	s32 oversize_amsdu;
	s32 phy_errs;
	s32 phy_err_drop;
	s32 mpdu_errs;
	s32 rx_ovfl_errs;
};

struct ath10k_fw_stats {
	struct list_head pdevs;
	struct list_head vdevs;
	struct list_head peers;

	/* Register and related dump, CT firmware only. */
	u32 mac_filter_addr_l32;
	u32 mac_filter_addr_u16;
	u32 dcu_slot_time;
	u32 phy_bb_mode_select;
	u32 pcu_bssid_l32;
	u32 pcu_bssid_u16;
	u32 pcu_bssid2_l32;
	u32 pcu_bssid2_u16;
	u32 pcu_sta_addr_l32;
	u32 pcu_sta_addr_u16;
	u32 mac_dma_cfg;
	u32 mac_dma_txcfg;
	u32 pcu_rxfilter;
	u32 phy_bb_gen_controls;
	u32 dma_imr;
	u32 dma_txrx_imr;
	u32 sw_powermode;
	u16 sw_chainmask_tx;
	u16 sw_chainmask_rx;
	u32 sw_opmode;
	u32 sw_rxfilter;
	u32 short_retries; // RTS packet retries
	u32 long_retries; // Data packet retries
	u32 adc_temp; /* ADC Temperature readings, one octet for each chain.
		       * Value of 0x78 for 2,3 means not-read/not-active,
		       * and 0x7B for 0,1 mean means the same.
		       */
};

#define ATH10K_TPC_TABLE_TYPE_FLAG	1
#define ATH10K_TPC_PREAM_TABLE_END	0xFFFF

struct ath10k_tpc_table {
	u32 pream_idx[WMI_TPC_RATE_MAX];
	u8 rate_code[WMI_TPC_RATE_MAX];
	char tpc_value[WMI_TPC_RATE_MAX][WMI_TPC_TX_N_CHAIN * WMI_TPC_BUF_SIZE];
};

struct ath10k_tpc_stats {
	u32 reg_domain;
	u32 chan_freq;
	u32 phy_mode;
	u32 twice_antenna_reduction;
	u32 twice_max_rd_power;
	s32 twice_antenna_gain;
	u32 power_limit;
	u32 num_tx_chain;
	u32 ctl;
	u32 rate_max;
	u8 flag[WMI_TPC_FLAG];
	struct ath10k_tpc_table tpc_table[WMI_TPC_FLAG];
};

struct ath10k_dfs_stats {
	u32 phy_errors;
	u32 pulses_total;
	u32 pulses_detected;
	u32 pulses_discarded;
	u32 radar_detected;
};

#define ATH10K_MAX_NUM_PEER_IDS (1 << 11) /* htt rx_desc limit */

struct ath10k_peer {
	struct list_head list;
	struct ieee80211_vif *vif;
	struct ieee80211_sta *sta;

	bool removed;
	int vdev_id;
	u8 addr[ETH_ALEN];
	DECLARE_BITMAP(peer_ids, ATH10K_MAX_NUM_PEER_IDS);

	/* protected by ar->data_lock */
	struct ieee80211_key_conf *keys[WMI_MAX_KEY_INDEX + 1];
};

struct ath10k_txq {
	struct list_head list;
	unsigned long num_fw_queued;
	unsigned long num_push_allowed;
};

struct ath10k_sta {
	struct ath10k_vif *arvif;

	/* the following are protected by ar->data_lock */
	u32 changed; /* IEEE80211_RC_* */
	u32 bw;
	u32 nss;
	u32 smps;
	u16 peer_id;

	struct work_struct update_wk;

#ifdef CONFIG_MAC80211_DEBUGFS
	/* protected by conf_mutex */
	bool aggr_mode;
	u64 rx_duration;
#endif
};

#define ATH10K_VDEV_SETUP_TIMEOUT_HZ (5 * HZ)

enum ath10k_beacon_state {
	ATH10K_BEACON_SCHEDULED = 0,
	ATH10K_BEACON_SENDING,
	ATH10K_BEACON_SENT,
};

struct ath10k_vif {
	struct list_head list;

	u32 vdev_id;
	u16 peer_id;
	enum wmi_vdev_type vdev_type;
	enum wmi_vdev_subtype vdev_subtype;
	u32 beacon_interval;
	u32 dtim_period;
	struct sk_buff *beacon;
	/* protected by data_lock */
	enum ath10k_beacon_state beacon_state;
	void *beacon_buf;
	dma_addr_t beacon_paddr;
	unsigned long tx_paused; /* arbitrary values defined by target */

	struct ath10k *ar;
	struct ieee80211_vif *vif;

	bool is_started;
	bool is_up;
	bool spectral_enabled;
	bool ps;
	u32 aid;
	u8 bssid[ETH_ALEN];

	struct ieee80211_key_conf *wep_keys[WMI_MAX_KEY_INDEX + 1];
	s8 def_wep_key_idx;

	u16 tx_seq_no;

	union {
		struct {
			u32 uapsd;
		} sta;
		struct {
			/* 512 stations */
			u8 tim_bitmap[64];
			u8 tim_len;
			u32 ssid_len;
			u8 ssid[IEEE80211_MAX_SSID_LEN];
			bool hidden_ssid;
			/* P2P_IE with NoA attribute for P2P_GO case */
			u32 noa_len;
			u8 *noa_data;
		} ap;
	} u;

	bool use_cts_prot;
	bool nohwcrypt; /* actual setting, based on firmware abilities, etc. */
	int num_legacy_stations;
	int txpower;
	/* Firmware allows configuring rate of each of these traffic types.
	 * 0xFF will mean value has not been set by user, and in that case,
	 * we will auto-adjust the rates based on the legacy rate mask.
	 **/
	u8 mcast_rate[NUM_NL80211_BANDS];
	u8 bcast_rate[NUM_NL80211_BANDS];
	u8 mgt_rate[NUM_NL80211_BANDS];
	struct wmi_wmm_params_all_arg wmm_params;
	struct work_struct ap_csa_work;
	struct delayed_work connection_loss_work;
	struct cfg80211_bitrate_mask bitrate_mask;
};

struct ath10k_vif_iter {
	u32 vdev_id;
	struct ath10k_vif *arvif;
};

/* This will store at least the last 128 entries.  Each dbglog message
 * is a max of 7 32-bit integers in length, but the length can be less
 * than that as well.
 */
#define ATH10K_DBGLOG_DATA_LEN (128 * 7)
struct ath10k_dbglog_entry_storage {
	u32 head_idx; /* Where to write next chunk of data */
	u32 tail_idx; /* Index of first msg */
	__le32 data[ATH10K_DBGLOG_DATA_LEN];
};

/* Just enough info to decode firmware debug-log argument length */
#define DBGLOG_NUM_ARGS_OFFSET           26
#define DBGLOG_NUM_ARGS_MASK             0xFC000000 /* Bit 26-31 */
#define DBGLOG_NUM_ARGS_MAX              5 /* firmware tool chain limit */

/* estimated values, hopefully these are enough */
#define ATH10K_ROM_BSS_BUF_LEN 30000
#define ATH10K_RAM_BSS_BUF_LEN 55000

/* used for crash-dump storage, protected by data-lock */
struct ath10k_fw_crash_data {
	bool crashed_since_read;

	uuid_le uuid;
	struct timespec timestamp;
	__le32 registers[REG_DUMP_COUNT_QCA988X];
	__le32 stack_buf[ATH10K_FW_STACK_SIZE / sizeof(__le32)];
	__le32 exc_stack_buf[ATH10K_FW_STACK_SIZE / sizeof(__le32)];
	__le32 stack_addr;
	__le32 exc_stack_addr;
	__le32 rom_bss_buf[ATH10K_ROM_BSS_BUF_LEN / sizeof(__le32)];
	__le32 ram_bss_buf[ATH10K_RAM_BSS_BUF_LEN / sizeof(__le32)];
};

struct ath10k_debug {
	struct dentry *debugfs_phy;

	struct ath10k_fw_stats fw_stats;
	struct completion fw_stats_complete;
	bool fw_stats_done;

	unsigned long htt_stats_mask;
	struct delayed_work htt_stats_dwork;
	struct delayed_work nop_dwork;
	struct ath10k_dfs_stats dfs_stats;
	struct ath_dfs_pool_stats dfs_pool_stats;

	/* used for tpc-dump storage, protected by data-lock */
	struct ath10k_tpc_stats *tpc_stats;

	struct completion tpc_complete;

	/* protected by conf_mutex */
	u32 fw_dbglog_mask;
	u32 fw_dbglog_level;
	u32 pktlog_filter;
	u32 reg_addr;
	u32 nf_cal_period;
	u32 nop_id;

	struct ath10k_dbglog_entry_storage dbglog_entry_data;

	struct ath10k_fw_crash_data *fw_crash_data;

	/* These counters are kept in software. */
	u64 rx_bytes; /* counter, total received bytes */

	u32 tx_ok; /* counter, OK tx status count. */
	u32 tx_noack; /* counter, no-ack tx status count. */
	u32 tx_discard; /* counter, discard tx status count. */
	u64 tx_ok_bytes;
	u64 tx_noack_bytes;
	u64 tx_discard_bytes;
	u64 tx_bytes; /* counter, total sent to firmware */
};

enum ath10k_state {
	ATH10K_STATE_OFF = 0,
	ATH10K_STATE_ON,

	/* When doing firmware recovery the device is first powered down.
	 * mac80211 is supposed to call in to start() hook later on. It is
	 * however possible that driver unloading and firmware crash overlap.
	 * mac80211 can wait on conf_mutex in stop() while the device is
	 * stopped in ath10k_core_restart() work holding conf_mutex. The state
	 * RESTARTED means that the device is up and mac80211 has started hw
	 * reconfiguration. Once mac80211 is done with the reconfiguration we
	 * set the state to STATE_ON in reconfig_complete(). */
	ATH10K_STATE_RESTARTING,
	ATH10K_STATE_RESTARTED,

	/* The device has crashed while restarting hw. This state is like ON
	 * but commands are blocked in HTC and -ECOMM response is given. This
	 * prevents completion timeouts and makes the driver more responsive to
	 * userspace commands. This is also prevents recursive recovery. */
	ATH10K_STATE_WEDGED,

	/* factory tests */
	ATH10K_STATE_UTF,
};

enum ath10k_firmware_mode {
	/* the default mode, standard 802.11 functionality */
	ATH10K_FIRMWARE_MODE_NORMAL,

	/* factory tests etc */
	ATH10K_FIRMWARE_MODE_UTF,
};

enum ath10k_fw_features {
	/* wmi_mgmt_rx_hdr contains extra RSSI information */
	ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX = 0,

	/* Firmware from 10X branch. Deprecated, don't use in new code. */
	ATH10K_FW_FEATURE_WMI_10X = 1,

	/* firmware support tx frame management over WMI, otherwise it's HTT */
	ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX = 2,

	/* Firmware does not support P2P */
	ATH10K_FW_FEATURE_NO_P2P = 3,

	/* Firmware 10.2 feature bit. The ATH10K_FW_FEATURE_WMI_10X feature
	 * bit is required to be set as well. Deprecated, don't use in new
	 * code.
	 */
	ATH10K_FW_FEATURE_WMI_10_2 = 4,

	/* Some firmware revisions lack proper multi-interface client powersave
	 * implementation. Enabling PS could result in connection drops,
	 * traffic stalls, etc.
	 */
	ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT = 5,

	/* Some firmware revisions have an incomplete WoWLAN implementation
	 * despite WMI service bit being advertised. This feature flag is used
	 * to distinguish whether WoWLAN is really supported or not.
	 */
	ATH10K_FW_FEATURE_WOWLAN_SUPPORT = 6,

	/* Don't trust error code from otp.bin */
	ATH10K_FW_FEATURE_IGNORE_OTP_RESULT = 7,

	/* Some firmware revisions pad 4th hw address to 4 byte boundary making
	 * it 8 bytes long in Native Wifi Rx decap.
	 */
	ATH10K_FW_FEATURE_NO_NWIFI_DECAP_4ADDR_PADDING = 8,

	/* Firmware supports bypassing PLL setting on init. */
	ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT = 9,

	/* Raw mode support. If supported, FW supports receiving and trasmitting
	 * frames in raw mode.
	 */
	ATH10K_FW_FEATURE_RAW_MODE_SUPPORT = 10,

	/* Firmware Supports Adaptive CCA*/
	ATH10K_FW_FEATURE_SUPPORTS_ADAPTIVE_CCA = 11,

	/* Firmware supports management frame protection */
	ATH10K_FW_FEATURE_MFP_SUPPORT = 12,

	/* Firmware supports pull-push model where host shares it's software
	 * queue state with firmware and firmware generates fetch requests
	 * telling host which queues to dequeue tx from.
	 *
	 * Primary function of this is improved MU-MIMO performance with
	 * multiple clients.
	 */
	ATH10K_FW_FEATURE_PEER_FLOW_CONTROL = 13,

	/* tx-status has the noack bits (CT firmware version 14 and higher ) */
	ATH10K_FW_FEATURE_HAS_TXSTATUS_NOACK = 30,

	/* Firmware from Candela Technologies, enables more VIFs, etc */
	ATH10K_FW_FEATURE_WMI_10X_CT = 31,

	/* Firmware from Candela Technologies with rx-software-crypt.
	 * Required for multiple stations connected to same AP when using
	 * encryption (ie, commercial version of CT firmware) */
	ATH10K_FW_FEATURE_CT_RXSWCRYPT = 32,

	/* Firmware supports extended wmi_common_peer_assoc_complete_cmd that contains
	 * an array of rate-disable masks.  This allows the host to have better control
	 * over what rates the firmware will use.  CT Firmware only (v15 and higher)
	 */
	ATH10K_FW_FEATURE_CT_RATEMASK = 33,

	/* Versions of firmware before approximately 10.2.4.72 would corrupt txop fields
	 * during burst.  Since this is fixed now, add a flag to denote this.
	 */
	ATH10K_FW_FEATURE_HAS_SAFE_BURST = 34,

	/* Register-dump is supported. */
	ATH10K_FW_FEATURE_REGDUMP_CT = 35,

	/* TX-Rate is reported. */
	ATH10K_FW_FEATURE_TXRATE_CT = 36,

	/* Firmware can flush all peers. */
	ATH10K_FW_FEATURE_FLUSH_ALL_CT = 37,

	/* Firmware can read memory with ping-pong protocol. */
	ATH10K_FW_FEATURE_PINGPONG_READ_CT = 38,

	/* Firmware can skip channel reservation. */
	ATH10K_FW_FEATURE_SKIP_CH_RES_CT = 39,

	/* Firmware supports NOPcan skip channel reservation. */
	ATH10K_FW_FEATURE_NOP_CT = 40,

	/* Firmware supports CT HTT MGT feature. */
	ATH10K_FW_FEATURE_HTT_MGT_CT = 41,

	/* Set-special cmd-id is supported. */
	ATH10K_FW_FEATURE_SET_SPECIAL_CT = 42,

	/* SW Beacon Miss is disabled in this kernel, so you have to
	 * let mac80211 manage the connection.
	 */
	ATH10K_FW_FEATURE_NO_BMISS_CT = 43,

	/* keep last */
	ATH10K_FW_FEATURE_COUNT,
};

enum ath10k_dev_flags {
	/* Indicates that ath10k device is during CAC phase of DFS */
	ATH10K_CAC_RUNNING,
	ATH10K_FLAG_CORE_REGISTERED,

	/* Device has crashed and needs to restart. This indicates any pending
	 * waiters should immediately cancel instead of waiting for a time out.
	 */
	ATH10K_FLAG_CRASH_FLUSH,

	/* Use Raw mode instead of native WiFi Tx/Rx encap mode.
	 * Raw mode supports both hardware and software crypto. Native WiFi only
	 * supports hardware crypto.
	 */
	ATH10K_FLAG_RAW_MODE,

	/* Disable HW crypto engine */
	ATH10K_FLAG_HW_CRYPTO_DISABLED,

	/* Bluetooth coexistance enabled */
	ATH10K_FLAG_BTCOEX,

	/* Per Station statistics service */
	ATH10K_FLAG_PEER_STATS,
};

enum ath10k_cal_mode {
	ATH10K_CAL_MODE_FILE,
	ATH10K_CAL_MODE_OTP,
	ATH10K_CAL_MODE_DT,
	ATH10K_PRE_CAL_MODE_FILE,
	ATH10K_PRE_CAL_MODE_DT,
	ATH10K_CAL_MODE_EEPROM,
};

enum ath10k_crypt_mode {
	/* Only use hardware crypto engine */
	ATH10K_CRYPT_MODE_HW,
	/* Only use software crypto engine */
	ATH10K_CRYPT_MODE_SW,
};

static inline const char *ath10k_cal_mode_str(enum ath10k_cal_mode mode)
{
	switch (mode) {
	case ATH10K_CAL_MODE_FILE:
		return "file";
	case ATH10K_CAL_MODE_OTP:
		return "otp";
	case ATH10K_CAL_MODE_DT:
		return "dt";
	case ATH10K_PRE_CAL_MODE_FILE:
		return "pre-cal-file";
	case ATH10K_PRE_CAL_MODE_DT:
		return "pre-cal-dt";
	case ATH10K_CAL_MODE_EEPROM:
		return "eeprom";
	}

	return "unknown";
}

enum ath10k_scan_state {
	ATH10K_SCAN_IDLE,
	ATH10K_SCAN_STARTING,
	ATH10K_SCAN_RUNNING,
	ATH10K_SCAN_ABORTING,
};

static inline const char *ath10k_scan_state_str(enum ath10k_scan_state state)
{
	switch (state) {
	case ATH10K_SCAN_IDLE:
		return "idle";
	case ATH10K_SCAN_STARTING:
		return "starting";
	case ATH10K_SCAN_RUNNING:
		return "running";
	case ATH10K_SCAN_ABORTING:
		return "aborting";
	}

	return "unknown";
}

enum ath10k_tx_pause_reason {
	ATH10K_TX_PAUSE_Q_FULL,
	ATH10K_TX_PAUSE_MAX,
};

struct ath10k_fw_file {
	const struct firmware *firmware;
	char fw_name[100];
	char fw_board_name[100];

	char fw_version[ETHTOOL_FWVERS_LEN];

	DECLARE_BITMAP(fw_features, ATH10K_FW_FEATURE_COUNT);

	enum ath10k_fw_wmi_op_version wmi_op_version;
	enum ath10k_fw_htt_op_version htt_op_version;

	const void *firmware_data;
	size_t firmware_len;

	const void *otp_data;
	size_t otp_len;

	const void *codeswap_data;
	size_t codeswap_len;

	/* These are written to only during first firmware load from user
	 * space so no need for any locking.
	 */
	u32 ram_bss_addr;
	u32 ram_bss_len;
	u32 rom_bss_addr;
	u32 rom_bss_len;
};

struct ath10k_fw_components {
	const struct firmware *board;
	const void *board_data;
	size_t board_len;

	struct ath10k_fw_file fw_file;
};

#if defined CONFIG_DMAR_TABLE && !defined STANDALONE_CT
#define MAX_DMA_DBG_ENTRIES 5000
struct dma_dbg_entry {
	unsigned long long addr;
	unsigned long long at; /* jiffies */
	unsigned long len;
	const char* type;
};

void ath10k_dbg_dma_map(struct ath10k* ar, unsigned long long addr, unsigned long len, const char* dbg);
#else
#define ath10k_dbg_dma_map(a, b, c, d) /* NOP */
#endif

struct ath10k {
	struct ath_common ath_common;
	struct ieee80211_hw *hw;
	struct ieee80211_ops *ops;
	struct device *dev;
	u8 mac_addr[ETH_ALEN];

#if defined CONFIG_DMAR_TABLE && !defined STANDALONE_CT
	unsigned int next_dma_dbg_idx;
	struct dma_dbg_entry dma_dbg[MAX_DMA_DBG_ENTRIES];
#endif

	struct ieee80211_iface_combination if_comb[8];

	enum ath10k_hw_rev hw_rev;
	u16 dev_id;
	bool fw_powerup_failed; /* If true, might take reboot to recover. */
	u32 chip_id;
	u32 target_version;
	u8 fw_version_major;
	bool use_swcrypt; /* Firmware (and driver) supports rx-sw-crypt? */
	u32 fw_version_minor;
	u16 fw_version_release;
	u16 fw_version_build;
	u32 fw_stats_req_mask;
	u32 phy_capability;
	u32 hw_min_tx_power;
	u32 hw_max_tx_power;
	u32 ht_cap_info;
	u32 vht_cap_info;
	u32 num_rf_chains;
	u32 max_spatial_stream;
	/* protected by conf_mutex */
	bool ani_enabled;

	bool p2p;
	bool ct_all_pkts_htt; /* CT firmware only: native-wifi for all pkts */

	struct {
		enum ath10k_bus bus;
		const struct ath10k_hif_ops *ops;
	} hif;

	struct completion target_suspend;

	const struct ath10k_hw_regs *regs;
	const struct ath10k_hw_values *hw_values;
	struct ath10k_bmi bmi;
	struct ath10k_wmi wmi;
	struct ath10k_htc htc;
	struct ath10k_htt htt;

	struct ath10k_hw_params {
		u32 id;
		u16 dev_id;
		const char *name;
		u32 patch_load_addr;
		int uart_pin;
		u32 otp_exe_param;

		/* This is true if given HW chip has a quirky Cycle Counter
		 * wraparound which resets to 0x7fffffff instead of 0. All
		 * other CC related counters (e.g. Rx Clear Count) are divided
		 * by 2 so they never wraparound themselves.
		 */
		bool has_shifted_cc_wraparound;

		/* Some of chip expects fragment descriptor to be continuous
		 * memory for any TX operation. Set continuous_frag_desc flag
		 * for the hardware which have such requirement.
		 */
		bool continuous_frag_desc;

		u32 channel_counters_freq_hz;

		/* Mgmt tx descriptors threshold for limiting probe response
		 * frames.
		 */
		u32 max_probe_resp_desc_thres;

		/* The padding bytes's location is different on various chips */
		enum ath10k_hw_4addr_pad hw_4addr_pad;

		u32 tx_chain_mask;
		u32 rx_chain_mask;
		u32 max_spatial_stream;
		u32 cal_data_len;

		struct ath10k_hw_params_fw {
			const char *dir;
			const char *board;
			size_t board_size;
			size_t board_ext_size;
		} fw;

		const struct ath10k_hw_ops *hw_ops;
	} hw_params;

	/* contains the firmware images used with ATH10K_FIRMWARE_MODE_NORMAL */
	struct ath10k_fw_components normal_mode_fw;

	/* READ-ONLY images of the running firmware, which can be either
	 * normal or UTF. Do not modify, release etc!
	 */
	const struct ath10k_fw_components *running_fw;

	const struct firmware *pre_cal_file;
	const struct firmware *cal_file;

	const struct firmware *fwcfg_file;
	struct {
#define ATH10K_FWCFG_FWVER          (1<<0)
#define ATH10K_FWCFG_VDEVS          (1<<1)
#define ATH10K_FWCFG_PEERS          (1<<2)
#define ATH10K_FWCFG_STATIONS       (1<<3)
#define ATH10K_FWCFG_NOHWCRYPT      (1<<4)
#define ATH10K_FWCFG_RATE_CTRL_OBJS (1<<5)
#define ATH10K_FWCFG_TX_DESC        (1<<6)
#define ATH10K_FWCFG_MAX_NSS        (1<<7)
#define ATH10K_FWCFG_NUM_TIDS       (1<<8)
#define ATH10K_FWCFG_ACTIVE_PEERS   (1<<9)
#define ATH10K_FWCFG_SKID_LIMIT     (1<<10)
#define ATH10K_FWCFG_REGDOM         (1<<11)
#define ATH10K_FWCFG_BMISS_VDEVS    (1<<12)
#define ATH10K_FWCFG_MAX_AMSDUS     (1<<13)

		u32 flags; /* let us know which fields have been set */
		char calname[100];
		char fwname[100];
		char bname[100]; /* board file name */
		u32 fwver;
		u32 vdevs;
		u32 stations;
		u32 peers;
		u32 nohwcrypt;
		u32 rate_ctrl_objs;
		u32 tx_desc; /* max_num_pending_tx descriptors */
		u32 max_nss; /* max_spatial_stream */
		u32 num_tids;
		u32 active_peers;
		u32 skid_limit;
		int regdom;
		u32 bmiss_vdevs; /* To disable, set to 0 */
		u32 max_amsdus;
	} fwcfg;

	struct {
		struct ath10k_swap_code_seg_info *firmware_swap_code_seg_info;
	} swap;

	struct {
		u32 vendor;
		u32 device;
		u32 subsystem_vendor;
		u32 subsystem_device;

		bool bmi_ids_valid;
		u8 bmi_board_id;
		u8 bmi_chip_id;
	} id;

	int fw_api;
	int bd_api;
	enum ath10k_cal_mode cal_mode;

	struct {
		struct completion started;
		struct completion completed;
		struct completion on_channel;
		struct delayed_work timeout;
		enum ath10k_scan_state state;
		bool is_roc;
		int vdev_id;
		int roc_freq;
		bool roc_notify;
	} scan;

	struct {
		struct ieee80211_supported_band sbands[NUM_NL80211_BANDS];
	} mac;

	/* should never be NULL; needed for regular htt rx */
	struct ieee80211_channel *rx_channel;

	/* valid during scan; needed for mgmt rx during scan */
	struct ieee80211_channel *scan_channel;

	/* current operating channel definition */
	struct cfg80211_chan_def chandef;

	/* currently configured operating channel in firmware */
	struct ieee80211_channel *tgt_oper_chan;

	unsigned long long free_vdev_map;
	struct ath10k_vif *monitor_arvif;
	bool monitor;
	int monitor_vdev_id;
	bool monitor_started;
	unsigned int filter_flags;
	unsigned long dev_flags;
	bool dfs_block_radar_events;
	int install_key_rv; /* Store error code from key-install */

	/* protected by conf_mutex */
	bool radar_enabled;
	int num_started_vdevs;
	u32 sta_xretry_kickout_thresh;

	/* Protected by conf-mutex */
	u8 cfg_tx_chainmask;
	u8 cfg_rx_chainmask;

	struct completion install_key_done;

	struct completion vdev_setup_done;

	struct workqueue_struct *workqueue;
	/* Auxiliary workqueue */
	struct workqueue_struct *workqueue_aux;

	/* prevents concurrent FW reconfiguration */
	struct mutex conf_mutex;

	/* protects shared structure data */
	spinlock_t data_lock;
	/* protects: ar->txqs, artxq->list */
	spinlock_t txqs_lock;

	struct list_head txqs;
	struct list_head arvifs;
	struct list_head peers;
	struct ath10k_peer *peer_map[ATH10K_MAX_NUM_PEER_IDS];
	wait_queue_head_t peer_mapping_wq;

	/* protected by conf_mutex */
	int num_peers;
	int num_stations;

	int max_num_peers;
	int max_num_stations;
	int max_num_vdevs;
	int max_num_tdls_vdevs;
	int num_active_peers;
	int num_tids;
	bool request_nohwcrypt; /* desired setting */
	u32 num_ratectrl_objs;
	u32 skid_limit;
	u32 bmiss_offload_max_vdev;
	int eeprom_regdom;

	struct work_struct svc_rdy_work;
	struct sk_buff *svc_rdy_skb;

	struct work_struct offchan_tx_work;
	struct sk_buff_head offchan_tx_queue;
	struct completion offchan_tx_completed;
	struct sk_buff *offchan_tx_skb;

	struct work_struct wmi_mgmt_tx_work;
	struct sk_buff_head wmi_mgmt_tx_queue;

	enum ath10k_state state;

	struct work_struct register_work;
	struct work_struct restart_work;

	/* cycle count is reported twice for each visited channel during scan.
	 * access protected by data_lock */
	u32 survey_last_rx_clear_count;
	u32 survey_last_cycle_count;
	struct survey_info survey[ATH10K_NUM_CHANS];

	/* Channel info events are expected to come in pairs without and with
	 * COMPLETE flag set respectively for each channel visit during scan.
	 *
	 * However there are deviations from this rule. This flag is used to
	 * avoid reporting garbage data.
	 */
	bool ch_info_can_report_survey;
	struct completion bss_survey_done;

	struct dfs_pattern_detector *dfs_detector;

	unsigned long tx_paused; /* see ATH10K_TX_PAUSE_ */

#ifdef CONFIG_ATH10K_DEBUGFS
	struct ath10k_debug debug;
	struct {
		/* relay(fs) channel for spectral scan */
		struct rchan *rfs_chan_spec_scan;

		/* spectral_mode and spec_config are protected by conf_mutex */
		enum ath10k_spectral_mode mode;
		struct ath10k_spec_scan config;
	} spectral;
#endif

	struct {
		/* protected by conf_mutex */
		struct ath10k_fw_components utf_mode_fw;

		/* protected by data_lock */
		bool utf_monitor;
	} testmode;

	struct {
		/* protected by data_lock */
		u32 fw_crash_counter;
		u32 fw_warm_reset_counter;
		u32 fw_cold_reset_counter;
	} stats;

	struct ath10k_thermal thermal;
	struct ath10k_wow wow;

	/* Index 0 is for 5Ghz, index 1 is for 2.4Ghz, CT firmware only. */
	/* be sure to flush this to firmware after resets */
	/* Includes various other backdoor hacks as well. */
	struct {
		struct {
#define MIN_CCA_PWR_COUNT 3
			u16 minCcaPwrCT[MIN_CCA_PWR_COUNT]; /* 0 means don't-set */
			u8 noiseFloorThresh; /* 0 means don't-set */
			/* Have to set this to 2 before minCcaPwr settings will be active.
			 * Values:  0  don't-set, 1 disable, 2 enable
			 */
			u8 enable_minccapwr_thresh;
		} bands[2];
		u8 thresh62_ext;
		u8 rc_rate_max_per_thr; /* Firmware rate-ctrl alg. tuning. */
		u8 tx_sta_bw_mask; /* 0:  all, 0x1: 20Mhz, 0x2 40Mhz, 0x4 80Mhz */
		bool allow_ibss_amsdu;
		bool rifs_enable_override;
		u16 max_txpower;
		u16 pdev_xretry_th; /* Max failed retries before wifi chip is reset, 10.1 firmware default is 0x40 */
		u32 wmi_wd_keepalive_ms; /* 0xFFFFFFFF means disable, otherwise, FW will assert after X ms of not receiving
					  * a NOP keepalive from the driver.  Suggested value is 0xFFFFFFFF, or 8000+.
					  * 0 means use whatever firmware defaults to (probably 8000).
					  * Units are actually 1/1024 of a second, but pretty close to ms, at least.
					  */
		u32 ct_pshack;
		u32 ct_csi;
	} eeprom_overrides;

	struct work_struct set_coverage_class_work;
	/* protected by conf_mutex */
	struct {
		/* writing also protected by data_lock */
		s16 coverage_class;

		u32 reg_phyclk;
		u32 reg_slottime_conf;
		u32 reg_slottime_orig;
		u32 reg_ack_cts_timeout_conf;
		u32 reg_ack_cts_timeout_orig;
	} fw_coverage;

	/* must be last */
	u8 drv_priv[0] __aligned(sizeof(void *));
};

static inline bool ath10k_peer_stats_enabled(struct ath10k *ar)
{
	if (test_bit(ATH10K_FLAG_PEER_STATS, &ar->dev_flags) &&
	    test_bit(WMI_SERVICE_PEER_STATS, ar->wmi.svc_map))
		return true;

	return false;
}

#define MAX_AR 50
extern struct ath10k* ar_array[MAX_AR];

struct ath10k *ath10k_core_create(size_t priv_size, struct device *dev,
				  enum ath10k_bus bus,
				  enum ath10k_hw_rev hw_rev,
				  const struct ath10k_hif_ops *hif_ops);
void ath10k_core_destroy(struct ath10k *ar);
void ath10k_core_get_fw_features_str(struct ath10k *ar,
				     char *buf,
				     size_t max_len);
int ath10k_core_fetch_firmware_api_n(struct ath10k *ar, const char *name,
				     struct ath10k_fw_file *fw_file);

int ath10k_core_start(struct ath10k *ar, enum ath10k_firmware_mode mode,
		      const struct ath10k_fw_components *fw_components);
int ath10k_wait_for_suspend(struct ath10k *ar, u32 suspend_opt);
void ath10k_core_stop(struct ath10k *ar);
int ath10k_core_register(struct ath10k *ar, u32 chip_id);
void ath10k_core_unregister(struct ath10k *ar);
void ath10k_core_free_limits(struct ath10k* ar);

#endif /* _CORE_H_ */
