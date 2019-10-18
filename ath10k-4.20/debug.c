/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2017 Qualcomm Atheros, Inc.
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
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

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <linux/crc32.h>
#include <linux/firmware.h>

#include "core.h"
#include "debug.h"
#include "hif.h"
#include "wmi-ops.h"
#include "mac.h"

/* ms */
#define ATH10K_DEBUG_HTT_STATS_INTERVAL 1000

#define ATH10K_DEBUG_CAL_DATA_LEN 12064

#define ATH10K_DEBUG_NOP_INTERVAL 2000 /* ms */

void ath10k_info(struct ath10k *ar, const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;
	if (ath10k_debug_mask & ATH10K_DBG_INFO_AS_DBG)
		dev_printk(KERN_DEBUG, ar->dev, "%pV", &vaf);
	else
		dev_info(ar->dev, "%pV", &vaf);
	trace_ath10k_log_info(ar, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(ath10k_info);

void ath10k_debug_print_hwfw_info(struct ath10k *ar)
{
	const struct firmware *firmware;
	char fw_features[360] = {};
	u32 crc = 0;

	ath10k_core_get_fw_features_str(ar, fw_features, sizeof(fw_features));

	ath10k_info(ar, "%s target 0x%08x chip_id 0x%08x sub %04x:%04x",
		    ar->hw_params.name,
		    ar->target_version,
		    ar->chip_id,
		    ar->id.subsystem_vendor, ar->id.subsystem_device);

	ath10k_info(ar, "kconfig debug %d debugfs %d tracing %d dfs %d testmode %d\n",
		    IS_ENABLED(CONFIG_ATH10K_DEBUG),
		    IS_ENABLED(CONFIG_ATH10K_DEBUGFS),
		    IS_ENABLED(CONFIG_ATH10K_TRACING),
		    IS_ENABLED(CONFIG_ATH10K_DFS_CERTIFIED),
		    IS_ENABLED(CONFIG_NL80211_TESTMODE));

	firmware = ar->normal_mode_fw.fw_file.firmware;
	if (firmware)
		crc = crc32_le(0, firmware->data, firmware->size);

	ath10k_info(ar, "firmware ver %s api %d features %s crc32 %08x\n",
		    ar->hw->wiphy->fw_version,
		    ar->fw_api,
		    fw_features,
		    crc);
}

void ath10k_debug_print_board_info(struct ath10k *ar)
{
	char boardinfo[100];
	const struct firmware *board;
	u32 crc;

	if (ar->id.bmi_ids_valid)
		scnprintf(boardinfo, sizeof(boardinfo), "%d:%d",
			  ar->id.bmi_chip_id, ar->id.bmi_board_id);
	else
		scnprintf(boardinfo, sizeof(boardinfo), "N/A");

	board = ar->normal_mode_fw.board;
	if (!IS_ERR_OR_NULL(board))
		crc = crc32_le(0, board->data, board->size);
	else
		crc = 0xdeadbeef;

	ath10k_info(ar, "board_file api %d bmi_id %s crc32 %08x",
		    ar->bd_api,
		    boardinfo,
		    crc);
}

void ath10k_debug_print_boot_info(struct ath10k *ar)
{
	ath10k_info(ar, "htt-ver %d.%d wmi-op %d htt-op %d cal %s max-sta %d raw %d hwcrypto %d\n",
		    ar->htt.target_version_major,
		    ar->htt.target_version_minor,
		    ar->normal_mode_fw.fw_file.wmi_op_version,
		    ar->normal_mode_fw.fw_file.htt_op_version,
		    ath10k_cal_mode_str(ar->cal_mode),
		    ar->max_num_stations,
		    test_bit(ATH10K_FLAG_RAW_MODE, &ar->dev_flags),
		    !test_bit(ATH10K_FLAG_HW_CRYPTO_DISABLED, &ar->dev_flags));
}

void ath10k_print_driver_info(struct ath10k *ar)
{
	ath10k_debug_print_hwfw_info(ar);
	ath10k_debug_print_board_info(ar);
	ath10k_debug_print_boot_info(ar);
}
EXPORT_SYMBOL(ath10k_print_driver_info);

void ath10k_set_debug_mask(unsigned int v) {
	ath10k_debug_mask = v;
}
EXPORT_SYMBOL(ath10k_set_debug_mask);

void ath10k_err(struct ath10k *ar, const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;
	dev_err(ar->dev, "%pV", &vaf);
	trace_ath10k_log_err(ar, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(ath10k_err);

void ath10k_warn(struct ath10k *ar, const char *fmt, ...)
{
	struct va_format vaf = {
		.fmt = fmt,
	};
	va_list args;

	va_start(args, fmt);
	vaf.va = &args;
	dev_warn(ar->dev, "%pV", &vaf);
	trace_ath10k_log_warn(ar, &vaf);

	va_end(args);
}
EXPORT_SYMBOL(ath10k_warn);

#ifdef CONFIG_ATH10K_DEBUGFS

static ssize_t ath10k_read_wmi_services(struct file *file,
					char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char *buf;
	size_t len = 0, buf_len = 8192;
	const char *name;
	ssize_t ret_cnt;
	bool enabled;
	int i;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);

	spin_lock_bh(&ar->data_lock);
	for (i = 0; i < WMI_SERVICE_MAX; i++) {
		enabled = test_bit(i, ar->wmi.svc_map);
		name = wmi_service_name(i);

		if (!name) {
			if (enabled)
				len += scnprintf(buf + len, buf_len - len,
						 "%-40s %s (bit %d)\n",
						 "unknown", "enabled", i);

			continue;
		}

		len += scnprintf(buf + len, buf_len - len,
				 "%-40s %s\n",
				 name, enabled ? "enabled" : "-");
	}
	spin_unlock_bh(&ar->data_lock);

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	mutex_unlock(&ar->conf_mutex);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_wmi_services = {
	.read = ath10k_read_wmi_services,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_misc(struct file *file,
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char *buf;
	unsigned int len = 0, buf_len = 1000;
	ssize_t ret_cnt;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);

	if (len > buf_len)
		len = buf_len;

	/* Probably need some sort of locking on the tx-queue?? */
	len = snprintf(buf, 1000, "off-channel qlen: %d\n",
		       skb_queue_len(&ar->offchan_tx_queue));

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	mutex_unlock(&ar->conf_mutex);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_misc = {
	.read = ath10k_read_misc,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_fwinfo(struct file *file,
				  char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char *buf;
	unsigned int len = 0, buf_len = 1000;
	ssize_t ret_cnt;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);

	len = snprintf(buf, buf_len, "directory: %s\nfirmware:  %s\nfwcfg:     fwcfg-%s-%s.txt\nbus:       %s\nfeatures:  ",
		       ar->hw_params.fw.dir, ar->running_fw->fw_file.fw_name,
		       ath10k_bus_str(ar->hif.bus), dev_name(ar->dev), dev_name(ar->dev));
	ath10k_core_get_fw_features_str(ar, buf + len, buf_len - len);

	/* Just to be safe */
	buf[buf_len - 1] = 0;
	len = strlen(buf);

	len += snprintf(buf + len, buf_len - len, "\nversion:   %s\nhw_rev:    ",
			ar->hw->wiphy->fw_version);
	switch (ar->hw_rev) {
	case ATH10K_HW_QCA988X:
		len += snprintf(buf + len, buf_len - len, "988x\n");
		break;
	case ATH10K_HW_QCA9887:
		len += snprintf(buf + len, buf_len - len, "9887\n");
		break;
	case ATH10K_HW_QCA9888:
		len += snprintf(buf + len, buf_len - len, "9888\n");
		break;
	case ATH10K_HW_WCN3990:
		len += snprintf(buf + len, buf_len - len, "3990\n");
		break;
	case ATH10K_HW_QCA6174:
		len += snprintf(buf + len, buf_len - len, "6174\n");
		break;
	case ATH10K_HW_QCA99X0:
		len += snprintf(buf + len, buf_len - len, "99x0\n");
		break;
	case ATH10K_HW_QCA9984:
		len += snprintf(buf + len, buf_len - len, "9984\n");
		break;
	case ATH10K_HW_QCA9377:
		len += snprintf(buf + len, buf_len - len, "9377\n");
		break;
	case ATH10K_HW_QCA4019:
		len += snprintf(buf + len, buf_len - len, "4019\n");
		break;
	}

	len += snprintf(buf + len, buf_len - len, "board:     %s\n",
			ar->normal_mode_fw.fw_file.fw_board_name);

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	mutex_unlock(&ar->conf_mutex);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_fwinfo_services = {
	.read = ath10k_read_fwinfo,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_peers(struct file *file,
				 char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char *buf;
	unsigned int len = 0, buf_len = 10000;
	ssize_t ret_cnt;
	struct ath10k_peer *peer;
	int q;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);
	spin_lock_bh(&ar->data_lock);

	list_for_each_entry(peer, &ar->peers, list) {
		len += snprintf(buf + len, buf_len - len, "%pM  vdev-id: %d  peer-ids:",
				peer->addr, peer->vdev_id);
		for (q = 0; q<ATH10K_MAX_NUM_PEER_IDS; q++) {
			if (test_bit(q, peer->peer_ids)) {
				len += snprintf(buf + len, buf_len - len, " %d", q);
			}
		}
		len += snprintf(buf + len, buf_len - len, "\n");
	}

	spin_unlock_bh(&ar->data_lock);

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	mutex_unlock(&ar->conf_mutex);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_peers = {
	.read = ath10k_read_peers,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static void ath10k_fw_stats_pdevs_free(struct list_head *head)
{
	struct ath10k_fw_stats_pdev *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath10k_fw_stats_vdevs_free(struct list_head *head)
{
	struct ath10k_fw_stats_vdev *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath10k_fw_stats_peers_free(struct list_head *head)
{
	struct ath10k_fw_stats_peer *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath10k_fw_extd_stats_peers_free(struct list_head *head)
{
	struct ath10k_fw_extd_stats_peer *i, *tmp;

	list_for_each_entry_safe(i, tmp, head, list) {
		list_del(&i->list);
		kfree(i);
	}
}

static void ath10k_debug_fw_stats_reset(struct ath10k *ar)
{
	spin_lock_bh(&ar->data_lock);
	ar->debug.fw_stats_done = false;
	ar->debug.fw_stats.extended = false;
	ath10k_fw_stats_pdevs_free(&ar->debug.fw_stats.pdevs);
	ath10k_fw_stats_vdevs_free(&ar->debug.fw_stats.vdevs);
	ath10k_fw_stats_peers_free(&ar->debug.fw_stats.peers);
	ath10k_fw_extd_stats_peers_free(&ar->debug.fw_stats.peers_extd);
	spin_unlock_bh(&ar->data_lock);
}

void ath10k_debug_fw_ratepwr_table_process(struct ath10k *ar, struct sk_buff *skb)
{
	size_t sz = skb->len;
	if (sz != sizeof(struct qc988xxEepromRateTbl)) {
		ath10k_info(ar, "Invalid ratepwr table results length, expected: %d  got: %d\n",
			    (int)(sizeof(struct qc988xxEepromRateTbl)), (int)sz);
		sz = min(sz, sizeof(struct qc988xxEepromRateTbl));
	}
	memcpy(ar->debug.ratepwr_tbl.data, skb->data, sz);
	complete(&ar->debug.ratepwr_tbl_complete);
}

void ath10k_debug_fw_powerctl_table_process(struct ath10k *ar, struct sk_buff *skb)
{
	size_t sz = skb->len;
	if (sz != sizeof(struct qca9880_power_ctrl)) {
		ath10k_info(ar, "Invalid powerctl table results length, expected: %d  got: %d\n",
			    (int)(sizeof(struct qca9880_power_ctrl)), (int)sz);
		sz = min(sz, sizeof(struct qca9880_power_ctrl));
	}
	memcpy(ar->debug.powerctl_tbl.data, skb->data, sz);
	complete(&ar->debug.powerctl_tbl_complete);
}

void ath10k_debug_fw_stats_process(struct ath10k *ar, struct sk_buff *skb)
{
	struct ath10k_fw_stats stats = {};
	bool is_start, is_started, is_end;
	size_t num_peers;
	size_t num_vdevs;
	int ret;
	const struct wmi_stats_event *ev = (void *)skb->data;

	INIT_LIST_HEAD(&stats.pdevs);
	INIT_LIST_HEAD(&stats.vdevs);
	INIT_LIST_HEAD(&stats.peers);
	INIT_LIST_HEAD(&stats.peers_extd);

	spin_lock_bh(&ar->data_lock);

	/*ath10k_warn(ar, "fw-stats-process: stats-id: 0x%x(0x%x)\n", ev->stats_id, __le32_to_cpu(ev->stats_id));*/
	/* CT Firmware only */
	if (__le32_to_cpu(ev->stats_id) == WMI_REQUEST_STAT_CUSTOM) {
		__le32* data;
		u32 stats_len;
		u32 *my_stats = NULL;
		u32 my_len = 0;

		if ((ar->running_fw->fw_file.wmi_op_version == ATH10K_FW_WMI_OP_VERSION_10_2) ||
		    (ar->running_fw->fw_file.wmi_op_version == ATH10K_FW_WMI_OP_VERSION_10_4) ||
		    (ar->running_fw->fw_file.wmi_op_version == ATH10K_FW_WMI_OP_VERSION_10_2_4)) {
			const struct wmi_10_2_stats_event *ev2 = (void *)skb->data;
			data = (__le32*)(ev2->data);
			stats_len = (skb->len - sizeof(*ev2)) / 4;
		} else {
			/* Must be 10.1 */
			data = (__le32*)(ev->data);
			stats_len =  (skb->len - sizeof(*ev)) / 4;
		}

		if (ev->num_pdev_stats == WMI_STAT_CUSTOM_RX_REORDER_STATS) {
			my_len = sizeof(ar->debug.rx_reorder_stats) / 4;
			my_len = min(my_len, stats_len);
			my_stats = (u32*)(&(ar->debug.rx_reorder_stats));
		}

		/* If we know about the stats, handle it here. */
		if (my_stats) {
			int i;
			for (i = 0; i<my_len; i++) {
				my_stats[i] = __le32_to_cpu(data[i]);
			}
		}
		ar->debug.fw_stats_done = true;
		complete(&ar->debug.fw_stats_complete);
		/*ath10k_warn(ar, "Completed stat-custom, my_len: %u\n", my_len);*/
		goto free;
	}

	if (__le32_to_cpu(ev->stats_id) == WMI_REQUEST_REGISTER_DUMP) {
		struct ath10k_reg_dump* regdump;
		struct ath10k_fw_stats* sptr = &ar->debug.fw_stats;
		int i;

		if ((ar->running_fw->fw_file.wmi_op_version == ATH10K_FW_WMI_OP_VERSION_10_2) ||
		    (ar->running_fw->fw_file.wmi_op_version == ATH10K_FW_WMI_OP_VERSION_10_4) ||
		    (ar->running_fw->fw_file.wmi_op_version == ATH10K_FW_WMI_OP_VERSION_10_2_4)) {
			const struct wmi_10_2_stats_event *ev2 = (void *)skb->data;
			regdump = (struct ath10k_reg_dump*)(ev2->data);
		} else {
			/* Must be 10.1 */
			regdump = (struct ath10k_reg_dump*)(ev->data);
		}

		for (i = 0; i < __le16_to_cpu(regdump->count); i++) {
			u32 id = __le32_to_cpu(regdump->regpair[i].reg_id);
			switch (id) {
			case REG_DUMP_NONE:
				break;
			case MAC_FILTER_ADDR_L32:
				sptr->mac_filter_addr_l32 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case MAC_FILTER_ADDR_U16:
				sptr->mac_filter_addr_u16 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case DCU_SLOT_TIME:
				sptr->dcu_slot_time = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PHY_BB_MODE_SELECT:
				sptr->phy_bb_mode_select = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_BSSID_L32:
				sptr->pcu_bssid_l32 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_BSSID_U16:
				sptr->pcu_bssid_u16 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_BSSID2_L32:
				sptr->pcu_bssid2_l32 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_BSSID2_U16:
				sptr->pcu_bssid2_u16 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_STA_ADDR_U16:
				sptr->pcu_sta_addr_u16 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case MAC_DMA_CFG:
				sptr->mac_dma_cfg = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case MAC_DMA_TXCFG:
				sptr->mac_dma_txcfg = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_STA_ADDR_L32:
				sptr->pcu_sta_addr_l32 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_RXFILTER:
				sptr->pcu_rxfilter = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PHY_BB_GEN_CONTROLS:
				sptr->phy_bb_gen_controls = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case DMA_IMR:
				sptr->dma_imr = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case DMA_TXRX_IMR:
				sptr->dma_txrx_imr = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case SW_POWERMODE:
				sptr->sw_powermode = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case SW_CHAINMASK:
				sptr->sw_chainmask_tx = (__le32_to_cpu(regdump->regpair[i].reg_val) >> 16);
				sptr->sw_chainmask_rx = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case SW_OPMODE:
				sptr->sw_opmode = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case SW_RXFILTER:
				sptr->sw_rxfilter = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case SW_LONG_RETRIES:
				sptr->long_retries = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case SW_SHORT_RETRIES:
				sptr->short_retries = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case ADC_TEMP:
				sptr->adc_temp = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case NF_CHAINS:
				sptr->nfcal = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			default: {
				/* Foward-compat logic */
				int max_supported = DBG_REG_DUMP_COUNT + ARRAY_SIZE(sptr->extra_regs);
				if (id >= DBG_REG_DUMP_COUNT && id < max_supported) {
					sptr->extra_regs[id - DBG_REG_DUMP_COUNT] = regdump->regpair[i].reg_val;
					sptr->extras_count = max(sptr->extras_count, (int)(id - DBG_REG_DUMP_COUNT) + 1);
				}
				//ath10k_warn(ar, "dbg-regs, max-supported: %d  id: %d  extras-count: %d\n",
				//	    max_supported, id, sptr->extras_count);
			} /* default case */
			}/* switch */
		}
		ar->debug.fw_stats_done = true;
		complete(&ar->debug.fw_stats_complete);
		goto free;
	}

	ret = ath10k_wmi_pull_fw_stats(ar, skb, &stats);
	if (ret) {
		ath10k_warn(ar, "failed to pull fw stats: %d\n", ret);
		goto free;
	}

	/* Stat data may exceed htc-wmi buffer limit. In such case firmware
	 * splits the stats data and delivers it in a ping-pong fashion of
	 * request cmd-update event.
	 *
	 * However there is no explicit end-of-data. Instead start-of-data is
	 * used as an implicit one. This works as follows:
	 *  a) discard stat update events until one with pdev stats is
	 *     delivered - this skips session started at end of (b)
	 *  b) consume stat update events until another one with pdev stats is
	 *     delivered which is treated as end-of-data and is itself discarded
	 */
	if (ath10k_peer_stats_enabled(ar))
		ath10k_sta_update_rx_duration(ar, &stats);

	if (ar->debug.fw_stats_done) {
		if (!ath10k_peer_stats_enabled(ar))
			ath10k_warn(ar, "received unsolicited stats update event\n");

		goto free;
	}

	num_peers = ath10k_wmi_fw_stats_num_peers(&ar->debug.fw_stats.peers);
	num_vdevs = ath10k_wmi_fw_stats_num_vdevs(&ar->debug.fw_stats.vdevs);
	is_start = (list_empty(&ar->debug.fw_stats.pdevs) &&
		    !list_empty(&stats.pdevs));
	is_end = (!list_empty(&ar->debug.fw_stats.pdevs) &&
		  !list_empty(&stats.pdevs));

	if (is_start)
		list_splice_tail_init(&stats.pdevs, &ar->debug.fw_stats.pdevs);

	if (is_end)
		ar->debug.fw_stats_done = true;

	is_started = !list_empty(&ar->debug.fw_stats.pdevs);

	if (is_started && !is_end) {
		if (num_peers > ATH10K_MAX_NUM_PEER_IDS) {
			/* Although this is unlikely impose a sane limit to
			 * prevent firmware from DoS-ing the host.
			 */
			ath10k_fw_stats_peers_free(&ar->debug.fw_stats.peers);
			ath10k_fw_extd_stats_peers_free(&ar->debug.fw_stats.peers_extd);
			ath10k_warn(ar, "dropping fw peer stats, num_peers: %d  max-peer-ids: %d\n",
				    (int)(num_peers), (int)(ATH10K_MAX_NUM_PEER_IDS));
			goto free;
		}

		if (num_vdevs > BITS_PER_LONG) {
			ath10k_fw_stats_vdevs_free(&ar->debug.fw_stats.vdevs);
			ath10k_warn(ar, "dropping fw vdev stats, num-vdevs: %d, bits-per-long: %d\n",
				    (int)(num_vdevs), (int)(BITS_PER_LONG));
			goto free;
		}

		if (!list_empty(&stats.peers))
			list_splice_tail_init(&stats.peers_extd,
					      &ar->debug.fw_stats.peers_extd);

		list_splice_tail_init(&stats.peers, &ar->debug.fw_stats.peers);
		list_splice_tail_init(&stats.vdevs, &ar->debug.fw_stats.vdevs);
	}

	complete(&ar->debug.fw_stats_complete);

free:
	/* In some cases lists have been spliced and cleared. Free up
	 * resources if that is not the case.
	 */
	ath10k_fw_stats_pdevs_free(&stats.pdevs);
	ath10k_fw_stats_vdevs_free(&stats.vdevs);
	ath10k_fw_stats_peers_free(&stats.peers);
	ath10k_fw_extd_stats_peers_free(&stats.peers_extd);

	spin_unlock_bh(&ar->data_lock);
}

int ath10k_debug_fw_stats_request(struct ath10k *ar)
{
	unsigned long timeout;
	int ret;

	lockdep_assert_held(&ar->conf_mutex);

	timeout = jiffies + msecs_to_jiffies(1 * HZ);

	ath10k_debug_fw_stats_reset(ar);

	for (;;) {
		if (time_after(jiffies, timeout))
			return -ETIMEDOUT;

		ret = ath10k_refresh_peer_stats(ar);
		if (ret)
			return ret;

		spin_lock_bh(&ar->data_lock);
		if (ar->debug.fw_stats_done) {
			spin_unlock_bh(&ar->data_lock);
			break;
		}
		spin_unlock_bh(&ar->data_lock);
	}

	return 0;
}

static int ath10k_fw_stats_open(struct inode *inode, struct file *file)
{
	struct ath10k *ar = inode->i_private;
	void *buf = NULL;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH10K_FW_STATS_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	ret = ath10k_debug_fw_stats_request(ar);
	if (ret) {
		ath10k_warn(ar, "failed to request fw stats: %d\n", ret);
		goto err_free;
	}

	ret = ath10k_wmi_fw_stats_fill(ar, &ar->debug.fw_stats, buf);
	if (ret) {
		ath10k_warn(ar, "failed to fill fw stats: %d\n", ret);
		goto err_free;
	}

	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath10k_fw_stats_release(struct inode *inode, struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static int ath10k_refresh_peer_stats_t(struct ath10k *ar, u32 type, u32 specifier)
{
	int ret;
	unsigned long time_left;

	/*ath10k_warn(ar, "Requesting stats (type 0x%x specifier %d jiffies: %lu)\n",
	  type, specifier, jiffies);*/
	reinit_completion(&ar->debug.fw_stats_complete);
	ret = ath10k_wmi_request_stats(ar, type, specifier);

	if (ret) {
		ath10k_warn(ar, "could not request stats (type %d ret %d specifier %d)\n",
			    type, ret, specifier);
		return ret;
	}

	/* ret means 'time-left' here */
	time_left =
		wait_for_completion_timeout(&ar->debug.fw_stats_complete, 1*HZ);

	/* ath10k_warn(ar, "Requested stats (type 0x%x ret %d specifier %d jiffies: %lu  time-left: %lu)\n",
	   type, ret, specifier, jiffies, time_left);*/

	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

int ath10k_refresh_peer_stats(struct ath10k *ar)
{
	return ath10k_refresh_peer_stats_t(ar, ar->fw_stats_req_mask, 0);
}

int ath10k_refresh_target_regs(struct ath10k *ar)
{
	if (test_bit(ATH10K_FW_FEATURE_REGDUMP_CT,
		     ar->running_fw->fw_file.fw_features))
		return ath10k_refresh_peer_stats_t(ar, WMI_REQUEST_REGISTER_DUMP, 0);
	return 0; /* fail silently if firmware does not support this option. */
}

int ath10k_refresh_target_rx_reorder_stats(struct ath10k *ar)
{
	if (test_bit(ATH10K_FW_FEATURE_CUST_STATS_CT,
		     ar->running_fw->fw_file.fw_features))
		return ath10k_refresh_peer_stats_t(ar, WMI_REQUEST_STAT_CUSTOM, WMI_STAT_CUSTOM_RX_REORDER_STATS);
	return 0; /* fail silently if firmware does not support this option. */
}


static ssize_t ath10k_read_rx_reorder_stats(struct file *file, char __user *user_buf,
					    size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	struct ath10k_rx_reorder_stats *rrs;
	char *buf = NULL;
	unsigned int len = 0, buf_len = 8000;
	ssize_t ret_cnt = 0;
	int ret;

	mutex_lock(&ar->conf_mutex);

	rrs = &ar->debug.rx_reorder_stats;

	if (ar->state != ATH10K_STATE_ON)
		goto exit;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		goto exit;

	ret = ath10k_refresh_target_rx_reorder_stats(ar);
	if (ret)
		goto exit;

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%30s\n",
			 "ath10k RX Reorder Stats");
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

#define PRINT_MY_STATS(a) len += scnprintf(buf + len, buf_len - len, "%30s %10d\n", #a, rrs->a)
	/* Non QoS MPDUs received */
	PRINT_MY_STATS(deliver_non_qos);
	/* MPDUs received in-order */
	PRINT_MY_STATS(deliver_in_order);
	/* Flush due to reorder timer expired */
	PRINT_MY_STATS(deliver_flush_timeout);
	/* Flush due to move out of window */
	PRINT_MY_STATS(deliver_flush_oow);
	/* Flush due to DELBA */
	PRINT_MY_STATS(deliver_flush_delba);
	/* MPDUs dropped due to FCS error */
	PRINT_MY_STATS(fcs_error);
	/* MPDUs dropped due to monitor mode non-data packet */
	PRINT_MY_STATS(mgmt_ctrl);
	/* MPDUs dropped due to invalid peer */
	PRINT_MY_STATS(invalid_peer);
	/* MPDUs dropped due to duplication (non aggregation) */
	PRINT_MY_STATS(dup_non_aggr);
	/* MPDUs dropped due to processed before */
	PRINT_MY_STATS(dup_past);
	/* MPDUs dropped due to duplicate in reorder queue */
	PRINT_MY_STATS(dup_in_reorder);
	/* Reorder timeout happened */
	PRINT_MY_STATS(reorder_timeout);
	/* invalid bar ssn */
	PRINT_MY_STATS(invalid_bar_ssn);
	/* reorder reset due to bar ssn */
	PRINT_MY_STATS(ssn_reset);

	/* Added by Ben */
	PRINT_MY_STATS(frag_invalid_peer);
	PRINT_MY_STATS(frag_fcs_error);
	PRINT_MY_STATS(frag_ok);
	PRINT_MY_STATS(frag_discards);

	PRINT_MY_STATS(rx_chatter);
	PRINT_MY_STATS(tkip_mic_error);
	PRINT_MY_STATS(tkip_decrypt_error);
	PRINT_MY_STATS(mpdu_length_error);
	PRINT_MY_STATS(non_frag_unicast_ok);

	PRINT_MY_STATS(rx_flush_ind); // Flushed these due to timeout, etc.
	PRINT_MY_STATS(rx_flush_ie_add); // Flushed these due to timeout, etc

	/* Wave-2 specific */
	PRINT_MY_STATS(rx_mesh_wrong_dest);
	PRINT_MY_STATS(rx_mesh_filter_ra);
	PRINT_MY_STATS(rx_mesh_filter_fromds);
	PRINT_MY_STATS(rx_mesh_filter_tods);
	PRINT_MY_STATS(rx_mesh_filter_nods);
	PRINT_MY_STATS(rx_radar_fft_war);
	PRINT_MY_STATS(rx_drop_encrypt_required);
	PRINT_MY_STATS(rx_mpdu_tid_err);
	PRINT_MY_STATS(rx_ba_statemachine_err);
	PRINT_MY_STATS(rx_drop_replay);
	PRINT_MY_STATS(rx_non_data_drop_no_bufs);

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

exit:
	mutex_unlock(&ar->conf_mutex);
	kfree(buf);
	return ret_cnt;
}

static ssize_t ath10k_read_fw_regs(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	struct ath10k_fw_stats *fw_regs;
	char *buf = NULL;
	unsigned int len = 0, buf_len = 8000;
	ssize_t ret_cnt = 0;
	int ret;
	int i;

	fw_regs = &ar->debug.fw_stats;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON)
		goto exit;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		goto exit;

	ret = ath10k_refresh_target_regs(ar);
	if (ret)
		goto exit;

	spin_lock_bh(&ar->data_lock);
	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%s (extras-count: %d)\n",
			 "ath10k Target Register Dump", fw_regs->extras_count);
	len += scnprintf(buf + len, buf_len - len, "%30s\n\n",
				 "=================");

	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "MAC-FILTER-ADDR-L32", fw_regs->mac_filter_addr_l32);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "MAC-FILTER-ADDR-U16", fw_regs->mac_filter_addr_u16);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "DCU-SLOT-TIME", fw_regs->dcu_slot_time);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PHY-MODE-SELECT", fw_regs->phy_bb_mode_select);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PHY-BB-GEN-CONTROLS", fw_regs->phy_bb_gen_controls);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "DMA-IMR", fw_regs->dma_imr);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "DMA-TXRX-IMR", fw_regs->dma_txrx_imr);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PCU-BSSID-L32", fw_regs->pcu_bssid_l32);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PCU-BSSID-U16", fw_regs->pcu_bssid_u16);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PCU-BSSID2-L32", fw_regs->pcu_bssid2_l32);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PCU-BSSID2-U16", fw_regs->pcu_bssid2_u16);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PCU-STA-ADDR-L32", fw_regs->pcu_sta_addr_l32);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "PCU-STA-ADDR-U16", fw_regs->pcu_sta_addr_u16);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "MAC-DMA-CFG", fw_regs->mac_dma_cfg);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "MAC-DMA-TXCFG", fw_regs->mac_dma_txcfg);

	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "SW-POWERMODE", fw_regs->sw_powermode);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "SW-CHAINMASK-TX", (u32)(fw_regs->sw_chainmask_tx));
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "SW-CHAINMASK-RX", (u32)(fw_regs->sw_chainmask_rx));
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "SW-OPMODE", fw_regs->sw_opmode);

	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "MAC-PCU-RXFILTER", fw_regs->pcu_rxfilter);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "SW-RXFILTER", fw_regs->sw_rxfilter);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "SHORT-RETRIES", fw_regs->short_retries);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "LONG-RETRIES", fw_regs->long_retries);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "ADC-TEMP", fw_regs->adc_temp);
	len += scnprintf(buf + len, buf_len - len, "%30s 0x%08x\n",
			 "NFCAL-PER-CHAIN", fw_regs->nfcal);

	for (i = 0; i<fw_regs->extras_count; i++) {
		len += scnprintf(buf + len, buf_len - len, "%26s%04d 0x%08x\n",
				 "", i + DBG_REG_DUMP_COUNT, fw_regs->extra_regs[i]);
	}

	spin_unlock_bh(&ar->data_lock);

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

exit:
	mutex_unlock(&ar->conf_mutex);
	kfree(buf);
	return ret_cnt;
}


static ssize_t ath10k_fw_stats_read(struct file *file, char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	size_t len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_fw_stats = {
	.open = ath10k_fw_stats_open,
	.release = ath10k_fw_stats_release,
	.read = ath10k_fw_stats_read,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_debug_fw_reset_stats_read(struct file *file,
						char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	size_t len = 0, buf_len = 500;
	char *buf;

	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	spin_lock_bh(&ar->data_lock);

	len += scnprintf(buf + len, buf_len - len,
			 "fw_crash_counter\t\t%d\n", ar->stats.fw_crash_counter);
	len += scnprintf(buf + len, buf_len - len,
			 "fw_warm_reset_counter\t\t%d\n",
			 ar->stats.fw_warm_reset_counter);
	len += scnprintf(buf + len, buf_len - len,
			 "fw_cold_reset_counter\t\t%d\n",
			 ar->stats.fw_cold_reset_counter);

	spin_unlock_bh(&ar->data_lock);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	kfree(buf);

	return ret;
}

static const struct file_operations fops_fw_reset_stats = {
	.open = simple_open,
	.read = ath10k_debug_fw_reset_stats_read,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/* This is a clean assert crash in firmware. */
static int ath10k_debug_fw_assert(struct ath10k *ar)
{
	struct wmi_vdev_install_key_cmd *cmd;
	struct sk_buff *skb;

	skb = ath10k_wmi_alloc_skb(ar, sizeof(*cmd) + 16);
	if (!skb)
		return -ENOMEM;

	cmd = (struct wmi_vdev_install_key_cmd *)skb->data;
	memset(cmd, 0, sizeof(*cmd));

	/* big enough number so that firmware asserts */
	cmd->vdev_id = __cpu_to_le32(0x7ffe);

	return ath10k_wmi_cmd_send(ar, skb,
				   ar->wmi.cmd->vdev_install_key_cmdid);
}

static const struct file_operations fops_fw_regs = {
	.read = ath10k_read_fw_regs,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static const struct file_operations fops_rx_reorder_stats = {
	.read = ath10k_read_rx_reorder_stats,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_simulate_fw_crash(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	const char buf[] =
		"To simulate firmware crash write one of the keywords to this file:\n"
		"`soft` - this will send WMI_FORCE_FW_HANG_ASSERT to firmware if FW supports that command.\n"
		"`hard` - this will send to firmware command with illegal parameters causing firmware crash.\n"
		"`assert` - this will send special illegal parameter to firmware to cause assert failure and crash.\n"
		"`hw-restart` - this will simply queue hw restart without fw/hw actually crashing.\n";

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

/* Simulate firmware crash:
 * 'soft': Call wmi command causing firmware hang. This firmware hang is
 * recoverable by warm firmware reset.
 * 'hard': Force firmware crash by setting any vdev parameter for not allowed
 * vdev id. This is hard firmware crash because it is recoverable only by cold
 * firmware reset.
 */
static ssize_t ath10k_write_simulate_fw_crash(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32] = {0};
	ssize_t rc;
	int ret;

	/* filter partial writes and invalid commands */
	if (*ppos != 0 || count >= sizeof(buf) || count == 0)
		return -EINVAL;

	rc = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);
	if (rc < 0)
		return rc;

	/* drop the possible '\n' from the end */
	if (buf[*ppos - 1] == '\n')
		buf[*ppos - 1] = '\0';

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_RESTARTED) {
		ret = -ENETDOWN;
		goto exit;
	}

	if (!strcmp(buf, "soft")) {
		ath10k_info(ar, "simulating soft firmware crash\n");
		ret = ath10k_wmi_force_fw_hang(ar, WMI_FORCE_FW_HANG_ASSERT, 0);
	} else if (!strcmp(buf, "hard")) {
		ath10k_info(ar, "simulating hard firmware crash\n");
		/* 0x7fff is vdev id, and it is always out of range for all
		 * firmware variants in order to force a firmware crash.
		 */
		ret = ath10k_wmi_vdev_set_param(ar, 0x7fff,
						ar->wmi.vdev_param->rts_threshold,
						0);
	} else if (!strcmp(buf, "assert")) {
		ath10k_info(ar, "simulating firmware assert crash\n");
		ret = ath10k_debug_fw_assert(ar);
	} else if (!strcmp(buf, "hw-restart")) {
		ath10k_info(ar, "user requested hw restart\n");
		queue_work(ar->workqueue, &ar->restart_work);
		ret = 0;
	} else {
		ret = -EINVAL;
		goto exit;
	}

	if (ret) {
		ath10k_warn(ar, "failed to simulate firmware crash: %d\n", ret);
		goto exit;
	}

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_simulate_fw_crash = {
	.read = ath10k_read_simulate_fw_crash,
	.write = ath10k_write_simulate_fw_crash,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_debug_level(struct file *file,
				       char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	int sz;
	const char buf[] =
		"To change debug level, set value adding up desired flags:\n"
		"PCI:                0x1\n"
		"WMI:                0x2\n"
		"HTC:                0x4\n"
		"HTT:                0x8\n"
		"MAC:               0x10\n"
		"BOOT:              0x20\n"
		"PCI-DUMP:          0x40\n"
		"HTT-DUMP:          0x80\n"
		"MGMT:             0x100\n"
		"DATA:             0x200\n"
		"BMI:              0x400\n"
		"REGULATORY:       0x800\n"
		"TESTMODE:        0x1000\n"
		"WMI-PRINT:       0x2000\n"
		"PCI-PS:          0x4000\n"
		"AHB:             0x8000\n"
		"SDIO:		 0x10000\n"
		"SDIO_DUMP:	 0x20000\n"
		"USB:		 0x40000\n"
		"USB_BULK:	 0x80000\n"
		"SNOC:		0x100000\n"
		"QMI:		0x200000\n"
		"BEACONS:      0x8000000\n"
		"NO-FW-DBGLOG:0x10000000\n"
		"MAC2:        0x20000000\n"
		"INFO-AS-DBG: 0x40000000\n"
		"FW:          0x80000000\n"
		"ALL:         0xEFFFFFFF\n";
	char wbuf[sizeof(buf) + 60];
	sz = snprintf(wbuf, sizeof(wbuf), "Current debug level: 0x%x\n\n%s",
		      ath10k_debug_mask, buf);
	wbuf[sizeof(wbuf) - 1] = 0;

	return simple_read_from_buffer(user_buf, count, ppos, wbuf, sz);
}

/* Set logging level.
 */
static ssize_t ath10k_write_debug_level(struct file *file,
					const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	unsigned long mask;

	ret = kstrtoul_from_user(user_buf, count, 0, &mask);
	if (ret)
		return ret;

	ath10k_warn(ar, "Setting debug-mask to: 0x%lx  old: 0x%x\n",
		    mask, ath10k_debug_mask);
	ath10k_debug_mask = mask;
	return count;
}

static const struct file_operations fops_debug_level = {
	.read = ath10k_read_debug_level,
	.write = ath10k_write_debug_level,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_set_rates(struct file *file,
				     char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	const char buf[] =
		"This is to set fixed bcast, mcast, and beacon rates.  Normal rate-ctrl\n"
		"is handled through normal API using 'iw', etc.\n"
		"To set a value, you specify the dev-name, type, band and rate-code:\n"
		"types: bcast, mcast, beacon\n"
		"bands: 2, 5, 60\n"
		"rate-codes: 0x43 1M, 0x42 2M, 0x41 5.5M, 0x40 11M, 0x3 6M, 0x7 9M, 0x2 12M, 0x6 18M, 0x1 24M, 0x5 36M, 0x0 48M, 0x4 54M, 0xFF default\n"
		" For example, to set beacon to 18Mbps on wlan0:  echo \"wlan0 beacon 2 0x6\" > /debug/..../set_rates\n";

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

/* Set the rates for specific types of traffic.
 */
static ssize_t ath10k_write_set_rates(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[80];
	int ret;
	struct ath10k_vif *arvif;
	struct ieee80211_vif *vif;
	unsigned int vdev_id = 0xFFFF;
	char* bufptr = buf;
	long rc;
	int cfg_band;
	struct cfg80211_chan_def def;
	char dev_name_match[IFNAMSIZ + 2];
	struct wireless_dev *wdev;
	int set_rate_type;

	memset(buf, 0, sizeof(buf));

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = 0;

	/* drop the possible '\n' from the end */
	if (buf[count - 1] == '\n')
		buf[count - 1] = 0;

	mutex_lock(&ar->conf_mutex);

	/* Ignore empty lines, 'echo' appends them sometimes at least. */
	if (buf[0] == 0) {
		ret = count;
		goto exit;
	}

	/* String starts with vdev name, ie 'wlan0'  Find the proper vif that
	 * matches the name.
	 */
	list_for_each_entry(arvif, &ar->arvifs, list) {
		vif = arvif->vif;
		wdev = ieee80211_vif_to_wdev(vif);

		if (!wdev)
			continue;
		snprintf(dev_name_match, sizeof(dev_name_match) - 1, "%s ", wdev->netdev->name);
		if (strncmp(dev_name_match, buf, strlen(dev_name_match)) == 0) {
			vdev_id = arvif->vdev_id;
			bufptr = buf + strlen(dev_name_match);
			break;
		}
	}

	if (vdev_id == 0xFFFF) {
		ath10k_warn(ar, "set-rate, unknown netdev name: %s\n", buf);
		ret = -EINVAL;
		goto exit;
	}

	/* Now, check the type. */
	if (strncmp(bufptr, "beacon ", strlen("beacon ")) == 0) {
		set_rate_type = ar->wmi.vdev_param->mgmt_rate;
		bufptr += strlen("beacon ");
	}
	else if (strncmp(bufptr, "bcast ", strlen("bcast ")) == 0) {
		set_rate_type = ar->wmi.vdev_param->bcast_data_rate;
		bufptr += strlen("bcast ");
	}
	else if (strncmp(bufptr, "mcast ", strlen("mcast ")) == 0) {
		set_rate_type = ar->wmi.vdev_param->mcast_data_rate;
		bufptr += strlen("mcast ");
	}
	else {
		ath10k_warn(ar, "set-rate, invalid rate type: %s\n",
			    bufptr);
		ret = -EINVAL;
		goto exit;
	}

	/* And the band */
	if (strncmp(bufptr, "2 ", 2) == 0) {
		cfg_band = NL80211_BAND_2GHZ;
		bufptr += 2;
	}
	else if (strncmp(bufptr, "5 ", 2) == 0) {
		cfg_band = NL80211_BAND_5GHZ;
		bufptr += 2;
	}
	else if (strncmp(bufptr, "60 ", 3) == 0) {
		cfg_band = NL80211_BAND_60GHZ;
		bufptr += 3;
	}
	else {
		ath10k_warn(ar, "set-rate, invalid band: %s\n",
			    bufptr);
		ret = -EINVAL;
		goto exit;
	}

	/* Parse the rate-code. */
	ret = kstrtol(bufptr, 0, &rc);
	if (ret != 0) {
		ath10k_warn(ar, "set-rate, invalid rate-code: %s\n", bufptr);
		goto exit;
	}

	/* Store the value so we can re-apply it if firmware is restarted. */
	if (set_rate_type == ar->wmi.vdev_param->mgmt_rate)
		arvif->mgt_rate[cfg_band] = rc;
	else if (set_rate_type == ar->wmi.vdev_param->bcast_data_rate)
		arvif->bcast_rate[cfg_band] = rc;
	else if (set_rate_type == ar->wmi.vdev_param->mcast_data_rate)
		arvif->mcast_rate[cfg_band] = rc;

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_RESTARTED) {
		/* OK, we will set it when vdev comes up */
		ath10k_warn(ar, "set-rates, deferred-state is down, vdev %i type: 0x%x rc: 0x%lx band: %d\n",
			    arvif->vdev_id, set_rate_type, rc, cfg_band);
		goto exit;
	}

	if (ath10k_mac_vif_chan(vif, &def) == 0) {
		if (def.chan->band != cfg_band) {
			/* We stored value, will apply it later if we move to the
			 * different band.
			 */
			ath10k_warn(ar, "set-rates, deferred-other-band, vdev %i type: 0x%x rc: 0x%lx band: %d\n",
				    arvif->vdev_id, set_rate_type, rc, cfg_band);
			goto exit;
		}
	}

	/* and finally, send results to the firmware. */
	ret = ath10k_wmi_vdev_set_param(ar, arvif->vdev_id, set_rate_type, rc);
	if (ret) {
		ath10k_warn(ar, "set-rates: vdev %i failed to set fixed rate, param 0x%x rate-code 0x%02lx\n",
			    arvif->vdev_id, set_rate_type, rc);
		goto exit;
	}

	ath10k_warn(ar, "set-rates, vdev %i type: 0x%x rc: 0x%lx band: %d\n",
		    arvif->vdev_id, set_rate_type, rc, cfg_band);

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_set_rates = {
	.read = ath10k_read_set_rates,
	.write = ath10k_write_set_rates,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};


static ssize_t ath10k_read_set_rate_override(struct file *file,
					     char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char* buf2;
	int size=8000;
	struct ath10k_vif *arvif;
	struct ieee80211_vif *vif;
	struct wireless_dev *wdev;
	int sofar;
	int rv;
	const char buf[] =
		"This allows specify specif tx rate parameters for all DATA frames on a vdev\n"
		"Only wave-2 CT firmware has full support.  Wave-1 CT firmware has at least\n"
		"some support (rix mostly).  Wave-2 does not use rix.\n"
		"To set a value, you specify the dev-name and key-value pairs:\n"
		"tpc=10 sgi=1 mcs=x nss=x pream=x retries=x dynbw=0|1 bw=x rix=x enable=0|1\n"
		"pream: 0=ofdm, 1=cck, 2=HT, 3=VHT\n"
		"tpc is in 1db increments, 255 means use defaults, bw is 0-3 for 20-160\n"
		" For example, wlan0:  echo \"wlan0 tpc=255 sgi=1 mcs=0 nss=1 pream=3 retries=1 dynbw=0 bw=0 active=1\" > ...ath10k/set_rate_override\n";

	buf2 = kzalloc(size, GFP_KERNEL);
	if (buf2 == NULL)
		return -ENOMEM;
	strcpy(buf2, buf);
	sofar = strlen(buf2);

	list_for_each_entry(arvif, &ar->arvifs, list) {
		vif = arvif->vif;
		wdev = ieee80211_vif_to_wdev(vif);

		if (!wdev)
			continue;

		sofar += scnprintf(buf2 + sofar, size - sofar,
				   "vdev %i(%s) active=%d tpc=%d sgi=%d mcs=%d nss=%d pream=%d retries=%d dynbw=%d bw=%d rix=%d\n",
				   arvif->vdev_id, wdev->netdev->name,
				   arvif->txo_active, arvif->txo_tpc, arvif->txo_sgi, arvif->txo_mcs,
				   arvif->txo_nss, arvif->txo_pream, arvif->txo_retries, arvif->txo_dynbw,
				   arvif->txo_bw, arvif->txo_rix);
		if (sofar >= size)
			break;
	}

	rv = simple_read_from_buffer(user_buf, count, ppos, buf2, sofar);
	kfree(buf2);
	return rv;
}

/* Set the rates for specific types of traffic.
 */
static ssize_t ath10k_write_set_rate_override(struct file *file,
					      const char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[180];
	char tmp[20];
	char* tok;
	int ret;
	struct ath10k_vif *arvif;
	struct ieee80211_vif *vif;
	unsigned int vdev_id = 0xFFFF;
	char* bufptr = buf;
	long rc;
	char dev_name_match[IFNAMSIZ + 2];
	struct wireless_dev *wdev;

	memset(buf, 0, sizeof(buf));

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = 0;

	/* drop the possible '\n' from the end */
	if (buf[count - 1] == '\n')
		buf[count - 1] = 0;

	mutex_lock(&ar->conf_mutex);

	/* Ignore empty lines, 'echo' appends them sometimes at least. */
	if (buf[0] == 0) {
		ret = count;
		goto exit;
	}

	/* String starts with vdev name, ie 'wlan0'  Find the proper vif that
	 * matches the name.
	 */
	list_for_each_entry(arvif, &ar->arvifs, list) {
		vif = arvif->vif;
		wdev = ieee80211_vif_to_wdev(vif);

		if (!wdev)
			continue;
		snprintf(dev_name_match, sizeof(dev_name_match) - 1, "%s ", wdev->netdev->name);
		if (strncmp(dev_name_match, buf, strlen(dev_name_match)) == 0) {
			vdev_id = arvif->vdev_id;
			bufptr = buf + strlen(dev_name_match) - 1;
			break;
		}
	}

	if (vdev_id == 0xFFFF) {
		if (strstr(buf, "active=0")) {
			/* Ignore, we are disabling it anyway */
			ret = count;
			goto exit;
		}
		else {
			ath10k_warn(ar, "set-rate-override, unknown netdev name: %s\n", buf);
		}
		ret = -EINVAL;
		goto exit;
	}

#define ATH10K_PARSE_LTOK(a) \
	if ((tok = strstr(bufptr, " " #a "="))) {			\
		char* tspace;						\
		tok += 1; /* move past initial space */			\
		strncpy(tmp, tok + strlen(#a "="), sizeof(tmp) - 1);	\
		tmp[sizeof(tmp) - 1] = 0;				\
		tspace = strstr(tmp, " ");				\
		if (tspace) { *tspace = 0; }				\
		if (kstrtol(tmp, 0, &rc) != 0) {			\
			ath10k_warn(ar, "set-rate-override: " #a "= could not be parsed, tmp: %s\n", tmp); \
		}							\
		else {							\
			arvif->txo_##a = rc;				\
		}							\
	}

	ATH10K_PARSE_LTOK(tpc);
	ATH10K_PARSE_LTOK(sgi);
	ATH10K_PARSE_LTOK(mcs);
	ATH10K_PARSE_LTOK(nss);
	ATH10K_PARSE_LTOK(pream);
	ATH10K_PARSE_LTOK(retries);
	ATH10K_PARSE_LTOK(dynbw);
	ATH10K_PARSE_LTOK(bw);
	ATH10K_PARSE_LTOK(rix);
	ATH10K_PARSE_LTOK(active);

	ath10k_warn(ar, "set-rate-overrides, vdev %i(%s) active=%d tpc=%d sgi=%d mcs=%d nss=%d pream=%d retries=%d dynbw=%d bw=%d rix=%d\n",
		    arvif->vdev_id, dev_name_match,
		    arvif->txo_active, arvif->txo_tpc, arvif->txo_sgi, arvif->txo_mcs,
		    arvif->txo_nss, arvif->txo_pream, arvif->txo_retries, arvif->txo_dynbw,
		    arvif->txo_bw, arvif->txo_rix);

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_set_rate_override = {
	.read = ath10k_read_set_rate_override,
	.write = ath10k_write_set_rate_override,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_chip_id(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	size_t len;
	char buf[50];

	len = scnprintf(buf, sizeof(buf), "0x%08x\n", ar->chip_id);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_chip_id = {
	.read = ath10k_read_chip_id,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_reg_addr_read(struct file *file,
				    char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u8 buf[32];
	size_t len = 0;
	u32 reg_addr;

	mutex_lock(&ar->conf_mutex);
	reg_addr = ar->debug.reg_addr;
	mutex_unlock(&ar->conf_mutex);

	len += scnprintf(buf + len, sizeof(buf) - len, "0x%x\n", reg_addr);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_reg_addr_write(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u32 reg_addr;
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0, &reg_addr);
	if (ret)
		return ret;

	if (!IS_ALIGNED(reg_addr, 4))
		return -EFAULT;

	mutex_lock(&ar->conf_mutex);
	ar->debug.reg_addr = reg_addr;
	mutex_unlock(&ar->conf_mutex);

	return count;
}

static const struct file_operations fops_reg_addr = {
	.read = ath10k_reg_addr_read,
	.write = ath10k_reg_addr_write,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_reg_value_read(struct file *file,
				     char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u8 buf[48];
	size_t len;
	u32 reg_addr, reg_val;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_UTF) {
		ret = -ENETDOWN;
		goto exit;
	}

	reg_addr = ar->debug.reg_addr;

	reg_val = ath10k_hif_read32(ar, reg_addr);
	len = scnprintf(buf, sizeof(buf), "0x%08x:0x%08x\n", reg_addr, reg_val);

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, len);

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_reg_value_write(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u32 reg_addr, reg_val;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_UTF) {
		ret = -ENETDOWN;
		goto exit;
	}

	reg_addr = ar->debug.reg_addr;

	ret = kstrtou32_from_user(user_buf, count, 0, &reg_val);
	if (ret)
		goto exit;

	ath10k_hif_write32(ar, reg_addr, reg_val);

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static void ath10k_dbg_drop_dbg_buffer(struct ath10k *ar)
{
	/* Find next message boundary */
	u32 lg_hdr;
	unsigned int acnt;
	int tail_idx = ar->debug.dbglog_entry_data.tail_idx;
	int h_idx = (tail_idx + 1) % ATH10K_DBGLOG_DATA_LEN;

	lockdep_assert_held(&ar->data_lock);

	/* Log header is second 32-bit word */
	lg_hdr = le32_to_cpu(ar->debug.dbglog_entry_data.data[h_idx]);

	acnt = (lg_hdr & DBGLOG_NUM_ARGS_MASK) >> DBGLOG_NUM_ARGS_OFFSET;

	if (acnt > DBGLOG_NUM_ARGS_MAX) {
		/* Some sort of corruption it seems, recover as best we can. */
		ath10k_err(ar, "invalid dbglog arg-count: %i %i %i\n",
			   acnt, ar->debug.dbglog_entry_data.tail_idx,
			   ar->debug.dbglog_entry_data.head_idx);
		ar->debug.dbglog_entry_data.tail_idx =
			ar->debug.dbglog_entry_data.head_idx;
		return;
	}

	/* Move forward over the args and the two header fields */
	ar->debug.dbglog_entry_data.tail_idx =
		(tail_idx + acnt + 2) % ATH10K_DBGLOG_DATA_LEN;
}

void ath10k_dbg_save_fw_dbg_buffer(struct ath10k *ar, __le32 *buffer, int len)
{
	int i;
	int z;
	u32 lg_hdr = 0;
	unsigned int acnt = 0;

	lockdep_assert_held(&ar->data_lock);

	/* Make sure input is sane */
	i = 0;
	while (i < len) {
		lg_hdr = le32_to_cpu(buffer[i + 1]);
		acnt = (lg_hdr & DBGLOG_NUM_ARGS_MASK) >> DBGLOG_NUM_ARGS_OFFSET;

		if (acnt > DBGLOG_NUM_ARGS_MAX) {
		bad:
			ath10k_err(ar, "Invalid fw-dbg-buffer, hdr-at[%i], len: %d arg-len: %d  hdr: 0x%x\n",
				   i + 1, len, acnt, lg_hdr);
			for (i = 0; i<len; i++) {
				ath10k_err(ar, "buffer[%i] 0x%x\n", i, le32_to_cpu(buffer[i]));
			}
			return;
		}
		i += 2 + acnt;
	}

	/* Some trailing garbage? */
	if (i != len)
		goto bad;

	z = ar->debug.dbglog_entry_data.head_idx;

	for (i = 0; i < len; i++) {
		ar->debug.dbglog_entry_data.data[z] = buffer[i];
		z++;
		if (z >= ATH10K_DBGLOG_DATA_LEN)
			z = 0;

		/* If we are about to over-write an old message, move the
		 * tail_idx to the next message.  If idx's are same, we
		 * are empty.
		 */
		if (z == ar->debug.dbglog_entry_data.tail_idx)
			ath10k_dbg_drop_dbg_buffer(ar);

		ar->debug.dbglog_entry_data.head_idx = z;
	}
}
EXPORT_SYMBOL(ath10k_dbg_save_fw_dbg_buffer);

static const struct file_operations fops_reg_value = {
	.read = ath10k_reg_value_read,
	.write = ath10k_reg_value_write,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_mem_value_read(struct file *file,
				     char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u8 *buf;
	int ret;

	if (*ppos < 0)
		return -EINVAL;

	if (!count)
		return 0;

	mutex_lock(&ar->conf_mutex);

	buf = vmalloc(count);
	if (!buf) {
		ret = -ENOMEM;
		goto exit;
	}

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_UTF) {
		ret = -ENETDOWN;
		goto exit;
	}

	ret = ath10k_hif_diag_read(ar, *ppos, buf, count);
	if (ret) {
		ath10k_warn(ar, "failed to read address 0x%08x via diagnose window fnrom debugfs: %d\n",
			    (u32)(*ppos), ret);
		goto exit;
	}

	ret = copy_to_user(user_buf, buf, count);
	if (ret) {
		ret = -EFAULT;
		goto exit;
	}

	count -= ret;
	*ppos += count;
	ret = count;

exit:
	vfree(buf);
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_mem_value_write(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u8 *buf;
	int ret;

	if (*ppos < 0)
		return -EINVAL;

	if (!count)
		return 0;

	mutex_lock(&ar->conf_mutex);

	buf = vmalloc(count);
	if (!buf) {
		ret = -ENOMEM;
		goto exit;
	}

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_UTF) {
		ret = -ENETDOWN;
		goto exit;
	}

	ret = copy_from_user(buf, user_buf, count);
	if (ret) {
		ret = -EFAULT;
		goto exit;
	}

	ret = ath10k_hif_diag_write(ar, *ppos, buf, count);
	if (ret) {
		ath10k_warn(ar, "failed to write address 0x%08x via diagnose window from debugfs: %d\n",
			    (u32)(*ppos), ret);
		goto exit;
	}

	*ppos += count;
	ret = count;

exit:
	vfree(buf);
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static const struct file_operations fops_mem_value = {
	.read = ath10k_mem_value_read,
	.write = ath10k_mem_value_write,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath10k_debug_htt_stats_req(struct ath10k *ar)
{
	u64 cookie;
	int ret;

	lockdep_assert_held(&ar->conf_mutex);

	if (ar->debug.htt_stats_mask == 0)
		/* htt stats are disabled */
		return 0;

	if (ar->state != ATH10K_STATE_ON)
		return 0;

	cookie = get_jiffies_64();

	ret = ath10k_htt_h2t_stats_req(&ar->htt, ar->debug.htt_stats_mask,
				       cookie);
	if (ret) {
		ath10k_warn(ar, "failed to send htt stats request: %d\n", ret);
		return ret;
	}

	queue_delayed_work(ar->workqueue, &ar->debug.htt_stats_dwork,
			   msecs_to_jiffies(ATH10K_DEBUG_HTT_STATS_INTERVAL));

	return 0;
}

static void ath10k_debug_htt_stats_dwork(struct work_struct *work)
{
	struct ath10k *ar = container_of(work, struct ath10k,
					 debug.htt_stats_dwork.work);

	mutex_lock(&ar->conf_mutex);

	ath10k_debug_htt_stats_req(ar);

	mutex_unlock(&ar->conf_mutex);
}

static void ath10k_debug_nop_dwork(struct work_struct *work)
{
	struct ath10k *ar = container_of(work, struct ath10k,
					 debug.nop_dwork.work);

	mutex_lock(&ar->conf_mutex);

	if (ar->state == ATH10K_STATE_ON) {
		int ret = ath10k_wmi_request_nop(ar);
		if (ret) {
			ath10k_warn(ar, "failed to send wmi nop: %d\n", ret);
		}
	}

	/* Re-arm periodic work. */
	queue_delayed_work(ar->workqueue, &ar->debug.nop_dwork,
			   msecs_to_jiffies(ATH10K_DEBUG_NOP_INTERVAL));

	mutex_unlock(&ar->conf_mutex);
}

static ssize_t ath10k_read_htt_stats_mask(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32];
	size_t len;

	len = scnprintf(buf, sizeof(buf), "%lu\n", ar->debug.htt_stats_mask);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_write_htt_stats_mask(struct file *file,
					   const char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	unsigned long mask;
	int ret;

	ret = kstrtoul_from_user(user_buf, count, 0, &mask);
	if (ret)
		return ret;

	/* max 8 bit masks (for now) */
	if (mask > 0xff)
		return -E2BIG;

	mutex_lock(&ar->conf_mutex);

	ar->debug.htt_stats_mask = mask;

	ret = ath10k_debug_htt_stats_req(ar);
	if (ret)
		goto out;

	ret = count;

out:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static const struct file_operations fops_htt_stats_mask = {
	.read = ath10k_read_htt_stats_mask,
	.write = ath10k_write_htt_stats_mask,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_htt_max_amsdu_ampdu(struct file *file,
					       char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[64];
	u8 amsdu, ampdu;
	size_t len;

	mutex_lock(&ar->conf_mutex);

	amsdu = ar->htt.max_num_amsdu;
	ampdu = ar->htt.max_num_ampdu;
	mutex_unlock(&ar->conf_mutex);

	len = scnprintf(buf, sizeof(buf), "%u %u\n", amsdu, ampdu);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_write_htt_max_amsdu_ampdu(struct file *file,
						const char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int res;
	char buf[64] = {0};
	unsigned int amsdu, ampdu;

	res = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos,
				     user_buf, count);
	if (res <= 0)
		return res;

	res = sscanf(buf, "%u %u", &amsdu, &ampdu);

	if (res != 2)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	res = ath10k_htt_h2t_aggr_cfg_msg(&ar->htt, ampdu, amsdu);
	if (res)
		goto out;

	res = count;
	ar->htt.max_num_amsdu = amsdu;
	ar->htt.max_num_ampdu = ampdu;

out:
	mutex_unlock(&ar->conf_mutex);
	return res;
}

static const struct file_operations fops_htt_max_amsdu_ampdu = {
	.read = ath10k_read_htt_max_amsdu_ampdu,
	.write = ath10k_write_htt_max_amsdu_ampdu,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_fw_dbglog(struct file *file,
				     char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	size_t len;
	char buf[96];

	len = scnprintf(buf, sizeof(buf), "0x%16llx %u\n",
			ar->debug.fw_dbglog_mask, ar->debug.fw_dbglog_level);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_write_fw_dbglog(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	char buf[96] = {0};
	unsigned int log_level;
	u64 mask;

	ret = simple_write_to_buffer(buf, sizeof(buf) - 1, ppos,
				     user_buf, count);
	if (ret <= 0)
		return ret;

	ret = sscanf(buf, "%llx %u", &mask, &log_level);

	if (!ret)
		return -EINVAL;

	if (ret == 1)
		/* default if user did not specify */
		log_level = ATH10K_DBGLOG_LEVEL_WARN;

	mutex_lock(&ar->conf_mutex);

	ar->debug.fw_dbglog_mask = mask;
	ar->debug.fw_dbglog_level = log_level;

	if (ar->state == ATH10K_STATE_ON) {
		ret = ath10k_wmi_dbglog_cfg(ar, ar->debug.fw_dbglog_mask,
					    ar->debug.fw_dbglog_level);
		if (ret) {
			ath10k_warn(ar, "dbglog cfg failed from debugfs: %d\n",
				    ret);
			goto exit;
		}
	}

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_read_ratepwr(struct file *file,
				   char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int size = 8000;
	u8 *buf = kzalloc(size, GFP_KERNEL);
	int retval = 0, len = 0;
	int mx = sizeof(ar->debug.ratepwr_tbl.data) / 4;
	int i;

	if (buf == NULL)
		return -ENOMEM;

	/* TODO:  Locking? */

	if (ar->state == ATH10K_STATE_ON) {
		unsigned long time_left;
		int ret;

		reinit_completion(&ar->debug.ratepwr_tbl_complete);

		ret = ath10k_wmi_request_ratepwr_tbl(ar);
		if (ret) {
			ath10k_warn(ar, "could not request ratepwr table: ret %d\n",
				    ret);
			time_left = 1;
		}
		else {
			time_left = wait_for_completion_timeout(&ar->debug.ratepwr_tbl_complete, 1*HZ);
		}

		/* ath10k_warn(ar, "Requested ratepwr (type 0x%x ret %d specifier %d jiffies: %lu  time-left: %lu)\n",
		   type, ret, specifier, jiffies, time_left);*/

		if (time_left == 0)
			ath10k_warn(ar, "Timeout requesting ratepwr table.\n");
	}

	len += scnprintf(buf + len, size - len, "RatePower table, length: %d\n",
			 ar->debug.ratepwr_tbl_len);
	for (i = 0; i<mx; i++) {
		len += scnprintf(buf + len, size - len, "%08x ", ar->debug.ratepwr_tbl.data[i]);
		if (((i + 1) % 8) == 0)
			buf[len - 1] = '\n';
	}
	buf[len - 1] = '\n';

	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;
}

static const struct file_operations fops_ratepwr_table = {
	.read = ath10k_read_ratepwr,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_powerctl(struct file *file,
				    char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int size = 8000;
	u8 *buf = kzalloc(size, GFP_KERNEL);
	int retval = 0, len = 0;
	int mx = sizeof(ar->debug.powerctl_tbl.data) / 4;
	int i;

	if (buf == NULL)
		return -ENOMEM;

	/* TODO:  Locking? */

	if (ar->state == ATH10K_STATE_ON) {
		unsigned long time_left;
		int ret;

		reinit_completion(&ar->debug.powerctl_tbl_complete);

		ret = ath10k_wmi_request_powerctl_tbl(ar);
		if (ret) {
			ath10k_warn(ar, "could not request powerctl table: ret %d\n",
				    ret);
			time_left = 1;
		}
		else {
			time_left = wait_for_completion_timeout(&ar->debug.powerctl_tbl_complete, 1*HZ);
		}

		/* ath10k_warn(ar, "Requested powerctl (type 0x%x ret %d specifier %d jiffies: %lu  time-left: %lu)\n",
		   type, ret, specifier, jiffies, time_left);*/

		if (time_left == 0)
			ath10k_warn(ar, "Timeout requesting powerctl table.\n");
	}

	len += scnprintf(buf + len, size - len, "PowerCtl table, length: %d\n",
			 ar->debug.powerctl_tbl_len);
	for (i = 0; i<mx; i++) {
		len += scnprintf(buf + len, size - len, "%08x ", ar->debug.powerctl_tbl.data[i]);
		if (((i + 1) % 8) == 0)
			buf[len - 1] = '\n';
	}
	buf[len - 1] = '\n';

	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;
}

static const struct file_operations fops_powerctl_table = {
	.read = ath10k_read_powerctl,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};


/* TODO:  Would be nice to always support ethtool stats, would need to
 * move the stats storage out of ath10k_debug, or always have ath10k_debug
 * struct available..
 */

/* This generally cooresponds to the debugfs fw_stats file */
static const char ath10k_gstrings_stats[][ETH_GSTRING_LEN] = {
	"tx_hw_reaped", /* from firmware, tx-pkts count */
	"tx_pkts_nic", /* from driver, tx-ok pkts */
	"tx_bytes_nic", /* from driver, tx-ok bytes */
	"tx_bytes_to_fw", /* sent to firmware, counts all failures */
	"rx_pkts_nic", /* From firmware...maybe should be from driver for symmetry? */
	"rx_bytes_nic", /* from driver, firmware does not keep this stat. */
	"rx_drop_unchain_oom", /* Dropped due to OOM pressure in unchain_msdu path */
	"rx_drop_decap_non_raw_chained",
	"rx_drop_no_freq",
	"rx_drop_cac_running",
	"d_noise_floor",
	"d_cycle_count", /* this is duty cycle counter, basically channel-time. 88MHz clock */
	"d_tx_cycle_count", /* tx cycle count */
	"d_rx_cycle_count", /* rx cycle count */
	"d_busy_count", /* Total channel busy time cycles (called 'clear' by firmware) */
	"d_flags", /* 0x1:  hw has shifted cycle-count wrap, see ath10k_hw_fill_survey_time */
	"d_phy_error",
	"d_rts_bad",
	"d_rts_good",
	"d_tx_power", /* in .5 dbM I think */
	"d_rx_crc_err", /* fcs_bad */
	"d_no_beacon",
	"d_tx_mpdus_queued",
	"d_tx_msdu_queued",
	"d_tx_msdu_dropped",
	"d_local_enqued",
	"d_local_freed",
	"d_tx_ppdu_hw_queued",
	"d_tx_ppdu_reaped",
	"d_tx_fifo_underrun",
	"d_tx_ppdu_abort",
	"d_tx_mpdu_requed",
	"d_tx_excessive_retries",
	"d_tx_hw_rate",
	"d_tx_dropped_sw_retries",
	"d_tx_noack", /* reported by driver */
	"d_tx_noack_bytes", /* reported by driver */
	"d_tx_discard", /* reported by driver */
	"d_tx_discard_bytes", /* reported by driver */
	"d_tx_illegal_rate",
	"d_tx_continuous_xretries",
	"d_tx_timeout",
	"d_tx_mpdu_txop_limit",
	"d_pdev_resets",
	"d_rx_mid_ppdu_route_change",
	"d_rx_status",
	"d_rx_extra_frags_ring0",
	"d_rx_extra_frags_ring1",
	"d_rx_extra_frags_ring2",
	"d_rx_extra_frags_ring3",
	"d_rx_msdu_htt",
	"d_rx_mpdu_htt",
	"d_rx_msdu_stack",
	"d_rx_mpdu_stack",
	"d_rx_phy_err",
	"d_rx_phy_err_drops",
	"d_rx_mpdu_errors", /* FCS, MIC, ENC */
	"d_fw_crash_count",
	"d_fw_warm_reset_count",
	"d_fw_cold_reset_count",
	"d_fw_powerup_failed", /* boolean */
	"d_short_tx_retries", /* RTS tx retries */
	"d_long_tx_retries", /* DATA tx retries */
	"d_fw_adc_temp", /* ADC Temperature readings. */
};

#define ATH10K_SSTATS_LEN ARRAY_SIZE(ath10k_gstrings_stats)

void ath10k_debug_get_et_strings(struct ieee80211_hw *hw,
				 struct ieee80211_vif *vif,
				 u32 sset, u8 *data)
{
	if (sset == ETH_SS_STATS)
		memcpy(data, *ath10k_gstrings_stats,
		       sizeof(ath10k_gstrings_stats));
}

int ath10k_debug_get_et_sset_count(struct ieee80211_hw *hw,
				   struct ieee80211_vif *vif, int sset)
{
	if (sset == ETH_SS_STATS)
		return ATH10K_SSTATS_LEN;

	return 0;
}

void ath10k_debug_get_et_stats2(struct ieee80211_hw *hw,
				struct ieee80211_vif *vif,
				struct ethtool_stats *stats, u64 *data, u32 level)
{
	struct ath10k *ar = hw->priv;
	static const struct ath10k_fw_stats_pdev zero_stats = {};
	const struct ath10k_fw_stats_pdev *pdev_stats;
	int i = 0, ret;
	u64 d_flags = 0;

	mutex_lock(&ar->conf_mutex);

	if (level && level < 5)
		goto skip_query_fw_stats;

	if (ar->state == ATH10K_STATE_ON) {
		ath10k_refresh_target_regs(ar); /* Request some CT FW stats. */
		ret = ath10k_debug_fw_stats_request(ar);
		if (ret) {
			/* just print a warning and try to use older results */
			ath10k_warn(ar,
				    "failed to get fw stats for ethtool: %d\n",
				    ret);
		}
	}

skip_query_fw_stats:
	pdev_stats = list_first_entry_or_null(&ar->debug.fw_stats.pdevs,
					      struct ath10k_fw_stats_pdev,
					      list);
	if (!pdev_stats) {
		/* no results available so just return zeroes */
		pdev_stats = &zero_stats;
	}

	spin_lock_bh(&ar->data_lock);

	if (ar->hw_params.cc_wraparound_type == ATH10K_HW_CC_WRAP_SHIFTED_ALL)
		d_flags |= 0x1;

	data[i++] = pdev_stats->hw_reaped; /* ppdu reaped */
	data[i++] = ar->debug.tx_ok;
	data[i++] = ar->debug.tx_ok_bytes;
	data[i++] = ar->debug.tx_bytes;
	data[i++] = pdev_stats->htt_mpdus;
	data[i++] = ar->debug.rx_bytes;
	data[i++] = ar->debug.rx_drop_unchain_oom;
	data[i++] = ar->debug.rx_drop_decap_non_raw_chained;
	data[i++] = ar->debug.rx_drop_no_freq;
	data[i++] = ar->debug.rx_drop_cac_running;
	data[i++] = pdev_stats->ch_noise_floor;
	data[i++] = pdev_stats->cycle_count;
	data[i++] = pdev_stats->tx_frame_count;
	data[i++] = pdev_stats->rx_frame_count;
	data[i++] = pdev_stats->rx_clear_count; /* yes, this appears to actually be 'busy' count */
	data[i++] = d_flags; /* give user-space a chance to decode cycle counters */
	data[i++] = pdev_stats->phy_err_count;
	data[i++] = pdev_stats->rts_bad;
	data[i++] = pdev_stats->rts_good;
	data[i++] = pdev_stats->chan_tx_power;
	data[i++] = pdev_stats->fcs_bad;
	data[i++] = pdev_stats->no_beacons;
	data[i++] = pdev_stats->mpdu_enqued;
	data[i++] = pdev_stats->msdu_enqued;
	data[i++] = pdev_stats->wmm_drop;
	data[i++] = pdev_stats->local_enqued;
	data[i++] = pdev_stats->local_freed;
	data[i++] = pdev_stats->hw_queued;
	data[i++] = pdev_stats->hw_reaped;
	data[i++] = pdev_stats->underrun;
	data[i++] = pdev_stats->tx_abort;
	data[i++] = pdev_stats->mpdus_requed;
	data[i++] = pdev_stats->tx_ko;
	data[i++] = pdev_stats->data_rc;
	data[i++] = pdev_stats->sw_retry_failure;
	data[i++] = ar->debug.tx_noack;
	data[i++] = ar->debug.tx_noack_bytes;
	data[i++] = ar->debug.tx_discard;
	data[i++] = ar->debug.tx_discard_bytes;
	data[i++] = pdev_stats->illgl_rate_phy_err;
	data[i++] = pdev_stats->pdev_cont_xretry;
	data[i++] = pdev_stats->pdev_tx_timeout;
	data[i++] = pdev_stats->txop_ovf;
	data[i++] = pdev_stats->pdev_resets;
	data[i++] = pdev_stats->mid_ppdu_route_change;
	data[i++] = pdev_stats->status_rcvd;
	data[i++] = pdev_stats->r0_frags;
	data[i++] = pdev_stats->r1_frags;
	data[i++] = pdev_stats->r2_frags;
	data[i++] = pdev_stats->r3_frags;
	data[i++] = pdev_stats->htt_msdus;
	data[i++] = pdev_stats->htt_mpdus;
	data[i++] = pdev_stats->loc_msdus;
	data[i++] = pdev_stats->loc_mpdus;
	data[i++] = pdev_stats->phy_errs;
	data[i++] = pdev_stats->phy_err_drop;
	data[i++] = pdev_stats->mpdu_errs;
	data[i++] = ar->stats.fw_crash_counter;
	data[i++] = ar->stats.fw_warm_reset_counter;
	data[i++] = ar->stats.fw_cold_reset_counter;
	data[i++] = ar->fw_powerup_failed;
	data[i++] = ar->debug.fw_stats.short_retries;
	data[i++] = ar->debug.fw_stats.long_retries;
	data[i++] = ar->debug.fw_stats.adc_temp;

	spin_unlock_bh(&ar->data_lock);

	mutex_unlock(&ar->conf_mutex);

	WARN_ON(i != ATH10K_SSTATS_LEN);
}

void ath10k_debug_get_et_stats(struct ieee80211_hw *hw,
                              struct ieee80211_vif *vif,
                              struct ethtool_stats *stats, u64 *data)
{
       ath10k_debug_get_et_stats2(hw, vif, stats, data, 0);
}


static const struct file_operations fops_fw_dbglog = {
	.read = ath10k_read_fw_dbglog,
	.write = ath10k_write_fw_dbglog,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath10k_debug_cal_data_fetch(struct ath10k *ar)
{
	u32 hi_addr;
	__le32 addr;
	int ret;

	lockdep_assert_held(&ar->conf_mutex);

	if (WARN_ON(ar->hw_params.cal_data_len > ATH10K_DEBUG_CAL_DATA_LEN))
		return -EINVAL;

	hi_addr = host_interest_item_address(HI_ITEM(hi_board_data));

	ret = ath10k_hif_diag_read(ar, hi_addr, &addr, sizeof(addr));
	if (ret) {
		ath10k_warn(ar, "failed to read hi_board_data address: %d\n",
			    ret);
		return ret;
	}

	ret = ath10k_hif_diag_read(ar, le32_to_cpu(addr), ar->debug.cal_data,
				   ar->hw_params.cal_data_len);
	if (ret) {
		ath10k_warn(ar, "failed to read calibration data: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ath10k_debug_cal_data_open(struct inode *inode, struct file *file)
{
	struct ath10k *ar = inode->i_private;

	mutex_lock(&ar->conf_mutex);

	if (ar->state == ATH10K_STATE_ON ||
	    ar->state == ATH10K_STATE_UTF) {
		ath10k_debug_cal_data_fetch(ar);
	}

	file->private_data = ar;
	mutex_unlock(&ar->conf_mutex);

	return 0;
}

static ssize_t ath10k_debug_cal_data_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;

	mutex_lock(&ar->conf_mutex);

	count = simple_read_from_buffer(user_buf, count, ppos,
					ar->debug.cal_data,
					ar->hw_params.cal_data_len);

	mutex_unlock(&ar->conf_mutex);

	return count;
}

static ssize_t ath10k_write_ani_enable(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	u8 enable;

	if (kstrtou8_from_user(user_buf, count, 0, &enable))
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->ani_enabled == enable) {
		ret = count;
		goto exit;
	}

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->ani_enable,
					enable);
	if (ret) {
		ath10k_warn(ar, "ani_enable failed from debugfs: %d\n", ret);
		goto exit;
	}
	ar->ani_enabled = enable;

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_read_ani_enable(struct file *file, char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	size_t len;
	char buf[32];

	len = scnprintf(buf, sizeof(buf), "%d\n", ar->ani_enabled);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_ani_enable = {
	.read = ath10k_read_ani_enable,
	.write = ath10k_write_ani_enable,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static const struct file_operations fops_cal_data = {
	.open = ath10k_debug_cal_data_open,
	.read = ath10k_debug_cal_data_read,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_nf_cal_period(struct file *file,
					 char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	size_t len;
	char buf[32];

	len = scnprintf(buf, sizeof(buf), "%d\n", ar->debug.nf_cal_period);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_write_nf_cal_period(struct file *file,
					  const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	unsigned long period;
	int ret;

	ret = kstrtoul_from_user(user_buf, count, 0, &period);
	if (ret)
		return ret;

	if (period > WMI_PDEV_PARAM_CAL_PERIOD_MAX)
		return -EINVAL;

	/* there's no way to switch back to the firmware default */
	if (period == 0)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	ar->debug.nf_cal_period = period;

	if (ar->state != ATH10K_STATE_ON) {
		/* firmware is not running, nothing else to do */
		ret = count;
		goto exit;
	}

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->cal_period,
					ar->debug.nf_cal_period);
	if (ret) {
		ath10k_warn(ar, "cal period cfg failed from debugfs: %d\n",
			    ret);
		goto exit;
	}

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static const struct file_operations fops_nf_cal_period = {
	.read = ath10k_read_nf_cal_period,
	.write = ath10k_write_nf_cal_period,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

#define ATH10K_TPC_CONFIG_BUF_SIZE	(1024 * 1024)

static int ath10k_debug_tpc_stats_request(struct ath10k *ar)
{
	int ret;
	unsigned long time_left;

	lockdep_assert_held(&ar->conf_mutex);

	reinit_completion(&ar->debug.tpc_complete);

	ret = ath10k_wmi_pdev_get_tpc_config(ar, WMI_TPC_CONFIG_PARAM);
	if (ret) {
		ath10k_warn(ar, "failed to request tpc config: %d\n", ret);
		return ret;
	}

	time_left = wait_for_completion_timeout(&ar->debug.tpc_complete,
						1 * HZ);
	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

void ath10k_debug_tpc_stats_process(struct ath10k *ar,
				    struct ath10k_tpc_stats *tpc_stats)
{
	spin_lock_bh(&ar->data_lock);

	kfree(ar->debug.tpc_stats);
	ar->debug.tpc_stats = tpc_stats;
	complete(&ar->debug.tpc_complete);

	spin_unlock_bh(&ar->data_lock);
}

void
ath10k_debug_tpc_stats_final_process(struct ath10k *ar,
				     struct ath10k_tpc_stats_final *tpc_stats)
{
	spin_lock_bh(&ar->data_lock);

	kfree(ar->debug.tpc_stats_final);
	ar->debug.tpc_stats_final = tpc_stats;
	complete(&ar->debug.tpc_complete);

	spin_unlock_bh(&ar->data_lock);
}

static void ath10k_tpc_stats_print(struct ath10k_tpc_stats *tpc_stats,
				   unsigned int j, char *buf, size_t *len)
{
	int i;
	size_t buf_len;
	static const char table_str[][5] = { " CDD",
					     "STBC",
					     "TXBF" };
	static const char pream_str[][6] = { "  CCK",
					     " OFDM",
					     " HT20",
					     " HT40",
					     "VHT20",
					     "VHT40",
					     "VHT80",
					     "HTCUP" };

	buf_len = ATH10K_TPC_CONFIG_BUF_SIZE;
	*len += scnprintf(buf + *len, buf_len - *len,
			  "*****************************************************\n");
	*len += scnprintf(buf + *len, buf_len - *len,
			  "******************* %s POWER TABLE ****************\n",
			  table_str[j]);
	*len += scnprintf(buf + *len, buf_len - *len,
			  "*****************************************************\n");
	*len += scnprintf(buf + *len, buf_len - *len,
			  "No.  Preamble Rate_code ");

	for (i = 0; i < WMI_TPC_TX_N_CHAIN; i++)
		*len += scnprintf(buf + *len, buf_len - *len,
				  "tpc_value%d ", i);

	*len += scnprintf(buf + *len, buf_len - *len, "\n");

	for (i = 0; i < tpc_stats->rate_max; i++) {
		*len += scnprintf(buf + *len, buf_len - *len,
				  "%3d     %s   0x%2x %s\n", i,
				  pream_str[tpc_stats->tpc_table[j].pream_idx[i]],
				  tpc_stats->tpc_table[j].rate_code[i],
				  tpc_stats->tpc_table[j].tpc_value[i]);
	}

	*len += scnprintf(buf + *len, buf_len - *len, "\n\n");
}

static void ath10k_tpc_stats_fill(struct ath10k *ar,
				  struct ath10k_tpc_stats *tpc_stats,
				  char *buf)
{
	int j;
	size_t len, buf_len;

	len = 0;
	buf_len = ATH10K_TPC_CONFIG_BUF_SIZE;

	spin_lock_bh(&ar->data_lock);

	if (!tpc_stats) {
		ath10k_warn(ar, "failed to get tpc stats\n");
		goto unlock;
	}

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len,
			 "*************************************\n");
	len += scnprintf(buf + len, buf_len - len,
			 "TPC config for channel %4d mode %d\n",
			 tpc_stats->chan_freq,
			 tpc_stats->phy_mode);
	len += scnprintf(buf + len, buf_len - len,
			 "*************************************\n");
	len += scnprintf(buf + len, buf_len - len,
			 "CTL		=  0x%2x Reg. Domain		= %2d\n",
			 tpc_stats->ctl,
			 tpc_stats->reg_domain);
	len += scnprintf(buf + len, buf_len - len,
			 "Antenna Gain	= %2d Reg. Max Antenna Gain	=  %2d\n",
			 tpc_stats->twice_antenna_gain,
			 tpc_stats->twice_antenna_reduction);
	len += scnprintf(buf + len, buf_len - len,
			 "Power Limit	= %2d Reg. Max Power		= %2d\n",
			 tpc_stats->power_limit,
			 tpc_stats->twice_max_rd_power / 2);
	len += scnprintf(buf + len, buf_len - len,
			 "Num tx chains	= %2d Num supported rates	= %2d\n",
			 tpc_stats->num_tx_chain,
			 tpc_stats->rate_max);

	for (j = 0; j < WMI_TPC_FLAG; j++) {
		switch (j) {
		case WMI_TPC_TABLE_TYPE_CDD:
			if (tpc_stats->flag[j] == ATH10K_TPC_TABLE_TYPE_FLAG) {
				len += scnprintf(buf + len, buf_len - len,
						 "CDD not supported\n");
				break;
			}

			ath10k_tpc_stats_print(tpc_stats, j, buf, &len);
			break;
		case WMI_TPC_TABLE_TYPE_STBC:
			if (tpc_stats->flag[j] == ATH10K_TPC_TABLE_TYPE_FLAG) {
				len += scnprintf(buf + len, buf_len - len,
						 "STBC not supported\n");
				break;
			}

			ath10k_tpc_stats_print(tpc_stats, j, buf, &len);
			break;
		case WMI_TPC_TABLE_TYPE_TXBF:
			if (tpc_stats->flag[j] == ATH10K_TPC_TABLE_TYPE_FLAG) {
				len += scnprintf(buf + len, buf_len - len,
						 "TXBF not supported\n***************************\n");
				break;
			}

			ath10k_tpc_stats_print(tpc_stats, j, buf, &len);
			break;
		default:
			len += scnprintf(buf + len, buf_len - len,
					 "Invalid Type\n");
			break;
		}
	}

unlock:
	spin_unlock_bh(&ar->data_lock);

	if (len >= buf_len)
		buf[len - 1] = 0;
	else
		buf[len] = 0;
}

static int ath10k_tpc_stats_open(struct inode *inode, struct file *file)
{
	struct ath10k *ar = inode->i_private;
	void *buf = NULL;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH10K_TPC_CONFIG_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	ret = ath10k_debug_tpc_stats_request(ar);
	if (ret) {
		ath10k_warn(ar, "failed to request tpc config stats: %d\n",
			    ret);
		goto err_free;
	}

	ath10k_tpc_stats_fill(ar, ar->debug.tpc_stats, buf);
	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath10k_tpc_stats_release(struct inode *inode, struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static ssize_t ath10k_tpc_stats_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	size_t len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_tpc_stats = {
	.open = ath10k_tpc_stats_open,
	.release = ath10k_tpc_stats_release,
	.read = ath10k_tpc_stats_read,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

int ath10k_debug_start(struct ath10k *ar)
{
	int ret;

	lockdep_assert_held(&ar->conf_mutex);

	ret = ath10k_debug_htt_stats_req(ar);
	if (ret)
		/* continue normally anyway, this isn't serious */
		ath10k_warn(ar, "failed to start htt stats workqueue: %d\n",
			    ret);

	if (ar->debug.fw_dbglog_mask) {
		ret = ath10k_wmi_dbglog_cfg(ar, ar->debug.fw_dbglog_mask,
					    ATH10K_DBGLOG_LEVEL_WARN);
		if (ret)
			/* not serious */
			ath10k_warn(ar, "failed to enable dbglog during start: %d",
				    ret);
	}

	if (ar->pktlog_filter) {
		ret = ath10k_wmi_pdev_pktlog_enable(ar,
						    ar->pktlog_filter);
		if (ret)
			/* not serious */
			ath10k_warn(ar,
				    "failed to enable pktlog filter %x: %d\n",
				    ar->pktlog_filter, ret);
	} else {
		ret = ath10k_wmi_pdev_pktlog_disable(ar);
		if (ret)
			/* not serious */
			ath10k_warn(ar, "failed to disable pktlog: %d\n", ret);
	}

	if (ar->debug.nf_cal_period &&
	    !test_bit(ATH10K_FW_FEATURE_NON_BMI,
		      ar->normal_mode_fw.fw_file.fw_features)) {
		ret = ath10k_wmi_pdev_set_param(ar,
						ar->wmi.pdev_param->cal_period,
						ar->debug.nf_cal_period);
		if (ret)
			/* not serious */
			ath10k_warn(ar, "cal period cfg failed from debug start: %d\n",
				    ret);
	}

	queue_delayed_work(ar->workqueue, &ar->debug.nop_dwork,
			   msecs_to_jiffies(ATH10K_DEBUG_NOP_INTERVAL));

	return ret;
}

void ath10k_debug_stop(struct ath10k *ar)
{
	lockdep_assert_held(&ar->conf_mutex);

	if (!test_bit(ATH10K_FW_FEATURE_NON_BMI,
		      ar->normal_mode_fw.fw_file.fw_features))
		ath10k_debug_cal_data_fetch(ar);

	/* Must not use _sync to avoid deadlock, we do that in
	 * ath10k_debug_destroy(). The check for htt_stats_mask is to avoid
	 * warning from del_timer().
	 */
	if (ar->debug.htt_stats_mask != 0)
		cancel_delayed_work(&ar->debug.htt_stats_dwork);

	cancel_delayed_work(&ar->debug.nop_dwork);

	ath10k_wmi_pdev_pktlog_disable(ar);
}

static ssize_t ath10k_write_simulate_radar(struct file *file,
					   const char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	struct ath10k_vif *arvif;

	/* Just check for for the first vif alone, as all the vifs will be
	 * sharing the same channel and if the channel is disabled, all the
	 * vifs will share the same 'is_started' state.
	 */
	arvif = list_first_entry(&ar->arvifs, typeof(*arvif), list);
	if (!arvif->is_started)
		return -EINVAL;

	ieee80211_radar_detected(ar->hw);

	return count;
}

static const struct file_operations fops_simulate_radar = {
	.write = ath10k_write_simulate_radar,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

#define ATH10K_DFS_STAT(s, p) (\
	len += scnprintf(buf + len, size - len, "%-28s : %10u\n", s, \
			 ar->debug.dfs_stats.p))

#define ATH10K_DFS_POOL_STAT(s, p) (\
	len += scnprintf(buf + len, size - len, "%-28s : %10u\n", s, \
			 ar->debug.dfs_pool_stats.p))

static ssize_t ath10k_read_dfs_stats(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	int retval = 0, len = 0;
	const int size = 8000;
	struct ath10k *ar = file->private_data;
	char *buf;

	buf = kzalloc(size, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	if (!ar->dfs_detector) {
		len += scnprintf(buf + len, size - len, "DFS not enabled\n");
		goto exit;
	}

	ar->debug.dfs_pool_stats =
			ar->dfs_detector->get_stats(ar->dfs_detector);

	len += scnprintf(buf + len, size - len, "Pulse detector statistics:\n");

	ATH10K_DFS_STAT("reported phy errors", phy_errors);
	ATH10K_DFS_STAT("pulse events reported", pulses_total);
	ATH10K_DFS_STAT("DFS pulses detected", pulses_detected);
	ATH10K_DFS_STAT("DFS pulses discarded", pulses_discarded);
	ATH10K_DFS_STAT("Radars detected", radar_detected);

	len += scnprintf(buf + len, size - len, "Global Pool statistics:\n");
	ATH10K_DFS_POOL_STAT("Pool references", pool_reference);
	ATH10K_DFS_POOL_STAT("Pulses allocated", pulse_allocated);
	ATH10K_DFS_POOL_STAT("Pulses alloc error", pulse_alloc_error);
	ATH10K_DFS_POOL_STAT("Pulses in use", pulse_used);
	ATH10K_DFS_POOL_STAT("Seqs. allocated", pseq_allocated);
	ATH10K_DFS_POOL_STAT("Seqs. alloc error", pseq_alloc_error);
	ATH10K_DFS_POOL_STAT("Seqs. in use", pseq_used);

	len += scnprintf(buf + len, size - len, "Last-DFS-Msg: %s\n",
			 ar->debug.dfs_last_msg);

exit:
	if (len > size)
		len = size;

	retval = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);

	return retval;
}

static const struct file_operations fops_dfs_stats = {
	.read = ath10k_read_dfs_stats,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_write_pktlog_filter(struct file *file,
					  const char __user *ubuf,
					  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u32 filter;
	int ret;

	if (kstrtouint_from_user(ubuf, count, 0, &filter))
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON) {
		ar->pktlog_filter = filter;
		ret = count;
		goto out;
	}

	if (filter == ar->pktlog_filter) {
		ret = count;
		goto out;
	}

	if (filter) {
		ret = ath10k_wmi_pdev_pktlog_enable(ar, filter);
		if (ret) {
			ath10k_warn(ar, "failed to enable pktlog filter %x: %d\n",
				    ar->pktlog_filter, ret);
			goto out;
		}
	} else {
		ret = ath10k_wmi_pdev_pktlog_disable(ar);
		if (ret) {
			ath10k_warn(ar, "failed to disable pktlog: %d\n", ret);
			goto out;
		}
	}

	ar->pktlog_filter = filter;
	ret = count;

out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static ssize_t ath10k_read_pktlog_filter(struct file *file, char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	char buf[32];
	struct ath10k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%08x\n",
			ar->pktlog_filter);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_pktlog_filter = {
	.read = ath10k_read_pktlog_filter,
	.write = ath10k_write_pktlog_filter,
	.open = simple_open
};

static ssize_t ath10k_write_thresh62_ext(struct file *file,
					 const char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u8 val;
	int ret = 0;

	if (kstrtou8_from_user(ubuf, count, 0, &val))
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);
	ar->eeprom_overrides.thresh62_ext = val;
	ret = ath10k_wmi_pdev_set_special(ar, SET_SPECIAL_ID_THRESH62_EXT, val);
	mutex_unlock(&ar->conf_mutex);

	return ret ?: count;
}

static ssize_t ath10k_read_thresh62_ext(struct file *file,
					char __user *ubuf,
					size_t count, loff_t *ppos)
{
	char buf[32];
	struct ath10k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			ar->eeprom_overrides.thresh62_ext);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_thresh62_ext = {
	.read = ath10k_read_thresh62_ext,
	.write = ath10k_write_thresh62_ext,
	.open = simple_open
};

static ssize_t ath10k_write_ct_special(struct file *file,
				       const char __user *ubuf,
				       size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u64 tmp;
	u32 id;
	u32 val;
	int ret = 0;

	if (kstrtou64_from_user(ubuf, count, 0, &tmp))
		return -EINVAL;

	id = tmp >> 32;
	val = tmp & 0xFFFFFFFF;

	mutex_lock(&ar->conf_mutex);
	if (id == SET_SPECIAL_ID_ACK_CTS) {
		ar->eeprom_overrides.reg_ack_cts = val;
	}
	else if (id == SET_SPECIAL_ID_SLOT) {
		ar->eeprom_overrides.reg_ifs_slot = val;
	}
	else if (id == SET_SPECIAL_ID_THRESH62_EXT) {
		ar->eeprom_overrides.thresh62_ext = val;
	}
	else if (id == SET_SPECIAL_ID_NOISE_FLR_THRESH) {
		u8 band = val >> 24;
		u8 type = (val >> 16) & 0xFF;
		if ((band > 2) || (type > CT_CCA_TYPE_MAX)) {
			ret = -EINVAL;
			goto unlock;
		}
		if (type <= CT_CCA_TYPE_MIN2)
			ar->eeprom_overrides.bands[band].minCcaPwrCT[type] = val & 0xFFFF;
		else if (type == CT_CCA_TYPE_NOISE_FLOOR)
			ar->eeprom_overrides.bands[band].noiseFloorThresh = val & 0xFFFF;
		else if (type == CT_CCA_TYPE_EN_MINCCAPWR)
			ar->eeprom_overrides.bands[band].enable_minccapwr_thresh = val & 0xFFFF;
	}
	else if (id == SET_SPECIAL_ID_IBSS_AMSDU_OK) {
		ar->eeprom_overrides.allow_ibss_amsdu = !!val;
		ath10k_warn(ar, "Setting ibss-amsdu-ok to %d\n",
			    ar->eeprom_overrides.allow_ibss_amsdu);
	}
	else if (id == SET_SPECIAL_ID_MAX_TXPOWER) {
		/* This can only be set once, and is designed to be
		 * a way to try to ensure that no other tools can
		 * accidently or otherwise set the power in the firmware
		 * higher.
		 */
		if (ar->eeprom_overrides.max_txpower == 0xFFFF) {
			ar->eeprom_overrides.max_txpower = val;
			ath10k_warn(ar, "Latching max-txpower to: %d (%d dBm)\n", val, val/2);
		}
		else {
			ath10k_err(ar, "Cannot re-set max-txpower, old: %d  new: %d (%d dBm)\n",
				   ar->eeprom_overrides.max_txpower, val, val/2);
			ret = -EPERM;
			goto unlock;
		}
	}
	else if (id == SET_SPECIAL_ID_RC_MAX_PER_THR) {
		ar->eeprom_overrides.rc_rate_max_per_thr = val;
		ath10k_warn(ar, "Setting rc-max-per-threshold to %d\n",
			    ar->eeprom_overrides.rc_rate_max_per_thr);
	}
	else if (id == SET_SPECIAL_ID_STA_TXBW_MASK) {
		/* Specify Station tx bandwidth mask (20, 40, 80Mhz). */
		ar->eeprom_overrides.tx_sta_bw_mask = val;
		ath10k_warn(ar, "Setting sta-tx-bw-mask to 0x%x\n", val);
	}
	else if (id == SET_SPECIAL_ID_PDEV_XRETRY_TH) {
		/* Set the threshold for resetting phy due to failed retries, U16 */
		ar->eeprom_overrides.pdev_xretry_th = val;
		ath10k_warn(ar, "Setting pdev-xretry-th to 0x%x\n", val);
	}
	else if (id == SET_SPECIAL_ID_RIFS_ENABLE) {
		/* Enable(1)/disable(0) baseband RIFS. */
		ar->eeprom_overrides.rifs_enable_override = val;
		ath10k_warn(ar, "Setting RIFS enable override to 0x%x\n", val);
	}
	else if (id == SET_SPECIAL_ID_WMI_WD) {
		ar->eeprom_overrides.wmi_wd_keepalive_ms = val;
		ath10k_warn(ar, "Setting WMI WD to 0x%x\n", val);
		if (val == 0)
			goto unlock; /* 0 means don't set */

		if (val == 0xFFFFFFFF)
			val = 0; /* 0xFFFFFFFF means disable, FW uses 0 to mean disable */
	}
	else if (id == SET_SPECIAL_ID_PSHACK) {
		ar->eeprom_overrides.ct_pshack = val;
		ath10k_warn(ar, "Setting CT-PSHACK override to 0x%x\n", val);
	}
	else if (id == SET_SPECIAL_ID_CSI) {
		ar->eeprom_overrides.ct_csi = val;
		ath10k_warn(ar, "Setting CT-CSI dump override to 0x%x\n", val);
	}
	else if (id == SET_SPECIAL_ID_BW_DISABLE_MASK) {
		/* Set bandwidth-disable mask */
		ar->eeprom_overrides.rate_bw_disable_mask = val;

		ath10k_warn(ar, "Setting pdev rate-bw-disable-mask to 0x%x.  Will take effect next time rates are configured.\n",
			    val);
	}
	else if (id == SET_SPECIAL_ID_TXBF_CV_MSG) {
		ar->eeprom_overrides.txbf_cv_msg = val;

		ath10k_warn(ar, "Setting pdev txbf-cv-msg to 0x%x.\n",
			    val);
	}
	else if (id == SET_SPECIAL_ID_RX_ALL_MGT) {
		ar->eeprom_overrides.rx_all_mgt = val;

		ath10k_warn(ar, "Setting pdev rx-all-mgt to 0x%x.\n",
			    val);
	}
	else if (id == SET_SPECIAL_ID_TX_HANG_COLD_RESET) {
		ar->eeprom_overrides.tx_hang_cold_reset_ok = !!val;
		ath10k_warn(ar, "Setting tx-hang-cold-reset-ok to %d\n",
			    ar->eeprom_overrides.tx_hang_cold_reset_ok);
	}
	else if (id == SET_SPECIAL_ID_DISABLE_IBSS_CCA) {
		ar->eeprom_overrides.disable_ibss_cca = val;
		ath10k_warn(ar, "Setting disable-ibss-cca to %d\n",
			    ar->eeprom_overrides.disable_ibss_cca);
	}
	else if (id == SET_SPECIAL_ID_RC_DBG) {
		/* Set Rate-Ctrl debugging */
		ar->eeprom_overrides.rc_debug = val;

		ath10k_warn(ar, "Setting firmware rc-debug to 0x%x.\n", val);
	}
	else if (id == SET_SPECIAL_ID_TX_DBG) {
		/* Set TX debugging */
		ar->eeprom_overrides.tx_debug = val;

		ath10k_warn(ar, "Setting firmware tx-debug to 0x%x.\n", val);
	}
	else if (id == SET_SPECIAL_ID_PEER_CT_ANTMASK) {
		/* Not stored in driver, will not be restored upon FW crash/restart */
		ath10k_warn(ar, "Setting ct-andmask for peer: %d to 0x%x.\n", val >> 16, val & 0x16);
	}
	else if (id == SET_SPECIAL_ID_EEPROM_CFG_ADDR_A) {
		/* Not stored in driver, will not be restored upon FW crash/restart */
		ath10k_warn(ar, "Adding EEPROM configAddr address setting 0x08%x.\n", val);
	}
	else if (id == SET_SPECIAL_ID_EEPROM_CFG_ADDR_V) {
		/* Not stored in driver, will not be restored upon FW crash/restart */
		ath10k_warn(ar, "Adding EEPROM configAddr value setting 0x08%x.\n", val);
	}
	else if (id == SET_SPECIAL_ID_PEER_STATS_PN) {
		ar->eeprom_overrides.peer_stats_pn = val;
		ath10k_warn(ar, "Setting peer-stats-pn to %d\n",
			    ar->eeprom_overrides.peer_stats_pn);
	}
	/* Below here are local driver hacks, and not necessarily passed directly to firmware. */
	else if (id == 0x1001) {
		/* Set station failed-transmit kickout threshold. */
		ar->sta_xretry_kickout_thresh = val;

		ath10k_warn(ar, "Setting pdev sta-xretry-kickout-thresh to 0x%x\n",
			    val);

		ath10k_mac_set_pdev_kickout(ar);
		goto unlock;
	}
	else if (id == 0x1002) {
		/* Set SU sounding frame timer. */
		ar->eeprom_overrides.su_sounding_timer_ms = val;

		ath10k_warn(ar, "Setting pdev su-sounding-timer-ms to 0x%x\n",
			    val);

		ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->txbf_sound_period_cmdid,
					  ar->eeprom_overrides.su_sounding_timer_ms);
		goto unlock;
	}
	else if (id == 0x1003) {
		/* Set MU sounding frame timer. */
		ar->eeprom_overrides.mu_sounding_timer_ms = val;

		ath10k_warn(ar, "Setting pdev mu-sounding-timer-ms to 0x%x\n",
			    val);

		/* Search for WMI_FWTEST_CMDID in core.c */
		ath10k_wmi_pdev_set_fwtest(ar, 81,
					  ar->eeprom_overrides.mu_sounding_timer_ms);
		goto unlock;
	}
	else if (id == 0x1004) {
		/* Set rc-txbf-probe. */
		ar->eeprom_overrides.rc_txbf_probe = val;

		ath10k_warn(ar, "Setting pdev rc-txbf-probe to 0x%x\n",
			    ar->eeprom_overrides.rc_txbf_probe);

		/* Search for WMI_FWTEST_CMDID in core.c */
		ath10k_wmi_pdev_set_fwtest(ar, 20,
					  ar->eeprom_overrides.rc_txbf_probe);
		goto unlock;
	}
	else if (id == 0x1005) {
		/* Over-write power-ctl table with what was ready in from the board data */
		/* Use with care! */
		ar->eeprom_overrides.apply_board_power_ctl_table = val;

		ath10k_warn(ar, "Setting overwrite power-ctl table with calibration-file data to: %d\n",
			    ar->eeprom_overrides.apply_board_power_ctl_table);

		ath10k_wmi_check_apply_board_power_ctl_table(ar);
		goto unlock;
	}
	/* else, pass it through to firmware...but will not be stored locally, so
	 * won't survive through firmware reboots, etc.
	 */

	if ((id & 0xFF0000) == 0xFF0000) {
		/* Send it to the firmware through the fwtest (stock-ish) API */
		/* Search for WMI_FWTEST_CMDID in core.c */
		if (ar->state == ATH10K_STATE_ON) {
			ret = ath10k_wmi_pdev_set_fwtest(ar, id & 0xFFFF, val);
		}
	}
	else {
		/* Send it to the firmware though ct-special API */
		if (ar->state == ATH10K_STATE_ON) {
			ret = ath10k_wmi_pdev_set_special(ar, id, val);
		}
	}
unlock:
	mutex_unlock(&ar->conf_mutex);

	return ret ?: count;
}

static ssize_t ath10k_read_ct_special(struct file *file,
				      char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	static const char buf[] =
		"BE WARNED:  You should understand the values before setting anything here.\n"
		"You could put your NIC out of spec or maybe even break the hardware if you\n"
		"put in bad values.\n\n"
		"Value is u64, encoded thus:\n"
		"id = t64 >> 32\n"
		"val = t64 & 0xFFFFFFFF\n"
		"id: 3 THRESH62_EXT (both bands use same value currently)\n"
		"  value = val & 0xFF;\n"
		"id: 4 CCA-Values, encoded as below:\n"
		"  band = val >> 24;  //(0 5Ghz, 1 2.4Ghz)\n"
		"  type = (val >> 16) & 0xFF; // 0-2 minCcaPwr[type], 3 noiseFloorThresh\n"
		"         4 enable_minccapwr_thresh\n"
		"  value = val & 0xFFFF;\n"
		"    Unless otherwise specified, 0 means don't set.\n"
		"    enable-minccapwr-thresh:  1 disabled, 2 enabled.\n"
		"id: 5 Allow-AMSDU-IBSS, 1 enabled, 0 disabled, global setting.\n"
		"id: 6 Max TX-Power, 0-65535:  Latch max-tx-power, in 0.5 dbM Units.\n"
		"id: 7 RC max PER Threshold: 0-256 (50 is default). Tune with Care.\n"
		"id: 8 STA-TX-BW-MASK,  0:  all, 0x1: 20Mhz, 0x2 40Mhz, 0x4 80Mhz (station vdevs only)\n"
		"id: 9 pdev failed retry threshold, U16, 10.1 firmware default is 0x40\n"
		"id: 0xA Enable(1)/Disable(0) baseband RIFS.  Default is disabled.\n"
		"id: 0xB WMI WD Keepalive(ms): 0xFFFFFFFF disables, otherwise suggest 8000+.\n"
		"id: 0xC Power-Save hack:  0x1 ignore PS sleep message from STA\n"
		"id:                       0x2 mark mcast as 'data-is-buffered' regardless\n"
		"id: 0xD Enable CSI reporting for at least probe requests.\n"
		"id: 0xE set rate-bandwidth-disable-mask: 20Mhz 0x1, 40Mhz 0x2, 80Mhz 0x4, 160Mhz 0x8.\n"
		"    Takes effect next time rates are set.  Set to 0x0 for default rates.\n"
		"id: 0xF Enable TXBF-CV-MSG.\n"
		"id: 0x10 rx-all-mgt.\n"
		"id: 0x11 allow tx-hang logic to try cold resets instead of just warm resets.\n"
		"id: 0x12 disable special CCA setting for IBSS queues.\n"
		"id: 0x13 set 5-bit antenna-mask for peer, format:  (peer-id << 16) | ant_mask\n"
		"id: 0x14 Add a 32-bit sticky register address override to the eeprom."
		"id: 0x15 Add a 32-bit sticky register value override to the eeprom."
		"id: 0x16 Enable/Disable reporting PN in peer-stats."
		"\nBelow here should work with most firmware, including non-CT firmware.\n"
		"id: 0x1001 set sta-kickout threshold due to tx-failures (0 means disable.  Default is 20 * 16.)\n"
		"id: 0x1002 set su-sounding-timer-ms (0 means use defaults next FW reload.  Default is 100, max is 500)\n"
		"id: 0x1003 set mu-sounding-timer-ms (0 means use defaults next FW reload.  Default is 40)\n"
		"id: 0x1004 set rc-txbf-probe (1 means sent txbf probe, 0 (default) means do not\n"
		"id: 0x1005 set apply-board-power-ctl-table (1 means apply, 0 means not)\n"
		"\n";

	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

static const struct file_operations fops_ct_special = {
	.read = ath10k_read_ct_special,
	.write = ath10k_write_ct_special,
	.open = simple_open
};


static ssize_t ath10k_write_quiet_period(struct file *file,
					 const char __user *ubuf,
					 size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u32 period;

	if (kstrtouint_from_user(ubuf, count, 0, &period))
		return -EINVAL;

	if (period < ATH10K_QUIET_PERIOD_MIN) {
		ath10k_warn(ar, "Quiet period %u can not be lesser than 25ms\n",
			    period);
		return -EINVAL;
	}
	mutex_lock(&ar->conf_mutex);
	ar->thermal.quiet_period = period;
	ath10k_thermal_set_throttling(ar);
	mutex_unlock(&ar->conf_mutex);

	return count;
}

static ssize_t ath10k_read_quiet_period(struct file *file, char __user *ubuf,
					size_t count, loff_t *ppos)
{
	char buf[32];
	struct ath10k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			ar->thermal.quiet_period);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_quiet_period = {
	.read = ath10k_read_quiet_period,
	.write = ath10k_write_quiet_period,
	.open = simple_open
};

static ssize_t ath10k_write_btcoex(struct file *file,
				   const char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32];
	size_t buf_size;
	int ret;
	bool val;
	u32 pdev_param;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, ubuf, buf_size))
		return -EFAULT;

	buf[buf_size] = '\0';

	if (strtobool(buf, &val) != 0)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_RESTARTED) {
		ret = -ENETDOWN;
		goto exit;
	}

	if (!(test_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags) ^ val)) {
		ret = count;
		goto exit;
	}

	pdev_param = ar->wmi.pdev_param->enable_btcoex;
	if (test_bit(ATH10K_FW_FEATURE_BTCOEX_PARAM,
		     ar->running_fw->fw_file.fw_features)) {
		ret = ath10k_wmi_pdev_set_param(ar, pdev_param, val);
		if (ret) {
			ath10k_warn(ar, "failed to enable btcoex: %d\n", ret);
			ret = count;
			goto exit;
		}
	} else {
		ath10k_info(ar, "restarting firmware due to btcoex change");
		queue_work(ar->workqueue, &ar->restart_work);
	}

	if (val)
		set_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags);
	else
		clear_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags);

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_read_btcoex(struct file *file, char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	struct ath10k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			test_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags));
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_btcoex = {
	.read = ath10k_read_btcoex,
	.write = ath10k_write_btcoex,
	.open = simple_open
};

static ssize_t ath10k_write_enable_extd_tx_stats(struct file *file,
						 const char __user *ubuf,
						 size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u32 filter;
	int ret;

	if (kstrtouint_from_user(ubuf, count, 0, &filter))
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON) {
		ar->debug.enable_extd_tx_stats = filter;
		ret = count;
		goto out;
	}

	if (filter == ar->debug.enable_extd_tx_stats) {
		ret = count;
		goto out;
	}

	ar->debug.enable_extd_tx_stats = filter;
	ret = count;

out:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static ssize_t ath10k_read_enable_extd_tx_stats(struct file *file,
						char __user *ubuf,
						size_t count, loff_t *ppos)

{
	char buf[32];
	struct ath10k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%08x\n",
			ar->debug.enable_extd_tx_stats);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_enable_extd_tx_stats = {
	.read = ath10k_read_enable_extd_tx_stats,
	.write = ath10k_write_enable_extd_tx_stats,
	.open = simple_open
};

static ssize_t ath10k_write_peer_stats(struct file *file,
				       const char __user *ubuf,
				       size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32];
	size_t buf_size;
	int ret;
	bool val;

	buf_size = min(count, (sizeof(buf) - 1));
	if (copy_from_user(buf, ubuf, buf_size))
		return -EFAULT;

	buf[buf_size] = '\0';

	if (strtobool(buf, &val) != 0)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_RESTARTED) {
		ret = -ENETDOWN;
		goto exit;
	}

	if (!(test_bit(ATH10K_FLAG_PEER_STATS, &ar->dev_flags) ^ val)) {
		ret = count;
		goto exit;
	}

	if (val)
		set_bit(ATH10K_FLAG_PEER_STATS, &ar->dev_flags);
	else
		clear_bit(ATH10K_FLAG_PEER_STATS, &ar->dev_flags);

	ath10k_info(ar, "restarting firmware due to Peer stats change");

	queue_work(ar->workqueue, &ar->restart_work);
	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static ssize_t ath10k_read_peer_stats(struct file *file, char __user *ubuf,
				      size_t count, loff_t *ppos)

{
	char buf[32];
	struct ath10k *ar = file->private_data;
	int len = 0;

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			test_bit(ATH10K_FLAG_PEER_STATS, &ar->dev_flags));
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations fops_peer_stats = {
	.read = ath10k_read_peer_stats,
	.write = ath10k_write_peer_stats,
	.open = simple_open
};

static ssize_t ath10k_debug_fw_checksums_read(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	size_t len = 0, buf_len = 4096;
	ssize_t ret_cnt;
	char *buf;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);

	len += scnprintf(buf + len, buf_len - len,
			 "firmware-N.bin\t\t%08x\n",
			 crc32_le(0, ar->normal_mode_fw.fw_file.firmware->data,
				  ar->normal_mode_fw.fw_file.firmware->size));
	len += scnprintf(buf + len, buf_len - len,
			 "athwlan\t\t\t%08x\n",
			 crc32_le(0, ar->normal_mode_fw.fw_file.firmware_data,
				  ar->normal_mode_fw.fw_file.firmware_len));
	len += scnprintf(buf + len, buf_len - len,
			 "otp\t\t\t%08x\n",
			 crc32_le(0, ar->normal_mode_fw.fw_file.otp_data,
				  ar->normal_mode_fw.fw_file.otp_len));
	len += scnprintf(buf + len, buf_len - len,
			 "codeswap\t\t%08x\n",
			 crc32_le(0, ar->normal_mode_fw.fw_file.codeswap_data,
				  ar->normal_mode_fw.fw_file.codeswap_len));
	len += scnprintf(buf + len, buf_len - len,
			 "board-N.bin\t\t%08x\n",
			 crc32_le(0, ar->normal_mode_fw.board->data,
				  ar->normal_mode_fw.board->size));
	len += scnprintf(buf + len, buf_len - len,
			 "board\t\t\t%08x\n",
			 crc32_le(0, ar->normal_mode_fw.board_data,
				  ar->normal_mode_fw.board_len));

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	mutex_unlock(&ar->conf_mutex);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_fw_checksums = {
	.read = ath10k_debug_fw_checksums_read,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_sta_tid_stats_mask_read(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32];
	size_t len;

	len = scnprintf(buf, sizeof(buf), "0x%08x\n", ar->sta_tid_stats_mask);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_sta_tid_stats_mask_write(struct file *file,
					       const char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32];
	ssize_t len;
	u32 mask;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoint(buf, 0, &mask))
		return -EINVAL;

	ar->sta_tid_stats_mask = mask;

	return len;
}

static const struct file_operations fops_sta_tid_stats_mask = {
	.read = ath10k_sta_tid_stats_mask_read,
	.write = ath10k_sta_tid_stats_mask_write,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath10k_debug_tpc_stats_final_request(struct ath10k *ar)
{
	int ret;
	unsigned long time_left;

	lockdep_assert_held(&ar->conf_mutex);

	reinit_completion(&ar->debug.tpc_complete);

	ret = ath10k_wmi_pdev_get_tpc_table_cmdid(ar, WMI_TPC_CONFIG_PARAM);
	if (ret) {
		ath10k_warn(ar, "failed to request tpc table cmdid: %d\n", ret);
		return ret;
	}

	time_left = wait_for_completion_timeout(&ar->debug.tpc_complete,
						1 * HZ);
	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

static int ath10k_tpc_stats_final_open(struct inode *inode, struct file *file)
{
	struct ath10k *ar = inode->i_private;
	void *buf;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON) {
		ret = -ENETDOWN;
		goto err_unlock;
	}

	buf = vmalloc(ATH10K_TPC_CONFIG_BUF_SIZE);
	if (!buf) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	ret = ath10k_debug_tpc_stats_final_request(ar);
	if (ret) {
		ath10k_warn(ar, "failed to request tpc stats final: %d\n",
			    ret);
		goto err_free;
	}

	ath10k_tpc_stats_fill(ar, ar->debug.tpc_stats, buf);
	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);
	return 0;

err_free:
	vfree(buf);

err_unlock:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static int ath10k_tpc_stats_final_release(struct inode *inode,
					  struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static ssize_t ath10k_tpc_stats_final_read(struct file *file,
					   char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	const char *buf = file->private_data;
	unsigned int len = strlen(buf);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_tpc_stats_final = {
	.open = ath10k_tpc_stats_final_open,
	.release = ath10k_tpc_stats_final_release,
	.read = ath10k_tpc_stats_final_read,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_write_warm_hw_reset(struct file *file,
					  const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	bool val;

	if (kstrtobool_from_user(user_buf, count, &val))
		return -EFAULT;

	if (!val)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON) {
		ret = -ENETDOWN;
		goto exit;
	}

	if (!(test_bit(WMI_SERVICE_RESET_CHIP, ar->wmi.svc_map)))
		ath10k_warn(ar, "wmi service for reset chip is not available\n");

	ret = ath10k_wmi_pdev_set_param(ar, ar->wmi.pdev_param->pdev_reset,
					WMI_RST_MODE_WARM_RESET);

	if (ret) {
		ath10k_warn(ar, "failed to enable warm hw reset: %d\n", ret);
		goto exit;
	}

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);
	return ret;
}

static const struct file_operations fops_warm_hw_reset = {
	.write = ath10k_write_warm_hw_reset,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static void ath10k_peer_ps_state_disable(void *data,
					 struct ieee80211_sta *sta)
{
	struct ath10k *ar = data;
	struct ath10k_sta *arsta = (struct ath10k_sta *)sta->drv_priv;

	spin_lock_bh(&ar->data_lock);
	arsta->peer_ps_state = WMI_PEER_PS_STATE_DISABLED;
	spin_unlock_bh(&ar->data_lock);
}

static ssize_t ath10k_write_ps_state_enable(struct file *file,
					    const char __user *user_buf,
					    size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	u32 param;
	u8 ps_state_enable;

	if (kstrtou8_from_user(user_buf, count, 0, &ps_state_enable))
		return -EINVAL;

	if (ps_state_enable > 1)
		return -EINVAL;

	mutex_lock(&ar->conf_mutex);

	if (ar->ps_state_enable == ps_state_enable) {
		ret = count;
		goto exit;
	}

	param = ar->wmi.pdev_param->peer_sta_ps_statechg_enable;
	ret = ath10k_wmi_pdev_set_param(ar, param, ps_state_enable);
	if (ret) {
		ath10k_warn(ar, "failed to enable ps_state_enable: %d\n",
			    ret);
		goto exit;
	}
	ar->ps_state_enable = ps_state_enable;

	if (!ar->ps_state_enable)
		ieee80211_iterate_stations_atomic(ar->hw,
						  ath10k_peer_ps_state_disable,
						  ar);

	ret = count;

exit:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_read_ps_state_enable(struct file *file,
					   char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int len = 0;
	char buf[32];

	mutex_lock(&ar->conf_mutex);
	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			ar->ps_state_enable);
	mutex_unlock(&ar->conf_mutex);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_ps_state_enable = {
	.read = ath10k_read_ps_state_enable,
	.write = ath10k_write_ps_state_enable,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

int ath10k_debug_create(struct ath10k *ar)
{
	ar->debug.cal_data = vzalloc(ATH10K_DEBUG_CAL_DATA_LEN);
	if (!ar->debug.cal_data)
		return -ENOMEM;

	INIT_LIST_HEAD(&ar->debug.fw_stats.pdevs);
	INIT_LIST_HEAD(&ar->debug.fw_stats.vdevs);
	INIT_LIST_HEAD(&ar->debug.fw_stats.peers);
	INIT_LIST_HEAD(&ar->debug.fw_stats.peers_extd);

	INIT_DELAYED_WORK(&ar->debug.nop_dwork, ath10k_debug_nop_dwork);

	return 0;
}

void ath10k_debug_destroy(struct ath10k *ar)
{
	vfree(ar->debug.cal_data);
	ar->debug.cal_data = NULL;

	ath10k_debug_fw_stats_reset(ar);

	kfree(ar->debug.tpc_stats);

	cancel_delayed_work_sync(&ar->debug.nop_dwork);
}

int ath10k_debug_register(struct ath10k *ar)
{
	ar->debug.debugfs_phy = debugfs_create_dir("ath10k",
						   ar->hw->wiphy->debugfsdir);
	if (IS_ERR_OR_NULL(ar->debug.debugfs_phy)) {
		if (IS_ERR(ar->debug.debugfs_phy))
			return PTR_ERR(ar->debug.debugfs_phy);

		return -ENOMEM;
	}

	INIT_DELAYED_WORK(&ar->debug.htt_stats_dwork,
			  ath10k_debug_htt_stats_dwork);

	init_completion(&ar->debug.tpc_complete);
	init_completion(&ar->debug.fw_stats_complete);
	init_completion(&ar->debug.ratepwr_tbl_complete);
	init_completion(&ar->debug.powerctl_tbl_complete);

	debugfs_create_file("fw_stats", 0400, ar->debug.debugfs_phy, ar,
			    &fops_fw_stats);

	debugfs_create_file("fw_reset_stats", 0400, ar->debug.debugfs_phy, ar,
			    &fops_fw_reset_stats);

	debugfs_create_file("fw_regs", 0400, ar->debug.debugfs_phy, ar,
			    &fops_fw_regs);

	debugfs_create_file("rx_reorder_stats", 0400, ar->debug.debugfs_phy, ar,
			    &fops_rx_reorder_stats);

	debugfs_create_file("wmi_services", 0400, ar->debug.debugfs_phy, ar,
			    &fops_wmi_services);

	debugfs_create_file("set_rates", 0600, ar->debug.debugfs_phy,
			    ar, &fops_set_rates);

	debugfs_create_file("set_rate_override", 0600, ar->debug.debugfs_phy,
			    ar, &fops_set_rate_override);

	debugfs_create_file("firmware_info", 0400, ar->debug.debugfs_phy, ar,
			    &fops_fwinfo_services);

	debugfs_create_file("simulate_fw_crash", 0600, ar->debug.debugfs_phy, ar,
			    &fops_simulate_fw_crash);

	debugfs_create_file("misc", 0400, ar->debug.debugfs_phy, ar,
			    &fops_misc);

	debugfs_create_file("debug_level", 0600, ar->debug.debugfs_phy,
			    ar, &fops_debug_level);

	debugfs_create_file("reg_addr", 0600, ar->debug.debugfs_phy, ar,
			    &fops_reg_addr);

	debugfs_create_file("reg_value", 0600, ar->debug.debugfs_phy, ar,
			    &fops_reg_value);

	debugfs_create_file("mem_value", 0600, ar->debug.debugfs_phy, ar,
			    &fops_mem_value);

	debugfs_create_file("chip_id", 0400, ar->debug.debugfs_phy, ar,
			    &fops_chip_id);

	debugfs_create_file("htt_stats_mask", 0600, ar->debug.debugfs_phy, ar,
			    &fops_htt_stats_mask);

	debugfs_create_file("htt_max_amsdu_ampdu", 0600, ar->debug.debugfs_phy, ar,
			    &fops_htt_max_amsdu_ampdu);

	debugfs_create_file("fw_dbglog", 0600, ar->debug.debugfs_phy, ar,
			    &fops_fw_dbglog);

	if (!test_bit(ATH10K_FW_FEATURE_NON_BMI,
		      ar->normal_mode_fw.fw_file.fw_features)) {
		debugfs_create_file("cal_data", 0400, ar->debug.debugfs_phy, ar,
				    &fops_cal_data);

		debugfs_create_file("nf_cal_period", 0600, ar->debug.debugfs_phy, ar,
				    &fops_nf_cal_period);
	}

	debugfs_create_file("ani_enable", 0600, ar->debug.debugfs_phy, ar,
			    &fops_ani_enable);

	if (IS_ENABLED(CONFIG_ATH10K_DFS_CERTIFIED)) {
		debugfs_create_file("dfs_simulate_radar", 0200, ar->debug.debugfs_phy,
				    ar, &fops_simulate_radar);

		debugfs_create_bool("dfs_block_radar_events", 0644,
				    ar->debug.debugfs_phy,
				    &ar->dfs_block_radar_events);

		debugfs_create_file("dfs_stats", 0400, ar->debug.debugfs_phy, ar,
				    &fops_dfs_stats);
	}

	debugfs_create_file("pktlog_filter", 0644, ar->debug.debugfs_phy, ar,
			    &fops_pktlog_filter);

	if (test_bit(WMI_SERVICE_THERM_THROT, ar->wmi.svc_map))
		debugfs_create_file("quiet_period", 0644, ar->debug.debugfs_phy, ar,
				    &fops_quiet_period);

	debugfs_create_file("powerctl_table", 0600, ar->debug.debugfs_phy, ar,
			    &fops_powerctl_table);

	debugfs_create_file("ratepwr_table", 0600, ar->debug.debugfs_phy, ar,
			    &fops_ratepwr_table);

	debugfs_create_file("tpc_stats", 0400, ar->debug.debugfs_phy, ar,
			    &fops_tpc_stats);

	debugfs_create_file("thresh62_ext", S_IRUGO | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_thresh62_ext);

	debugfs_create_file("ct_special", S_IRUGO | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_ct_special);

	if (test_bit(WMI_SERVICE_COEX_GPIO, ar->wmi.svc_map))
		debugfs_create_file("btcoex", 0644, ar->debug.debugfs_phy, ar,
				    &fops_btcoex);

	debugfs_create_file("peers", 0400, ar->debug.debugfs_phy, ar,
			    &fops_peers);
	if (test_bit(WMI_SERVICE_PEER_STATS, ar->wmi.svc_map)) {
		debugfs_create_file("peer_stats", 0644, ar->debug.debugfs_phy, ar,
				    &fops_peer_stats);

		debugfs_create_file("enable_extd_tx_stats", 0644,
				    ar->debug.debugfs_phy, ar,
				    &fops_enable_extd_tx_stats);
	}

	debugfs_create_file("fw_checksums", 0400, ar->debug.debugfs_phy, ar,
			    &fops_fw_checksums);

	if (IS_ENABLED(CONFIG_MAC80211_DEBUGFS))
		debugfs_create_file("sta_tid_stats_mask", 0600,
				    ar->debug.debugfs_phy,
				    ar, &fops_sta_tid_stats_mask);

	if (test_bit(WMI_SERVICE_TPC_STATS_FINAL, ar->wmi.svc_map))
		debugfs_create_file("tpc_stats_final", 0400,
				    ar->debug.debugfs_phy, ar,
				    &fops_tpc_stats_final);

	debugfs_create_file("warm_hw_reset", 0600, ar->debug.debugfs_phy, ar,
			    &fops_warm_hw_reset);

	debugfs_create_file("ps_state_enable", 0600, ar->debug.debugfs_phy, ar,
			    &fops_ps_state_enable);

	return 0;
}

void ath10k_debug_unregister(struct ath10k *ar)
{
	cancel_delayed_work_sync(&ar->debug.nop_dwork);
	cancel_delayed_work_sync(&ar->debug.htt_stats_dwork);
}

#endif /* CONFIG_ATH10K_DEBUGFS */

#ifdef CONFIG_ATH10K_DEBUG
void ath10k_dbg(struct ath10k *ar, enum ath10k_debug_mask mask,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	if (ath10k_debug_mask & mask)
		dev_printk(KERN_DEBUG, ar->dev, "%pV", &vaf);

	trace_ath10k_log_dbg(ar, mask, &vaf);

	va_end(args);
}
EXPORT_SYMBOL(ath10k_dbg);

void ath10k_dbg_dump(struct ath10k *ar,
		     enum ath10k_debug_mask mask,
		     const char *msg, const char *prefix,
		     const void *buf, size_t len)
{
	char linebuf[256];
	size_t linebuflen;
	const void *ptr;

	if (ath10k_debug_mask & mask) {
		if (msg)
			ath10k_dbg(ar, mask, "%s\n", msg);

		for (ptr = buf; (ptr - buf) < len; ptr += 16) {
			linebuflen = 0;
			linebuflen += scnprintf(linebuf + linebuflen,
						sizeof(linebuf) - linebuflen,
						"%s%08x: ",
						(prefix ? prefix : ""),
						(unsigned int)(ptr - buf));
			hex_dump_to_buffer(ptr, len - (ptr - buf), 16, 1,
					   linebuf + linebuflen,
					   sizeof(linebuf) - linebuflen, true);
			dev_printk(KERN_DEBUG, ar->dev, "%s\n", linebuf);
		}
	}

	/* tracing code doesn't like null strings :/ */
	trace_ath10k_log_dbg_dump(ar, msg ? msg : "", prefix ? prefix : "",
				  buf, len);
}
EXPORT_SYMBOL(ath10k_dbg_dump);

#endif /* CONFIG_ATH10K_DEBUG */

void ath10k_dbg_print_fw_dbg_buffer(struct ath10k *ar, __le32 *ibuf, int len,
				    const char* lvl)
{
	/* Print out raw hex, external tools can decode if
	 * they care.
	 * TODO:  Add ar identifier to messages.
	 */
	int q = 0;

	dev_printk(lvl, ar->dev, "ath10k_pci ATH10K_DBG_BUFFER:\n");
	while (q < len) {
		if (q + 8 <= len) {
			printk("%sath10k: [%04d]: %08X %08X %08X %08X %08X %08X %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1], ibuf[q+2], ibuf[q+3],
			       ibuf[q+4], ibuf[q+5], ibuf[q+6], ibuf[q+7]);
			q += 8;
		}
		else if (q + 7 <= len) {
			printk("%sath10k: [%04d]: %08X %08X %08X %08X %08X %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1], ibuf[q+2], ibuf[q+3],
			       ibuf[q+4], ibuf[q+5], ibuf[q+6]);
			q += 7;
		}
		else if (q + 6 <= len) {
			printk("%sath10k: [%04d]: %08X %08X %08X %08X %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1], ibuf[q+2], ibuf[q+3],
			       ibuf[q+4], ibuf[q+5]);
			q += 6;
		}
		else if (q + 5 <= len) {
			printk("%sath10k: [%04d]: %08X %08X %08X %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1], ibuf[q+2], ibuf[q+3],
			       ibuf[q+4]);
			q += 5;
		}
		else if (q + 4 <= len) {
			printk("%sath10k: [%04d]: %08X %08X %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1], ibuf[q+2], ibuf[q+3]);
			q += 4;
		}
		else if (q + 3 <= len) {
			printk("%sath10k: [%04d]: %08X %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1], ibuf[q+2]);
			q += 3;
		}
		else if (q + 2 <= len) {
			printk("%sath10k: [%04d]: %08X %08X\n",
			       lvl, q,
			       ibuf[q], ibuf[q+1]);
			q += 2;
		}
		else if (q + 1 <= len) {
			printk("%sath10k: [%04d]: %08X\n",
			       lvl, q,
			       ibuf[q]);
			q += 1;
		}
		else {
			break;
		}
	}/* while */

	dev_printk(lvl, ar->dev, "ATH10K_END\n");
}
EXPORT_SYMBOL(ath10k_dbg_print_fw_dbg_buffer);
