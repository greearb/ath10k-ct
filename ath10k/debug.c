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

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <linux/utsname.h>
#include <linux/crc32.h>
#include <linux/firmware.h>

#include "core.h"
#include "debug.h"
#include "hif.h"
#include "wmi-ops.h"
#include "mac.h"

/* ms */
#define ATH10K_DEBUG_HTT_STATS_INTERVAL 1000

#define ATH10K_DEBUG_NOP_INTERVAL 2000 /* ms */

#define ATH10K_FW_CRASH_DUMP_VERSION 1

/**
 * enum ath10k_fw_crash_dump_type - types of data in the dump file
 * @ATH10K_FW_CRASH_DUMP_REGDUMP: Register crash dump in binary format
 * @ATH10K_FW_ERROR_DUMP_DBGLOG:  Recent firmware debug log entries
 * @ATH10K_FW_CRASH_DUMP_STACK:   Stack memory contents.
 * @ATH10K_FW_CRASH_DUMP_EXC_STACK:   Exception stack memory contents.
 * @ATH10K_FW_CRASH_DUMP_RAM_BSS:  BSS area for RAM code
 * @ATH10K_FW_CRASH_DUMP_ROM_BSS:  BSS area for ROM code
 */
enum ath10k_fw_crash_dump_type {
	ATH10K_FW_CRASH_DUMP_REGISTERS = 0,
	ATH10K_FW_CRASH_DUMP_DBGLOG = 1,
	ATH10K_FW_CRASH_DUMP_STACK = 2,
	ATH10K_FW_CRASH_DUMP_EXC_STACK = 3,
	ATH10K_FW_CRASH_DUMP_RAM_BSS = 4,
	ATH10K_FW_CRASH_DUMP_ROM_BSS = 5,

	ATH10K_FW_CRASH_DUMP_MAX,
};

struct ath10k_tlv_dump_data {
	/* see ath10k_fw_crash_dump_type above */
	__le32 type;

	/* in bytes */
	__le32 tlv_len;

	/* pad to 32-bit boundaries as needed */
	u8 tlv_data[];
} __packed;

struct ath10k_dump_file_data {
	/* dump file information */

	/* "ATH10K-FW-DUMP" */
	char df_magic[16];

	__le32 len;

	/* file dump version */
	__le32 version;

	/* some info we can get from ath10k struct that might help */

	u8 uuid[16];

	__le32 chip_id;

	/* 0 for now, in place for later hardware */
	__le32 bus_type;

	__le32 target_version;
	__le32 fw_version_major;
	__le32 fw_version_minor;
	__le32 fw_version_release;
	__le32 fw_version_build;
	__le32 phy_capability;
	__le32 hw_min_tx_power;
	__le32 hw_max_tx_power;
	__le32 ht_cap_info;
	__le32 vht_cap_info;
	__le32 num_rf_chains;

	/* firmware version string */
	char fw_ver[ETHTOOL_FWVERS_LEN];

	/* Kernel related information */

	/* time-of-day stamp */
	__le64 tv_sec;

	/* time-of-day stamp, nano-seconds */
	__le64 tv_nsec;

	/* LINUX_VERSION_CODE */
	__le32 kernel_ver_code;

	/* VERMAGIC_STRING */
	char kernel_ver[64];

	__le32 stack_addr;
	__le32 exc_stack_addr;
	__le32 rom_bss_addr;
	__le32 ram_bss_addr;

	/* room for growth w/out changing binary format */
	u8 unused[112];

	/* struct ath10k_tlv_dump_data + more */
	u8 data[0];
} __packed;

struct ath10k_dbglog_entry_storage_user {
	__le32 head_idx; /* Where to write next chunk of data */
	__le32 tail_idx; /* Index of first msg */
	__le32 data[ATH10K_DBGLOG_DATA_LEN];
} __packed;

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
	char fw_features[256] = {};
	u32 crc = 0;

	ath10k_core_get_fw_features_str(ar, fw_features, sizeof(fw_features));

	ath10k_info(ar, "%s target 0x%08x chip_id 0x%08x sub %04x:%04x",
		    ar->hw_params.name,
		    ar->target_version,
		    ar->chip_id,
		    ar->id.subsystem_vendor, ar->id.subsystem_device);

	ath10k_info(ar, "kconfig debug %d debugfs %d tracing %d dfs %d testmode %d\n",
		    config_enabled(CONFIG_ATH10K_DEBUG),
		    config_enabled(CONFIG_ATH10K_DEBUGFS),
		    config_enabled(CONFIG_ATH10K_TRACING),
		    config_enabled(CONFIG_ATH10K_DFS_CERTIFIED),
		    config_enabled(CONFIG_NL80211_TESTMODE));

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

	if (ar->id.bmi_ids_valid)
		scnprintf(boardinfo, sizeof(boardinfo), "%d:%d",
			  ar->id.bmi_chip_id, ar->id.bmi_board_id);
	else
		scnprintf(boardinfo, sizeof(boardinfo), "N/A");

	ath10k_info(ar, "board_file api %d bmi_id %s crc32 %08x",
		    ar->bd_api,
		    boardinfo,
		    crc32_le(0, ar->normal_mode_fw.board->data,
			     ar->normal_mode_fw.board->size));
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
	unsigned int len = 0, buf_len = 4096;
	const char *name;
	ssize_t ret_cnt;
	bool enabled;
	int i;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mutex_lock(&ar->conf_mutex);

	if (len > buf_len)
		len = buf_len;

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
	case ATH10K_HW_QCA9887:
		len += snprintf(buf + len, buf_len - len, "9887\n");
		break;
	case ATH10K_HW_QCA988X:
		len += snprintf(buf + len, buf_len - len, "988x\n");
		break;
	case ATH10K_HW_QCA9888:
		len += snprintf(buf + len, buf_len - len, "9888\n");
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

static void ath10k_debug_fw_stats_reset(struct ath10k *ar)
{
	spin_lock_bh(&ar->data_lock);
	ar->debug.fw_stats_done = false;
	ath10k_fw_stats_pdevs_free(&ar->debug.fw_stats.pdevs);
	ath10k_fw_stats_vdevs_free(&ar->debug.fw_stats.vdevs);
	ath10k_fw_stats_peers_free(&ar->debug.fw_stats.peers);
	spin_unlock_bh(&ar->data_lock);
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

	spin_lock_bh(&ar->data_lock);

	/* CT Firmware only */
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
			switch (__le16_to_cpu(regdump->regpair[i].reg_id)) {
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
				sptr->pcu_bssid_l32 = __le32_to_cpu(regdump->regpair[i].reg_val);
				break;
			case PCU_BSSID2_U16:
				sptr->pcu_bssid_u16 = __le32_to_cpu(regdump->regpair[i].reg_val);
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
			}/* switch */
		}
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
		ath10k_sta_update_rx_duration(ar, &stats.peers);

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
		if (num_peers >= ATH10K_MAX_NUM_PEER_IDS) {
			/* Although this is unlikely impose a sane limit to
			 * prevent firmware from DoS-ing the host.
			 */
			ath10k_fw_stats_peers_free(&ar->debug.fw_stats.peers);
			ath10k_warn(ar, "dropping fw peer stats\n");
			goto free;
		}

		if (num_vdevs >= BITS_PER_LONG) {
			ath10k_fw_stats_vdevs_free(&ar->debug.fw_stats.vdevs);
			ath10k_warn(ar, "dropping fw vdev stats\n");
			goto free;
		}

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

	spin_unlock_bh(&ar->data_lock);
}

static int ath10k_debug_fw_stats_request(struct ath10k *ar)
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

int ath10k_refresh_peer_stats_t(struct ath10k *ar, u32 type)
{
	int ret;
	unsigned long time_left;

	reinit_completion(&ar->debug.fw_stats_complete);
	ret = ath10k_wmi_request_stats(ar, type);

	if (ret) {
		ath10k_warn(ar, "could not request stats (type %d ret %d)\n",
			    type, ret);
		return ret;
	}

	/* ret means 'time-left' here */
	time_left =
		wait_for_completion_timeout(&ar->debug.fw_stats_complete, 1*HZ);
	if (time_left == 0)
		return -ETIMEDOUT;

	return 0;
}

int ath10k_refresh_peer_stats(struct ath10k *ar)
{
	return ath10k_refresh_peer_stats_t(ar, ar->fw_stats_req_mask);
}

int ath10k_refresh_target_regs(struct ath10k *ar)
{
	if (test_bit(ATH10K_FW_FEATURE_REGDUMP_CT,
		     ar->running_fw->fw_file.fw_features))
		return ath10k_refresh_peer_stats_t(ar, WMI_REQUEST_REGISTER_DUMP);
	return 0; /* fail silently if firmware does not support this option. */
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
	len += scnprintf(buf + len, buf_len - len, "%30s\n",
			 "ath10k Target Register Dump");
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
			 "ADC-TEMP", fw_regs->adc_temp);

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
	unsigned int len = strlen(buf);

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
	int ret, len, buf_len;
	char *buf;

	buf_len = 500;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	spin_lock_bh(&ar->data_lock);

	len = 0;
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
	char buf[32];
	int ret;

	mutex_lock(&ar->conf_mutex);

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = 0;

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_RESTARTED) {
		ret = -ENETDOWN;
		goto exit;
	}

	/* drop the possible '\n' from the end */
	if (buf[count - 1] == '\n') {
		buf[count - 1] = 0;
		count--;
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
		"MAC2:        0x20000000\n"
		"INFO-AS-DBG: 0x40000000\n"
		"FW:          0x80000000\n"
		"ALL:         0xFFFFFFFF\n";
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
		return ret;
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

static ssize_t ath10k_read_chip_id(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	unsigned int len;
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

struct ath10k_fw_crash_data *
ath10k_debug_get_new_fw_crash_data(struct ath10k *ar)
{
	struct ath10k_fw_crash_data *crash_data = ar->debug.fw_crash_data;

	lockdep_assert_held(&ar->data_lock);

	uuid_le_gen(&crash_data->uuid);
	getnstimeofday(&crash_data->timestamp);

	return crash_data;
}
EXPORT_SYMBOL(ath10k_debug_get_new_fw_crash_data);

static void ath10k_dbg_drop_dbg_buffer(struct ath10k *ar)
{
	/* Find next message boundary */
	u32 lg_hdr;
	int acnt;
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

	lockdep_assert_held(&ar->data_lock);

	z = ar->debug.dbglog_entry_data.head_idx;

	/* Don't save any new logs until user-space reads this. */
	if (ar->debug.fw_crash_data &&
	    ar->debug.fw_crash_data->crashed_since_read) {
		ath10k_warn(ar, "dropping dbg buffer due to crash since read\n");
		return;
	}

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

static struct ath10k_dump_file_data *ath10k_build_dump_file(struct ath10k *ar)
{
	struct ath10k_fw_crash_data *crash_data = ar->debug.fw_crash_data;
	struct ath10k_dump_file_data *dump_data;
	struct ath10k_tlv_dump_data *dump_tlv;
	struct ath10k_dbglog_entry_storage_user *dbglog_storage;
	int hdr_len = sizeof(*dump_data);
	unsigned int len, sofar = 0;
	unsigned char *buf;
	int tmp;

	BUILD_BUG_ON(sizeof(struct ath10k_dbglog_entry_storage) !=
		     sizeof(struct ath10k_dbglog_entry_storage_user));

	len = hdr_len;
	len += sizeof(*dump_tlv) + sizeof(crash_data->registers);
	len += sizeof(*dump_tlv) + sizeof(ar->debug.dbglog_entry_data);
	len += sizeof(*dump_tlv) + sizeof(crash_data->stack_buf);
	len += sizeof(*dump_tlv) + sizeof(crash_data->exc_stack_buf);

	if (ar->running_fw->fw_file.ram_bss_addr &&
	    ar->running_fw->fw_file.ram_bss_len)
		len += sizeof(*dump_tlv) + ar->running_fw->fw_file.ram_bss_len;

	if (ar->running_fw->fw_file.rom_bss_addr &&
	    ar->running_fw->fw_file.rom_bss_len)
		len += sizeof(*dump_tlv) + ar->running_fw->fw_file.rom_bss_len;

	sofar += hdr_len;

	/* This is going to get big when we start dumping FW RAM and such,
	 * so go ahead and use vmalloc.
	 */
	buf = vzalloc(len);
	if (!buf)
		return NULL;

	spin_lock_bh(&ar->data_lock);

	if (!crash_data->crashed_since_read) {
		spin_unlock_bh(&ar->data_lock);
		vfree(buf);
		return NULL;
	}

	dump_data = (struct ath10k_dump_file_data *)(buf);
	strlcpy(dump_data->df_magic, "ATH10K-FW-DUMP",
		sizeof(dump_data->df_magic));
	dump_data->len = cpu_to_le32(len);

	dump_data->version = cpu_to_le32(ATH10K_FW_CRASH_DUMP_VERSION);

	memcpy(dump_data->uuid, &crash_data->uuid, sizeof(dump_data->uuid));
	dump_data->chip_id = cpu_to_le32(ar->chip_id);
	dump_data->bus_type = cpu_to_le32(0);
	dump_data->target_version = cpu_to_le32(ar->target_version);
	dump_data->fw_version_major = cpu_to_le32(ar->fw_version_major);
	dump_data->fw_version_minor = cpu_to_le32(ar->fw_version_minor);
	dump_data->fw_version_release = cpu_to_le32(ar->fw_version_release);
	dump_data->fw_version_build = cpu_to_le32(ar->fw_version_build);
	dump_data->phy_capability = cpu_to_le32(ar->phy_capability);
	dump_data->hw_min_tx_power = cpu_to_le32(ar->hw_min_tx_power);
	dump_data->hw_max_tx_power = cpu_to_le32(ar->hw_max_tx_power);
	dump_data->ht_cap_info = cpu_to_le32(ar->ht_cap_info);
	dump_data->vht_cap_info = cpu_to_le32(ar->vht_cap_info);
	dump_data->num_rf_chains = cpu_to_le32(ar->num_rf_chains);
	dump_data->stack_addr = cpu_to_le32(crash_data->stack_addr);
	dump_data->exc_stack_addr = cpu_to_le32(crash_data->exc_stack_addr);
	dump_data->rom_bss_addr =
		cpu_to_le32(ar->running_fw->fw_file.rom_bss_addr);
	dump_data->ram_bss_addr =
		cpu_to_le32(ar->running_fw->fw_file.ram_bss_addr);

	strlcpy(dump_data->fw_ver, ar->hw->wiphy->fw_version,
		sizeof(dump_data->fw_ver));

	dump_data->kernel_ver_code = 0;
	strlcpy(dump_data->kernel_ver, init_utsname()->release,
		sizeof(dump_data->kernel_ver));

	dump_data->tv_sec = cpu_to_le64(crash_data->timestamp.tv_sec);
	dump_data->tv_nsec = cpu_to_le64(crash_data->timestamp.tv_nsec);

	/* Gather crash-dump */
	dump_tlv = (struct ath10k_tlv_dump_data *)(buf + sofar);
	dump_tlv->type = cpu_to_le32(ATH10K_FW_CRASH_DUMP_REGISTERS);
	dump_tlv->tlv_len = cpu_to_le32(sizeof(crash_data->registers));
	memcpy(dump_tlv->tlv_data, &crash_data->registers,
	       sizeof(crash_data->registers));
	sofar += sizeof(*dump_tlv) + sizeof(crash_data->registers);

	/* Gather dbg-log */
	tmp = sizeof(ar->debug.dbglog_entry_data);
	dump_tlv = (struct ath10k_tlv_dump_data *)(buf + sofar);
	dump_tlv->type = cpu_to_le32(ATH10K_FW_CRASH_DUMP_DBGLOG);
	dump_tlv->tlv_len = cpu_to_le32(tmp);
	dbglog_storage =
		(struct ath10k_dbglog_entry_storage_user *)(dump_tlv->tlv_data);
	memcpy(dbglog_storage->data, ar->debug.dbglog_entry_data.data,
	       sizeof(dbglog_storage->data));
	dbglog_storage->head_idx =
		cpu_to_le32(ar->debug.dbglog_entry_data.head_idx);
	dbglog_storage->tail_idx =
		cpu_to_le32(ar->debug.dbglog_entry_data.tail_idx);
	sofar += sizeof(*dump_tlv) + tmp;

	/* Gather firmware stack dump */
	tmp = sizeof(crash_data->stack_buf);
	dump_tlv = (struct ath10k_tlv_dump_data *)(buf + sofar);
	dump_tlv->type = cpu_to_le32(ATH10K_FW_CRASH_DUMP_STACK);
	dump_tlv->tlv_len = cpu_to_le32(tmp);
	memcpy(dump_tlv->tlv_data, crash_data->stack_buf, tmp);
	sofar += sizeof(*dump_tlv) + tmp;

	/* Gather firmware exception stack dump */
	tmp = sizeof(crash_data->exc_stack_buf);
	dump_tlv = (struct ath10k_tlv_dump_data *)(buf + sofar);
	dump_tlv->type = cpu_to_le32(ATH10K_FW_CRASH_DUMP_EXC_STACK);
	dump_tlv->tlv_len = cpu_to_le32(tmp);
	memcpy(dump_tlv->tlv_data, crash_data->exc_stack_buf, tmp);
	sofar += sizeof(*dump_tlv) + tmp;

	if (ar->running_fw->fw_file.ram_bss_addr &&
	    ar->running_fw->fw_file.ram_bss_len) {
		tmp = ar->running_fw->fw_file.ram_bss_len;
		dump_tlv = (struct ath10k_tlv_dump_data *)(buf + sofar);
		dump_tlv->type = cpu_to_le32(ATH10K_FW_CRASH_DUMP_RAM_BSS);
		dump_tlv->tlv_len = cpu_to_le32(tmp);
		memcpy(dump_tlv->tlv_data, crash_data->ram_bss_buf, tmp);
		sofar += sizeof(*dump_tlv) + tmp;
	}

	if (ar->running_fw->fw_file.rom_bss_addr &&
	    ar->running_fw->fw_file.rom_bss_len) {
		tmp = ar->running_fw->fw_file.rom_bss_len;
		dump_tlv = (struct ath10k_tlv_dump_data *)(buf + sofar);
		dump_tlv->type = cpu_to_le32(ATH10K_FW_CRASH_DUMP_ROM_BSS);
		dump_tlv->tlv_len = cpu_to_le32(tmp);
		memcpy(dump_tlv->tlv_data, crash_data->rom_bss_buf, tmp);
		sofar += sizeof(*dump_tlv) + tmp;
	}

	ar->debug.fw_crash_data->crashed_since_read = false;

	WARN_ON(sofar != len);
	spin_unlock_bh(&ar->data_lock);

	return dump_data;
}

static int ath10k_fw_crash_dump_open(struct inode *inode, struct file *file)
{
	struct ath10k *ar = inode->i_private;
	struct ath10k_dump_file_data *dump;

	dump = ath10k_build_dump_file(ar);
	if (!dump)
		return -ENODATA;

	file->private_data = dump;

	return 0;
}

static ssize_t ath10k_fw_crash_dump_read(struct file *file,
					 char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	struct ath10k_dump_file_data *dump_file = file->private_data;

	return simple_read_from_buffer(user_buf, count, ppos,
				       dump_file,
				       le32_to_cpu(dump_file->len));
}

static int ath10k_fw_crash_dump_release(struct inode *inode,
					struct file *file)
{
	vfree(file->private_data);

	return 0;
}

static const struct file_operations fops_fw_crash_dump = {
	.open = ath10k_fw_crash_dump_open,
	.read = ath10k_fw_crash_dump_read,
	.release = ath10k_fw_crash_dump_release,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_reg_addr_read(struct file *file,
				    char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	u8 buf[32];
	unsigned int len = 0;
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
	unsigned int len;
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
	unsigned int len;

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
	unsigned int len;

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
	char buf[64];
	unsigned int amsdu, ampdu;

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = 0;

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
	unsigned int len;
	char buf[64];

	len = scnprintf(buf, sizeof(buf), "0x%08x %u\n",
			ar->debug.fw_dbglog_mask, ar->debug.fw_dbglog_level);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath10k_write_fw_dbglog(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	int ret;
	char buf[64];
	unsigned int log_level, mask;

	simple_write_to_buffer(buf, sizeof(buf) - 1, ppos, user_buf, count);

	/* make sure that buf is null terminated */
	buf[sizeof(buf) - 1] = 0;

	ret = sscanf(buf, "%x %u", &mask, &log_level);

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

void ath10k_debug_get_et_stats(struct ieee80211_hw *hw,
			       struct ieee80211_vif *vif,
			       struct ethtool_stats *stats, u64 *data)
{
	struct ath10k *ar = hw->priv;
	static const struct ath10k_fw_stats_pdev zero_stats = {};
	const struct ath10k_fw_stats_pdev *pdev_stats;
	int i = 0, ret;
	u64 d_flags = 0;

	mutex_lock(&ar->conf_mutex);

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

	pdev_stats = list_first_entry_or_null(&ar->debug.fw_stats.pdevs,
					      struct ath10k_fw_stats_pdev,
					      list);
	if (!pdev_stats) {
		/* no results available so just return zeroes */
		pdev_stats = &zero_stats;
	}

	spin_lock_bh(&ar->data_lock);

	if (ar->hw_params.has_shifted_cc_wraparound)
		d_flags |= 0x1;

	data[i++] = pdev_stats->hw_reaped; /* ppdu reaped */
	data[i++] = ar->debug.tx_ok;
	data[i++] = ar->debug.tx_ok_bytes;
	data[i++] = ar->debug.tx_bytes;
	data[i++] = pdev_stats->htt_mpdus;
	data[i++] = ar->debug.rx_bytes;
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

static const struct file_operations fops_fw_dbglog = {
	.read = ath10k_read_fw_dbglog,
	.write = ath10k_write_fw_dbglog,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath10k_debug_cal_data_open(struct inode *inode, struct file *file)
{
	struct ath10k *ar = inode->i_private;
	void *buf;
	u32 hi_addr;
	__le32 addr;
	int ret;

	mutex_lock(&ar->conf_mutex);

	if (ar->state != ATH10K_STATE_ON &&
	    ar->state != ATH10K_STATE_UTF) {
		ret = -ENETDOWN;
		goto err;
	}

	buf = vmalloc(ar->hw_params.cal_data_len);
	if (!buf) {
		ret = -ENOMEM;
		goto err;
	}

	hi_addr = host_interest_item_address(HI_ITEM(hi_board_data));

	ret = ath10k_hif_diag_read(ar, hi_addr, &addr, sizeof(addr));
	if (ret) {
		ath10k_warn(ar, "failed to read hi_board_data address: %d\n", ret);
		goto err_vfree;
	}

	ret = ath10k_hif_diag_read(ar, le32_to_cpu(addr), buf,
				   ar->hw_params.cal_data_len);
	if (ret) {
		ath10k_warn(ar, "failed to read calibration data: %d\n", ret);
		goto err_vfree;
	}

	file->private_data = buf;

	mutex_unlock(&ar->conf_mutex);

	return 0;

err_vfree:
	vfree(buf);

err:
	mutex_unlock(&ar->conf_mutex);

	return ret;
}

static ssize_t ath10k_debug_cal_data_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	void *buf = file->private_data;

	return simple_read_from_buffer(user_buf, count, ppos,
				       buf, ar->hw_params.cal_data_len);
}

static int ath10k_debug_cal_data_release(struct inode *inode,
					 struct file *file)
{
	vfree(file->private_data);

	return 0;
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
	int len = 0;
	char buf[32];

	len = scnprintf(buf, sizeof(buf) - len, "%d\n",
			ar->ani_enabled);

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
	.release = ath10k_debug_cal_data_release,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath10k_read_nf_cal_period(struct file *file,
					 char __user *user_buf,
					 size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	unsigned int len;
	char buf[32];

	len = scnprintf(buf, sizeof(buf), "%d\n",
			ar->debug.nf_cal_period);

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

static void ath10k_tpc_stats_print(struct ath10k_tpc_stats *tpc_stats,
				   unsigned int j, char *buf, unsigned int *len)
{
	unsigned int i, buf_len;
	static const char table_str[][5] = { "CDD",
					     "STBC",
					     "TXBF" };
	static const char pream_str[][6] = { "CCK",
					     "OFDM",
					     "HT20",
					     "HT40",
					     "VHT20",
					     "VHT40",
					     "VHT80",
					     "HTCUP" };

	buf_len = ATH10K_TPC_CONFIG_BUF_SIZE;
	*len += scnprintf(buf + *len, buf_len - *len,
			  "********************************\n");
	*len += scnprintf(buf + *len, buf_len - *len,
			  "******************* %s POWER TABLE ****************\n",
			  table_str[j]);
	*len += scnprintf(buf + *len, buf_len - *len,
			  "********************************\n");
	*len += scnprintf(buf + *len, buf_len - *len,
			  "No.  Preamble Rate_code tpc_value1 tpc_value2 tpc_value3\n");

	for (i = 0; i < tpc_stats->rate_max; i++) {
		*len += scnprintf(buf + *len, buf_len - *len,
				  "%8d %s 0x%2x %s\n", i,
				  pream_str[tpc_stats->tpc_table[j].pream_idx[i]],
				  tpc_stats->tpc_table[j].rate_code[i],
				  tpc_stats->tpc_table[j].tpc_value[i]);
	}

	*len += scnprintf(buf + *len, buf_len - *len,
			  "***********************************\n");
}

static void ath10k_tpc_stats_fill(struct ath10k *ar,
				  struct ath10k_tpc_stats *tpc_stats,
				  char *buf)
{
	unsigned int len, j, buf_len;

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

	for (j = 0; j < tpc_stats->num_tx_chain ; j++) {
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
	unsigned int len = strlen(buf);

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

	if (ar->debug.pktlog_filter) {
		ret = ath10k_wmi_pdev_pktlog_enable(ar,
						    ar->debug.pktlog_filter);
		if (ret)
			/* not serious */
			ath10k_warn(ar,
				    "failed to enable pktlog filter %x: %d\n",
				    ar->debug.pktlog_filter, ret);
	} else {
		ret = ath10k_wmi_pdev_pktlog_disable(ar);
		if (ret)
			/* not serious */
			ath10k_warn(ar, "failed to disable pktlog: %d\n", ret);
	}

	if (ar->debug.nf_cal_period) {
		ret = ath10k_wmi_pdev_set_param(ar,
						ar->wmi.pdev_param->cal_period,
						ar->debug.nf_cal_period);
		if (ret)
			/* not serious */
			ath10k_warn(ar, "cal period cfg failed from debug start: %d\n",
				    ret);
	}

	return ret;
}

void ath10k_debug_stop(struct ath10k *ar)
{
	lockdep_assert_held(&ar->conf_mutex);

	/* Must not use _sync to avoid deadlock, we do that in
	 * ath10k_debug_destroy(). The check for htt_stats_mask is to avoid
	 * warning from del_timer(). */
	if (ar->debug.htt_stats_mask != 0)
		cancel_delayed_work(&ar->debug.htt_stats_dwork);

	ath10k_wmi_pdev_pktlog_disable(ar);
}

static ssize_t ath10k_write_simulate_radar(struct file *file,
					   const char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;

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
		ar->debug.pktlog_filter = filter;
		ret = count;
		goto out;
	}

	if (filter == ar->debug.pktlog_filter) {
		ret = count;
		goto out;
	}

	if (filter) {
		ret = ath10k_wmi_pdev_pktlog_enable(ar, filter);
		if (ret) {
			ath10k_warn(ar, "failed to enable pktlog filter %x: %d\n",
				    ar->debug.pktlog_filter, ret);
			goto out;
		}
	} else {
		ret = ath10k_wmi_pdev_pktlog_disable(ar);
		if (ret) {
			ath10k_warn(ar, "failed to disable pktlog: %d\n", ret);
			goto out;
		}
	}

	ar->debug.pktlog_filter = filter;
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
			ar->debug.pktlog_filter);
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
	if (id == SET_SPECIAL_ID_THRESH62_EXT) {
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
	/* Below here are local driver hacks, and not necessarily passed directly to firmware. */
	else if (id == 0x1001) {
		/* Set station failed-transmit kickout threshold. */
		ar->sta_xretry_kickout_thresh = val;

		ath10k_warn(ar, "Setting pdev sta-xretry-kickout-thresh to 0x%x\n",
			    val);

		ath10k_mac_set_pdev_kickout(ar);
		goto unlock;
	}
	/* else, pass it through to firmware...but will not be stored locally, so
	 * won't survive through firmware reboots, etc.
	 */

	/* Send it to the firmware. */
	ret = ath10k_wmi_pdev_set_special(ar, id, val);
unlock:
	mutex_unlock(&ar->conf_mutex);

	return ret ?: count;
}

static ssize_t ath10k_read_ct_special(struct file *file,
				      char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	const char buf[] =
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
		"id: 8 STA-TX-BW-MASK,  0:  all, 0x1: 20Mhz, 0x2 40Mhz, 0x4 80Mhz \n"
		"id: 9 pdev failed retry threshold, U16, 10.1 firmware default is 0x40\n"
		"id: 0xA Enable(1)/Disable(0) baseband RIFS.  Default is disabled.\n"
		"id: 0xB WMI WD Keepalive(ms): 0xFFFFFFFF disables, otherwise suggest 8000+.\n"
		"\nBelow here are not actually sent to firmware directly, but configure the driver.\n"
		"id: 0x1001 set sta-kickout threshold due to tx-failures (0 means disable.  Default is 20 * 16.)\n"
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

	if (val)
		set_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags);
	else
		clear_bit(ATH10K_FLAG_BTCOEX, &ar->dev_flags);

	ath10k_info(ar, "restarting firmware due to btcoex change");

	queue_work(ar->workqueue, &ar->restart_work);
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
	unsigned int len = 0, buf_len = 4096;
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

int ath10k_debug_create(struct ath10k *ar)
{
	ar->debug.fw_crash_data = vzalloc(sizeof(*ar->debug.fw_crash_data));
	if (!ar->debug.fw_crash_data)
		return -ENOMEM;

	INIT_LIST_HEAD(&ar->debug.fw_stats.pdevs);
	INIT_LIST_HEAD(&ar->debug.fw_stats.vdevs);
	INIT_LIST_HEAD(&ar->debug.fw_stats.peers);

	return 0;
}

void ath10k_debug_destroy(struct ath10k *ar)
{
	vfree(ar->debug.fw_crash_data);
	ar->debug.fw_crash_data = NULL;

	ath10k_debug_fw_stats_reset(ar);

	kfree(ar->debug.tpc_stats);
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

	INIT_DELAYED_WORK(&ar->debug.nop_dwork, ath10k_debug_nop_dwork);

	queue_delayed_work(ar->workqueue, &ar->debug.nop_dwork,
			   msecs_to_jiffies(ATH10K_DEBUG_NOP_INTERVAL));

	INIT_DELAYED_WORK(&ar->debug.htt_stats_dwork,
			  ath10k_debug_htt_stats_dwork);

	init_completion(&ar->debug.tpc_complete);
	init_completion(&ar->debug.fw_stats_complete);

	debugfs_create_file("fw_stats", S_IRUSR, ar->debug.debugfs_phy, ar,
			    &fops_fw_stats);

	debugfs_create_file("fw_reset_stats", S_IRUSR, ar->debug.debugfs_phy,
			    ar, &fops_fw_reset_stats);

	debugfs_create_file("fw_regs", S_IRUSR, ar->debug.debugfs_phy, ar,
			    &fops_fw_regs);

	debugfs_create_file("wmi_services", S_IRUSR, ar->debug.debugfs_phy, ar,
			    &fops_wmi_services);

	debugfs_create_file("set_rates", S_IRUSR | S_IWUSR, ar->debug.debugfs_phy,
			    ar, &fops_set_rates);

	debugfs_create_file("firmware_info", S_IRUSR, ar->debug.debugfs_phy, ar,
			    &fops_fwinfo_services);

	debugfs_create_file("simulate_fw_crash", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_simulate_fw_crash);

	debugfs_create_file("misc", S_IRUSR, ar->debug.debugfs_phy, ar,
			    &fops_misc);

	debugfs_create_file("fw_crash_dump", S_IRUSR, ar->debug.debugfs_phy,
			    ar, &fops_fw_crash_dump);

	debugfs_create_file("reg_addr", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_reg_addr);

	debugfs_create_file("debug_level", S_IRUSR, ar->debug.debugfs_phy,
			    ar, &fops_debug_level);

	debugfs_create_file("reg_value", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_reg_value);

	debugfs_create_file("mem_value", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_mem_value);

	debugfs_create_file("chip_id", S_IRUSR, ar->debug.debugfs_phy,
			    ar, &fops_chip_id);

	debugfs_create_file("htt_stats_mask", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_htt_stats_mask);

	debugfs_create_file("htt_max_amsdu_ampdu", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar,
			    &fops_htt_max_amsdu_ampdu);

	debugfs_create_file("fw_dbglog", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_fw_dbglog);

	debugfs_create_file("cal_data", S_IRUSR, ar->debug.debugfs_phy,
			    ar, &fops_cal_data);

	debugfs_create_file("ani_enable", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_ani_enable);

	debugfs_create_file("nf_cal_period", S_IRUSR | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_nf_cal_period);

	if (config_enabled(CONFIG_ATH10K_DFS_CERTIFIED)) {
		debugfs_create_file("dfs_simulate_radar", S_IWUSR,
				    ar->debug.debugfs_phy, ar,
				    &fops_simulate_radar);

		debugfs_create_bool("dfs_block_radar_events", S_IWUSR,
				    ar->debug.debugfs_phy,
				    &ar->dfs_block_radar_events);

		debugfs_create_file("dfs_stats", S_IRUSR,
				    ar->debug.debugfs_phy, ar,
				    &fops_dfs_stats);
	}

	debugfs_create_file("pktlog_filter", S_IRUGO | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_pktlog_filter);

	debugfs_create_file("quiet_period", S_IRUGO | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_quiet_period);

	debugfs_create_file("tpc_stats", S_IRUSR,
			    ar->debug.debugfs_phy, ar, &fops_tpc_stats);

	debugfs_create_file("thresh62_ext", S_IRUGO | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_thresh62_ext);

	debugfs_create_file("ct_special", S_IRUGO | S_IWUSR,
			    ar->debug.debugfs_phy, ar, &fops_ct_special);

	if (test_bit(WMI_SERVICE_COEX_GPIO, ar->wmi.svc_map))
		debugfs_create_file("btcoex", S_IRUGO | S_IWUSR,
				    ar->debug.debugfs_phy, ar, &fops_btcoex);

	if (test_bit(WMI_SERVICE_PEER_STATS, ar->wmi.svc_map))
		debugfs_create_file("peer_stats", S_IRUGO | S_IWUSR,
				    ar->debug.debugfs_phy, ar,
				    &fops_peer_stats);

	debugfs_create_file("fw_checksums", S_IRUSR,
			    ar->debug.debugfs_phy, ar, &fops_fw_checksums);

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
	unsigned int linebuflen;
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
