/*
 * Author: Piotr Gawlowicz <gawlowicz.p@gmail.com>
 */

#include <linux/relay.h>
#include "core.h"
#include "debug.h"
#include "wmi-ops.h"

static void send_csi_sample(struct ath10k *ar,
			    const struct csi_sample_tlv *csi_sample_tlv)
{
	int length;

	if (!ar->csi.rfs_chan_csi)
		return;

	length = __be16_to_cpu(csi_sample_tlv->length) +
		 sizeof(*csi_sample_tlv);

	relay_write(ar->csi.rfs_chan_csi, csi_sample_tlv, length);
}

int ath10k_csi_process(struct ath10k *ar, u8 *buf, u16 length)
{
	int ret = 0;
	u8 *ibuf;
	u16 ilen;
	struct csi_sample_ath10k *csi_sample;
	u8 mbuf[sizeof(*csi_sample) + CSI_ATH10K_MAX_SIZE];

	/* ath10k: CSI report accumulator. */
	//u8 csi_data[4096];
	//u16 csi_data_len;

	ibuf = ar->csi_data;
	ilen = ar->csi_data_len;

	if (ilen < 64 || ilen > CSI_ATH10K_MAX_SIZE)
	{
		ath10k_warn(ar, "Cannot send CSI over relayFS with length %d\n", ilen);
		return -EINVAL;
	}

	csi_sample = (struct csi_sample_ath10k *)&mbuf;
	csi_sample->tlv.type = 0;
	csi_sample->tlv.length = __cpu_to_be16(ilen);
	memcpy(csi_sample->data, ibuf, ilen);
	ath10k_warn(ar, "Send CSI over relayFS, length %d\n", ilen);

	send_csi_sample(ar, &csi_sample->tlv);

	return ret;
}

static struct ath10k_vif *ath10k_get_csi_vdev(struct ath10k *ar)
{
	struct ath10k_vif *arvif;

	lockdep_assert_held(&ar->conf_mutex);

	if (list_empty(&ar->arvifs))
		return NULL;

	/* if there already is a vif reporting csi, return that. */
	list_for_each_entry(arvif, &ar->arvifs, list)
		if (arvif->csi_enabled)
			return arvif;

	/* otherwise, return the first vif. */
	return list_first_entry(&ar->arvifs, typeof(*arvif), list);
}

static int ath10k_csi_config(struct ath10k *ar,
				       enum ath10k_csi_mode mode)
{
	struct ath10k_vif *arvif;
	int vdev_id, count, res = 0;

	lockdep_assert_held(&ar->conf_mutex);

	if (mode == CSI_DISABLED)
	{
		ar->eeprom_overrides.ct_csi = 0;
		ath10k_warn(ar, "Disable CSI dump\n");
	}

	if (mode == CSI_ENABLED)
	{
		ar->eeprom_overrides.ct_csi = 1;
		ath10k_warn(ar, "Enable CSI dump\n");
	}

	ath10k_wmi_pdev_set_special(ar, SET_SPECIAL_ID_CSI, ar->eeprom_overrides.ct_csi);

	return 0;
}

static ssize_t read_file_csi_ctl(struct file *file, char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char *mode = "";
	size_t len;
	enum ath10k_csi_mode csi_mode;

	mutex_lock(&ar->conf_mutex);
	csi_mode = ar->csi.mode;
	mutex_unlock(&ar->conf_mutex);

	switch (csi_mode) {
	case CSI_DISABLED:
		mode = "disable";
		break;
	case CSI_ENABLED:
		mode = "enable";
		break;
	}

	len = strlen(mode);
	return simple_read_from_buffer(user_buf, count, ppos, mode, len);
}

static ssize_t write_file_csi_ctl(struct file *file,
					const char __user *user_buf,
					size_t count, loff_t *ppos)
{
	struct ath10k *ar = file->private_data;
	char buf[32];
	ssize_t len;
	int res;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';

	mutex_lock(&ar->conf_mutex);

	if (strncmp("enable", buf, 6) == 0) {
		res = ath10k_csi_config(ar, CSI_ENABLED);
	} else if (strncmp("disable", buf, 7) == 0) {
		res = ath10k_csi_config(ar, CSI_DISABLED);
	} else {
		res = -EINVAL;
		ath10k_warn(ar, "Unknown command for CSI dump\n");
	}

	mutex_unlock(&ar->conf_mutex);

	if (res < 0)
		return res;

	return count;
}

static const struct file_operations fops_csi_ctl = {
	.read = read_file_csi_ctl,
	.write = write_file_csi_ctl,
	.open = simple_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};


static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	struct dentry *buf_file;

	buf_file = debugfs_create_file(filename, mode, parent, buf,
				       &relay_file_operations);
	if (IS_ERR(buf_file))
		return NULL;

	*is_global = 1;
	return buf_file;
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);

	return 0;
}

static struct rchan_callbacks rfs_csi_cb = {
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};

int ath10k_csi_start(struct ath10k *ar)
{
	struct ath10k_vif *arvif;

	lockdep_assert_held(&ar->conf_mutex);

	list_for_each_entry(arvif, &ar->arvifs, list)
		arvif->csi_enabled = 0;

	ar->csi.mode = CSI_DISABLED;

	return 0;
}

int ath10k_csi_vif_stop(struct ath10k_vif *arvif)
{
	if (!arvif->csi_enabled)
		return 0;

	return ath10k_csi_config(arvif->ar, CSI_DISABLED);
}

int ath10k_csi_create(struct ath10k *ar)
{
	ar->csi.rfs_chan_csi = relay_open("csi",
						     ar->debug.debugfs_phy,
						     1140, 2500,
						     &rfs_csi_cb, NULL);
	debugfs_create_file("csi_ctl",
			    0600,
			    ar->debug.debugfs_phy, ar,
			    &fops_csi_ctl);

	return 0;
}

void ath10k_csi_destroy(struct ath10k *ar)
{
	if (ar->csi.rfs_chan_csi) {
		relay_close(ar->csi.rfs_chan_csi);
		ar->csi.rfs_chan_csi = NULL;
	}
}
