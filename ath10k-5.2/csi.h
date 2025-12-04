/*
 * Author: Piotr Gawlowicz <gawlowicz.p@gmail.com>
 */

#ifndef CSI_H
#define CSI_H

/* enum ath10k_csi_mode:
 *
 * @CSI_DISABLED: csi mode is disabled
 * @CSI_ENABLED: csi mode is enabled
 */
enum ath10k_csi_mode {
	CSI_DISABLED = 0,
	CSI_ENABLED,
};

struct csi_sample_tlv {
	u8 type;
	__be16 length;
	/* type dependent data follows */
} __packed;

struct csi_sample_ath10k {
	struct csi_sample_tlv tlv;
	u8 data[0];
} __packed;

#define CSI_ATH10K_MAX_SIZE		4000

#ifdef CONFIG_ATH10K_SPECTRAL

int ath10k_csi_process(struct ath10k *ar, u8 *buf, u16 length);
int ath10k_csi_start(struct ath10k *ar);
int ath10k_csi_vif_stop(struct ath10k_vif *arvif);
int ath10k_csi_create(struct ath10k *ar);
void ath10k_csi_destroy(struct ath10k *ar);

#else

static inline int
ath10k_csi_process(struct ath10k *ar,
			    struct wmi_phyerr_ev_arg *phyerr,
			    const struct phyerr_fft_report *fftr,
			    size_t bin_len, u64 tsf)
{
	return 0;
}

static inline int ath10k_csi_start(struct ath10k *ar)
{
	return 0;
}

static inline int ath10k_csi_vif_stop(struct ath10k_vif *arvif)
{
	return 0;
}

static inline int ath10k_csi_create(struct ath10k *ar)
{
	return 0;
}

static inline void ath10k_csi_destroy(struct ath10k *ar)
{
}

#endif /* CONFIG_ATH10K_SPECTRAL */

#endif /* CSI_H */
