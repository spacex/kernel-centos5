/******************************************************************************
 *
 * Copyright(c) 2003 - 2007 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * James P. Ketrenos <ipw2100-admin@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *****************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/wireless.h>
#include <net/mac80211.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>

#include "iwlwifi.h"
#include "iwl-4965.h"
#include "iwl-helpers.h"

#define IWL_DECLARE_RATE_INFO(r, s, ip, in, rp, rn, pp, np)    \
	[IWL_RATE_##r##M_INDEX] = { IWL_RATE_##r##M_PLCP,      \
				    IWL_RATE_SISO_##s##M_PLCP, \
				    IWL_RATE_MIMO_##s##M_PLCP, \
				    IWL_RATE_##r##M_IEEE,      \
				    IWL_RATE_##ip##M_INDEX,    \
				    IWL_RATE_##in##M_INDEX,    \
				    IWL_RATE_##rp##M_INDEX,    \
				    IWL_RATE_##rn##M_INDEX,    \
				    IWL_RATE_##pp##M_INDEX,    \
				    IWL_RATE_##np##M_INDEX }

/*
 * Parameter order:
 *   rate, ht rate, prev rate, next rate, prev tgg rate, next tgg rate
 *
 * If there isn't a valid next or previous rate then INV is used which
 * maps to IWL_RATE_INVALID
 *
 */
const struct iwl_rate_info iwl_rates[IWL_RATE_COUNT] = {
	IWL_DECLARE_RATE_INFO(1, INV, INV, 2, INV, 2, INV, 2),    /*  1mbps */
	IWL_DECLARE_RATE_INFO(2, INV, 1, 5, 1, 5, 1, 5),          /*  2mbps */
	IWL_DECLARE_RATE_INFO(5, INV, 2, 6, 2, 11, 2, 11),        /*5.5mbps */
	IWL_DECLARE_RATE_INFO(11, INV, 9, 12, 5, 12, 5, 18),      /* 11mbps */
	IWL_DECLARE_RATE_INFO(6, 6, 5, 9, 5, 11, 5, 11),        /*  6mbps */
	IWL_DECLARE_RATE_INFO(9, 6, 6, 11, 5, 11, 5, 11),       /*  9mbps */
	IWL_DECLARE_RATE_INFO(12, 12, 11, 18, 11, 18, 11, 18),   /* 12mbps */
	IWL_DECLARE_RATE_INFO(18, 18, 12, 24, 12, 24, 11, 24),   /* 18mbps */
	IWL_DECLARE_RATE_INFO(24, 24, 18, 36, 18, 36, 18, 36),   /* 24mbps */
	IWL_DECLARE_RATE_INFO(36, 36, 24, 48, 24, 48, 24, 48),   /* 36mbps */
	IWL_DECLARE_RATE_INFO(48, 48, 36, 54, 36, 54, 36, 54),   /* 48mbps */
	IWL_DECLARE_RATE_INFO(54, 54, 48, INV, 48, INV, 48, INV),/* 54mbps */
	IWL_DECLARE_RATE_INFO(60, 60, 48, INV, 48, INV, 48, INV),/* 60mbps */
};

static int is_fat_channel(struct iwl_priv *priv)
{
	return ((priv->active_rxon.flags & RXON_FLG_CHANNEL_MODE_PURE_40_MSK) ||
		(priv->active_rxon.flags & RXON_FLG_CHANNEL_MODE_MIXED_MSK));
}

static u8 is_single_stream(struct iwl_priv *priv)
{
#ifdef CONFIG_IWLWIFI_HT
	if (!priv->is_ht_enabled || !priv->current_assoc_ht.is_ht ||
	    (priv->active_rate_ht[1] == 0) ||
	    (priv->ps_mode == IWL_MIMO_PS_STATIC))
		return 1;
#else
	return 1;
#endif	/*CONFIG_IWLWIFI_HT */
	return 0;
}

/*
 * Determine how many receiver/antenna chains to use.
 * More provides better reception via diversity.  Fewer saves power.
 * MIMO (dual stream) requires at least 2, but works better with 3.
 * This does not determine *which* chains to use, just how many.
 */
static int iwl4965_get_rx_chain_counter(struct iwl_priv *priv,
					u8 * idle_state, u8 * rx_state)
{
	u8 is_single = is_single_stream(priv);
	u8 is_cam = (priv->status & STATUS_POWER_PMI) ? 0 : 1;

	/* # of Rx chains to use when expecting MIMO. */
	if (is_single || (!is_cam && (priv->ps_mode == IWL_MIMO_PS_STATIC)))
		*rx_state = 2;
	else
		*rx_state = 3;

	/* # Rx chains when idling and maybe trying to save power */
	switch (priv->ps_mode) {
	case IWL_MIMO_PS_STATIC:
	case IWL_MIMO_PS_DYNAMIC:
		*idle_state = (is_cam) ? 2 : 1;
		break;
	case IWL_MIMO_PS_NONE:
		*idle_state = (is_cam) ? *rx_state : 1;
		break;
	default:
		*idle_state = 1;
		break;
	}

	return 0;
}

int iwl_hw_rxq_stop(struct iwl_priv *priv)
{
	int rc;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	/* stop HW */
	iwl_write_restricted(priv, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);
	rc = iwl_poll_restricted_bit(priv, FH_MEM_RSSR_RX_STATUS_REG,
				     (1 << 24), 1000);
	if (rc < 0)
		IWL_ERROR("Can't stop Rx DMA.\n");

	iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

u8 iwl_hw_find_station(struct iwl_priv * priv, const u8 * bssid)
{
	int i;
	int start = 0;
	int ret = IWL_INVALID_STATION;
	unsigned long flags;

	if ((priv->iw_mode == IEEE80211_IF_TYPE_IBSS) ||
	    (priv->iw_mode == IEEE80211_IF_TYPE_AP))
		start = IWL_STA_ID;

	if (is_broadcast_ether_addr(bssid))
		return IWL_BROADCAST_ID;

	spin_lock_irqsave(&priv->sta_lock, flags);
	for (i = start; i < (start + priv->num_stations); i++)
		if ((priv->stations[i].used) &&
		    (!compare_ether_addr
		     (priv->stations[i].sta.sta.addr, bssid))) {
			ret = i;
			goto out;
		}

	IWL_DEBUG_ASSOC("can not find STA " MAC_FMT " total %d\n",
			MAC_ARG(bssid), priv->num_stations);

 out:
	spin_unlock_irqrestore(&priv->sta_lock, flags);
	return ret;
}

static int iwl4965_nic_set_pwr_src(struct iwl_priv *priv, int pwr_max)
{
	int rc = 0;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	if (!pwr_max) {
		u32 val;
		rc = pci_read_config_dword(priv->pci_dev, 0x0C8, &val);

		if (val & PCI_CFG_PMC_PME_FROM_D3COLD_SUPPORT) {
			iwl_set_bits_mask_restricted_reg(
				priv, ALM_APMG_PS_CTL,
				APMG_PS_CTRL_REG_VAL_POWER_SRC_VAUX,
				~APMG_PS_CTRL_REG_MSK_POWER_SRC);

		}
	} else {
		iwl_set_bits_mask_restricted_reg(
			priv, ALM_APMG_PS_CTL,
			APMG_PS_CTRL_REG_VAL_POWER_SRC_VMAIN,
			~APMG_PS_CTRL_REG_MSK_POWER_SRC);

	}

	iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	return rc;
}

static int iwl4965_rx_init(struct iwl_priv *priv, struct iwl_rx_queue *rxq)
{
	int rc;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	/* stop HW */
	iwl_write_restricted(priv, FH_MEM_RCSR_CHNL0_CONFIG_REG, 0);

	iwl_write_restricted(priv, FH_RSCSR_CHNL0_RBDCB_WPTR_REG, 0);
	iwl_write_restricted(priv, FH_RSCSR_CHNL0_RBDCB_BASE_REG,
			     rxq->dma_addr >> 8);

	iwl_write_restricted(priv, FH_RSCSR_CHNL0_STTS_WPTR_REG,
			     (priv->hw_setting.shared_phys +
			      offsetof(struct iwl_shared, val0)) >> 4);

	iwl_write_restricted(priv, FH_MEM_RCSR_CHNL0_CONFIG_REG,
			     FH_RCSR_RX_CONFIG_CHNL_EN_ENABLE_VAL |
			     FH_RCSR_CHNL0_RX_CONFIG_IRQ_DEST_INT_HOST_VAL |
			     IWL_FH_RCSR_RX_CONFIG_REG_VAL_RB_SIZE_4K |
			     /*0x10 << 4 | */
			     (RX_QUEUE_SIZE_LOG <<
			      FH_RCSR_RX_CONFIG_RBDCB_SIZE_BITSHIFT));

	/*
	 * iwl_write32(priv,CSR_INT_COAL_REG,0);
	 */

	iwl_release_restricted_access(priv);

	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

static int iwl4965_kw_init(struct iwl_priv *priv)
{
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&priv->lock, flags);
	rc = iwl_grab_restricted_access(priv);
	if (rc)
		goto out;

	iwl_write_restricted(priv, IWL_FH_KW_MEM_ADDR_REG,
			     (priv->kw.dma_addr >> 4));
	iwl_release_restricted_access(priv);
out:
	spin_unlock_irqrestore(&priv->lock, flags);
	return rc;
}

static int iwl4965_kw_alloc(struct iwl_priv *priv)
{
	struct pci_dev *dev = priv->pci_dev;
	struct iwl_kw *kw = &priv->kw;
	kw->size = IWL4965_KW_SIZE;	/* TBW need set somewhere else */
	kw->v_addr = pci_alloc_consistent(dev, kw->size, &kw->dma_addr);
	if (!kw->v_addr)
		return -ENOMEM;

	return 0;
}

#define CHECK_AND_PRINT(x) ((eeprom_ch->flags & EEPROM_CHANNEL_##x) \
			    ? # x " " : "")

int iwl4965_set_fat_chan_info(struct iwl_priv *priv, int phymode,
			      int channel,
			      const struct iwl_eeprom_channel *eeprom_ch,
			      u8 fat_extension_channel)
{
	struct iwl_channel_info *ch_info;

	ch_info = (struct iwl_channel_info *)iwl_get_channel_info(priv,
						phymode,
						channel);
	if (!is_channel_valid(ch_info))
		return -1;

		IWL_DEBUG_INFO("FAT Ch. %d [%sGHz] %s%s%s%s%s%s(" BIT_FMT8
				" %ddBm): Ad-Hoc %ssupported\n",
				ch_info->channel,
				is_channel_a_band(ch_info) ?
				"5.2" : "2.4",
				CHECK_AND_PRINT(IBSS),
				CHECK_AND_PRINT(ACTIVE),
				CHECK_AND_PRINT(RADAR),
				CHECK_AND_PRINT(WIDE),
				CHECK_AND_PRINT(NARROW),
				CHECK_AND_PRINT(DFS),
				BIT_ARG8(eeprom_ch->flags),
				eeprom_ch->
				max_power_avg,
				((eeprom_ch->
				flags & EEPROM_CHANNEL_IBSS)
				&& !(eeprom_ch->
				flags & EEPROM_CHANNEL_RADAR))
				? "" : "not ");

	ch_info->fat_eeprom = *eeprom_ch;
	ch_info->fat_max_power_avg = eeprom_ch->max_power_avg;
	ch_info->fat_curr_txpow = eeprom_ch->max_power_avg;
	ch_info->fat_min_power = 0;
	ch_info->fat_scan_power = eeprom_ch->max_power_avg;
	ch_info->fat_flags = eeprom_ch->flags;
	ch_info->fat_extension_channel = fat_extension_channel;

	return 0;
}

static void iwl4965_kw_free(struct iwl_priv *priv)
{
	struct pci_dev *dev = priv->pci_dev;
	struct iwl_kw *kw = &priv->kw;
	if (kw->v_addr) {
		pci_free_consistent(dev, kw->size, kw->v_addr, kw->dma_addr);
		memset(kw, 0, sizeof(*kw));
	}

}

/**
 * iwl4965_txq_ctx_reset - Reset TX queue context
 * Destroys all DMA structures and initialise them again
 *
 * @param priv
 * @return error code
 */
static int iwl4965_txq_ctx_reset(struct iwl_priv *priv)
{
	int rc = 0;
	int txq_id, num_slots;
	unsigned long flags;

	iwl4965_kw_free(priv);

	iwl_hw_txq_ctx_free(priv);

	/* Tx CMD queue */
	rc = iwl4965_kw_alloc(priv);
	if (rc) {
		IWL_ERROR("Keep Warm allocation failed");
		goto error_kw;
	}

	spin_lock_irqsave(&priv->lock, flags);

	rc = iwl_grab_restricted_access(priv);
	if (unlikely(rc)) {
		IWL_ERROR("TX reset failed");
		spin_unlock_irqrestore(&priv->lock, flags);
		goto error_reset;
	}

	iwl_write_restricted_reg(priv, SCD_TXFACT, 0);
	iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	rc = iwl4965_kw_init(priv);
	if (rc) {
		IWL_ERROR("kw_init failed\n");
		goto error_reset;
	}

	/* Tx queue(s) */
	for (txq_id = 0; txq_id < priv->hw_setting.max_queue_number; txq_id++) {
		num_slots = (txq_id == IWL_CMD_QUEUE_NUM) ?
					TFD_CMD_SLOTS : TFD_TX_CMD_SLOTS;
		rc = iwl_tx_queue_init(priv, &priv->txq[txq_id], num_slots,
				       txq_id);
		if (rc) {
			IWL_ERROR("Tx %d queue init failed\n", txq_id);
			goto error;
		}
	}

	return rc;

 error:
	iwl_hw_txq_ctx_free(priv);
 error_reset:
	iwl4965_kw_free(priv);
 error_kw:
	return rc;
}

int iwl_hw_nic_init(struct iwl_priv *priv)
{
	int rc;
	unsigned long flags;
	struct iwl_rx_queue *rxq = &priv->rxq;
	u8 rev_id;
	u32 val;
	u8 val_link;

	iwl_power_init_handle(priv);

	/* nic_init */
	spin_lock_irqsave(&priv->lock, flags);

	iwl_set_bit(priv, CSR_GIO_CHICKEN_BITS,
		    CSR_GIO_CHICKEN_BITS_REG_BIT_DIS_L0S_EXIT_TIMER);

	iwl_set_bit(priv, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
	rc = iwl_poll_bit(priv, CSR_GP_CNTRL,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25000);
	if (rc < 0) {
		spin_unlock_irqrestore(&priv->lock, flags);
		IWL_DEBUG_INFO("Failed to init the card\n");
		return rc;
	}

	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	iwl_read_restricted_reg(priv, APMG_CLK_CTRL_REG);

	iwl_write_restricted_reg(priv, APMG_CLK_CTRL_REG,
				 APMG_CLK_REG_VAL_DMA_CLK_RQT |
				 APMG_CLK_REG_VAL_BSM_CLK_RQT);
	iwl_read_restricted_reg(priv, APMG_CLK_CTRL_REG);

	udelay(20);

	iwl_set_bits_restricted_reg(priv, ALM_APMG_PCIDEV_STT,
				    APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE);

	iwl_release_restricted_access(priv);
	iwl_write32(priv, CSR_INT_COALESCING, 512 / 32);
	spin_unlock_irqrestore(&priv->lock, flags);

	/* Determine HW type */
	rc = pci_read_config_byte(priv->pci_dev, PCI_REVISION_ID, &rev_id);
	if (rc)
		return rc;

	IWL_DEBUG_INFO("HW Revision ID = 0x%X\n", rev_id);

	iwl4965_nic_set_pwr_src(priv, 1);
	spin_lock_irqsave(&priv->lock, flags);

	if ((rev_id & 0x80) == 0x80 && (rev_id & 0x7f) < 8) {
		pci_read_config_dword(priv->pci_dev, 0xe8, &val);
		/* Enable No Snoop field */
		pci_write_config_dword(priv->pci_dev, 0xe8, val & ~(1 << 11));
	}

	spin_unlock_irqrestore(&priv->lock, flags);

	/* Read the EEPROM */
	rc = iwl_eeprom_init(priv);
	if (rc)
		return rc;

	if (priv->eeprom.calib_version < EEPROM_TX_POWER_VERSION_NEW) {
		IWL_ERROR("Older EEPROM detected!  Aborting.\n");
		return -EINVAL;
	}

	pci_read_config_byte(priv->pci_dev, PCI_LINK_CTRL, &val_link);

	/* disable L1 entry -- workaround for pre-B1 */
	pci_write_config_byte(priv->pci_dev, PCI_LINK_CTRL, val_link & ~0x02);

	spin_lock_irqsave(&priv->lock, flags);

	/* set CSR_HW_CONFIG_REG for uCode use */

	iwl_set_bit(priv, CSR_SW_VER, CSR_HW_IF_CONFIG_REG_BIT_KEDRON_R |
		    CSR_HW_IF_CONFIG_REG_BIT_RADIO_SI |
		    CSR_HW_IF_CONFIG_REG_BIT_MAC_SI);

	rc = iwl_grab_restricted_access(priv);
	if (rc < 0) {
		spin_unlock_irqrestore(&priv->lock, flags);
		IWL_DEBUG_INFO("Failed to init the card\n");
		return rc;
	}

	iwl_read_restricted_reg(priv, ALM_APMG_PS_CTL);
	iwl_set_bits_restricted_reg(priv, ALM_APMG_PS_CTL,
				    APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ);
	udelay(5);
	iwl_clear_bits_restricted_reg(priv, ALM_APMG_PS_CTL,
				      APMG_PS_CTRL_REG_VAL_ALM_R_RESET_REQ);

	iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	iwl_hw_card_show_info(priv);

	/* end nic_init */

	/* Allocate the RX queue, or reset if it is already allocated */
	if (!rxq->bd) {
		rc = iwl_rx_queue_alloc(priv);
		if (rc) {
			IWL_ERROR("Unable to initialize Rx queue\n");
			return -ENOMEM;
		}
	} else
		iwl_rx_queue_reset(priv, rxq);

	iwl_rx_replenish(priv, 1);

	iwl4965_rx_init(priv, rxq);

	spin_lock_irqsave(&priv->lock, flags);

	rxq->need_update = 1;
	iwl_rx_queue_update_write_ptr(priv, rxq);

	spin_unlock_irqrestore(&priv->lock, flags);
	rc = iwl4965_txq_ctx_reset(priv);
	if (rc)
		return rc;

	if (priv->eeprom.sku_cap & EEPROM_SKU_CAP_SW_RF_KILL_ENABLE)
		IWL_DEBUG_RF_KILL("SW RF KILL supported in EEPROM.\n");

	if (priv->eeprom.sku_cap & EEPROM_SKU_CAP_HW_RF_KILL_ENABLE)
		IWL_DEBUG_RF_KILL("HW RF KILL supported in EEPROM.\n");

	priv->status |= STATUS_INIT;

	return 0;
}

int iwl_hw_nic_stop_master(struct iwl_priv *priv)
{
	int rc = 0;
	u32 reg_val;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	/* set stop master bit */
	iwl_set_bit(priv, CSR_RESET, CSR_RESET_REG_FLAG_STOP_MASTER);

	reg_val = iwl_read32(priv, CSR_GP_CNTRL);

	if (CSR_GP_CNTRL_REG_FLAG_MAC_POWER_SAVE ==
	    (reg_val & CSR_GP_CNTRL_REG_MSK_POWER_SAVE_TYPE)) {
		IWL_DEBUG_INFO
		    ("Card in power save, master is already stopped\n");
	} else {
		rc = iwl_poll_bit(priv,
				  CSR_RESET,
				  CSR_RESET_REG_FLAG_MASTER_DISABLED,
				  CSR_RESET_REG_FLAG_MASTER_DISABLED, 100);
		if (rc < 0) {
			spin_unlock_irqrestore(&priv->lock, flags);
			return rc;
		}
	}

	spin_unlock_irqrestore(&priv->lock, flags);
	IWL_DEBUG_INFO("stop master\n");

	return rc;
}

void iwl_hw_txq_ctx_stop(struct iwl_priv *priv)
{

	int txq_id;
	unsigned long flags;

	/* reset TFD queues */
	for (txq_id = 0; txq_id < IWL4965_NUM_QUEUES; txq_id++) {
		spin_lock_irqsave(&priv->lock, flags);
		if (iwl_grab_restricted_access(priv)) {
			spin_unlock_irqrestore(&priv->lock, flags);
			continue;
		}

		iwl_write_restricted(priv,
				     IWL_FH_TCSR_CHNL_TX_CONFIG_REG(txq_id),
				     0x0);
		iwl_poll_restricted_bit(priv, IWL_FH_TSSR_TX_STATUS_REG,
					IWL_FH_TSSR_TX_STATUS_REG_MSK_CHNL_IDLE
					(txq_id), 200);
		iwl_release_restricted_access(priv);
		spin_unlock_irqrestore(&priv->lock, flags);
	}

	iwl_hw_txq_ctx_free(priv);
}

int iwl_hw_nic_reset(struct iwl_priv *priv)
{
	int rc = 0;
	unsigned long flags;

	iwl_hw_nic_stop_master(priv);

	spin_lock_irqsave(&priv->lock, flags);

	iwl_set_bit(priv, CSR_RESET, CSR_RESET_REG_FLAG_SW_RESET);

	udelay(10);

	iwl_set_bit(priv, CSR_GP_CNTRL, CSR_GP_CNTRL_REG_FLAG_INIT_DONE);
	rc = iwl_poll_bit(priv, CSR_RESET,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY,
			  CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY, 25);

	udelay(10);

	rc = iwl_grab_restricted_access(priv);
	if (!rc) {
		iwl_write_restricted_reg(priv, ALM_APMG_CLK_EN,
					 APMG_CLK_REG_VAL_DMA_CLK_RQT |
					 APMG_CLK_REG_VAL_BSM_CLK_RQT);

		udelay(10);

		iwl_set_bits_restricted_reg(
			priv, ALM_APMG_PCIDEV_STT,
			APMG_DEV_STATE_REG_VAL_L1_ACTIVE_DISABLE);

		iwl_release_restricted_access(priv);
	}

	spin_unlock_irqrestore(&priv->lock, flags);

	spin_lock_irqsave(&priv->lock, flags);

	priv->status &= ~STATUS_HCMD_ACTIVE;
	wake_up_interruptible(&priv->wait_command_queue);

	spin_unlock_irqrestore(&priv->lock, flags);

	return rc;

}

#define REG_RECALIB_PERIOD (60)

/**
 * iwl4965_bg_statistics_periodic - Timer callback to queue statistics
 *
 * This callback is provided in order to queue the statistics_work
 * in work_queue context (v. softirq)
 *
 * This timer function is continually reset to execute within
 * REG_RECALIB_PERIOD seconds since the last STATISTICS_NOTIFICATION
 * was received.  We need to ensure we receive the statistics in order
 * to update the temperature used for calibrating the TXPOWER.  However,
 * we can't send the statistics command from softirq context (which
 * is the context which timers run at) so we have to queue off the
 * statistics_work to actually send the command to the hardware.
 */
static void iwl4965_bg_statistics_periodic(unsigned long data)
{
	struct iwl_priv *priv = (struct iwl_priv *)data;

	queue_work(priv->workqueue, &priv->statistics_work);
}

/**
 * iwl4965_bg_statistics_work - Send the statistics request to the hardware.
 *
 * This is queued by iwl_bg_statistics_periodic.
 */
static void iwl4965_bg_statistics_work(void *p)
{
	struct iwl_priv *priv = p;

	if (priv->status & STATUS_EXIT_PENDING)
		return;

	mutex_lock(&priv->mutex);
	iwl_send_statistics_request(priv);
	mutex_unlock(&priv->mutex);
}

#define CT_LIMIT_CONST		259
#define TM_CT_KILL_THRESHOLD	110

void iwl4965_rf_kill_ct_config(struct iwl_priv *priv)
{
	struct iwl_ct_kill_config cmd;
	u32 R1 = 0, R2 = 0, R3 = 0;
	u32 temp_th = 0;
	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(&priv->lock, flags);
	iwl_write32(priv, CSR_UCODE_DRV_GP1_CLR,
		    CSR_UCODE_DRV_GP1_REG_BIT_CT_KILL_EXIT);
	spin_unlock_irqrestore(&priv->lock, flags);

	if (priv->statistics.flag & STATISTICS_REPLY_FLG_FAT_MODE_MSK) {
		R1 = priv->card_alive_init.therm_r1[1];
		R2 = priv->card_alive_init.therm_r2[1];
		R3 = priv->card_alive_init.therm_r3[1];
	} else {
		R1 = priv->card_alive_init.therm_r1[0];
		R2 = priv->card_alive_init.therm_r2[0];
		R3 = priv->card_alive_init.therm_r3[0];
	}

	temp_th = CELSIUS_TO_KELVIN(TM_CT_KILL_THRESHOLD);

	cmd.critical_temperature_R = ((temp_th * (R3-R1))/CT_LIMIT_CONST) + R2;
	rc = iwl_send_cmd_pdu(priv,
			      REPLY_CT_KILL_CONFIG_CMD, sizeof(cmd), &cmd);
	if (rc)
		IWL_ERROR("REPLY_CT_KILL_CONFIG_CMD failed\n");
	else
		IWL_WARNING("REPLY_CT_KILL_CONFIG_CMD succeeded\n");

	return;
}

#ifdef CONFIG_IWLWIFI_SENSITIVITY

/* "false alarms" are signals that our DSP tries to lock onto,
 *   but then determines that they are either noise, or transmissions
 *   from a distant wireless network (also "noise", really) that get
 *   "stepped on" by stronger transmissions within our own network.
 * This algorithm attempts to set a sensitivity level that is high
 *   enough to receive all of our own network traffic, but not so
 *   high that our DSP gets too busy trying to lock onto non-network
 *   activity/noise. */
static int iwl4965_sens_energy_cck(struct iwl_priv *priv,
				   u32 norm_fa,
				   u32 rx_enable_time,
				   struct statistics_general_data *rx_info)
{
	u32 max_nrg_cck = 0;
	int i = 0;
	u8 max_silence_rssi = 0;
	u32 silence_ref = 0;
	u8 silence_rssi_a = 0;
	u8 silence_rssi_b = 0;
	u8 silence_rssi_c = 0;
	u32 val;

	/* "false_alarms" values below are cross-multiplications to assess the
	 *   numbers of false alarms within the measured period of actual Rx
	 *   (Rx is off when we're txing), vs the min/max expected false alarms
	 *   (some should be expected if rx is sensitive enough) in a
	 *   hypothetical listening period of 200 time units (TU), 204.8 msec:
	 *
	 * MIN_FA/fixed-time < false_alarms/actual-rx-time < MAX_FA/beacon-time
	 *
	 * */
	u32 false_alarms = norm_fa * 200 * 1024;
	u32 max_false_alarms = MAX_FA_CCK * rx_enable_time;
	u32 min_false_alarms = MIN_FA_CCK * rx_enable_time;
	struct iwl_sensitivity_data *data = NULL;

	data = &(priv->sensitivity_data);

	data->nrg_auto_corr_silence_diff = 0;

	/* Find max silence rssi among all 3 receivers.
	 * This is background noise, which may include transmissions from other
	 *    networks, measured during silence before our network's beacon */
	silence_rssi_a = (u8)((rx_info->beacon_silence_rssi_a &
			    ALL_BAND_FILTER)>>8);
	silence_rssi_b = (u8)((rx_info->beacon_silence_rssi_b &
			    ALL_BAND_FILTER)>>8);
	silence_rssi_c = (u8)((rx_info->beacon_silence_rssi_c &
			    ALL_BAND_FILTER)>>8);

	val = max(silence_rssi_b, silence_rssi_c);
	max_silence_rssi = max(silence_rssi_a, (u8) val);

	/* Store silence rssi in 20-beacon history table */
	data->nrg_silence_rssi[data->nrg_silence_idx] = max_silence_rssi;
	data->nrg_silence_idx++;
	if (data->nrg_silence_idx >= NRG_NUM_PREV_STAT_L)
		data->nrg_silence_idx = 0;

	/* Find max silence rssi across 20 beacon history */
	for (i = 0; i < NRG_NUM_PREV_STAT_L; i++) {
		val = data->nrg_silence_rssi[i];
		silence_ref = max(silence_ref, val);
	}
	IWL_DEBUG_CALIB("silence a %u, b %u, c %u, 20-bcn max %u\n",
			silence_rssi_a, silence_rssi_b, silence_rssi_c,
			silence_ref);

	/* Find max rx energy (min value!) among all 3 receivers,
	 *   measured during beacon frame.
	 * Save it in 10-beacon history table. */
	i = data->nrg_energy_idx;
	val = min(rx_info->beacon_energy_b, rx_info->beacon_energy_c);
	data->nrg_value[i] = min(rx_info->beacon_energy_a, val);

	data->nrg_energy_idx++;
	if (data->nrg_energy_idx >= 10)
		data->nrg_energy_idx = 0;

	/* Find min rx energy (max value) across 10 beacon history.
	 * This is the minimum signal level that we want to receive well.
	 * Add backoff (margin so we don't miss slightly lower energy frames).
	 * This establishes an upper bound (min value) for energy threshold. */
	max_nrg_cck = data->nrg_value[0];
	for (i = 1; i < 10; i++)
		max_nrg_cck = (u32) max(max_nrg_cck, (data->nrg_value[i]));
	max_nrg_cck += 6;

	IWL_DEBUG_CALIB("rx energy a %u, b %u, c %u, 10-bcn max/min %u\n",
			rx_info->beacon_energy_a, rx_info->beacon_energy_b,
			rx_info->beacon_energy_c, max_nrg_cck - 6);

	/* Count number of consecutive beacons with fewer-than-desired
	 *   false alarms. */
	if (false_alarms < min_false_alarms)
		data->num_in_cck_no_fa++;
	else
		data->num_in_cck_no_fa = 0;
	IWL_DEBUG_CALIB("consecutive bcns with few false alarms = %u\n",
			data->num_in_cck_no_fa);

	/* If we got too many false alarms this time, reduce sensitivity */
	if (false_alarms > max_false_alarms) {
		IWL_DEBUG_CALIB("norm FA %u > max FA %u\n",
			     false_alarms, max_false_alarms);
		IWL_DEBUG_CALIB("... reducing sensitivity\n");
		data->nrg_curr_state = IWL_FA_TOO_MANY;

		if (data->auto_corr_cck > AUTO_CORR_MAX_TH_CCK) {
			/* Store for "fewer than desired" on later beacon */
			data->nrg_silence_ref = silence_ref;

			/* increase energy threshold (reduce nrg value)
			 *   to decrease sensitivity */
			if (data->nrg_th_cck > (NRG_MAX_CCK + NRG_STEP_CCK))
				data->nrg_th_cck = data->nrg_th_cck
							 - NRG_STEP_CCK;
		}

		/* increase auto_corr values to decrease sensitivity */
		if (data->auto_corr_cck < AUTO_CORR_MAX_TH_CCK)
			data->auto_corr_cck = AUTO_CORR_MAX_TH_CCK + 1;
		else {
			val = data->auto_corr_cck + AUTO_CORR_STEP_CCK;
			data->auto_corr_cck = min((u32)AUTO_CORR_MAX_CCK, val);
		}
		val = data->auto_corr_cck_mrc + AUTO_CORR_STEP_CCK;
		data->auto_corr_cck_mrc = min((u32)AUTO_CORR_MAX_CCK_MRC, val);

	/* Else if we got fewer than desired, increase sensitivity */
	} else if (false_alarms < min_false_alarms) {
		data->nrg_curr_state = IWL_FA_TOO_FEW;

		/* Compare silence level with silence level for most recent
		 *   healthy number or too many false alarms */
		data->nrg_auto_corr_silence_diff = (s32)data->nrg_silence_ref -
						   (s32)silence_ref;

		IWL_DEBUG_CALIB("norm FA %u < min FA %u, silence diff %d\n",
			 false_alarms, min_false_alarms,
			 data->nrg_auto_corr_silence_diff);

		/* Increase value to increase sensitivity, but only if:
		 * 1a) previous beacon did *not* have *too many* false alarms
		 * 1b) AND there's a significant difference in Rx levels
		 *      from a previous beacon with too many, or healthy # FAs
		 * OR 2) We've seen a lot of beacons (100) with too few
		 *       false alarms */
		if ((data->nrg_prev_state != IWL_FA_TOO_MANY) &&
			((data->nrg_auto_corr_silence_diff > NRG_DIFF) ||
			(data->num_in_cck_no_fa > MAX_NUMBER_CCK_NO_FA))) {

			IWL_DEBUG_CALIB("... increasing sensitivity\n");
			/* Increase nrg value to increase sensitivity */
			val = data->nrg_th_cck + NRG_STEP_CCK;
			data->nrg_th_cck = min((u32)NRG_MIN_CCK, val);

			/* Decrease auto_corr values to increase sensitivity */
			val = data->auto_corr_cck - AUTO_CORR_STEP_CCK;
			data->auto_corr_cck = max((u32)AUTO_CORR_MIN_CCK, val);

			val = data->auto_corr_cck_mrc - AUTO_CORR_STEP_CCK;
			data->auto_corr_cck_mrc =
					 max((u32)AUTO_CORR_MIN_CCK_MRC, val);

		} else {
			IWL_DEBUG_CALIB("... but not changing sensitivity\n");
		}


	/* Else we got a healthy number of false alarms, keep status quo */
	} else {
		IWL_DEBUG_CALIB(" FA in safe zone\n");
		data->nrg_curr_state = IWL_FA_GOOD_RANGE;

		/* Store for use in "fewer than desired" with later beacon */
		data->nrg_silence_ref = silence_ref;

		/* If previous beacon had too many false alarms,
		 *   give it some extra margin by reducing sensitivity again
		 *   (but don't go below measured energy of desired Rx) */
		if (IWL_FA_TOO_MANY == data->nrg_prev_state) {
			IWL_DEBUG_CALIB("... increasing margin\n");
			data->nrg_th_cck -= NRG_MARGIN;
		}
	}

	/* Make sure the energy threshold does not go above the measured
	 *   energy of the desired Rx signals (reduced by backoff margin),
	 *   or else we might start missing Rx frames.
	 * Lower value is higher energy, so we use max()! */
	data->nrg_th_cck = max(max_nrg_cck, data->nrg_th_cck);
	IWL_DEBUG_CALIB("new nrg_th_cck %u\n", data->nrg_th_cck);

	data->nrg_prev_state = data->nrg_curr_state;

	return 0;
}


static int iwl4965_sens_auto_corr_ofdm(struct iwl_priv *priv,
				       u32 norm_fa,
				       u32 rx_enable_time)
{
	u32 val;
	u32 false_alarms = norm_fa * 200 * 1024;
	u32 max_false_alarms = MAX_FA_OFDM * rx_enable_time;
	u32 min_false_alarms = MIN_FA_OFDM * rx_enable_time;
	struct iwl_sensitivity_data *data = NULL;

	data = &(priv->sensitivity_data);

	/* If we got too many false alarms this time, reduce sensitivity */
	if (false_alarms > max_false_alarms) {

		IWL_DEBUG_CALIB("norm FA %u > max FA %u)\n",
			     false_alarms, max_false_alarms);

		val = data->auto_corr_ofdm + AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm =
				min((u32)AUTO_CORR_MAX_OFDM, val);

		val = data->auto_corr_ofdm_mrc + AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm_mrc =
				min((u32)AUTO_CORR_MAX_OFDM_MRC, val);

		val = data->auto_corr_ofdm_x1 + AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm_x1 =
				min((u32)AUTO_CORR_MAX_OFDM_X1, val);

		val = data->auto_corr_ofdm_mrc_x1 + AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm_mrc_x1 =
				min((u32)AUTO_CORR_MAX_OFDM_MRC_X1, val);
	}

	/* Else if we got fewer than desired, increase sensitivity */
	else if (false_alarms < min_false_alarms) {

		IWL_DEBUG_CALIB("norm FA %u < min FA %u\n",
			     false_alarms, min_false_alarms);

		val = data->auto_corr_ofdm - AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm =
				max((u32)AUTO_CORR_MIN_OFDM, val);

		val = data->auto_corr_ofdm_mrc - AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm_mrc =
				max((u32)AUTO_CORR_MIN_OFDM_MRC, val);

		val = data->auto_corr_ofdm_x1 - AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm_x1 =
				max((u32)AUTO_CORR_MIN_OFDM_X1, val);

		val = data->auto_corr_ofdm_mrc_x1 - AUTO_CORR_STEP_OFDM;
		data->auto_corr_ofdm_mrc_x1 =
				max((u32)AUTO_CORR_MIN_OFDM_MRC_X1, val);
	}

	else {
		IWL_DEBUG_CALIB("min FA %u < norm FA %u < max FA %u OK\n",
			 min_false_alarms, false_alarms, max_false_alarms);
	}

	return 0;
}

static int iwl_sensitivity_callback(struct iwl_priv *priv,
				    struct iwl_cmd *cmd, struct sk_buff *skb)
{
	/* We didn't cache the SKB; let the caller free it */
	return 1;
}

/* Prepare a SENSITIVITY_CMD, send to uCode if values have changed */
static int iwl4965_sensitivity_write(struct iwl_priv *priv, u8 flags)
{
	int rc = 0;
	struct iwl_sensitivity_cmd cmd ;
	struct iwl_sensitivity_data *data = NULL;
	struct iwl_host_cmd cmd_out = {
		.id = SENSITIVITY_CMD,
		.len = sizeof(struct iwl_sensitivity_cmd),
		.meta.flags = flags,
		.data = &cmd,
	};

	data = &(priv->sensitivity_data);

	memset(&cmd, 0, sizeof(cmd));

	cmd.table[HD_AUTO_CORR32_X4_TH_ADD_MIN_INDEX] =
					(u16)data->auto_corr_ofdm;
	cmd.table[HD_AUTO_CORR32_X4_TH_ADD_MIN_MRC_INDEX] =
					(u16)data->auto_corr_ofdm_mrc;
	cmd.table[HD_AUTO_CORR32_X1_TH_ADD_MIN_INDEX] =
					(u16)data->auto_corr_ofdm_x1;
	cmd.table[HD_AUTO_CORR32_X1_TH_ADD_MIN_MRC_INDEX] =
					(u16)data->auto_corr_ofdm_mrc_x1;

	cmd.table[HD_AUTO_CORR40_X4_TH_ADD_MIN_INDEX] =
					(u16)data->auto_corr_cck;
	cmd.table[HD_AUTO_CORR40_X4_TH_ADD_MIN_MRC_INDEX] =
					(u16)data->auto_corr_cck_mrc;

	cmd.table[HD_MIN_ENERGY_CCK_DET_INDEX] = (u16)data->nrg_th_cck;
	cmd.table[HD_MIN_ENERGY_OFDM_DET_INDEX] = (u16)data->nrg_th_ofdm;

	cmd.table[HD_BARKER_CORR_TH_ADD_MIN_INDEX] = 190;
	cmd.table[HD_BARKER_CORR_TH_ADD_MIN_MRC_INDEX] = 390;
	cmd.table[HD_OFDM_ENERGY_TH_IN_INDEX] = 62;

	IWL_DEBUG_CALIB("ofdm: ac %u mrc %u x1 %u mrc_x1 %u thresh %u\n",
			data->auto_corr_ofdm, data->auto_corr_ofdm_mrc,
			data->auto_corr_ofdm_x1, data->auto_corr_ofdm_mrc_x1,
			data->nrg_th_ofdm);

	IWL_DEBUG_CALIB("cck: ac %u mrc %u thresh %u\n",
			data->auto_corr_cck, data->auto_corr_cck_mrc,
			data->nrg_th_cck);

	cmd.control = SENSITIVITY_CMD_CONTROL_WORK_TABLE;

	if (flags & CMD_ASYNC)
		cmd_out.meta.u.callback = iwl_sensitivity_callback;

	/* Don't send command to uCode if nothing has changed */
	if (!memcmp(&cmd.table[0], &(priv->sensitivity_tbl[0]),
		    sizeof(u16)*HD_TABLE_SIZE)) {
		IWL_DEBUG_CALIB("No change in SENSITIVITY_CMD\n");
		return 0;
	}

	/* Copy table for comparison next time */
	memcpy(&(priv->sensitivity_tbl[0]), &(cmd.table[0]),
	       sizeof(u16)*HD_TABLE_SIZE);

	rc = iwl_send_cmd(priv, &cmd_out);
	if (!rc) {
		IWL_DEBUG_CALIB("SENSITIVITY_CMD succeeded\n");
		return rc;
	}

	return 0;
}

void iwl4965_init_sensitivity(struct iwl_priv *priv, u8 flags, u8 force)
{
	int rc = 0;
	int i;
	struct iwl_sensitivity_data *data = NULL;

	IWL_DEBUG_CALIB("Start iwl4965_init_sensitivity\n");

	if (force)
		memset(&(priv->sensitivity_tbl[0]), 0,
			sizeof(u16)*HD_TABLE_SIZE);

	/* Clear driver's sensitivity algo data */
	data = &(priv->sensitivity_data);
	memset(data, 0, sizeof(struct iwl_sensitivity_data));

	data->num_in_cck_no_fa = 0;
	data->nrg_curr_state = IWL_FA_TOO_MANY;
	data->nrg_prev_state = IWL_FA_TOO_MANY;
	data->nrg_silence_ref = 0;
	data->nrg_silence_idx = 0;
	data->nrg_energy_idx = 0;

	for (i = 0; i < 10; i++)
		data->nrg_value[i] = 0;

	for (i = 0; i < NRG_NUM_PREV_STAT_L; i++)
		data->nrg_silence_rssi[i] = 0;

	data->auto_corr_ofdm = 90;
	data->auto_corr_ofdm_mrc = 170;
	data->auto_corr_ofdm_x1  = 105;
	data->auto_corr_ofdm_mrc_x1 = 220;
	data->auto_corr_cck = AUTO_CORR_CCK_MIN_VAL_DEF;
	data->auto_corr_cck_mrc = 200;
	data->nrg_th_cck = 100;
	data->nrg_th_ofdm = 100;

	data->last_bad_plcp_cnt_ofdm = 0;
	data->last_fa_cnt_ofdm = 0;
	data->last_bad_plcp_cnt_cck = 0;
	data->last_fa_cnt_cck = 0;

	/* Clear prior Sensitivity command data to force send to uCode */
	if (force)
		memset(&(priv->sensitivity_tbl[0]), 0,
		    sizeof(u16)*HD_TABLE_SIZE);

	rc |= iwl4965_sensitivity_write(priv, flags);
	IWL_DEBUG_CALIB("<<return 0x%X\n", rc);

	return;
}


/* Reset differential Rx gains in NIC to prepare for chain noise calibration.
 * Called after every association, but this runs only once!
 *  ... once chain noise is calibrated the first time, it's good forever.  */
void iwl4965_chain_noise_reset(struct iwl_priv *priv)
{
	struct iwl_chain_noise_data *data = NULL;
	int rc = 0;

	data = &(priv->chain_noise_data);
	if ((data->state == IWL_CHAIN_NOISE_ALIVE) && iwl_is_associated(priv)) {
		struct iwl_calibration_cmd cmd;

		memset(&cmd, 0, sizeof(cmd));
		cmd.opCode = PHY_CALIBRATE_DIFF_GAIN_CMD;
		cmd.diff_gain_a = 0;
		cmd.diff_gain_b = 0;
		cmd.diff_gain_c = 0;
		rc = iwl_send_cmd_pdu(priv, REPLY_PHY_CALIBRATION_CMD,
				 sizeof(cmd), &cmd);
		msleep(4);
		data->state = IWL_CHAIN_NOISE_ACCUMULATE;
		IWL_DEBUG_CALIB("Run chain_noise_calibrate\n");
	}
	return;
}

/*
 * Accumulate 20 beacons of signal and noise statistics for each of
 *   3 receivers/antennas/rx-chains, then figure out:
 * 1)  Which antennas are connected.
 * 2)  Differential rx gain settings to balance the 3 receivers.
 */
static void iwl4965_noise_calibration(struct iwl_priv *priv,
				      struct iwl_notif_statistics *stat_resp)
{
	struct iwl_chain_noise_data *data = NULL;
	int rc = 0;

	u32 chain_noise_a;
	u32 chain_noise_b;
	u32 chain_noise_c;
	u32 chain_sig_a;
	u32 chain_sig_b;
	u32 chain_sig_c;
	u32 average_sig[NUM_RX_CHAINS] = {INITIALIZATION_VALUE};
	u32 average_noise[NUM_RX_CHAINS] = {INITIALIZATION_VALUE};
	u32 max_average_sig;
	u16 max_average_sig_antenna_i;
	u32 min_average_noise = MIN_AVERAGE_NOISE_MAX_VALUE;
	u16 min_average_noise_antenna_i = INITIALIZATION_VALUE;
	u16 i = 0;
	u16 chan_num = INITIALIZATION_VALUE;
	u32 band = INITIALIZATION_VALUE;
	u32 active_chains = 0;
	unsigned long flags;
	struct statistics_rx_non_phy *rx_info = &(stat_resp->rx.general);

	data = &(priv->chain_noise_data);

	/* Accumulate just the first 20 beacons after the first association,
	 *   then we're done forever. */
	if (data->state != IWL_CHAIN_NOISE_ACCUMULATE ) {
		if (data->state == IWL_CHAIN_NOISE_ALIVE)
			IWL_DEBUG_CALIB("Wait for noise calib reset\n");
		return;
	}

	spin_lock_irqsave(&priv->lock, flags);
	if (rx_info->interference_data_flag != 1) {
		IWL_DEBUG_CALIB(" << Interference data unavailable\n");
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	band = (priv->staging_rxon.flags & RXON_FLG_BAND_24G_MSK) ? 0 : 1;
	chan_num = priv->staging_rxon.channel;

	/* Make sure we accumulate data for just the associated channel
	 *   (even if scanning). */
	if ((chan_num != (stat_resp->flag >> 16)) ||
	   ((STATISTICS_REPLY_FLG_BAND_24G_MSK ==
	     (stat_resp->flag & STATISTICS_REPLY_FLG_BAND_24G_MSK)) &&
	    band)) {
		IWL_DEBUG_CALIB("Stats not from chan=%d, band=%d\n",
				 chan_num, band);
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	/* Accumulate beacon statistics values across 20 beacons */
	chain_noise_a = (rx_info->beacon_silence_rssi_a & IN_BAND_FILTER);
	chain_noise_b = (rx_info->beacon_silence_rssi_b & IN_BAND_FILTER);
	chain_noise_c = (rx_info->beacon_silence_rssi_c & IN_BAND_FILTER);

	chain_sig_a = (rx_info->beacon_rssi_a & IN_BAND_FILTER);
	chain_sig_b = (rx_info->beacon_rssi_b & IN_BAND_FILTER);
	chain_sig_c = (rx_info->beacon_rssi_c & IN_BAND_FILTER);

	spin_unlock_irqrestore(&priv->lock, flags);

	data->beacon_count ++;

	data->chain_noise_a = (chain_noise_a + data->chain_noise_a);
	data->chain_noise_b = (chain_noise_b + data->chain_noise_b);
	data->chain_noise_c = (chain_noise_c + data->chain_noise_c);

	data->chain_signal_a = (chain_sig_a + data->chain_signal_a);
	data->chain_signal_b = (chain_sig_b + data->chain_signal_b);
	data->chain_signal_c = (chain_sig_c + data->chain_signal_c);

	IWL_DEBUG_CALIB("chan=%d, band=%d, beacon=%d\n", chan_num, band,
			data->beacon_count);
	IWL_DEBUG_CALIB("chain_sig: a %d b %d c %d\n",
			chain_sig_a, chain_sig_b, chain_sig_c);
	IWL_DEBUG_CALIB("chain_noise: a %d b %d c %d\n",
			chain_noise_a, chain_noise_b, chain_noise_c);

	/* If this is the 20th beacon, determine:
	 * 1)  Disconnected antennas (using signal strengths)
	 * 2)  Differential gain (using silence noise) to balance receivers */
	if (data->beacon_count == CAL_NUM_OF_BEACONS) {

		/* Analyze signal for disconnected antenna */
		average_sig[0] = (data->chain_signal_a) /
					CAL_NUM_OF_BEACONS;
		average_sig[1] = (data->chain_signal_b) /
					CAL_NUM_OF_BEACONS;
		average_sig[2] = (data->chain_signal_c) /
					CAL_NUM_OF_BEACONS;

		if (average_sig[0] >= average_sig[1]) {
			max_average_sig = average_sig[0];
			max_average_sig_antenna_i = 0;
			active_chains = (1 << max_average_sig_antenna_i);
		} else {
			max_average_sig = average_sig[1];
			max_average_sig_antenna_i = 1;
			active_chains = (1 << max_average_sig_antenna_i);
		}

		if (average_sig[2] >= max_average_sig) {
			max_average_sig = average_sig[2];
			max_average_sig_antenna_i = 2;
			active_chains = (1 << max_average_sig_antenna_i);
		}

		IWL_DEBUG_CALIB("average_sig: a %d b %d c %d\n",
			     average_sig[0], average_sig[1], average_sig[2]);
		IWL_DEBUG_CALIB("max_average_sig = %d, antenna %d\n",
			     max_average_sig, max_average_sig_antenna_i);

		/* Compare signal strengths for all 3 receivers. */
		for (i = 0; i < NUM_RX_CHAINS; i++) {
			if (i != max_average_sig_antenna_i) {
				s32 rssiDelta = (max_average_sig -
						 average_sig[i]);

				/* If signal is very weak, compared with
				 * strongest, mark it as disconnected. */
				if (rssiDelta > MAXIMUM_ALLOWED_PATHLOSS)
					data->disconn_array[i] = 1;
				else
					active_chains |= (1 << i);
			IWL_DEBUG_CALIB("i = %d  rssiDelta = %d  "
				     "disconn_array[i] = %d\n",
				     i, rssiDelta,
				     data->disconn_array[i]);
			}
		}

		/*If both chains A & B are disconnected -
		 * connect B and leave A as is */
		if (data->disconn_array[CHAIN_A] &&
		   data->disconn_array[CHAIN_B]) {
			data->disconn_array[CHAIN_B] = 0;
			active_chains |= (1 << CHAIN_B);
			IWL_DEBUG_CALIB("both A & B chains are disconnected! "
				     "W/A - declare B as connected\n");
		}

		IWL_DEBUG_CALIB("active_chains (bitwise) = 0x%x\n",
				active_chains);

		/* Save for use within RXON, TX, SCAN commands, etc. */
		priv->valid_antenna = active_chains;

		/* Analyze noise for rx balance */
		average_noise[0] = ((data->chain_noise_a)/CAL_NUM_OF_BEACONS);
		average_noise[1] = ((data->chain_noise_b)/CAL_NUM_OF_BEACONS);
		average_noise[2] = ((data->chain_noise_c)/CAL_NUM_OF_BEACONS);

		for (i = 0; i < NUM_RX_CHAINS; i++) {
			if (!(data->disconn_array[i]) &&
			   (average_noise[i] <= min_average_noise)) {
				/* This means that chain i is active and has
				 * lower noise values so far: */
				min_average_noise = average_noise[i];
				min_average_noise_antenna_i = i;
			}
		}

		data->delta_gain_code[min_average_noise_antenna_i] = 0;

		IWL_DEBUG_CALIB("average_noise: a %d b %d c %d\n",
				average_noise[0], average_noise[1],
				average_noise[2]);

		IWL_DEBUG_CALIB("min_average_noise = %d, antenna %d\n",
				min_average_noise, min_average_noise_antenna_i);

		for (i = 0; i < NUM_RX_CHAINS; i++) {
			s32 delta_g = 0;

			if (!(data->disconn_array[i]) &&
			    (data->delta_gain_code[i] ==
			     CHAIN_NOISE_DELTA_GAIN_INIT_VAL)) {
				delta_g = average_noise[i] - min_average_noise;
				data->delta_gain_code[i] = (u8)((delta_g *
								    10) / 15);
				if (CHAIN_NOISE_MAX_DELTA_GAIN_CODE <
				   data->delta_gain_code[i])
					data->delta_gain_code[i] =
					  CHAIN_NOISE_MAX_DELTA_GAIN_CODE;

				data->delta_gain_code[i] =
					(data->delta_gain_code[i] | (1 << 2));
			} else {
				data->delta_gain_code[i] = 0;
			}
		}
		IWL_DEBUG_CALIB("delta_gain_codes: a %d b %d c %d\n",
			     data->delta_gain_code[0],
			     data->delta_gain_code[1],
			     data->delta_gain_code[2]);

		/* Differential gain gets sent to uCode only once */
		if (!data->radio_write) {
			struct iwl_calibration_cmd cmd;
			data->radio_write = 1;

			memset(&cmd, 0, sizeof(cmd));
			cmd.opCode = PHY_CALIBRATE_DIFF_GAIN_CMD;
			cmd.diff_gain_a = data->delta_gain_code[0];
			cmd.diff_gain_b = data->delta_gain_code[1];
			cmd.diff_gain_c = data->delta_gain_code[2];
			rc = iwl_send_cmd_pdu(priv, REPLY_PHY_CALIBRATION_CMD,
					      sizeof(cmd), &cmd);
			if (rc)
				IWL_DEBUG_CALIB("fail sending cmd "
					     "REPLY_PHY_CALIBRATION_CMD \n");

			/* TODO we might want recalculate
			 * rx_chain in rxon cmd */

			/* Mark so we run this algo only once! */
			data->state = IWL_CHAIN_NOISE_CALIBRATED;
		}
		data->chain_noise_a = 0;
		data->chain_noise_b = 0;
		data->chain_noise_c = 0;
		data->chain_signal_a = 0;
		data->chain_signal_b = 0;
		data->chain_signal_c = 0;
		data->beacon_count = 0;
	}
	return;
}

static void iwl4965_sensitivity_calibration(struct iwl_priv *priv,
					    struct iwl_notif_statistics *resp)
{
	int rc = 0;
	u32 rx_enable_time;
	u32 fa_cck;
	u32 fa_ofdm;
	u32 bad_plcp_cck;
	u32 bad_plcp_ofdm;
	u32 norm_fa_ofdm;
	u32 norm_fa_cck;
	struct iwl_sensitivity_data *data = NULL;
	struct statistics_rx_non_phy *rx_info = &(resp->rx.general);
	struct statistics_rx *statistics = &(resp->rx);
	unsigned long flags;
	struct statistics_general_data statis;

	data = &(priv->sensitivity_data);

	if (!iwl_is_associated(priv)) {
		IWL_DEBUG_CALIB("<< - not associated\n");
		return;
	}

	spin_lock_irqsave(&priv->lock, flags);
	if (rx_info->interference_data_flag != 1) {
		IWL_DEBUG_CALIB("<< invalid data.\n");
		spin_unlock_irqrestore(&priv->lock, flags);
		return;
	}

	/* Extract Statistics: */
	rx_enable_time = rx_info->channel_load;
	fa_cck = statistics->cck.false_alarm_cnt;
	fa_ofdm = statistics->ofdm.false_alarm_cnt;
	bad_plcp_cck = statistics->cck.plcp_err;
	bad_plcp_ofdm = statistics->ofdm.plcp_err;

	statis.beacon_silence_rssi_a =
			statistics->general.beacon_silence_rssi_a;
	statis.beacon_silence_rssi_b =
			statistics->general.beacon_silence_rssi_b;
	statis.beacon_silence_rssi_c =
			statistics->general.beacon_silence_rssi_c;
	statis.beacon_energy_a =
			statistics->general.beacon_energy_a;
	statis.beacon_energy_b =
			statistics->general.beacon_energy_b;
	statis.beacon_energy_c =
			statistics->general.beacon_energy_c;

	spin_unlock_irqrestore(&priv->lock, flags);

	IWL_DEBUG_CALIB("rx_enable_time = %u usecs\n", rx_enable_time);

	if (!rx_enable_time) {
		IWL_DEBUG_CALIB("<< RX Enable Time == 0! \n");
		return;
	}

	/* These statistics increase monotonically, and do not reset
	 *   at each beacon.  Calculate difference from last value, or just
	 *   use the new statistics value if it has reset or wrapped around. */
	if (data->last_bad_plcp_cnt_cck > bad_plcp_cck)
		data->last_bad_plcp_cnt_cck = bad_plcp_cck;
	else {
		bad_plcp_cck -= data->last_bad_plcp_cnt_cck;
		data->last_bad_plcp_cnt_cck += bad_plcp_cck;
	}

	if (data->last_bad_plcp_cnt_ofdm > bad_plcp_ofdm)
		data->last_bad_plcp_cnt_ofdm = bad_plcp_ofdm;
	else {
		bad_plcp_ofdm -= data->last_bad_plcp_cnt_ofdm;
		data->last_bad_plcp_cnt_ofdm += bad_plcp_ofdm;
	}

	if (data->last_fa_cnt_ofdm > fa_ofdm)
		data->last_fa_cnt_ofdm = fa_ofdm;
	else{
		fa_ofdm -= data->last_fa_cnt_ofdm;
		data->last_fa_cnt_ofdm += fa_ofdm;
	}

	if (data->last_fa_cnt_cck > fa_cck)
		data->last_fa_cnt_cck = fa_cck;
	else {
		fa_cck -= data->last_fa_cnt_cck;
		data->last_fa_cnt_cck += fa_cck;
	}

	/* Total aborted signal locks */
	norm_fa_ofdm = fa_ofdm + bad_plcp_ofdm;
	norm_fa_cck = fa_cck + bad_plcp_cck;

	IWL_DEBUG_CALIB("cck: fa %u badp %u  ofdm: fa %u badp %u\n", fa_cck,
			bad_plcp_cck, fa_ofdm, bad_plcp_ofdm);

	iwl4965_sens_auto_corr_ofdm(priv, norm_fa_ofdm, rx_enable_time);

	iwl4965_sens_energy_cck(priv, norm_fa_cck,
					rx_enable_time, &statis);

	rc |= iwl4965_sensitivity_write(priv, CMD_ASYNC);
	return;
}

static void iwl4965_bg_sensitivity_work(void *p)
{
	struct iwl_priv *priv = p;

	mutex_lock(&priv->mutex);

	if ((priv->status & STATUS_EXIT_PENDING) ||
	    (priv->status & STATUS_SCANNING)) {
		mutex_unlock(&priv->mutex);
		return;
	}

	if (priv->start_calib) {
		iwl4965_noise_calibration(priv, &priv->statistics);

		if (priv->sensitivity_data.state ==
					IWL_SENS_CALIB_NEED_REINIT) {
			iwl4965_init_sensitivity(priv, CMD_ASYNC, 0);
			priv->sensitivity_data.state = IWL_SENS_CALIB_ALLOWED;
		} else {
			iwl4965_sensitivity_calibration(priv,
							&priv->statistics);
		}
	}

	mutex_unlock(&priv->mutex);
	return;
}
#endif /*CONFIG_IWLWIFI_SENSITIVITY*/

static void iwl4965_bg_txpower_work(void *p)
{
	struct iwl_priv *priv = p;

	mutex_lock(&priv->mutex);

	/* If a scan happened to start before we got here
	 * then just return; the statistics notification will
	 * kick off another scheduled work to compensate for
	 * any temperature delta we missed here. */
	if ((priv->status & STATUS_EXIT_PENDING) ||
	    priv->status & STATUS_SCANNING) {
		mutex_unlock(&priv->mutex);
		return;
	}

	/* Regardless of if we are assocaited, we must reconfigure the
	 * TX power since frames can be sent on non-radar channels while
	 * not associated */
	iwl_hw_reg_send_txpower(priv);

	/* Update last_temperature to keep is_calib_needed from running
	 * when it isn't needed... */
	priv->last_temperature = priv->temperature;

	mutex_unlock(&priv->mutex);
}

static void iwl4965_set_wr_ptrs(struct iwl_priv *priv, int txq_id, u32 index)
{
	iwl_write_restricted(priv, HBUS_TARG_WRPTR,
			     (index & 0xff) | (txq_id << 8));
	iwl_write_restricted_reg(priv, SCD_QUEUE_RDPTR(txq_id), index);
}

static void iwl4965_tx_queue_set_status(struct iwl_priv *priv,
			    struct iwl_tx_queue *txq, int tx_fifo_id,
			    int sched_retry, int active)
{
	int txq_id = txq->q.id;

	txq->sched_retry = sched_retry;
	txq->sched_retry = active;

	iwl_write_restricted_reg(priv,
				SCD_QUEUE_STATUS_BITS(txq_id),
				(active << SCD_QUEUE_STTS_REG_POS_ACTIVE)|
				(tx_fifo_id << SCD_QUEUE_STTS_REG_POS_TXF)|
				(sched_retry << SCD_QUEUE_STTS_REG_POS_WSL)|
				(sched_retry << SCD_QUEUE_STTS_REG_POS_SCD_ACK)|
				SCD_QUEUE_STTS_REG_MSK);

	IWL_DEBUG_INFO("%s %s Queue %d on AC %d\n",
		(active?"Activete":"Deactivate"),
		sched_retry?"BA":"AC", txq_id, tx_fifo_id);
}


static const u16 default_ac_to_tx_fifo[] = {
	IWL_TX_QUEUE_AC1, IWL_TX_QUEUE_AC0,
	IWL_TX_QUEUE_AC2, IWL_TX_QUEUE_AC3,
	IWL_TX_QUEUE_HCCA_1, IWL_TX_QUEUE_HCCA_2
};

int iwl4965_alive_notify(struct iwl_priv *priv)
{
	u32 a;
	int i = 0;
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&priv->lock, flags);

#ifdef CONFIG_IWLWIFI_SENSITIVITY
	memset(&(priv->sensitivity_data), 0,
	       sizeof(struct iwl_sensitivity_data));
	memset(&(priv->chain_noise_data), 0,
	       sizeof(struct iwl_chain_noise_data));
	for (i = 0; i < NUM_RX_CHAINS; i++)
		priv->chain_noise_data.delta_gain_code[i] =
				CHAIN_NOISE_DELTA_GAIN_INIT_VAL;
#endif /* CONFIG_IWLWIFI_SENSITIVITY*/
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	priv->scd_base_addr = iwl_read_restricted_reg(priv, SCD_SRAM_BASE_ADDR);
	a = priv->scd_base_addr + SCD_CONTEXT_DATA_OFFSET;
	for (; a < priv->scd_base_addr + SCD_TX_STTS_BITMAP_OFFSET; a += 4)
		iwl_write_restricted_mem(priv, a, 0);
	for (; a < priv->scd_base_addr + SCD_TRANSLATE_TBL_OFFSET; a += 4)
		iwl_write_restricted_mem(priv, a, 0);
	for (;
	     a < sizeof(u16) * IWL4965_NUM_QUEUES;
	     a += 4)
		iwl_write_restricted_mem(priv, a, 0);

	iwl_write_restricted_reg(priv, SCD_DRAM_BASE_ADDR,
				 (priv->hw_setting.shared_phys +
				  offsetof(struct iwl_shared,
					   queues_byte_cnt_tbls))
				 >> 10);
	iwl_write_restricted_reg(priv, SCD_QUEUECHAIN_SEL, 0);

	/* initiate the queues */
	for (i = 0; i < IWL4965_NUM_QUEUES; i++) {
		iwl_write_restricted_reg(priv, SCD_QUEUE_RDPTR(i), 0);
		iwl_write_restricted(priv, HBUS_TARG_WRPTR, 0 | (i << 8));
		iwl_write_restricted_mem(priv, priv->scd_base_addr +
					SCD_CONTEXT_QUEUE_OFFSET(i),
					(SCD_WIN_SIZE <<
					SCD_QUEUE_CTX_REG1_WIN_SIZE_POS) &
					SCD_QUEUE_CTX_REG1_WIN_SIZE_MSK);
		iwl_write_restricted_mem(priv, priv->scd_base_addr +
					SCD_CONTEXT_QUEUE_OFFSET(i) +
					sizeof(u32),
					(SCD_FRAME_LIMIT <<
					SCD_QUEUE_CTX_REG2_FRAME_LIMIT_POS) &
					SCD_QUEUE_CTX_REG2_FRAME_LIMIT_MSK);

	}
	iwl_write_restricted_reg(priv, SCD_INTERRUPT_MASK,
				 (1 << IWL4965_NUM_QUEUES) - 1);

	iwl_write_restricted_reg(priv, SCD_TXFACT,
				 SCD_TXFACT_REG_TXFIFO_MASK(0, 7));

	iwl4965_set_wr_ptrs(priv, IWL_CMD_QUEUE_NUM, 0);
	iwl4965_tx_queue_set_status(priv, &priv->txq[IWL_CMD_QUEUE_NUM],
				    IWL_CMD_FIFO_NUM, 0, 1);
	/* map qos queues to fifos one-to-one */
	for (i = 0; i < GLOBAL_ARRAY_SIZE(default_ac_to_tx_fifo); i++) {
		int ac = default_ac_to_tx_fifo[i];
		iwl4965_tx_queue_set_status(priv, &priv->txq[ac], ac, 0, 1);
	}

	iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	return 0;
}

int iwl_hw_set_hw_setting(struct iwl_priv *priv)
{
	priv->hw_setting.shared_virt =
	    pci_alloc_consistent(priv->pci_dev,
				 sizeof(struct iwl_shared),
				 &priv->hw_setting.shared_phys);

	if (!priv->hw_setting.shared_virt)
		return -1;

	memset(priv->hw_setting.shared_virt, 0, sizeof(struct iwl_shared));

	priv->hw_setting.max_queue_number = IWL4965_NUM_QUEUES;
	priv->hw_setting.ac_queue_count = AC_NUM;

	priv->hw_setting.cck_flag = RATE_MCS_CCK_MSK;
	priv->hw_setting.tx_cmd_len = sizeof(struct iwl_tx_cmd);
	priv->hw_setting.max_rxq_size = RX_QUEUE_SIZE;
	priv->hw_setting.max_rxq_log = RX_QUEUE_SIZE_LOG;
	return 0;
}

/**
 * iwl_hw_txq_ctx_free - Free TXQ Context
 *
 * Destroy all TX DMA queues and structures
 */
void iwl_hw_txq_ctx_free(struct iwl_priv *priv)
{
	int txq_id;

	/* Tx queues */
	for (txq_id = 0; txq_id < priv->hw_setting.max_queue_number; txq_id++)
		iwl_tx_queue_free(priv, &priv->txq[txq_id]);

	iwl4965_kw_free(priv);
}

/**
 * iwl_hw_tx_queue_free_tfd -  Free one TFD, those at index [txq->q.last_used]
 *
 * Does NOT advance any indexes
 */
int iwl_hw_tx_queue_free_tfd(struct iwl_priv *priv, struct iwl_tx_queue *txq)
{
	struct iwl_tfd_frame *bd_tmp = (struct iwl_tfd_frame *)&txq->bd[0];
	struct iwl_tfd_frame *bd = &bd_tmp[txq->q.last_used];
	struct pci_dev *dev = priv->pci_dev;
	int i;
	int counter = 0;
	int index, is_odd;

	/* classify bd */
	if (txq->q.id == IWL_CMD_QUEUE_NUM)
		/* nothing to cleanup after for host commands */
		return 0;

	/* sanity check */
	counter = IWL_GET_BITS(*bd, num_tbs);
	if (counter > MAX_NUM_OF_TBS) {
		IWL_ERROR("Too many chunks: %i\n", counter);
		/* @todo issue fatal error, it is quite serious situation */
		return 0;
	}

	/* unmap chunks if any */

	for (i = 0; i < counter; i++) {
		index = i / 2;
		is_odd = i % 2;

		if (is_odd)
			pci_unmap_single(
				dev,
				IWL_GET_BITS(bd->pa[index], tb2_addr_lo16) |
				(IWL_GET_BITS(bd->pa[index],
					      tb2_addr_hi20) << 16),
				IWL_GET_BITS(bd->pa[index], tb2_len),
				PCI_DMA_TODEVICE);

		else if (i > 0)
			pci_unmap_single(dev,
					 le32_to_cpu(bd->pa[index].tb1_addr),
					 IWL_GET_BITS(bd->pa[index], tb1_len),
					 PCI_DMA_TODEVICE);

		if (txq->txb[txq->q.last_used].skb[i]) {
			struct sk_buff *skb = txq->txb[txq->q.last_used].skb[i];

			dev_kfree_skb(skb);
			txq->txb[txq->q.last_used].skb[i] = NULL;
		}
	}
	return 0;
}

int iwl_hw_reg_set_txpower(struct iwl_priv *priv, s8 power)
{
	IWL_ERROR("TODO: Implement iwl_hw_reg_set_txpower!\n");
	return -EINVAL;
}

#define TX_POWER_IWL_ILLEGAL_VDET    -100000
#define TX_POWER_IWL_ILLEGAL_VOLTAGE -10000
#define TX_POWER_IWL_CLOSED_LOOP_MIN_POWER 18
#define TX_POWER_IWL_CLOSED_LOOP_MAX_POWER 34
#define TX_POWER_IWL_VDET_SLOPE_BELOW_NOMINAL 17
#define TX_POWER_IWL_VDET_SLOPE_ABOVE_NOMINAL 20
#define TX_POWER_IWL_NOMINAL_POWER            26
#define TX_POWER_IWL_CLOSED_LOOP_ITERATION_LIMIT 1
#define TX_POWER_IWL_VOLTAGE_CODES_PER_03V       7
#define TX_POWER_IWL_DEGREES_PER_VDET_CODE       11
#define IWL_TX_POWER_MAX_NUM_PA_MEASUREMENTS 1
#define IWL_TX_POWER_CCK_COMPENSATION_B_STEP (9)
#define IWL_TX_POWER_CCK_COMPENSATION_C_STEP (5)

static s32 iwl4965_math_div_round(s32 num, s32 denom, s32 * res)
{
	s32 sign = 1;

	if (num < 0) {
		sign = -sign;
		num = -num;
	}
	if (denom < 0) {
		sign = -sign;
		denom = -denom;
	}
	*res = 1;
	*res = ((num * 2 + denom) / (denom * 2)) * sign;

	return 1;
}

static s32 iwl4965_get_voltage_compensation(u32 eeprom_voltage,
					    u32 current_voltage)
{
	s32 comp = 0;

	if ((TX_POWER_IWL_ILLEGAL_VOLTAGE == eeprom_voltage) ||
	    (TX_POWER_IWL_ILLEGAL_VOLTAGE == current_voltage))
		return 0;

	iwl4965_math_div_round(current_voltage - eeprom_voltage,
			       TX_POWER_IWL_VOLTAGE_CODES_PER_03V, &comp);

	if (current_voltage > eeprom_voltage)
		comp *= 2;
	if ((comp < -2) || (comp > 2))
		comp = 0;

	return comp;
}

static const struct iwl_channel_info *iwl4965_get_current_txpower_info(
	struct iwl_priv *priv, u8 *band, u8 *channel, u8 *is_fat,
	u8 *ctrl_chan_high)
{
	const struct iwl_channel_info *ch_info;

	*ctrl_chan_high = 0;
	*channel = priv->active_rxon.channel;
	*band = ((priv->phymode == MODE_IEEE80211B) ||
		 (priv->phymode == MODE_IEEE80211G) ||
		 (priv->phymode == MODE_ATHEROS_TURBOG)) ? 1 : 0;

	ch_info = iwl_get_channel_info(priv, priv->phymode,
				       priv->active_rxon.channel);

	if (!is_channel_valid(ch_info))
		return NULL;

	*is_fat = is_fat_channel(priv);

	if (*is_fat)
		if (priv->active_rxon.flags &
		    RXON_FLG_CONTROL_CHANNEL_LOC_HIGH_MSK)
			*ctrl_chan_high = 1;

	return ch_info;
}

static s32 iwl4965_get_txatten_group_from_channel(u32 channel)
{
	if (channel >= CALIB_IWL_TX_ATTEN_GR5_FCH &&
	    channel <= CALIB_IWL_TX_ATTEN_GR5_LCH)
		return CALIB_CH_GROUP_5;

	if (channel >= CALIB_IWL_TX_ATTEN_GR1_FCH &&
	    channel <= CALIB_IWL_TX_ATTEN_GR1_LCH)
		return CALIB_CH_GROUP_1;

	if (channel >= CALIB_IWL_TX_ATTEN_GR2_FCH &&
	    channel <= CALIB_IWL_TX_ATTEN_GR2_LCH)
		return CALIB_CH_GROUP_2;

	if (channel >= CALIB_IWL_TX_ATTEN_GR3_FCH &&
	    channel <= CALIB_IWL_TX_ATTEN_GR3_LCH)
		return CALIB_CH_GROUP_3;

	if (channel >= CALIB_IWL_TX_ATTEN_GR4_FCH &&
	    channel <= CALIB_IWL_TX_ATTEN_GR4_LCH)
		return CALIB_CH_GROUP_4;

	IWL_ERROR("Can't find txatten group for channel %d.\n", channel);
	return -1;
}

static u32 iwl4965_get_sub_band(const struct iwl_priv *priv, u32 channel)
{
	s32 sub_band = -1;

	for (sub_band = 0; sub_band < EEPROM_TX_POWER_BANDS; sub_band++) {

		if (priv->eeprom.calib_info.band_info_tbl[sub_band].ch_from ==
		    0)
			continue;

		if ((channel >=
		     priv->eeprom.calib_info.band_info_tbl[sub_band].ch_from)
		    && (channel <=
			priv->eeprom.calib_info.band_info_tbl[sub_band].ch_to))
			break;
	}

	return sub_band;
}

static s32 iwl4965_interpolate_value(s32 x, s32 x1, s32 y1, s32 x2, s32 y2)
{
	s32 val;

	if (x2 == x1)
		return y1;
	else {
		iwl4965_math_div_round((x2 - x) * (y1 - y2), (x2 - x1), &val);
		return val + y2;
	}
}

static int iwl4965_interpolate_chan(
	struct iwl_priv *priv, u32 channel,
	struct iwl_eeprom_calib_channel_info *chan_info)
{
	s32 s = -1;
	u32 c;
	u32 m;
	const struct iwl_eeprom_calib_measurement *m1;
	const struct iwl_eeprom_calib_measurement *m2;
	struct iwl_eeprom_calib_measurement *omeas;
	u32 ch_i1;
	u32 ch_i2;

	s = iwl4965_get_sub_band(priv, channel);
	if (s >= EEPROM_TX_POWER_BANDS) {
		IWL_ERROR("Tx Power can not find channel %d ", channel);
		return -1;
	}

	ch_i1 = priv->eeprom.calib_info.band_info_tbl[s].ch1.ch_num;
	ch_i2 = priv->eeprom.calib_info.band_info_tbl[s].ch2.ch_num;
	chan_info->ch_num = (u8) channel;

	IWL_DEBUG_TXPOWER("channel %d subband %d factory cal ch %d & %d\n",
			  channel, s, ch_i1, ch_i2);

	for (c = 0; c < EEPROM_TX_POWER_TX_CHAINS; c++) {
		for (m = 0; m < EEPROM_TX_POWER_MEASUREMENTS; m++) {
			m1 = &(priv->eeprom.calib_info.band_info_tbl[s].ch1.
			       measurements[c][m]);
			m2 = &(priv->eeprom.calib_info.band_info_tbl[s].ch2.
			       measurements[c][m]);
			omeas = &(chan_info->measurements[c][m]);

			omeas->actual_pow =
			    (u8) iwl4965_interpolate_value(channel, ch_i1,
							   m1->actual_pow,
							   ch_i2,
							   m2->actual_pow);
			omeas->gain_idx =
			    (u8) iwl4965_interpolate_value(channel, ch_i1,
							   m1->gain_idx, ch_i2,
							   m2->gain_idx);
			omeas->temperature =
			    (u8) iwl4965_interpolate_value(channel, ch_i1,
							   m1->temperature,
							   ch_i2,
							   m2->temperature);
			omeas->pa_det =
			    (s8) iwl4965_interpolate_value(channel, ch_i1,
							   m1->pa_det, ch_i2,
							   m2->pa_det);

			IWL_DEBUG_TXPOWER
			    ("chain %d meas %d AP1=%d AP2=%d AP=%d\n", c, m,
			     m1->actual_pow, m2->actual_pow, omeas->actual_pow);
			IWL_DEBUG_TXPOWER
			    ("chain %d meas %d NI1=%d NI2=%d NI=%d\n", c, m,
			     m1->gain_idx, m2->gain_idx, omeas->gain_idx);
			IWL_DEBUG_TXPOWER
			    ("chain %d meas %d PA1=%d PA2=%d PA=%d\n", c, m,
			     m1->pa_det, m2->pa_det, omeas->pa_det);
			IWL_DEBUG_TXPOWER
			    ("chain %d meas %d  T1=%d  T2=%d  T=%d\n", c, m,
			     m1->temperature, m2->temperature,
			     omeas->temperature);
		}
	}

	return 0;
}

/* bit-rate-dependent table to prevent Tx distortion, in half-dB units,
 * for OFDM 6, 12, 18, 24, 36, 48, 54, 60 MBit, and CCK all rates. */
static s32 back_off_table[] = {
	10, 10, 10, 10, 10, 15, 17, 20,	/* OFDM SISO 20 MHz */
	10, 10, 10, 10, 10, 15, 17, 20,	/* OFDM MIMO 20 MHz */
	10, 10, 10, 10, 10, 15, 17, 20,	/* OFDM SISO 40 MHz */
	10, 10, 10, 10, 10, 15, 17, 20,	/* OFDM MIMO 40 MHz */
	10			/* CCK */
};

/* Thermal compensation values for txpower for various frequency ranges ...
 *   ratios from 3:1 to 4.5:1 of degrees (Celsius) per half-dB gain adjust */
static struct iwl_txpower_comp_entry {
	s32 degrees_per_05db_a;
	s32 degrees_per_05db_a_denom;
} tx_power_cmp_tble[CALIB_CH_GROUP_MAX] = {
	{9, 2},			/* group 0 5.2, ch  34-43 */
	{4, 1},			/* group 1 5.2, ch  44-70 */
	{4, 1},			/* group 2 5.2, ch  71-124 */
	{4, 1},			/* group 3 5.2, ch 125-200 */
	{3, 1}			/* group 4 2.4, ch   all */
};

static s32 get_min_power_index(s32 rate_power_index, u32 band)
{
	if (!band) {
		if ((rate_power_index % 8) <= 4)
			return MIN_TX_GAIN_INDEX_52GHZ_EXT;
	}
	return MIN_TX_GAIN_INDEX;
}

struct gain_entry {
	u8 dsp;
	u8 radio;
};

static const struct gain_entry gain_table[2][108] = {
	/* 5.2GHz power gain index table */
	{
	 {123, 0x3F},		/* highest txpower */
	 {117, 0x3F},
	 {110, 0x3F},
	 {104, 0x3F},
	 {98, 0x3F},
	 {110, 0x3E},
	 {104, 0x3E},
	 {98, 0x3E},
	 {110, 0x3D},
	 {104, 0x3D},
	 {98, 0x3D},
	 {110, 0x3C},
	 {104, 0x3C},
	 {98, 0x3C},
	 {110, 0x3B},
	 {104, 0x3B},
	 {98, 0x3B},
	 {110, 0x3A},
	 {104, 0x3A},
	 {98, 0x3A},
	 {110, 0x39},
	 {104, 0x39},
	 {98, 0x39},
	 {110, 0x38},
	 {104, 0x38},
	 {98, 0x38},
	 {110, 0x37},
	 {104, 0x37},
	 {98, 0x37},
	 {110, 0x36},
	 {104, 0x36},
	 {98, 0x36},
	 {110, 0x35},
	 {104, 0x35},
	 {98, 0x35},
	 {110, 0x34},
	 {104, 0x34},
	 {98, 0x34},
	 {110, 0x33},
	 {104, 0x33},
	 {98, 0x33},
	 {110, 0x32},
	 {104, 0x32},
	 {98, 0x32},
	 {110, 0x31},
	 {104, 0x31},
	 {98, 0x31},
	 {110, 0x30},
	 {104, 0x30},
	 {98, 0x30},
	 {110, 0x25},
	 {104, 0x25},
	 {98, 0x25},
	 {110, 0x24},
	 {104, 0x24},
	 {98, 0x24},
	 {110, 0x23},
	 {104, 0x23},
	 {98, 0x23},
	 {110, 0x22},
	 {104, 0x18},
	 {98, 0x18},
	 {110, 0x17},
	 {104, 0x17},
	 {98, 0x17},
	 {110, 0x16},
	 {104, 0x16},
	 {98, 0x16},
	 {110, 0x15},
	 {104, 0x15},
	 {98, 0x15},
	 {110, 0x14},
	 {104, 0x14},
	 {98, 0x14},
	 {110, 0x13},
	 {104, 0x13},
	 {98, 0x13},
	 {110, 0x12},
	 {104, 0x08},
	 {98, 0x08},
	 {110, 0x07},
	 {104, 0x07},
	 {98, 0x07},
	 {110, 0x06},
	 {104, 0x06},
	 {98, 0x06},
	 {110, 0x05},
	 {104, 0x05},
	 {98, 0x05},
	 {110, 0x04},
	 {104, 0x04},
	 {98, 0x04},
	 {110, 0x03},
	 {104, 0x03},
	 {98, 0x03},
	 {110, 0x02},
	 {104, 0x02},
	 {98, 0x02},
	 {110, 0x01},
	 {104, 0x01},
	 {98, 0x01},
	 {110, 0x00},
	 {104, 0x00},
	 {98, 0x00},
	 {93, 0x00},
	 {88, 0x00},
	 {83, 0x00},
	 {78, 0x00},
	 },
	/* 2.4GHz power gain index table */
	{
	 {110, 0x3f},		/* highest txpower */
	 {104, 0x3f},
	 {98, 0x3f},
	 {110, 0x3e},
	 {104, 0x3e},
	 {98, 0x3e},
	 {110, 0x3d},
	 {104, 0x3d},
	 {98, 0x3d},
	 {110, 0x3c},
	 {104, 0x3c},
	 {98, 0x3c},
	 {110, 0x3b},
	 {104, 0x3b},
	 {98, 0x3b},
	 {110, 0x3a},
	 {104, 0x3a},
	 {98, 0x3a},
	 {110, 0x39},
	 {104, 0x39},
	 {98, 0x39},
	 {110, 0x38},
	 {104, 0x38},
	 {98, 0x38},
	 {110, 0x37},
	 {104, 0x37},
	 {98, 0x37},
	 {110, 0x36},
	 {104, 0x36},
	 {98, 0x36},
	 {110, 0x35},
	 {104, 0x35},
	 {98, 0x35},
	 {110, 0x34},
	 {104, 0x34},
	 {98, 0x34},
	 {110, 0x33},
	 {104, 0x33},
	 {98, 0x33},
	 {110, 0x32},
	 {104, 0x32},
	 {98, 0x32},
	 {110, 0x31},
	 {104, 0x31},
	 {98, 0x31},
	 {110, 0x30},
	 {104, 0x30},
	 {98, 0x30},
	 {110, 0x6},
	 {104, 0x6},
	 {98, 0x6},
	 {110, 0x5},
	 {104, 0x5},
	 {98, 0x5},
	 {110, 0x4},
	 {104, 0x4},
	 {98, 0x4},
	 {110, 0x3},
	 {104, 0x3},
	 {98, 0x3},
	 {110, 0x2},
	 {104, 0x2},
	 {98, 0x2},
	 {110, 0x1},
	 {104, 0x1},
	 {98, 0x1},
	 {110, 0x0},
	 {104, 0x0},
	 {98, 0x0},
	 {97, 0},
	 {96, 0},
	 {95, 0},
	 {94, 0},
	 {93, 0},
	 {92, 0},
	 {91, 0},
	 {90, 0},
	 {89, 0},
	 {88, 0},
	 {87, 0},
	 {86, 0},
	 {85, 0},
	 {84, 0},
	 {83, 0},
	 {82, 0},
	 {81, 0},
	 {80, 0},
	 {79, 0},
	 {78, 0},
	 {77, 0},
	 {76, 0},
	 {75, 0},
	 {74, 0},
	 {73, 0},
	 {72, 0},
	 {71, 0},
	 {70, 0},
	 {69, 0},
	 {68, 0},
	 {67, 0},
	 {66, 0},
	 {65, 0},
	 {64, 0},
	 {63, 0},
	 {62, 0},
	 {61, 0},
	 {60, 0},
	 {59, 0},
	 }
};

/**
 * iwl_hw_reg_send_txpower - Configure the TXPOWER level user limit
 *
 * Uses the active RXON for channel, band, and characteristics (fat, high)
 * The power limit is taken from priv->user_txpower_limit.
 */
int iwl_hw_reg_send_txpower(struct iwl_priv *priv)
{
	u16 radio_gain;
	u16 dsp_atten;
	u8 saturation_power;
	s32 target_power;
	s32 user_target_power;
	s32 power_limit;
	s32 current_temp;
	s32 reg_limit;
	s32 current_regulatory;
	s32 txatten_group = CALIB_CH_GROUP_MAX;
	int i = 0;
	int c;
	struct iwl_tx_power_table_cmd cmd = { 0 };
	const struct iwl_channel_info *ch_info = NULL;
	struct iwl_eeprom_calib_channel_info ch_eeprom_info;
	const struct iwl_eeprom_calib_measurement *measurement;
	int rc = 0;
	s16 voltage;
	s32 voltage_compensation;
	s32 degrees_per_05db_num;
	s32 degrees_per_05db_denom;
	s32 factory_temp;
	s32 temperature_comp[2];
	s32 factory_gain_index[2];
	s32 factory_actual_pwr[2];
	s32 power_index;
	u8 band = 0;
	u8 channel = 0;
	u8 is_fat = 0;
	u8 ctrl_chan_high = 0;

	if (priv->status & STATUS_SCANNING) {
		/* If this gets hit a lot, switch it to a BUG() and catch
		 * the stack trace to find out who is calling this during
		 * a scan. */
		IWL_WARNING("TX Power requested while scanning!\n");
		return -EAGAIN;
	}

	/* Sanity check requested level (dBm) */
	if (priv->user_txpower_limit < IWL_TX_POWER_TARGET_POWER_MIN) {
		IWL_WARNING("Requested user TXPOWER %d below limit.\n",
			    priv->user_txpower_limit);
		return -EINVAL;
	}
	if (priv->user_txpower_limit > IWL_TX_POWER_TARGET_POWER_MAX) {
		IWL_WARNING("Requested user TXPOWER %d above limit.\n",
			    priv->user_txpower_limit);
		return -EINVAL;
	}

	/* user_txpower_limit is in dBm, convert to half-dBm (half-dB units
	 *   are used for indexing into txpower table) */
	user_target_power = 2 * priv->user_txpower_limit;

	/* Get current (RXON) channel, band, width */
	ch_info =
	    iwl4965_get_current_txpower_info(priv, &band, &channel, &is_fat,
					     &ctrl_chan_high);

	IWL_DEBUG_TXPOWER("chan %d band %d is_fat %d\n", channel, band,
			  is_fat);

	if (!ch_info)
		return -1;

	cmd.band = band;
	cmd.channel = channel;
	cmd.channel_normal_width = 0;

	/* get txatten group, used to select 1) thermal txpower adjustment
	 *   and 2) mimo txpower balance between Tx chains. */
	txatten_group = iwl4965_get_txatten_group_from_channel(channel);
	if (txatten_group < 0)
		return -1;

	IWL_DEBUG_TXPOWER("channel %d belongs to txatten group %d\n",
			  channel, txatten_group);

	if (is_fat) {
		if (ctrl_chan_high)
			channel -= 2;
		else
			channel += 2;
	}

	/* hardware txpower limits ...
	 * saturation (clipping distortion) txpowers are in half-dBm */
	if (band)
		saturation_power = priv->eeprom.calib_info.saturation_power24;
	else
		saturation_power = priv->eeprom.calib_info.saturation_power52;

	if (saturation_power < IWL_TX_POWER_SATURATION_MIN ||
	    saturation_power > IWL_TX_POWER_SATURATION_MAX) {
		if (band)
			saturation_power = IWL_TX_POWER_DEFAULT_SATURATION_24;
		else
			saturation_power = IWL_TX_POWER_DEFAULT_SATURATION_52;
	}

	/* regulatory txpower limits ... reg_limit values are in half-dBm,
	 *   max_power_avg values are in dBm, convert * 2 */
	if (is_fat)
		reg_limit = ch_info->fat_max_power_avg * 2;
	else
		reg_limit = ch_info->max_power_avg * 2;

	if ((reg_limit < IWL_TX_POWER_REGULATORY_MIN) ||
	    (reg_limit > IWL_TX_POWER_REGULATORY_MAX)) {
		if (band)
			reg_limit = IWL_TX_POWER_DEFAULT_REGULATORY_24;
		else
			reg_limit = IWL_TX_POWER_DEFAULT_REGULATORY_52;
	}

	/* Interpolate txpower calibration values for this channel,
	 *   based on factory calibration tests on spaced channels. */
	iwl4965_interpolate_chan(priv, channel, &ch_eeprom_info);

	/* calculate tx gain adjustment based on power supply voltage */
	voltage = (s16)le16_to_cpu(priv->eeprom.calib_info.voltage);
	voltage_compensation =
	    iwl4965_get_voltage_compensation(voltage,
					     priv->card_alive_init.voltage);

	IWL_DEBUG_TXPOWER("curr volt %d eeprom volt %d volt comp %d\n",
			  priv->card_alive_init.voltage,
			  voltage, voltage_compensation);

	/* get current temperature (Celsius) */
	current_temp = max(priv->temperature, IWL_TX_POWER_TEMPERATURE_MIN);
	current_temp = min(priv->temperature, IWL_TX_POWER_TEMPERATURE_MAX);
	current_temp = KELVIN_TO_CELSIUS(current_temp);

	if (-40 > current_temp) {
		IWL_WARNING("Invalid temperature %d, can't calculate "
			    "txpower\n", current_temp);
		return -EINVAL;
	}

	/* select thermal txpower adjustment params, based on channel group
	 *   (same frequency group used for mimo txatten adjustment) */
	degrees_per_05db_num =
	    tx_power_cmp_tble[txatten_group].degrees_per_05db_a;
	degrees_per_05db_denom =
	    tx_power_cmp_tble[txatten_group].degrees_per_05db_a_denom;

	/* get per-chain txpower values from factory measurements */
	for (c = 0; c < 2; c++) {
		measurement = &ch_eeprom_info.measurements[c][1];

		/* txgain adjustment (in half-dB steps) based on difference
		 *   between factory and current temperature */
		factory_temp = measurement->temperature;
		iwl4965_math_div_round((current_temp - factory_temp) *
				       degrees_per_05db_denom,
				       degrees_per_05db_num,
				       &temperature_comp[c]);

		factory_gain_index[c] = measurement->gain_idx;
		factory_actual_pwr[c] = measurement->actual_pow;

		IWL_DEBUG_TXPOWER("chain = %d\n", c);
		IWL_DEBUG_TXPOWER("fctry tmp %d, "
				  "curr tmp %d, comp %d steps\n",
				  factory_temp, current_temp,
				  temperature_comp[c]);

		IWL_DEBUG_TXPOWER("fctry idx %d, fctry pwr %d\n",
				  factory_gain_index[c],
				  factory_actual_pwr[c]);
	}

	/* for each of 33 bit-rates (including 1 for CCK) */
	for (i = 0; i <= POWER_TABLE_NUM_HT_OFDM_ENTRIES; i++) {
		u8 is_mimo_rate;
		union tx_power_dual_stream_u *tx_power;

		/* for mimo, reduce each chain's txpower by half
		 * (3dB, 6 steps), so total output power is regulatory
		 * compliant. */
		if (i & 0x8) {
			current_regulatory = reg_limit -
			    IWL_TX_POWER_MIMO_REGULATORY_COMPENSATION;
			is_mimo_rate = 1;
		} else {
			current_regulatory = reg_limit;
			is_mimo_rate = 0;
		}

		/* find txpower limit, either hardware or regulatory */
		power_limit = saturation_power - back_off_table[i];
		if (power_limit > current_regulatory)
			power_limit = current_regulatory;

		/* reduce user's txpower request if necessary
		 * for this rate on this channel */
		target_power = user_target_power;
		if (target_power > power_limit)
			target_power = power_limit;

		IWL_DEBUG_TXPOWER("rate %d sat %d reg %d usr %d tgt %d\n",
				  i, saturation_power - back_off_table[i],
				  current_regulatory, user_target_power,
				  target_power);

		/* for each of 2 Tx chains (radio transmitters) */
		for (c = 0; c < 2; c++) {
			s32 atten_value;

			if (is_mimo_rate)
				atten_value =
				    priv->card_alive_init.
				    tx_atten[txatten_group][c];
			else
				atten_value = 0;

			/* calculate index; higher index means lower txpower */
			power_index = (u8) (factory_gain_index[c] -
					    (target_power -
					     factory_actual_pwr[c]) -
					    temperature_comp[c] -
					    voltage_compensation +
					    atten_value);

/*                      IWL_DEBUG_TXPOWER("calculated txpower index %d\n", */
/*                               power_index); */

			if (power_index < get_min_power_index(i, band))
				power_index = get_min_power_index(i, band);

			/* adjust 5 GHz index to support negative indexes */
			if (!band)
				power_index += 9;

			/* CCK, rate 32, reduce txpower for CCK */
			if (POWER_TABLE_NUM_HT_OFDM_ENTRIES == i) {
				power_index +=
				    IWL_TX_POWER_CCK_COMPENSATION_C_STEP;
				tx_power = &(cmd.tx_power.legacy_cck_power);
			}

			/* OFDM, rates 0-31 */
			else {
				tx_power = &(cmd.tx_power.ht_ofdm_power[i]);
			}

			/* stay within the table! */
			if (power_index > 107) {
				IWL_WARNING("txpower index %d > 107\n",
					    power_index);
				power_index = 107;
			}
			if (power_index < 0) {
				IWL_WARNING("txpower index %d < 0\n",
					    power_index);
				power_index = 0;
			}

			/* fill txpower command for this rate/chain */
			radio_gain = gain_table[band][power_index].radio;
			dsp_atten = gain_table[band][power_index].dsp;

			if (c == 0) {
				tx_power->s.ramon_tx_gain = radio_gain;
				tx_power->s.dsp_predis_atten = dsp_atten;
			} else {
				tx_power->s.ramon_tx_gain |= (radio_gain << 8);
				tx_power->s.dsp_predis_atten |=
				    (dsp_atten << 8);
			}

			IWL_DEBUG_TXPOWER("chain %d mimo %d index %d "
					  "gain 0x%02x dsp %d\n",
					  c, atten_value, power_index,
					  radio_gain, dsp_atten);

		}		/* for each chain */

	}			/* for each rate */

	rc = iwl_send_cmd_pdu(priv, REPLY_TX_PWR_TABLE_CMD, sizeof(cmd), &cmd);

	return rc;
}

#define RTS_HCCA_RETRY_LIMIT		3
#define RTS_DFAULT_RETRY_LIMIT		60

void iwl_hw_build_tx_cmd_rate(struct iwl_priv *priv,
			      struct iwl_cmd *cmd,
			      struct ieee80211_tx_control *ctrl,
			      struct ieee80211_hdr *hdr, int sta_id,
			      int is_hcca)
{
	unsigned long flags;
	int rate = ctrl->tx_rate;
	u8 rts_retry_limit = 0;
	u8 data_retry_limit = 0;
	u32 tx_flags;

	tx_flags = cmd->cmd.tx.tx_flags;

	rate = iwl_rates[ctrl->tx_rate].plcp;

	spin_lock_irqsave(&priv->sta_lock, flags);

	priv->stations[sta_id].current_rate.rate_n_flags = rate;

	if ((priv->iw_mode == IEEE80211_IF_TYPE_IBSS) &&
	    (sta_id != IWL_BROADCAST_ID) && (sta_id != IWL_MULTICAST_ID))
		priv->stations[IWL_STA_ID].current_rate.rate_n_flags = rate;

	spin_unlock_irqrestore(&priv->sta_lock, flags);

	rts_retry_limit = (is_hcca) ?
	    RTS_HCCA_RETRY_LIMIT : RTS_DFAULT_RETRY_LIMIT;

	if (ieee80211_is_probe_response(hdr->frame_control)) {
		data_retry_limit = 3;
		if (data_retry_limit < rts_retry_limit)
			rts_retry_limit = data_retry_limit;
	} else
		data_retry_limit = IWL_DEFAULT_TX_RETRY;

	if (priv->data_retry_limit != -1)
		data_retry_limit = priv->data_retry_limit;

	if (WLAN_FC_GET_TYPE(hdr->frame_control) == IEEE80211_FTYPE_MGMT) {
		switch (WLAN_FC_GET_STYPE(hdr->frame_control)) {
		case IEEE80211_STYPE_AUTH:
		case IEEE80211_STYPE_DEAUTH:
		case IEEE80211_STYPE_ASSOC_REQ:
		case IEEE80211_STYPE_REASSOC_REQ:
			if (tx_flags & TX_CMD_FLG_RTS_MSK) {
				tx_flags &= ~TX_CMD_FLG_RTS_MSK;
				tx_flags |= TX_CMD_FLG_CTS_MSK;
			}
			break;
		default:
			break;
		}
	}

	cmd->cmd.tx.rts_retry_limit = rts_retry_limit;
	cmd->cmd.tx.data_retry_limit = data_retry_limit;
	cmd->cmd.tx.rate.s.rate = rate;
	cmd->cmd.tx.tx_flags = tx_flags;
}

int iwl_hw_get_rx_read(struct iwl_priv *priv)
{
	struct iwl_shared *shared_data =
	    (struct iwl_shared *)priv->hw_setting.shared_virt;

	return IWL_GET_BITS(*shared_data, rb_closed_stts_rb_num);
}

int iwl_hw_get_temperature(struct iwl_priv *priv)
{
	return priv->temperature;
}

int iwl_hw_get_beacon_cmd(struct iwl_priv *priv,
			  struct iwl_frame *frame, u16 rate)
{
	struct iwl_tx_beacon_cmd *tx_beacon_cmd;
	int frame_size;

	if ((rate == IWL_RATE_1M_PLCP) || (rate >= IWL_RATE_2M_PLCP))
		rate |= RATE_MCS_CCK_MSK;

	tx_beacon_cmd = &frame->u.beacon;
	memset(tx_beacon_cmd, 0, sizeof(*tx_beacon_cmd));

	tx_beacon_cmd->tx.sta_id = IWL_BROADCAST_ID;
	tx_beacon_cmd->tx.stop_time.life_time = 0xFFFFFFFF;

	frame_size = iwl_fill_beacon_frame(priv,
				tx_beacon_cmd->frame,
				BROADCAST_ADDR,
				sizeof(frame->u) - sizeof(*tx_beacon_cmd));

	tx_beacon_cmd->tx.len = frame_size;

	tx_beacon_cmd->tx.rate.rate_n_flags = rate;
	tx_beacon_cmd->tx.tx_flags = (TX_CMD_FLG_SEQ_CTL_MSK |
				TX_CMD_FLG_TSF_MSK | TX_CMD_FLG_STA_RATE_MSK);
	return (sizeof(*tx_beacon_cmd) + frame_size);
}

int iwl_hw_tx_queue_init(struct iwl_priv *priv, struct iwl_tx_queue *txq)
{
	int rc;
	unsigned long flags;
	int txq_id = txq->q.id;

	spin_lock_irqsave(&priv->lock, flags);
	rc = iwl_grab_restricted_access(priv);
	if (rc) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return rc;
	}

	iwl_write_restricted(priv, FH_MEM_CBBC_QUEUE(txq_id),
			     txq->q.dma_addr >> 8);
	iwl_write_restricted(
		priv, IWL_FH_TCSR_CHNL_TX_CONFIG_REG(txq_id),
		IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CHNL_ENABLE |
		IWL_FH_TCSR_TX_CONFIG_REG_VAL_DMA_CREDIT_ENABLE_VAL);
	iwl_release_restricted_access(priv);
	spin_unlock_irqrestore(&priv->lock, flags);
	return 0;
}

static inline u32 iwl4965_get_dma_lo_address(dma_addr_t addr)
{
	return (u32) (addr & 0xffffffff);
}

static inline u8 iwl4965_get_dma_hi_address(dma_addr_t addr)
{
	return sizeof(addr) > sizeof(u32) ? (addr >> 16) >> 16 : 0;
}

int iwl_hw_tx_queue_attach_buffer_to_tfd(struct iwl_priv *priv,
					 void *ptr, dma_addr_t addr, u16 len)
{
	int index, is_odd;
	struct iwl_tfd_frame *tfd = ptr;
	u32 num_tbs = IWL_GET_BITS(*tfd, num_tbs);

	if ((num_tbs >= MAX_NUM_OF_TBS) || (num_tbs < 0)) {
		IWL_ERROR("Error can not send more than %d chunks\n",
			  MAX_NUM_OF_TBS);
		return -EINVAL;
	}

	index = num_tbs / 2;
	is_odd = num_tbs % 2;

	if (!is_odd) {
		tfd->pa[index].tb1_addr = cpu_to_le32(
			     iwl4965_get_dma_lo_address(addr));
		IWL_SET_BITS(tfd->pa[index], tb1_addr_hi,
			     iwl4965_get_dma_hi_address(addr));
		IWL_SET_BITS(tfd->pa[index], tb1_len, len);
	} else {
		IWL_SET_BITS(tfd->pa[index], tb2_addr_lo16,
			     (u32) (addr & 0xffff));
		IWL_SET_BITS(tfd->pa[index], tb2_addr_hi20, addr >> 16);
		IWL_SET_BITS(tfd->pa[index], tb2_len, len);
	}

	IWL_SET_BITS(*tfd, num_tbs, num_tbs + 1);

	return 0;
}

void iwl_hw_card_show_info(struct iwl_priv *priv)
{
	u16 hw_version = priv->eeprom.board_revision_4965;

	IWL_DEBUG_INFO("4965ABGN HW Version %u.%u.%u\n",
		       ((hw_version >> 8) & 0x0F),
		       ((hw_version >> 8) >> 4), (hw_version & 0x00FF));

	IWL_DEBUG_INFO("4965ABGN PBA Number %.16s\n",
		       priv->eeprom.board_pba_number_4965);
}

#define IWL_TX_CRC_SIZE		4
#define IWL_TX_DELIMITER_SIZE	4

int iwl4965_tx_queue_update_wr_ptr(struct iwl_priv *priv,
				   struct iwl_tx_queue *txq, u16 byte_cnt)
{
	int len;
	int txq_id = txq->q.id;
	struct iwl_shared *shared_data =
	    (struct iwl_shared *)priv->hw_setting.shared_virt;

	if (txq->need_update == 0)
		return 0;

	len = byte_cnt + IWL_TX_CRC_SIZE + IWL_TX_DELIMITER_SIZE;

	IWL_SET_BITS(shared_data->queues_byte_cnt_tbls[txq_id].
		     tfd_offset[txq->q.first_empty], byte_cnt, len);

	if (txq->q.first_empty < IWL4965_MAX_WIN_SIZE)
		IWL_SET_BITS(shared_data->queues_byte_cnt_tbls[txq_id].
			     tfd_offset[IWL4965_QUEUE_SIZE + txq->q.first_empty],
			     byte_cnt, len);

	return 0;
}

#define IWL4965_LEGACY_SWITCH_ANTENNA	0
#define IWL4965_LECACY_SWITCH_SISO		1
#define IWL4965_LEGACY_SWITCH_MIMO	        2

#define IWL4965_GOOD_RATIO			12800

#define IWL_ACTION_LIMIT		3
#define IWL4965_LEGACY_FAILURE_LIMIT	160
#define IWL4965_LEGACY_SUCCESS_LIMIT	480
#define IWL4965_LEGACY_TABLE_COUNT		160

#define IWL4965_NONE_LEGACY_FAILURE_LIMIT	400
#define IWL4965_NONE_LEGACY_SUCCESS_LIMIT	4500
#define IWL4965_NONE_LEGACY_TABLE_COUNT	1500

#define IWL4965_RATE_SCALE_SWITCH  (10880)

/* Set up Rx receiver/antenna/chain usage in "staging" RXON image.
 * This should not be used for scan command ... it puts data in wrong place.  */
void iwl4965_set_rxon_chain(struct iwl_priv *priv)
{
	u8 is_single = is_single_stream(priv);
	u8 idle_state, rx_state;

	priv->staging_rxon.rx_chain = 0;
	rx_state = idle_state = 3;

	/* Tell uCode which antennas are actually connected.
	 * Before first association, we assume all antennas are connected.
	 * Just after first association, iwl4965_noise_calibration()
	 *    checks which antennas actually *are* connected. */
	priv->staging_rxon.rx_chain |=
	    (priv->valid_antenna << RXON_RX_CHAIN_VALID_POS);

	/* How many receivers should we use? */
	iwl4965_get_rx_chain_counter(priv, &idle_state, &rx_state);
	priv->staging_rxon.rx_chain |= (rx_state << RXON_RX_CHAIN_MIMO_CNT_POS);
	priv->staging_rxon.rx_chain |= (idle_state << RXON_RX_CHAIN_CNT_POS);

	if (!is_single && !(priv->status & STATUS_POWER_PMI) && (rx_state >= 2))
		priv->staging_rxon.rx_chain |= RXON_RX_CHAIN_MIMO_FORCE_MSK;
	else
		priv->staging_rxon.rx_chain &= ~RXON_RX_CHAIN_MIMO_FORCE_MSK;

	IWL_DEBUG_ASSOC("rx chain %X\n", priv->staging_rxon.rx_chain);
}

int iwl4965_tx_cmd(struct iwl_priv *priv, struct iwl_cmd *out_cmd,
		   u8 sta_id, dma_addr_t txcmd_phys,
		   struct ieee80211_hdr *hdr, u8 hdr_len,
		   struct ieee80211_tx_control *ctrl, void *sta_in)
{
	struct iwl_tx_cmd cmd;
	struct iwl_tx_cmd *tx = (struct iwl_tx_cmd *)&out_cmd->cmd.payload[0];
	dma_addr_t scratch_phys;
	u8 unicast = 0;
	u8 is_data = 1;
	u16 fc;
	int rate_index = min(ctrl->tx_rate & 0xffff, IWL_RATE_COUNT - 1);

	unicast = !is_multicast_ether_addr(hdr->addr1);

	fc = le16_to_cpu(hdr->frame_control);
	if (WLAN_FC_GET_TYPE(fc) != IEEE80211_FTYPE_DATA)
		is_data = 0;

	memcpy(&cmd, &(out_cmd->cmd.tx), sizeof(struct iwl_tx_cmd));
	memset(tx, 0, sizeof(struct iwl_tx_cmd));
	memcpy(tx->hdr, hdr, hdr_len);

	tx->len = cmd.len;
	tx->driver_txop = cmd.driver_txop;
	tx->stop_time.life_time = cmd.stop_time.life_time;
	tx->tx_flags = cmd.tx_flags;
	tx->sta_id = cmd.sta_id;
	tx->tid_tspec = cmd.tid_tspec;
	tx->timeout.pm_frame_timeout = cmd.timeout.pm_frame_timeout;
	tx->next_frame_len = cmd.next_frame_len;

	tx->sec_ctl = cmd.sec_ctl;
	memcpy(&(tx->key[0]), &(cmd.key[0]), 16);
	tx->tx_flags = cmd.tx_flags;

	tx->rts_retry_limit = cmd.rts_retry_limit;
	tx->data_retry_limit = cmd.data_retry_limit;

	scratch_phys = txcmd_phys + sizeof(struct iwl_cmd_header) +
	    offsetof(struct iwl_tx_cmd, scratch);
	tx->dram_lsb_ptr = iwl4965_get_dma_lo_address(scratch_phys);
	tx->dram_msb_ptr = iwl4965_get_dma_hi_address(scratch_phys);

	/* Hard coded to start at the highest retry fallback position
	 * until the 4965 specific rate control algorithm is tied in */
	tx->initial_rate_index = LINK_QUAL_MAX_RETRY_NUM - 1;
	tx->rate.s.rate = iwl_rates[rate_index].plcp;

	/* Alternate between antenna A and B for successive frames */
	if (priv->use_ant_b_for_management_frame) {
		priv->use_ant_b_for_management_frame = 0;
		tx->rate.rate_n_flags |= RATE_MCS_ANT_B_MSK;
		tx->rate.rate_n_flags &= ~RATE_MCS_ANT_A_MSK;
	} else {
		priv->use_ant_b_for_management_frame = 1;
		tx->rate.rate_n_flags |= RATE_MCS_ANT_A_MSK;
		tx->rate.rate_n_flags &= ~RATE_MCS_ANT_B_MSK;
	}

	if (!unicast || !is_data ) {
		if ((rate_index >= IWL_FIRST_CCK_RATE) &&
		    (rate_index <= IWL_LAST_CCK_RATE))
			tx->rate.rate_n_flags |= RATE_MCS_CCK_MSK;

	} else {
		tx->initial_rate_index = 0;
		tx->tx_flags |= TX_CMD_FLG_STA_RATE_MSK;
	}

	if (ieee80211_is_probe_request(fc))
		tx->tx_flags |= TX_CMD_FLG_TSF_MSK;
	else if (ieee80211_is_back_request(fc))
		tx->tx_flags |= TX_CMD_FLG_ACK_MSK |
			TX_CMD_FLG_IMM_BA_RSP_MASK;

	return 0;
}

/**
 * iwl4965_sign_extend - Sign extend a value using specified bit as sign-bit
 *
 * Example: sign_extend(9, 3) would return -7 as bit3 of 1001b is 1
 * and bit0..2 is 001b which when sign extended to 1111111111111001b is -7.
 *
 * @param oper value to sign extend
 * @param index 0 based bit index (0<=index<32) to sign bit
 */
static s32 iwl4965_sign_extend(u32 oper, u8 index)
{
	u32 bit;
	u32 mask;

	/* If the index is the MSB or higher then just return the
	 * operand cast to a signed value */
	if (index > 30)
		return oper;

	bit = 1 << index;
	mask = ~(bit - 1);

	/* negative -- sign extend */
	if (oper & bit)
		return oper |= mask;

	/* positive -- sign clear */
	return oper &= ~mask;
}

/**
 * iwl4965_get_temperature - return the calibrated temperature (in Kelvin)
 * @statistics: Provides the temperature reading from the uCode
 *
 * A return of <0 indicates bogus data in the statistics
 */
int iwl4965_get_temperature(const struct iwl_priv *priv)
{
	s32 temperature;
	s32 vt;
	s32 R1, R2, R3, R4;

	if ((priv->status & STATUS_TEMPERATURE) &&
		(priv->statistics.flag & STATISTICS_REPLY_FLG_FAT_MODE_MSK)) {
		IWL_DEBUG_TEMP("Running FAT temperature calibration\n");
		R1 = priv->card_alive_init.therm_r1[1];
		R2 = priv->card_alive_init.therm_r2[1];
		R3 = priv->card_alive_init.therm_r3[1];
		R4 = priv->card_alive_init.therm_r4[1];
	} else {
		IWL_DEBUG_TEMP("Running temperature calibration\n");
		R1 = priv->card_alive_init.therm_r1[0];
		R2 = priv->card_alive_init.therm_r2[0];
		R3 = priv->card_alive_init.therm_r3[0];
		R4 = priv->card_alive_init.therm_r4[0];
	}

	/*
	 * Temperature is only 23 bits so sign extend out to 32
	 *
	 * NOTE If we haven't received a statistics notification yet
	 * with an updated temperature, use R4 provided to us in the
	 * ALIVE response. */
	if (!(priv->status & STATUS_TEMPERATURE))
		vt = iwl4965_sign_extend(R4, 23);
	else
		vt = iwl4965_sign_extend(priv->statistics.general.temperature,
					 23);

	IWL_DEBUG_TEMP("Calib values R[1-3]: %d %d %d R4: %d\n",
		       R1, R2, R3, vt);

	if (R3 == R1) {
		IWL_ERROR("Calibration conflict R1 == R3\n");
		return -1;
	}

	/* Calculate temperature in degrees Kelvin, adjust by 97%.
	 * Add offset to center the adjustment around 0 degrees Centigrade. */
	temperature = TEMPERATURE_CALIB_A_VAL * (vt - R2);
	temperature /= (R3 - R1);
	temperature = (temperature * 97) / 100 +
	    TEMPERATURE_CALIB_KELVIN_OFFSET;

	IWL_DEBUG_TEMP("Calibrated temperature: %dK, %dC\n", temperature,
	    KELVIN_TO_CELSIUS(temperature));

	return temperature;
}

/* Adjust Txpower only if temperature variance is greater than threshold. */
#define IWL_TEMPERATURE_THRESHOLD   3

/**
 * iwl4965_is_temp_calib_needed - determines if new calibration is needed
 *
 * If the temperature changed has changed sufficiently, then a recalibration
 * is needed.
 *
 * Assumes caller will replace priv->last_temperature once calibration
 * executed.
 */
static int iwl4965_is_temp_calib_needed(struct iwl_priv *priv)
{
	int temp_diff;

	if (!(priv->status & STATUS_STATISTICS)) {
		IWL_DEBUG_TEMP("Temperature not updated -- no statistics.\n");
		return 0;
	}

	temp_diff = priv->temperature - priv->last_temperature;

	/* get absolute value */
	if (temp_diff < 0) {
		IWL_DEBUG_POWER("Getting cooler, delta %d, \n", temp_diff);
		temp_diff = -temp_diff;
	} else if (temp_diff == 0)
		IWL_DEBUG_POWER("Same temp, \n");
	else
		IWL_DEBUG_POWER("Getting warmer, delta %d, \n", temp_diff);

	if (temp_diff < IWL_TEMPERATURE_THRESHOLD) {
		IWL_DEBUG_POWER("Thermal txpower calib not needed\n");
		return 0;
	}

	IWL_DEBUG_POWER("Thermal txpower calib needed\n");

	return 1;
}

void iwl_hw_rx_statistics(struct iwl_priv *priv, struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (void *)rxb->skb->data;
	int change;
	s32 temp;

	IWL_DEBUG_RX("Statistics notification received (%d vs %d).\n",
		     (int)sizeof(priv->statistics), pkt->len);

	change = ((priv->statistics.general.temperature !=
		   pkt->u.stats.general.temperature) ||
		  ((priv->statistics.flag &
		    STATISTICS_REPLY_FLG_FAT_MODE_MSK) !=
		   (pkt->u.stats.flag & STATISTICS_REPLY_FLG_FAT_MODE_MSK)));

	memcpy(&priv->statistics, &pkt->u.stats, sizeof(priv->statistics));

	priv->status |= STATUS_STATISTICS;

	/* Reschedule the statistics timer to occur in
	 * REG_RECALIB_PERIOD seconds to ensure we get a
	 * thermal update even if the uCode doesn't give
	 * us one */
	mod_timer(&priv->statistics_periodic, jiffies +
		  msecs_to_jiffies(REG_RECALIB_PERIOD * 1000));

#ifdef CONFIG_IWLWIFI_SENSITIVITY
	if (unlikely(!(priv->status & STATUS_SCANNING)) &&
	    (pkt->hdr.cmd == STATISTICS_NOTIFICATION))
		queue_work(priv->workqueue, &priv->sensitivity_work);
#endif
	/* If the hardware hasn't reported a change in
	 * temperature then don't bother computing a
	 * calibrated temperature value */
	if (!change)
		return;

	temp = iwl4965_get_temperature(priv);
	if (temp < 0)
		return;

	if (priv->temperature != temp) {
		if (priv->temperature)
			IWL_DEBUG_TEMP("Temperature changed "
				       "from %dC to %dC\n",
				       KELVIN_TO_CELSIUS(priv->temperature),
				       KELVIN_TO_CELSIUS(temp));
		else
			IWL_DEBUG_TEMP("Temperature "
				       "initialized to %dC\n",
				       KELVIN_TO_CELSIUS(temp));
	}

	priv->temperature = temp;
	priv->status |= STATUS_TEMPERATURE;

	if (unlikely(!(priv->status & STATUS_SCANNING) &&
		     iwl4965_is_temp_calib_needed(priv)))
		queue_work(priv->workqueue, &priv->txpower_work);
}

static void iwl4965_handle_data_packet(struct iwl_priv *priv, int is_data,
				       int include_phy,
				       struct iwl_rx_mem_buffer *rxb,
				       struct ieee80211_rx_status *stats)
{
	struct iwl_rx_packet *pkt = (struct iwl_rx_packet *)rxb->skb->data;
	struct iwl4965_rx_phy_res *rx_start = (include_phy) ?
	    (struct iwl4965_rx_phy_res *)&(pkt->u.raw[0]) : NULL;
	struct ieee80211_hdr *hdr;
	unsigned int len;
	u32 *rx_end;
	unsigned int skblen;
	u32 ampd_status;

	if (!include_phy && priv->last_phy_res[0])
		rx_start = (struct iwl4965_rx_phy_res *)&priv->last_phy_res[1];

	if (!rx_start) {
		IWL_ERROR("MPDU frame without a PHY data\n");
		return;
	}
	if (include_phy) {
		hdr = (struct ieee80211_hdr *)((u8 *) & rx_start[1] +
					       rx_start->cfg_phy_cnt);

		len = rx_start->byte_count;

		rx_end = (u32 *) ((u8 *) & pkt->u.raw[0] +
				  sizeof(struct iwl4965_rx_phy_res) +
				  rx_start->cfg_phy_cnt + len);

	} else {
		struct iwl4965_rx_mpdu_res_start *amsdu =
		    (struct iwl4965_rx_mpdu_res_start *)pkt->u.raw;

		hdr = (void *)(pkt->u.raw +
			       sizeof(struct iwl4965_rx_mpdu_res_start));
		rx_end = (u32 *) (((u8 *) hdr) + amsdu->byte_count);
		len = amsdu->byte_count;
		rx_start->byte_count = len;
	}
	if (len > 2342 || len < 16) {
		IWL_DEBUG_DROP("byte count out of range [16,2342]"
			       " : %d\n", len);
		return;

	}

	ampd_status = *rx_end;
	skblen = ((u8 *) rx_end - (u8 *) & pkt->u.raw[0]) + sizeof(u32);

	/* start from MAC */
	skb_reserve(rxb->skb, (void *)hdr - (void *)pkt);
	skb_put(rxb->skb, len);	/* end where data ends */

	/* We only process data packets if the interface is open */
	if (unlikely(!priv->is_open)) {
		IWL_DEBUG_DROP
		    ("Dropping packet while interface is not open.\n");
		return;
	}

	if (priv->iw_mode == IEEE80211_IF_TYPE_MNTR) {
		if (param_hwcrypto)
			iwl_set_decrypted_flag(priv, rxb->skb,
					       ampd_status, stats);
		iwl_handle_data_packet_monitor(priv, rxb, hdr, len, stats, 0);
		return;
	}

	stats->flag = 0;
	hdr = (struct ieee80211_hdr *)rxb->skb->data;

	if (param_hwcrypto)
		iwl_set_decrypted_flag(priv, rxb->skb, ampd_status, stats);

	ieee80211_rx_irqsafe(priv->hw, rxb->skb, stats);
	priv->alloc_rxb_skb--;
	rxb->skb = NULL;
#ifdef LED
	priv->led_packets += len;
	iwl_setup_activity_timer(priv);
#endif
}

/* Calc max signal level (dBm) among 3 possible receivers */
static int iwl4965_calc_rssi(struct iwl4965_rx_phy_res *rx_resp)
{
	/* data from PHY/DSP regarding signal strength, etc.,
	 *   contents are always there, not configurable by host.  */
	struct iwl4965_rx_non_cfg_phy *ncphy =
	    (struct iwl4965_rx_non_cfg_phy *)rx_resp->non_cfg_phy;
	u32 agc = (ncphy->agc_info & IWL_AGC_DB_MASK) >> IWL_AGC_DB_POS;

	u32 valid_antennae =
	    (rx_resp->phy_flags & RX_PHY_FLAGS_ANTENNAE_MASK) >>
	    RX_PHY_FLAGS_ANTENNAE_OFFSET;
	u8 max_rssi = 0;
	u32 i;

	/* Find max rssi among 3 possible receivers.
	 * These values are measured by the digital signal processor (DSP).
	 * They should stay fairly constant even as the signal strength varies,
	 *   if the radio's automatic gain control (AGC) is working right.
	 * AGC value (see below) will provide the "interesting" info. */
	for (i = 0; i < 3; i++)
		if (valid_antennae & (1 << i))
			max_rssi = max(ncphy->rssi_info[i << 1], max_rssi);

	IWL_DEBUG_STATS("Rssi In A %d B %d C %d Max %d AGC dB %d\n",
		ncphy->rssi_info[0], ncphy->rssi_info[2], ncphy->rssi_info[4],
		max_rssi, agc);

	/* dBm = max_rssi dB - agc dB - constant.
	 * Higher AGC (higher radio gain) means lower signal. */
	return (max_rssi - agc - IWL_RSSI_OFFSET);
}

#ifdef CONFIG_IWLWIFI_HT

/* Parsed Information Elements */
struct ieee802_11_elems {
	u8 *ds_params;
	u8 ds_params_len;
	u8 *tim;
	u8 tim_len;
	u8 *ibss_params;
	u8 ibss_params_len;
	u8 *erp_info;
	u8 erp_info_len;
	u8 *ht_cap_param;
	u8 ht_cap_param_len;
	u8 *ht_extra_param;
	u8 ht_extra_param_len;
};

static int parse_elems(u8 * start, size_t len, struct ieee802_11_elems *elems)
{
	size_t left = len;
	u8 *pos = start;
	int unknown = 0;

	memset(elems, 0, sizeof(*elems));

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		left -= 2;

		if (elen > left)
			return -1;

		switch (id) {
		case WLAN_EID_DS_PARAMS:
			elems->ds_params = pos;
			elems->ds_params_len = elen;
			break;
		case WLAN_EID_TIM:
			elems->tim = pos;
			elems->tim_len = elen;
			break;
		case WLAN_EID_IBSS_PARAMS:
			elems->ibss_params = pos;
			elems->ibss_params_len = elen;
			break;
		case WLAN_EID_ERP_INFO:
			elems->erp_info = pos;
			elems->erp_info_len = elen;
			break;
		case WLAN_EID_HT_CAPABILITY:
			elems->ht_cap_param = pos;
			elems->ht_cap_param_len = elen;
			break;
		case WLAN_EID_HT_EXTRA_INFO:
			elems->ht_extra_param = pos;
			elems->ht_extra_param_len = elen;
			break;
		default:
			unknown++;
			break;
		}

		left -= elen;
		pos += elen;
	}

	return 0;
}
#endif /* CONFIG_IWLWIFI_HT */

static void iwl4965_sta_modify_ps_wake(struct iwl_priv *priv, int sta_id)
{
	unsigned long lock_flags;
	spin_lock_irqsave(&priv->sta_lock, lock_flags);
	priv->stations[sta_id].sta.station_flags &= ~STA_FLG_PWR_SAVE_MSK;
	priv->stations[sta_id].sta.station_flags_msk = STA_FLG_PWR_SAVE_MSK;
	priv->stations[sta_id].sta.sta.modify_mask = 0;
	priv->stations[sta_id].sta.mode |= STA_CONTROL_MODIFY_MSK;
	spin_unlock_irqrestore(&priv->sta_lock, lock_flags);
	/* assuming we are in rx flow and the lock is already locked */
	iwl_send_add_station(priv, &priv->stations[sta_id].sta,
			     CMD_ASYNC | CMD_NO_LOCK);
}

/* Called for REPLY_4965_RX (legacy ABG frames), or
 * REPLY_RX_MPDU_CMD (HT high-throughput N frames). */
static void iwl4965_rx_reply_rx(struct iwl_priv *priv,
				struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (void *)rxb->skb->data;

	/* Use phy data (Rx signal strength, etc.) contained within
	 *   this rx packet for legacy frames,
	 *   or phy data cached from REPLY_RX_PHY_CMD for HT frames. */
	int include_phy = (pkt->hdr.cmd == REPLY_4965_RX);
	struct iwl4965_rx_phy_res *rx_start = (include_phy) ?
		(struct iwl4965_rx_phy_res *)&(pkt->u.raw[0]) :
		(struct iwl4965_rx_phy_res *)&priv->last_phy_res[1];

	u32 *rx_end;
	unsigned int len = 0;
	struct ieee80211_hdr *header;
	u16 fc;
	struct ieee80211_rx_status stats = {
		.mactime = rx_start->beacon_time_stamp,
		.freq = ieee80211chan2mhz(le16_to_cpu(rx_start->channel)),
		.channel = rx_start->channel,
		.phymode =
			(rx_start->phy_flags & RX_RES_PHY_FLAGS_BAND_24_MSK) ?
			MODE_IEEE80211G : MODE_IEEE80211A,
		.antenna = 0,
		.rate = rx_start->rate.s.rate,
		.flag = rx_start->phy_flags,
	};
	u8 network_packet;

	if ((unlikely(rx_start->cfg_phy_cnt > 20))) {
		IWL_DEBUG_DROP
			("dsp size out of range [0,20]: "
			 "%d/n", rx_start->cfg_phy_cnt);
		return;
	}
	if (!include_phy) {
		if (priv->last_phy_res[0])
			rx_start = (struct iwl4965_rx_phy_res *)
				&priv->last_phy_res[1];
		else
			rx_start = NULL;
	}

	if (!rx_start) {
		IWL_ERROR("MPDU frame without a PHY data\n");
		return;
	}

	if (include_phy) {
		header = (struct ieee80211_hdr *)((u8 *) & rx_start[1]
						  + rx_start->cfg_phy_cnt);

		len = rx_start->byte_count;
		rx_end = (u32 *) (pkt->u.raw + rx_start->cfg_phy_cnt +
				  sizeof(struct iwl4965_rx_phy_res) +
				  rx_start->byte_count);
	} else {
		struct iwl4965_rx_mpdu_res_start *amsdu =
			(struct iwl4965_rx_mpdu_res_start *)pkt->u.raw;

		header = (void *)(pkt->u.raw +
				  sizeof(struct iwl4965_rx_mpdu_res_start));
		len = amsdu->byte_count;
		rx_end =
			(u32 *) (pkt->u.raw +
				 sizeof(struct iwl4965_rx_mpdu_res_start) +
				 amsdu->byte_count);
	}

	if (!(*rx_end & RX_RES_STATUS_NO_CRC32_ERROR) ||
	    !(*rx_end & RX_RES_STATUS_NO_RXE_OVERFLOW)) {
		IWL_DEBUG_RX("Bad CRC or FIFO: 0x%08X.\n", *rx_end);
		return;
	}

	stats.freq = ieee80211chan2mhz((stats.channel));
	stats.flag = 0;

	/* Find max signal strength (dBm) among 3 antenna/receiver chains */
	stats.ssi = iwl4965_calc_rssi(rx_start);

	IWL_DEBUG_RX("Rssi %d, TSF %lu\n", stats.ssi,
		 (long unsigned int)le64_to_cpu(rx_start->timestamp));

	/* Sensitivity algo, if used (only while associated, not scanning),
	 * calculates signal-to-noise ratio in dB.  Use this if available,
	 * else calculate signal quality using only the signal strength. */
	if (priv->last_rx_snr && iwl_is_associated(priv) &&
			!(priv->status & STATUS_SCANNING)) {
		/* TODO:  Find better noise level reference, use
		 *        in iwl_calc_sig_qual() */
		stats.noise = stats.ssi - priv->last_rx_snr;
		stats.signal = iwl_calc_sig_qual(stats.ssi, 0);
	} else {
		stats.signal = iwl_calc_sig_qual(stats.ssi, 0);

		/* Reset noise values if not associated or snr not available. */
		/* Set default noise value to -127 ... this works better than
		 *   0 when averaging frames with/without noise info;
		 *   measured dBm values are always negative ... using a
		 *   negative value as the default keeps all averages
		 *   within an s8's (used in some apps) range of negative
		 *   values. */
		priv->last_rx_snr = 0;
		priv->last_rx_noise = -127;
		stats.noise = -127;
	}
	IWL_DEBUG_STATS("Rssi %d noise %d qual %d snr db %d\n", stats.ssi,
			stats.noise, stats.signal, priv->last_rx_snr);

#ifdef CONFIG_IWLWIFI_DEBUG
	/* TODO:  Parts of iwl_report_frame are broken for 4965 */
	if (iwl_debug_level & (IWL_DL_RX))
		/* Set "1" to report good data frames in groups of 100 */
		iwl_report_frame(priv, pkt, header, 1);
#endif

	network_packet = iwl_is_network_packet(priv, header);
	if (network_packet) {
		priv->last_rx_rssi = stats.ssi;
		priv->last_rx_noise = stats.noise;
		priv->last_beacon_time = rx_start->beacon_time_stamp;
		priv->last_tsf = rx_start->timestamp;
	}

	fc = le16_to_cpu(header->frame_control);
	switch (WLAN_FC_GET_TYPE(fc)) {
	case IEEE80211_FTYPE_MGMT:
		switch (WLAN_FC_GET_STYPE(fc)) {
		case IEEE80211_STYPE_PROBE_RESP:
		case IEEE80211_STYPE_BEACON:
			if ((priv->iw_mode == IEEE80211_IF_TYPE_STA &&
			     !compare_ether_addr(header->addr2, priv->bssid)) ||
			    (priv->iw_mode == IEEE80211_IF_TYPE_IBSS &&
			     !compare_ether_addr(header->addr3, priv->bssid))) {
				struct ieee80211_mgmt *mgmt =
					(struct ieee80211_mgmt *)header;
				u32 *pos;

				pos = (u32 *) & mgmt->u.beacon.timestamp;
				priv->timestamp0 = le32_to_cpu(pos[0]);
				priv->timestamp1 = le32_to_cpu(pos[1]);
				priv->beacon_int = le16_to_cpu(
				    mgmt->u.beacon.beacon_int);
				if (priv->call_post_assoc_from_beacon &&
				    (priv->iw_mode == IEEE80211_IF_TYPE_STA)) {
					priv->call_post_assoc_from_beacon = 0;
					queue_work(priv->workqueue,
					    &priv->post_associate);
				}
			}
			break;

		case IEEE80211_STYPE_ACTION:
			break;

			/*
			 * TODO: There is no callback function from upper
			 * stack to inform us when associated status. this
			 * work around to sniff assoc_resp management frame
			 * and finish the association process.
			 */
		case IEEE80211_STYPE_ASSOC_RESP:
		case IEEE80211_STYPE_REASSOC_RESP:
			if (network_packet && iwl_is_associated(priv)) {
#ifdef CONFIG_IWLWIFI_HT
				u8 *pos = NULL;
				struct ieee802_11_elems elems;
#endif				/*CONFIG_IWLWIFI_HT */
				struct ieee80211_mgmt *mgnt =
					(struct ieee80211_mgmt *)header;

				priv->assoc_id = (~((1 << 15) | (1 << 14))
						  & mgnt->u.assoc_resp.aid);
				priv->assoc_capability =
					le16_to_cpu(
						mgnt->u.assoc_resp.capab_info);
#ifdef CONFIG_IWLWIFI_HT
				pos = mgnt->u.assoc_resp.variable;
				if (!parse_elems(pos,
						 len - (pos - (u8 *) mgnt),
						 &elems)) {
					if (elems.ht_extra_param &&
					    elems.ht_cap_param)
						break;
				}
#endif				/*CONFIG_IWLWIFI_HT */
				/* assoc_id is 0 no association */
				if (!priv->assoc_id)
					break;
				if (priv->beacon_int)
					queue_work(priv->workqueue,
					    &priv->post_associate);
				else
					priv->call_post_assoc_from_beacon = 1;
			}

			break;

		case IEEE80211_STYPE_PROBE_REQ:
			if ((priv->iw_mode == IEEE80211_IF_TYPE_IBSS) &&
			    !iwl_is_associated(priv)) {
				IWL_DEBUG_DROP("Dropping (non network): "
					       MAC_FMT ", " MAC_FMT ", "
					       MAC_FMT "\n",
					       MAC_ARG(header->addr1),
					       MAC_ARG(header->addr2),
					       MAC_ARG(header->addr3));
				return;
			}
		}
		iwl4965_handle_data_packet(priv, 0, include_phy, rxb, &stats);
		break;

	case IEEE80211_FTYPE_CTL:
		break;

	case IEEE80211_FTYPE_DATA:
		/* FIXME - patch for PS in AP mode */
		if (priv->iw_mode == IEEE80211_IF_TYPE_AP) {
			u8 sta_id = iwl_hw_find_station(priv, header->addr2);
			u8 sta_awake;
			u16 ps_bit;

			if (sta_id == IWL_INVALID_STATION)
				break;

			sta_awake = (priv->stations[sta_id].ps_status ==
				     STA_PS_STATUS_WAKE);
			ps_bit = (header->frame_control  &
				  cpu_to_le16(IEEE80211_FCTL_PM));
			if (sta_awake && ps_bit) {
				priv->stations[sta_id].ps_status =
					STA_PS_STATUS_SLEEP;
			} else if (!sta_awake && !ps_bit) {
				iwl4965_sta_modify_ps_wake(priv, sta_id);
				priv->stations[sta_id].ps_status =
						STA_PS_STATUS_WAKE;
			}
		}

		if (unlikely(!network_packet))
			IWL_DEBUG_DROP("Dropping (non network): "
				       MAC_FMT ", " MAC_FMT ", "
				       MAC_FMT "\n",
				       MAC_ARG(header->addr1),
				       MAC_ARG(header->addr2),
				       MAC_ARG(header->addr3));
		else if (unlikely(is_duplicate_packet(priv, header)))
			IWL_DEBUG_DROP("Dropping (dup): " MAC_FMT ", "
				       MAC_FMT ", " MAC_FMT "\n",
				       MAC_ARG(header->addr1),
				       MAC_ARG(header->addr2),
				       MAC_ARG(header->addr3));
		else
			iwl4965_handle_data_packet(priv, 1, include_phy, rxb,
						   &stats);
		break;
	default:
		break;

	}
}

/* Cache phy data (Rx signal strength, etc) for HT frame (REPLY_RX_PHY_CMD).
 * This will be used later in iwl4965_rx_reply_rx() for REPLY_RX_MPDU_CMD. */
static void iwl4965_rx_reply_rx_phy(struct iwl_priv *priv,
				    struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (void *)rxb->skb->data;
	priv->last_phy_res[0] = 1;
	memcpy(&priv->last_phy_res[1], &(pkt->u.raw[0]),
	       sizeof(struct iwl4965_rx_phy_res));
}

static void iwl4965_rx_missed_beacon_notif (struct iwl_priv *priv,
					   struct iwl_rx_mem_buffer *rxb)

{
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	struct iwl_rx_packet *pkt = (void *)rxb->skb->data;
	struct iwl_missed_beacon_notif *missed_beacon;

	missed_beacon = &pkt->u.missed_beacon;
	if (missed_beacon->consequtive_missed_beacons > 5) {
		IWL_DEBUG_CALIB("missed bcn cnsq %d totl %d rcd %d expctd %d\n",
			    missed_beacon->consequtive_missed_beacons,
			    missed_beacon->total_missed_becons,
			    missed_beacon->num_recvd_beacons,
			    missed_beacon->num_expected_beacons);
		priv->sensitivity_data.state = IWL_SENS_CALIB_NEED_REINIT;
		if (unlikely(!(priv->status & STATUS_SCANNING)))
			queue_work(priv->workqueue, &priv->sensitivity_work);
	}
#endif /*CONFIG_IWLWIFI_SENSITIVITY*/
}

#ifdef CONFIG_IWLWIFI_HT_AGG

static void iwl4965_rx_reply_compressed_ba(struct iwl_priv *priv,
					   struct iwl_rx_mem_buffer *rxb)
{
	struct iwl_rx_packet *pkt = (void *)rxb->skb->data;
	struct iwl_compressed_ba_resp *compressed_ba = &pkt->u.compressed_ba;
	int index = iwl_queue_dec_wrap(compressed_ba->scd_ssn & 0xff, 0xff);
	struct iwl_tx_queue *txq = NULL;

	BUG_ON(compressed_ba->scd_flow >= ARRAY_SIZE(priv->txq));
	txq = &priv->txq[compressed_ba->scd_flow];

	/* TODO: Need to get this copy more sefely - now good for debug */
	IWL_DEBUG_TX_REPLY("REPLY_COMPRESSED_BA Received from " MAC_FMT
			   " , sta_id = %d\n",
			   MAC_ARG((u8 *) & compressed_ba->sta_addr_lo32),
			   compressed_ba->sta_id);
	IWL_DEBUG_TX_REPLY
	    ("TID = %d, seq_ctl = %d, bitmap = 0x%x%x, scd_flow = %d, "
	     "scd_ssn = %d\n",
	     compressed_ba->tid, compressed_ba->ba_seq_ctl,
	     compressed_ba->ba_bitmap0, compressed_ba->ba_bitmap1,
	     compressed_ba->scd_flow, compressed_ba->scd_ssn);

	/* releases all the TFDs until the SSN */
	if (txq->q.last_used != (compressed_ba->scd_ssn & 0xff))
		iwl_tx_queue_reclaim(priv, compressed_ba->scd_flow, index);

}
#endif	/* CONFIG_IWLWIFI_HT_AGG */

/*
 * RATE SCALE CODE
 */
int iwl4965_init_hw_rates(struct iwl_priv *priv, struct ieee80211_rate *rates)
{
	return 0;
}


/**
 * iwl4965_add_station - Initialize a station's hardware rate table
 *
 * The uCode contains a table of fallback rates and retries per rate
 * for automatic fallback during transmission.
 *
 * NOTE: This initializes the table for a single retry per data rate
 * which is not optimal.  Setting up an intelligent retry per rate
 * requires feedback from transmission, which isn't exposed through
 * rc80211_simple which is what this driver is currently using.
 *
 */
void iwl4965_add_station(struct iwl_priv *priv, const u8 * addr, int is_ap)
{
	int i, r;
	struct iwl_link_quality_cmd link_cmd = {
		.reserved1 = 0,
	};
	struct iwl_rate *table = link_cmd.rate_scale_table;

	/* Set up the rate scaling to start at 54M and fallback
	 * all the way to 1M in IEEE order and then spin on IEEE */
	i = 0;
	if (is_ap)
		r = IWL_RATE_54M_INDEX;
	else if ((priv->phymode == MODE_IEEE80211A) ||
		 (priv->phymode == MODE_ATHEROS_TURBO))
		r = IWL_RATE_6M_INDEX;
	else
		r = IWL_RATE_1M_INDEX;

	while (i < LINK_QUAL_MAX_RETRY_NUM) {
		if (r >= IWL_FIRST_CCK_RATE && r <= IWL_LAST_CCK_RATE) {
			table[i].rate_n_flags |= RATE_MCS_CCK_MSK;
		}
		table[i].s.rate = iwl_rates[r].plcp;
		table[i].rate_n_flags |= RATE_MCS_ANT_B_MSK;
		table[i].rate_n_flags &= ~RATE_MCS_ANT_A_MSK;
		r = iwl_get_prev_ieee_rate(r);
		i++;
	}

	link_cmd.general_params.single_stream_ant_msk = 2;
	link_cmd.general_params.dual_stream_ant_msk = 3;
	link_cmd.agg_params.agg_dis_start_th = 3;
	link_cmd.agg_params.agg_time_limit = 4000;

	/* Update the rate scaling for control frame Tx to AP */
	link_cmd.sta_id = is_ap ? IWL_AP_ID : IWL_BROADCAST_ID;

	iwl_send_cmd_pdu(priv, REPLY_TX_LINK_QUALITY_CMD, sizeof(link_cmd),
			 &link_cmd);
}

#ifdef CONFIG_IWLWIFI_HT

static u8 iwl_is_channel_extension(struct iwl_priv *priv, int phymode,
				   int channel, u8 extension_chan_offset)
{
	const struct iwl_channel_info *ch_info;

	ch_info = iwl_get_channel_info(priv, phymode, channel);
	if (!is_channel_valid(ch_info))
		return 0;

	if (extension_chan_offset == IWL_EXT_CHANNEL_OFFSET_AUTO)
		return 0;

	if ((ch_info->fat_extension_channel == extension_chan_offset) ||
	    (ch_info->fat_extension_channel == HT_IE_EXT_CHANNEL_MAX))
		return 1;

	return 0;
}

static u8 iwl_is_fat_tx_allowed(struct iwl_priv *priv,
				const struct sta_ht_info *ht_info)
{

	if (priv->channel_width != IWL_CHANNEL_WIDTH_40MHZ)
		return 0;

	if (ht_info->supported_chan_width != IWL_CHANNEL_WIDTH_40MHZ)
		return 0;

	if (ht_info->extension_chan_offset == IWL_EXT_CHANNEL_OFFSET_AUTO)
		return 0;

	/* no fat tx allowed on 2.4GHZ */
	if ((priv->phymode != MODE_IEEE80211A) &&
	    (priv->phymode != MODE_ATHEROS_TURBO))
		return 0;
	return (iwl_is_channel_extension(priv, priv->phymode,
					 ht_info->control_chan,
					 ht_info->extension_chan_offset));
}

void iwl4965_set_rxon_ht(struct iwl_priv *priv,
			 struct sta_ht_info *ht_info)
{
	struct iwl_rxon_cmd *rxon = &priv->staging_rxon;
	u32 val;

	if (!ht_info->is_ht)
		return;

	if (iwl_is_fat_tx_allowed(priv, ht_info))
		rxon->flags |= RXON_FLG_CHANNEL_MODE_MIXED_MSK;
	else
		rxon->flags |= RXON_FLG_CHANNEL_MODE_LEGACY_MSK;

	if (rxon->channel != ht_info->control_chan) {
		IWL_DEBUG_ASSOC("control diff than current %d %d\n",
				rxon->channel, ht_info->control_chan);
		rxon->channel = ht_info->control_chan;
		return;
	}

	rxon->flags &= ~RXON_FLG_CONTROL_CHANNEL_LOCATION_MSK;

	switch (ht_info->extension_chan_offset) {
	case IWL_EXT_CHANNEL_OFFSET_ABOVE:
		rxon->flags |= RXON_FLG_CONTROL_CHANNEL_LOC_LOW_MSK;
		break;
	case IWL_EXT_CHANNEL_OFFSET_BELOW:
		rxon->flags |= RXON_FLG_CONTROL_CHANNEL_LOC_HIGH_MSK;
		break;
	case IWL_EXT_CHANNEL_OFFSET_AUTO:
		rxon->flags &= ~RXON_FLG_CHANNEL_MODE_MIXED_MSK;
		break;
	default:
		break;
	}

	val = ht_info->operating_mode;

	rxon->flags |= val << RXON_FLG_HT_OPERATING_MODE_POS;

	priv->active_rate_ht[0] = ht_info->supp_rates[0];
	priv->active_rate_ht[1] = ht_info->supp_rates[1];
	iwl4965_set_rxon_chain(priv);

	IWL_DEBUG_ASSOC("supported HT rate 0x%X %X "
			"falgs 0x%X operation 0x%X\n",
			priv->active_rate_ht[0], priv->active_rate_ht[1],
			rxon->flags, ht_info->operating_mode);
	return;
}
void iwl4965_set_ht_add_station(struct iwl_priv *priv,
				u8 index, u8 need_to_lock)
{
	u32 val;
	u32 sta_rate;
	u32 sta_flag;
	unsigned long flags = 0;
	u8 i = index;
	struct sta_ht_info *ht_info = &priv->current_assoc_ht;

	if (need_to_lock)
		spin_lock_irqsave(&priv->sta_lock, flags);

	priv->current_channel_width = IWL_CHANNEL_WIDTH_20MHZ;
	if (!ht_info->is_ht)
		goto done;

	sta_rate = priv->stations[i].sta.tx_rate.rate_n_flags;
	sta_flag = priv->stations[i].sta.station_flags;

	if (ht_info->tx_mimo_ps_mode == IWL_MIMO_PS_DYNAMIC)
		sta_flag |= STA_FLG_RTS_MIMO_PROT_MSK;
	else
		sta_flag &= ~STA_FLG_RTS_MIMO_PROT_MSK;

	val = (u32) ht_info->ampdu_factor;
	sta_flag |= val << STA_FLG_MAX_AGG_SIZE_POS;

	val = (u32) ht_info->mpdu_density;
	sta_flag |= val << STA_FLG_AGG_MPDU_DENSITY_POS;

	if ((ht_info->sgf & HT_SHORT_GI_20MHZ_ONLY) &&
	    (ht_info->sgf & HT_SHORT_GI_40MHZ_ONLY)) {
		val = 1;
		sta_rate |= ((val << RATE_MCS_SGI_POS) & RATE_MCS_SGI_MSK);
	}

	val = ht_info->is_green_field;
	sta_rate |= ((val << RATE_MCS_GF_POS) & RATE_MCS_GF_MSK);

	sta_rate &= (~RATE_MCS_FAT_MSK);
	sta_flag &= (~STA_FLG_FAT_EN_MSK);

	ht_info->tx_chan_width = IWL_CHANNEL_WIDTH_20MHZ;
	ht_info->chan_width_cap = IWL_CHANNEL_WIDTH_20MHZ;

	if (iwl_is_fat_tx_allowed(priv, ht_info)) {
		sta_flag |= STA_FLG_FAT_EN_MSK;
		ht_info->chan_width_cap = IWL_CHANNEL_WIDTH_40MHZ;

		if (ht_info->supported_chan_width == IWL_CHANNEL_WIDTH_40MHZ) {
			sta_rate |= RATE_MCS_FAT_MSK;
			ht_info->tx_chan_width = IWL_CHANNEL_WIDTH_40MHZ;
		}
	}

	priv->current_channel_width = ht_info->tx_chan_width;

	priv->stations[i].sta.tx_rate.rate_n_flags = sta_rate;
	priv->stations[i].sta.station_flags = sta_flag;

 done:
	if (need_to_lock)
		spin_unlock_irqrestore(&priv->sta_lock, flags);

	return;
}
#endif /* CONFIG_IWLWIFI_HT */

#ifdef CONFIG_IWLWIFI_HT_AGG
static void iwl_sta_modify_enable_tid_tx(struct iwl_priv *priv, int sta_id,
					 int tid)
{
	unsigned long lock_flags;
	spin_lock_irqsave(&priv->sta_lock, lock_flags);
	priv->stations[sta_id].sta.sta.modify_mask |= STA_MODIFY_TID_DISABLE_TX;
	priv->stations[sta_id].sta.tid_disable_tx &= ~(1 << tid);
	priv->stations[sta_id].sta.mode |= STA_CONTROL_MODIFY_MSK;
	spin_unlock_irqrestore(&priv->sta_lock, lock_flags);
	iwl_send_add_station(priv, &priv->stations[sta_id].sta, CMD_ASYNC);
}

#endif /* CONFIG_IWLWIFI_HT_AGG */

/* Set up 4965-specific Rx frame reply handlers */
void iwl_hw_rx_handler_setup(struct iwl_priv *priv)
{
	/* Legacy Rx frames */
	priv->rx_handlers[REPLY_4965_RX] = iwl4965_rx_reply_rx;

	/* High-throughput (HT) Rx frames */
	priv->rx_handlers[REPLY_RX_PHY_CMD] = iwl4965_rx_reply_rx_phy;
	priv->rx_handlers[REPLY_RX_MPDU_CMD] = iwl4965_rx_reply_rx;

	priv->rx_handlers[MISSED_BEACONS_NOTIFICATION] =
	    iwl4965_rx_missed_beacon_notif;

#ifdef CONFIG_IWLWIFI_HT_AGG
	priv->rx_handlers[REPLY_COMPRESSED_BA] = iwl4965_rx_reply_compressed_ba;
#endif
}

void iwl_hw_setup_deferred_work(struct iwl_priv *priv)
{
	INIT_WORK(&priv->txpower_work, iwl4965_bg_txpower_work, priv);
	INIT_WORK(&priv->statistics_work, iwl4965_bg_statistics_work, priv);
#ifdef CONFIG_IWLWIFI_SENSITIVITY
	INIT_WORK(&priv->sensitivity_work, iwl4965_bg_sensitivity_work, priv);
#endif
#ifdef CONFIG_IWLWIFI_HT_AGG
	INIT_WORK(&priv->agg_work, iwl4965_bg_agg_work, priv);
#endif
	init_timer(&priv->statistics_periodic);
	priv->statistics_periodic.data = (unsigned long)priv;
	priv->statistics_periodic.function = iwl4965_bg_statistics_periodic;
}

void iwl_hw_cancel_deferred_work(struct iwl_priv *priv)
{
	del_timer_sync(&priv->statistics_periodic);

	cancel_delayed_work(&priv->init_alive_start);
}

struct pci_device_id iwl_hw_card_ids[] = {
	{0x8086, 0x4229, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0x8086, 0x4230, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0}
};

MODULE_DEVICE_TABLE(pci, iwl_hw_card_ids);
