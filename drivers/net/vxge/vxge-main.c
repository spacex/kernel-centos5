/******************************************************************************
* This software may be used and distributed according to the terms of
* the GNU General Public License (GPL), incorporated herein by reference.
* Drivers based on or derived from this code fall under the GPL and must
* retain the authorship, copyright and license notice.  This file is not
* a complete program and may only be used when the entire operating
* system is licensed under the GPL.
* See the file COPYING in this distribution for more information.
*
* vxge-main.c: Driver for Neterion Inc's X3100 Series 10GbE PCIe I/O
*              Virtualized Server Adapter.
* Copyright(c) 2002-2009 Neterion Inc.
*
* The module loadable parameters that are supported by the driver and a brief
* explanation of all the variables:
* vlan_tag_strip:
*	Strip VLAN Tag enable/disable. Instructs the device to remove
*	the VLAN tag from all received tagged frames that are not
*	replicated at the internal L2 switch.
*		0 - Do not strip the VLAN tag.
*		1 - Strip the VLAN tag.
*
* addr_learn_en:
*	Enable learning the mac address of the guest OS interface in
*	a virtualization environment.
*		0 - DISABLE
*		1 - ENABLE
*
* max_config_port:
*	Maximum number of port to be supported.
*		MIN -1 and MAX - 2
*
* max_config_vpath:
*	This configures the maximum no of VPATH configures for each
* 	device function.
*		MIN - 1 and MAX - 17
*
* max_config_dev:
*	This configures maximum no of Device function to be enabled.
*		MIN - 1 and MAX - 17
*
******************************************************************************/

#include <linux/if_vlan.h>
#include <linux/pci.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include "vxge-main.h"
#include "vxge-reg.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Neterion's X3100 Series 10GbE PCIe I/O"
	"Virtualized Server Adapter");

static DEFINE_PCI_DEVICE_TABLE(vxge_id_table) = {
	{PCI_VENDOR_ID_S2IO, PCI_DEVICE_ID_TITAN_WIN, PCI_ANY_ID,
	PCI_ANY_ID},
	{PCI_VENDOR_ID_S2IO, PCI_DEVICE_ID_TITAN_UNI, PCI_ANY_ID,
	PCI_ANY_ID},
	{0}
};

MODULE_DEVICE_TABLE(pci, vxge_id_table);

VXGE_MODULE_PARAM_INT(vlan_tag_strip, VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE);
VXGE_MODULE_PARAM_INT(addr_learn_en, VXGE_HW_MAC_ADDR_LEARN_DEFAULT);
VXGE_MODULE_PARAM_INT(max_config_port, VXGE_MAX_CONFIG_PORT);
VXGE_MODULE_PARAM_INT(max_config_vpath, VXGE_USE_DEFAULT);
VXGE_MODULE_PARAM_INT(max_mac_vpath, VXGE_MAX_MAC_ADDR_COUNT);
VXGE_MODULE_PARAM_INT(max_config_dev, VXGE_MAX_CONFIG_DEV);

static u16 vpath_selector[VXGE_HW_MAX_VIRTUAL_PATHS] =
		{0, 1, 3, 3, 7, 7, 7, 7, 15, 15, 15, 15, 15, 15, 15, 15, 31};
static unsigned int bw_percentage[VXGE_HW_MAX_VIRTUAL_PATHS] =
	{[0 ...(VXGE_HW_MAX_VIRTUAL_PATHS - 1)] = 0xFF};
module_param_array(bw_percentage, uint, NULL, 0);

static struct vxge_drv_config *driver_config;

static inline int is_vxge_card_up(struct vxgedev *vdev)
{
	return test_bit(__VXGE_STATE_CARD_UP, &vdev->state);
}

static inline void VXGE_COMPLETE_VPATH_TX(struct vxge_fifo *fifo)
{
	unsigned long flags = 0;
	struct sk_buff **skb_ptr = NULL;
	struct sk_buff **temp;
#define NR_SKB_COMPLETED 128
	struct sk_buff *completed[NR_SKB_COMPLETED];
	int more;

	do {
		more = 0;
		skb_ptr = completed;

		if (spin_trylock_irqsave(&fifo->tx_lock, flags)) {
			vxge_hw_vpath_poll_tx(fifo->handle, &skb_ptr,
						NR_SKB_COMPLETED, &more);
			spin_unlock_irqrestore(&fifo->tx_lock, flags);
		}
		/* free SKBs */
		for (temp = completed; temp != skb_ptr; temp++)
			dev_kfree_skb_irq(*temp);
	} while (more) ;
}

static inline void VXGE_COMPLETE_ALL_TX(struct vxgedev *vdev)
{
	int i;

	/* Complete all transmits */
	for (i = 0; i < vdev->no_of_vpath; i++)
		VXGE_COMPLETE_VPATH_TX(&vdev->vpaths[i].fifo);
}

static inline void VXGE_COMPLETE_ALL_RX(struct vxgedev *vdev)
{
	int i;
	struct vxge_ring *ring;

	/* Complete all receives*/
	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		/* We're netpoll. Avoid race with NAPI polling this ring. */
		if (spin_trylock(&ring->poll_lock)) {
			vxge_hw_vpath_poll_rx(ring->handle);
			spin_unlock(&ring->poll_lock);
		}
	}
}

/*
 * MultiQ manipulation helper functions
 */
void vxge_stop_all_tx_queue(struct vxgedev *vdev)
{
	int i;
	struct net_device *dev = vdev->ndev;

	if (vdev->config.tx_steering_type != TX_MULTIQ_STEERING) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			vdev->vpaths[i].fifo.queue_state = VPATH_QUEUE_STOP;
	}
	netif_stop_queue(dev);
}

void vxge_stop_tx_queue(struct vxge_fifo *fifo)
{
	struct net_device *dev = fifo->ndev;

	if (fifo->tx_steering_type != TX_MULTIQ_STEERING)
		fifo->queue_state = VPATH_QUEUE_STOP;

	netif_stop_queue(dev);
}

void vxge_start_all_tx_queue(struct vxgedev *vdev)
{
	int i;
	struct net_device *dev = vdev->ndev;

	if (vdev->config.tx_steering_type != TX_MULTIQ_STEERING) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			vdev->vpaths[i].fifo.queue_state = VPATH_QUEUE_START;
	}
	netif_start_queue(dev);
}

static void vxge_wake_all_tx_queue(struct vxgedev *vdev)
{
	int i;
	struct net_device *dev = vdev->ndev;

	if (vdev->config.tx_steering_type != TX_MULTIQ_STEERING) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			vdev->vpaths[i].fifo.queue_state = VPATH_QUEUE_START;
	}
	netif_wake_queue(dev);
}

void vxge_wake_tx_queue(struct vxge_fifo *fifo, struct sk_buff *skb)
{
	struct net_device *dev = fifo->ndev;

	if (fifo->tx_steering_type == TX_MULTIQ_STEERING) {
		if (netif_queue_stopped(dev))
			netif_wake_queue(dev);
	} else {
		if (fifo->queue_state == VPATH_QUEUE_STOP)
			if (netif_queue_stopped(dev)) {
				fifo->queue_state = VPATH_QUEUE_START;
				netif_wake_queue(dev);
			}
	}
}

/*
 * vxge_callback_link_up
 *
 * This function is called during interrupt context to notify link up state
 * change.
 */
void
vxge_callback_link_up(struct __vxge_hw_device *hldev)
{
	struct net_device *dev = hldev->ndev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		vdev->ndev->name, __func__, __LINE__);
	printk(KERN_NOTICE "%s: Link Up\n", vdev->ndev->name);
	vdev->stats.link_up++;

	netif_carrier_on(vdev->ndev);
	vxge_wake_all_tx_queue(vdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", vdev->ndev->name, __func__, __LINE__);
}

/*
 * vxge_callback_link_down
 *
 * This function is called during interrupt context to notify link down state
 * change.
 */
void
vxge_callback_link_down(struct __vxge_hw_device *hldev)
{
	struct net_device *dev = hldev->ndev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d", vdev->ndev->name, __func__, __LINE__);
	printk(KERN_NOTICE "%s: Link Down\n", vdev->ndev->name);

	vdev->stats.link_down++;
	netif_carrier_off(vdev->ndev);
	vxge_stop_all_tx_queue(vdev);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", vdev->ndev->name, __func__, __LINE__);
}

/*
 * vxge_rx_alloc
 *
 * Allocate SKB.
 */
static struct sk_buff*
vxge_rx_alloc(void *dtrh, struct vxge_ring *ring, const int skb_size)
{
	struct net_device    *dev;
	struct sk_buff       *skb;
	struct vxge_rx_priv *rx_priv;

	dev = ring->ndev;
	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);

	rx_priv = vxge_hw_ring_rxd_private_get(dtrh);

	/* try to allocate skb first. this one may fail */
	skb = netdev_alloc_skb(dev, skb_size +
	VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);
	if (skb == NULL) {
		vxge_debug_mem(VXGE_ERR,
			"%s: out of memory to allocate SKB", dev->name);
		ring->stats.skb_alloc_fail++;
		return NULL;
	}

	vxge_debug_mem(VXGE_TRACE,
		"%s: %s:%d  Skb : 0x%p", ring->ndev->name,
		__func__, __LINE__, skb);

	skb_reserve(skb, VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);

	rx_priv->skb = skb;
	rx_priv->skb_data = NULL;
	rx_priv->data_size = skb_size;
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);

	return skb;
}

/*
 * vxge_rx_map
 */
static int vxge_rx_map(void *dtrh, struct vxge_ring *ring)
{
	struct vxge_rx_priv *rx_priv;
	dma_addr_t dma_addr;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);
	rx_priv = vxge_hw_ring_rxd_private_get(dtrh);

	rx_priv->skb_data = rx_priv->skb->data;
	dma_addr = pci_map_single(ring->pdev, rx_priv->skb_data,
				rx_priv->data_size, PCI_DMA_FROMDEVICE);

	if (unlikely(pci_dma_mapping_error(dma_addr))) {
		ring->stats.pci_map_fail++;
		return -EIO;
	}
	vxge_debug_mem(VXGE_TRACE,
		"%s: %s:%d  1 buffer mode dma_addr = 0x%llx",
		ring->ndev->name, __func__, __LINE__,
		(unsigned long long)dma_addr);
	vxge_hw_ring_rxd_1b_set(dtrh, dma_addr, rx_priv->data_size);

	rx_priv->data_dma = dma_addr;
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);

	return 0;
}

/*
 * vxge_rx_initial_replenish
 * Allocation of RxD as an initial replenish procedure.
 */
static enum vxge_hw_status
vxge_rx_initial_replenish(void *dtrh, void *userdata)
{
	struct vxge_ring *ring = (struct vxge_ring *)userdata;
	struct vxge_rx_priv *rx_priv;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);
	if (vxge_rx_alloc(dtrh, ring,
			  VXGE_LL_MAX_FRAME_SIZE(ring->ndev)) == NULL)
		return VXGE_HW_FAIL;

	if (vxge_rx_map(dtrh, ring)) {
		rx_priv = vxge_hw_ring_rxd_private_get(dtrh);
		dev_kfree_skb(rx_priv->skb);

		return VXGE_HW_FAIL;
	}
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);

	return VXGE_HW_OK;
}

static inline void
vxge_rx_complete(struct vxge_ring *ring, struct sk_buff *skb, u16 vlan,
		 int pkt_length, struct vxge_hw_ring_rxd_info *ext_info)
{

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
			ring->ndev->name, __func__, __LINE__);
	skb->protocol = eth_type_trans(skb, ring->ndev);
	skb->dev = ring->ndev;

	ring->stats.rx_frms++;
	ring->stats.rx_bytes += pkt_length;

	if (skb->pkt_type == PACKET_MULTICAST)
		ring->stats.rx_mcast++;

	vxge_debug_rx(VXGE_TRACE,
		"%s: %s:%d  skb protocol = %d",
		ring->ndev->name, __func__, __LINE__, skb->protocol);

	if (ring->gro_enable) {
		if (ring->vlgrp && ext_info->vlan &&
			(ring->vlan_tag_strip ==
				VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE))
			vlan_gro_receive(ring->napi_p, ring->vlgrp,
					ext_info->vlan, skb);
		else
			napi_gro_receive(ring->napi_p, skb);
	} else {
		if (ring->vlgrp && vlan &&
			(ring->vlan_tag_strip ==
				VXGE_HW_VPATH_RPA_STRIP_VLAN_TAG_ENABLE))
			vlan_hwaccel_receive_skb(skb, ring->vlgrp, vlan);
		else
			netif_receive_skb(skb);
	}
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d Exiting...", ring->ndev->name, __func__, __LINE__);
}

static inline void vxge_re_pre_post(void *dtr, struct vxge_ring *ring,
				    struct vxge_rx_priv *rx_priv)
{
	pci_dma_sync_single_for_device(ring->pdev,
		rx_priv->data_dma, rx_priv->data_size, PCI_DMA_FROMDEVICE);

	vxge_hw_ring_rxd_1b_set(dtr, rx_priv->data_dma, rx_priv->data_size);
	vxge_hw_ring_rxd_pre_post(ring->handle, dtr);
}

static inline void vxge_post(int *dtr_cnt, void **first_dtr,
			     void *post_dtr, struct __vxge_hw_ring *ringh)
{
	int dtr_count = *dtr_cnt;
	if ((*dtr_cnt % VXGE_HW_RXSYNC_FREQ_CNT) == 0) {
		if (*first_dtr)
			vxge_hw_ring_rxd_post_post_wmb(ringh, *first_dtr);
		*first_dtr = post_dtr;
	} else
		vxge_hw_ring_rxd_post_post(ringh, post_dtr);
	dtr_count++;
	*dtr_cnt = dtr_count;
}

/*
 * vxge_rx_1b_compl
 *
 * If the interrupt is because of a received frame or if the receive ring
 * contains fresh as yet un-processed frames, this function is called.
 */
enum vxge_hw_status
vxge_rx_1b_compl(struct __vxge_hw_ring *ringh, void *dtr,
		 u8 t_code, void *userdata)
{
	struct vxge_ring *ring = (struct vxge_ring *)userdata;
	struct  net_device *dev = ring->ndev;
	unsigned int dma_sizes;
	void *first_dtr = NULL;
	int dtr_cnt = 0;
	int data_size;
	dma_addr_t data_dma;
	int pkt_length;
	struct sk_buff *skb;
	struct vxge_rx_priv *rx_priv;
	struct vxge_hw_ring_rxd_info ext_info;
	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		ring->ndev->name, __func__, __LINE__);
	ring->pkts_processed = 0;

	vxge_hw_ring_replenish(ringh);

	do {
		prefetch((char *)dtr + L1_CACHE_BYTES);
		rx_priv = vxge_hw_ring_rxd_private_get(dtr);
		skb = rx_priv->skb;
		data_size = rx_priv->data_size;
		data_dma = rx_priv->data_dma;
		prefetch(rx_priv->skb_data);

		vxge_debug_rx(VXGE_TRACE,
			"%s: %s:%d  skb = 0x%p",
			ring->ndev->name, __func__, __LINE__, skb);

		vxge_hw_ring_rxd_1b_get(ringh, dtr, &dma_sizes);
		pkt_length = dma_sizes;

		pkt_length -= ETH_FCS_LEN;

		vxge_debug_rx(VXGE_TRACE,
			"%s: %s:%d  Packet Length = %d",
			ring->ndev->name, __func__, __LINE__, pkt_length);

		vxge_hw_ring_rxd_1b_info_get(ringh, dtr, &ext_info);

		/* check skb validity */
		vxge_assert(skb);

		prefetch((char *)skb + L1_CACHE_BYTES);
		if (unlikely(t_code)) {

			if (vxge_hw_ring_handle_tcode(ringh, dtr, t_code) !=
				VXGE_HW_OK) {

				ring->stats.rx_errors++;
				vxge_debug_rx(VXGE_TRACE,
					"%s: %s :%d Rx T_code is %d",
					ring->ndev->name, __func__,
					__LINE__, t_code);

				/* If the t_code is not supported and if the
				 * t_code is other than 0x5 (unparseable packet
				 * such as unknown UPV6 header), Drop it !!!
				 */
				vxge_re_pre_post(dtr, ring, rx_priv);

				vxge_post(&dtr_cnt, &first_dtr, dtr, ringh);
				ring->stats.rx_dropped++;
				continue;
			}
		}

		if (pkt_length > VXGE_LL_RX_COPY_THRESHOLD) {

			if (vxge_rx_alloc(dtr, ring, data_size) != NULL) {

				if (!vxge_rx_map(dtr, ring)) {
					skb_put(skb, pkt_length);

					pci_unmap_single(ring->pdev, data_dma,
						data_size, PCI_DMA_FROMDEVICE);

					vxge_hw_ring_rxd_pre_post(ringh, dtr);
					vxge_post(&dtr_cnt, &first_dtr, dtr,
						ringh);
				} else {
					dev_kfree_skb(rx_priv->skb);
					rx_priv->skb = skb;
					rx_priv->data_size = data_size;
					vxge_re_pre_post(dtr, ring, rx_priv);

					vxge_post(&dtr_cnt, &first_dtr, dtr,
						ringh);
					ring->stats.rx_dropped++;
					break;
				}
			} else {
				vxge_re_pre_post(dtr, ring, rx_priv);

				vxge_post(&dtr_cnt, &first_dtr, dtr, ringh);
				ring->stats.rx_dropped++;
				break;
			}
		} else {
			struct sk_buff *skb_up;

			skb_up = netdev_alloc_skb(dev, pkt_length +
				VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);
			if (skb_up != NULL) {
				skb_reserve(skb_up,
				    VXGE_HW_HEADER_ETHERNET_II_802_3_ALIGN);

				pci_dma_sync_single_for_cpu(ring->pdev,
					data_dma, data_size,
					PCI_DMA_FROMDEVICE);

				vxge_debug_mem(VXGE_TRACE,
					"%s: %s:%d  skb_up = %p",
					ring->ndev->name, __func__,
					__LINE__, skb);
				memcpy(skb_up->data, skb->data, pkt_length);

				vxge_re_pre_post(dtr, ring, rx_priv);

				vxge_post(&dtr_cnt, &first_dtr, dtr,
					ringh);
				/* will netif_rx small SKB instead */
				skb = skb_up;
				skb_put(skb, pkt_length);
			} else {
				vxge_re_pre_post(dtr, ring, rx_priv);

				vxge_post(&dtr_cnt, &first_dtr, dtr, ringh);
				vxge_debug_rx(VXGE_ERR,
					"%s: vxge_rx_1b_compl: out of "
					"memory", dev->name);
				ring->stats.skb_alloc_fail++;
				break;
			}
		}

		if ((ext_info.proto & VXGE_HW_FRAME_PROTO_TCP_OR_UDP) &&
		    !(ext_info.proto & VXGE_HW_FRAME_PROTO_IP_FRAG) &&
		    ring->rx_csum && /* Offload Rx side CSUM */
		    ext_info.l3_cksum == VXGE_HW_L3_CKSUM_OK &&
		    ext_info.l4_cksum == VXGE_HW_L4_CKSUM_OK)
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		else
			skb->ip_summed = CHECKSUM_NONE;

		vxge_rx_complete(ring, skb, ext_info.vlan,
			pkt_length, &ext_info);

		ring->budget--;
		ring->pkts_processed++;
		if (!ring->budget)
			break;

	} while (vxge_hw_ring_rxd_next_completed(ringh, &dtr,
		&t_code) == VXGE_HW_OK);

	if (first_dtr)
		vxge_hw_ring_rxd_post_post_wmb(ringh, first_dtr);

	dev->last_rx = jiffies;

	vxge_debug_entryexit(VXGE_TRACE,
				"%s:%d  Exiting...",
				__func__, __LINE__);
	return VXGE_HW_OK;
}

/*
 * vxge_xmit_compl
 *
 * If an interrupt was raised to indicate DMA complete of the Tx packet,
 * this function is called. It identifies the last TxD whose buffer was
 * freed and frees all skbs whose data have already DMA'ed into the NICs
 * internal memory.
 */
enum vxge_hw_status
vxge_xmit_compl(struct __vxge_hw_fifo *fifo_hw, void *dtr,
		enum vxge_hw_fifo_tcode t_code, void *userdata,
		struct sk_buff ***skb_ptr, int nr_skb, int *more)
{
	struct vxge_fifo *fifo = (struct vxge_fifo *)userdata;
	struct sk_buff *skb, **done_skb = *skb_ptr;
	int pkt_cnt = 0;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d Entered....", __func__, __LINE__);

	do {
		int frg_cnt;
		skb_frag_t *frag;
		int i = 0, j;
		struct vxge_tx_priv *txd_priv =
			vxge_hw_fifo_txdl_private_get(dtr);

		skb = txd_priv->skb;
		frg_cnt = skb_shinfo(skb)->nr_frags;
		frag = &skb_shinfo(skb)->frags[0];

		vxge_debug_tx(VXGE_TRACE,
				"%s: %s:%d fifo_hw = %p dtr = %p "
				"tcode = 0x%x", fifo->ndev->name, __func__,
				__LINE__, fifo_hw, dtr, t_code);
		/* check skb validity */
		vxge_assert(skb);
		vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d skb = %p itxd_priv = %p frg_cnt = %d",
			fifo->ndev->name, __func__, __LINE__,
			skb, txd_priv, frg_cnt);
		if (unlikely(t_code)) {
			fifo->stats.tx_errors++;
			vxge_debug_tx(VXGE_ERR,
				"%s: tx: dtr %p completed due to "
				"error t_code %01x", fifo->ndev->name,
				dtr, t_code);
			vxge_hw_fifo_handle_tcode(fifo_hw, dtr, t_code);
		}

		/*  for unfragmented skb */
		pci_unmap_single(fifo->pdev, txd_priv->dma_buffers[i++],
				skb_headlen(skb), PCI_DMA_TODEVICE);

		for (j = 0; j < frg_cnt; j++) {
			pci_unmap_page(fifo->pdev,
					txd_priv->dma_buffers[i++],
					frag->size, PCI_DMA_TODEVICE);
			frag += 1;
		}

		vxge_hw_fifo_txdl_free(fifo_hw, dtr);

		/* Updating the statistics block */
		fifo->stats.tx_frms++;
		fifo->stats.tx_bytes += skb->len;

		*done_skb++ = skb;

		if (--nr_skb <= 0) {
			*more = 1;
			break;
		}

		pkt_cnt++;
		if (pkt_cnt > fifo->indicate_max_pkts)
			break;

	} while (vxge_hw_fifo_txdl_next_completed(fifo_hw,
				&dtr, &t_code) == VXGE_HW_OK);

	*skb_ptr = done_skb;
	vxge_wake_tx_queue(fifo, skb);

	vxge_debug_entryexit(VXGE_TRACE,
				"%s: %s:%d  Exiting...",
				fifo->ndev->name, __func__, __LINE__);
	return VXGE_HW_OK;
}

/* select a vpath to transmit the packet */
static u32 vxge_get_vpath_no(struct vxgedev *vdev, struct sk_buff *skb,
	int *do_lock)
{
	u16 queue_len, counter = 0;
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *ip;
		struct tcphdr *th;

		ip = ip_hdr(skb);

		if ((ip->frag_off & htons(IP_OFFSET|IP_MF)) == 0) {
			th = (struct tcphdr *)(((unsigned char *)ip) +
					ip->ihl*4);

			queue_len = vdev->no_of_vpath;
			counter = (ntohs(th->source) +
				ntohs(th->dest)) &
				vdev->vpath_selector[queue_len - 1];
			if (counter >= queue_len)
				counter = queue_len - 1;

			if (ip->protocol == IPPROTO_UDP) {
#ifdef NETIF_F_LLTX
				*do_lock = 0;
#endif
			}
		}
	}
	return counter;
}

static enum vxge_hw_status vxge_search_mac_addr_in_list(
	struct vxge_vpath *vpath, u64 del_mac)
{
	struct list_head *entry, *next;
	list_for_each_safe(entry, next, &vpath->mac_addr_list) {
		if (((struct vxge_mac_addrs *)entry)->macaddr == del_mac)
			return TRUE;
	}
	return FALSE;
}

static int vxge_learn_mac(struct vxgedev *vdev, u8 *mac_header)
{
	struct macInfo mac_info;
	u8 *mac_address = NULL;
	u64 mac_addr = 0, vpath_vector = 0;
	int vpath_idx = 0;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath = NULL;
	struct __vxge_hw_device *hldev;

	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	mac_address = (u8 *)&mac_addr;
	memcpy(mac_address, mac_header, ETH_ALEN);

	/* Is this mac address already in the list? */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		vpath = &vdev->vpaths[vpath_idx];
		if (vxge_search_mac_addr_in_list(vpath, mac_addr))
			return vpath_idx;
	}

	memset(&mac_info, 0, sizeof(struct macInfo));
	memcpy(mac_info.macaddr, mac_header, ETH_ALEN);

	/* Any vpath has room to add mac address to its da table? */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		vpath = &vdev->vpaths[vpath_idx];
		if (vpath->mac_addr_cnt < vpath->max_mac_addr_cnt) {
			/* Add this mac address to this vpath */
			mac_info.vpath_no = vpath_idx;
			mac_info.state = VXGE_LL_MAC_ADDR_IN_DA_TABLE;
			status = vxge_add_mac_addr(vdev, &mac_info);
			if (status != VXGE_HW_OK)
				return -EPERM;
			return vpath_idx;
		}
	}

	mac_info.state = VXGE_LL_MAC_ADDR_IN_LIST;
	vpath_idx = 0;
	mac_info.vpath_no = vpath_idx;
	/* Is the first vpath already selected as catch-basin ? */
	vpath = &vdev->vpaths[vpath_idx];
	if (vpath->mac_addr_cnt > vpath->max_mac_addr_cnt) {
		/* Add this mac address to this vpath */
		if (FALSE == vxge_mac_list_add(vpath, &mac_info))
			return -EPERM;
		return vpath_idx;
	}

	/* Select first vpath as catch-basin */
	vpath_vector = vxge_mBIT(vpath->device_id);
	status = vxge_hw_mgmt_reg_write(vpath->vdev->devh,
				vxge_hw_mgmt_reg_type_mrpcim,
				0,
				(ulong)offsetof(
					struct vxge_hw_mrpcim_reg,
					rts_mgr_cbasin_cfg),
				vpath_vector);
	if (status != VXGE_HW_OK) {
		vxge_debug_tx(VXGE_ERR,
			"%s: Unable to set the vpath-%d in catch-basin mode",
			VXGE_DRIVER_NAME, vpath->device_id);
		return -EPERM;
	}

	if (FALSE == vxge_mac_list_add(vpath, &mac_info))
		return -EPERM;

	return vpath_idx;
}

/**
 * vxge_xmit
 * @skb : the socket buffer containing the Tx data.
 * @dev : device pointer.
 *
 * This function is the Tx entry point of the driver. Neterion NIC supports
 * certain protocol assist features on Tx side, namely  CSO, S/G, LSO.
 * NOTE: when device cant queue the pkt, just the trans_start variable will
 * not be upadted.
*/
static int
vxge_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vxge_fifo *fifo = NULL;
	void *dtr_priv;
	void *dtr = NULL;
	struct vxgedev *vdev = NULL;
	enum vxge_hw_status status;
	int frg_cnt, first_frg_len;
	skb_frag_t *frag;
	int i = 0, j = 0, avail;
	u64 dma_pointer;
	struct vxge_tx_priv *txdl_priv = NULL;
	struct __vxge_hw_fifo *fifo_hw;
	int offload_type;
	unsigned long flags = 0;
	int vpath_no = 0;
	int do_spin_tx_lock = 1;

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
			dev->name, __func__, __LINE__);

	/* A buffer with no data will be dropped */
	if (unlikely(skb->len <= 0)) {
		vxge_debug_tx(VXGE_ERR,
			"%s: Buffer has no data..", dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	vdev = (struct vxgedev *)netdev_priv(dev);

	if (unlikely(!is_vxge_card_up(vdev))) {
		vxge_debug_tx(VXGE_ERR,
			"%s: vdev not initialized", dev->name);
		dev_kfree_skb(skb);
		return NETDEV_TX_OK;
	}

	if (vdev->config.addr_learn_en) {
		vpath_no = vxge_learn_mac(vdev, skb->data + ETH_ALEN);
		if (vpath_no == -EPERM) {
			vxge_debug_tx(VXGE_ERR,
				"%s: Failed to store the mac address",
				dev->name);
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}

	if (vdev->config.tx_steering_type == TX_MULTIQ_STEERING)
		vpath_no = skb_get_queue_mapping(skb);
	else if (vdev->config.tx_steering_type == TX_PORT_STEERING)
		vpath_no = vxge_get_vpath_no(vdev, skb, &do_spin_tx_lock);

	vxge_debug_tx(VXGE_TRACE, "%s: vpath_no= %d", dev->name, vpath_no);

	if (vpath_no >= vdev->no_of_vpath)
		vpath_no = 0;

	fifo = &vdev->vpaths[vpath_no].fifo;
	fifo_hw = fifo->handle;

	if (do_spin_tx_lock)
		spin_lock_irqsave(&fifo->tx_lock, flags);
	else {
		if (unlikely(!spin_trylock_irqsave(&fifo->tx_lock, flags)))
			return NETDEV_TX_LOCKED;
	}

	if (vdev->config.tx_steering_type == TX_MULTIQ_STEERING) {
		if (netif_queue_stopped(dev)) {
			spin_unlock_irqrestore(&fifo->tx_lock, flags);
			return NETDEV_TX_BUSY;
		}
	} else if (unlikely(fifo->queue_state == VPATH_QUEUE_STOP)) {
		if (netif_queue_stopped(dev)) {
			spin_unlock_irqrestore(&fifo->tx_lock, flags);
			return NETDEV_TX_BUSY;
		}
	}
	avail = vxge_hw_fifo_free_txdl_count_get(fifo_hw);
	if (avail == 0) {
		vxge_debug_tx(VXGE_ERR,
			"%s: No free TXDs available", dev->name);
		fifo->stats.txd_not_free++;
		vxge_stop_tx_queue(fifo);
		goto _exit2;
	}

	/* Last TXD?  Stop tx queue to avoid dropping packets.  TX
	 * completion will resume the queue.
	 */
	if (avail == 1)
		vxge_stop_tx_queue(fifo);

	status = vxge_hw_fifo_txdl_reserve(fifo_hw, &dtr, &dtr_priv);
	if (unlikely(status != VXGE_HW_OK)) {
		vxge_debug_tx(VXGE_ERR,
		   "%s: Out of descriptors .", dev->name);
		fifo->stats.txd_out_of_desc++;
		vxge_stop_tx_queue(fifo);
		goto _exit2;
	}

	vxge_debug_tx(VXGE_TRACE,
		"%s: %s:%d fifo_hw = %p dtr = %p dtr_priv = %p",
		dev->name, __func__, __LINE__,
		fifo_hw, dtr, dtr_priv);

	if (vdev->vlgrp && vlan_tx_tag_present(skb)) {
		u16 vlan_tag = vlan_tx_tag_get(skb);
		vxge_hw_fifo_txdl_vlan_set(dtr, vlan_tag);
	}

	first_frg_len = skb_headlen(skb);

	dma_pointer = pci_map_single(fifo->pdev, skb->data, first_frg_len,
				PCI_DMA_TODEVICE);

	if (unlikely(pci_dma_mapping_error(dma_pointer))) {
		vxge_hw_fifo_txdl_free(fifo_hw, dtr);
		vxge_stop_tx_queue(fifo);
		fifo->stats.pci_map_fail++;
		goto _exit2;
	}

	txdl_priv = vxge_hw_fifo_txdl_private_get(dtr);
	txdl_priv->skb = skb;
	txdl_priv->dma_buffers[j] = dma_pointer;

	frg_cnt = skb_shinfo(skb)->nr_frags;
	vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d skb = %p txdl_priv = %p "
			"frag_cnt = %d dma_pointer = 0x%llx", dev->name,
			__func__, __LINE__, skb, txdl_priv,
			frg_cnt, (unsigned long long)dma_pointer);

	vxge_hw_fifo_txdl_buffer_set(fifo_hw, dtr, j++, dma_pointer,
		first_frg_len);

	frag = &skb_shinfo(skb)->frags[0];
	for (i = 0; i < frg_cnt; i++) {
		/* ignore 0 length fragment */
		if (!frag->size)
			continue;

		dma_pointer =
			(u64)pci_map_page(fifo->pdev, frag->page,
				frag->page_offset, frag->size,
				PCI_DMA_TODEVICE);

		if (unlikely(pci_dma_mapping_error(dma_pointer)))
			goto _exit0;
		vxge_debug_tx(VXGE_TRACE,
			"%s: %s:%d frag = %d dma_pointer = 0x%llx",
				dev->name, __func__, __LINE__, i,
				(unsigned long long)dma_pointer);

		txdl_priv->dma_buffers[j] = dma_pointer;
		vxge_hw_fifo_txdl_buffer_set(fifo_hw, dtr, j++, dma_pointer,
					frag->size);
		frag += 1;
	}

	offload_type = vxge_offload_type(skb);

	if (offload_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6)) {

		int mss = vxge_tcp_mss(skb);
		if (mss) {
			vxge_debug_tx(VXGE_TRACE,
				"%s: %s:%d mss = %d",
				dev->name, __func__, __LINE__, mss);
			vxge_hw_fifo_txdl_mss_set(dtr, mss);
		} else {
			vxge_assert(skb->len <=
				dev->mtu + VXGE_HW_MAC_HEADER_MAX_SIZE);
			vxge_assert(0);
			goto _exit1;
		}
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL)
		vxge_hw_fifo_txdl_cksum_set_bits(dtr,
					VXGE_HW_FIFO_TXD_TX_CKO_IPV4_EN |
					VXGE_HW_FIFO_TXD_TX_CKO_TCP_EN |
					VXGE_HW_FIFO_TXD_TX_CKO_UDP_EN);

	vxge_hw_fifo_txdl_post(fifo_hw, dtr);
	dev->trans_start = jiffies;
	spin_unlock_irqrestore(&fifo->tx_lock, flags);

	VXGE_COMPLETE_VPATH_TX(fifo);
	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d  Exiting...",
		dev->name, __func__, __LINE__);
	return NETDEV_TX_OK;

_exit0:
	vxge_debug_tx(VXGE_TRACE, "%s: pci_map_page failed", dev->name);

_exit1:
	j = 0;
	frag = &skb_shinfo(skb)->frags[0];

	pci_unmap_single(fifo->pdev, txdl_priv->dma_buffers[j++],
			skb_headlen(skb), PCI_DMA_TODEVICE);

	for (; j < i; j++) {
		pci_unmap_page(fifo->pdev, txdl_priv->dma_buffers[j],
			frag->size, PCI_DMA_TODEVICE);
		frag += 1;
	}

	vxge_hw_fifo_txdl_free(fifo_hw, dtr);
_exit2:
	dev_kfree_skb(skb);
	spin_unlock_irqrestore(&fifo->tx_lock, flags);
	VXGE_COMPLETE_VPATH_TX(fifo);

	return NETDEV_TX_OK;
}

/*
 * vxge_rx_term
 *
 * Function will be called by hw function to abort all outstanding receive
 * descriptors.
 */
static void
vxge_rx_term(void *dtrh, enum vxge_hw_rxd_state state, void *userdata)
{
	struct vxge_ring *ring = (struct vxge_ring *)userdata;
	struct vxge_rx_priv *rx_priv =
		vxge_hw_ring_rxd_private_get(dtrh);

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
			ring->ndev->name, __func__, __LINE__);
	if (state != VXGE_HW_RXD_STATE_POSTED)
		return;

	pci_unmap_single(ring->pdev, rx_priv->data_dma,
		rx_priv->data_size, PCI_DMA_FROMDEVICE);

	dev_kfree_skb(rx_priv->skb);
	rx_priv->skb_data = NULL;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d  Exiting...",
		ring->ndev->name, __func__, __LINE__);
}

/*
 * vxge_tx_term
 *
 * Function will be called to abort all outstanding tx descriptors
 */
static void
vxge_tx_term(void *dtrh, enum vxge_hw_txdl_state state, void *userdata)
{
	struct vxge_fifo *fifo = (struct vxge_fifo *)userdata;
	skb_frag_t *frag;
	int i = 0, j, frg_cnt;
	struct vxge_tx_priv *txd_priv = vxge_hw_fifo_txdl_private_get(dtrh);
	struct sk_buff *skb = txd_priv->skb;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	if (state != VXGE_HW_TXDL_STATE_POSTED)
		return;

	/* check skb validity */
	vxge_assert(skb);
	frg_cnt = skb_shinfo(skb)->nr_frags;
	frag = &skb_shinfo(skb)->frags[0];

	/*  for unfragmented skb */
	pci_unmap_single(fifo->pdev, txd_priv->dma_buffers[i++],
		skb_headlen(skb), PCI_DMA_TODEVICE);

	for (j = 0; j < frg_cnt; j++) {
		pci_unmap_page(fifo->pdev, txd_priv->dma_buffers[i++],
			       frag->size, PCI_DMA_TODEVICE);
		frag += 1;
	}

	dev_kfree_skb(skb);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_set_multicast
 * @dev: pointer to the device structure
 *
 * Entry point for multicast address enable/disable
 * This function is a driver entry point which gets called by the kernel
 * whenever multicast addresses must be enabled/disabled. This also gets
 * called to set/reset promiscuous mode. Depending on the deivce flag, we
 * determine, if multicast address must be enabled or if promiscuous mode
 * is to be disabled etc.
 */
static void vxge_set_multicast(struct net_device *dev)
{
	struct dev_mc_list *mclist;
	struct vxgedev *vdev;
	int i, mcast_cnt = 0;
	struct __vxge_hw_device *hldev;
	struct vxge_vpath *vpath;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct macInfo mac_info;
	int vpath_idx = 0;
	struct vxge_mac_addrs *mac_entry;
	struct list_head *list_head;
	struct list_head *entry, *next;
	u8 *mac_address = NULL;

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device  *)vdev->devh;

	if (unlikely(!is_vxge_card_up(vdev)))
		return;

	if ((dev->flags & IFF_ALLMULTI) && (!vdev->all_multi_flg)) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);
			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR, "failed to enable "
						"multicast, status %d", status);
			vdev->all_multi_flg = 1;
		}
	} else if (!(dev->flags & IFF_ALLMULTI) && (vdev->all_multi_flg)) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);
			status = vxge_hw_vpath_mcast_disable(vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR, "failed to disable "
						"multicast, status %d", status);
			vdev->all_multi_flg = 0;
		}
	}


	if (!vdev->config.addr_learn_en) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);

			if (dev->flags & IFF_PROMISC)
				status = vxge_hw_vpath_promisc_enable(
					vpath->handle);
			else
				status = vxge_hw_vpath_promisc_disable(
					vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR, "failed to %s promisc"
					", status %d", dev->flags&IFF_PROMISC ?
					"enable" : "disable", status);
		}
	}

	memset(&mac_info, 0, sizeof(struct macInfo));
	/* Update individual M_CAST address list */
	if ((!vdev->all_multi_flg) && dev->mc_count) {
		mcast_cnt = vdev->vpaths[0].mcast_addr_cnt;
		list_head = &vdev->vpaths[0].mac_addr_list;
		if ((dev->mc_count +
			(vdev->vpaths[0].mac_addr_cnt - mcast_cnt)) >
				vdev->vpaths[0].max_mac_addr_cnt)
			goto _set_all_mcast;

		/* Delete previous MC's */
		for (i = 0; i < mcast_cnt; i++) {
			list_for_each_safe(entry, next, list_head) {
				mac_entry = (struct vxge_mac_addrs *) entry;
				/* Copy the mac address to delete */
				mac_address = (u8 *)&mac_entry->macaddr;
				memcpy(mac_info.macaddr, mac_address, ETH_ALEN);

				/* Is this a multicast address */
				if (0x01 & mac_info.macaddr[0]) {
					for (vpath_idx = 0; vpath_idx <
						vdev->no_of_vpath;
						vpath_idx++) {
						mac_info.vpath_no = vpath_idx;
						status = vxge_del_mac_addr(
								vdev,
								&mac_info);
					}
				}
			}
		}

		/* Add new ones */
		for (i = 0, mclist = dev->mc_list; i < dev->mc_count;
			i++, mclist = mclist->next) {

			memcpy(mac_info.macaddr, mclist->dmi_addr, ETH_ALEN);
			for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath;
					vpath_idx++) {
				mac_info.vpath_no = vpath_idx;
				mac_info.state = VXGE_LL_MAC_ADDR_IN_DA_TABLE;
				status = vxge_add_mac_addr(vdev, &mac_info);
				if (status != VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
						"%s:%d Setting individual"
						"multicast address failed",
						__func__, __LINE__);
					goto _set_all_mcast;
				}
			}
		}

		return;
_set_all_mcast:
		mcast_cnt = vdev->vpaths[0].mcast_addr_cnt;
		/* Delete previous MC's */
		for (i = 0; i < mcast_cnt; i++) {
			list_for_each_safe(entry, next, list_head) {
				mac_entry = (struct vxge_mac_addrs *) entry;
				/* Copy the mac address to delete */
				mac_address = (u8 *)&mac_entry->macaddr;
				memcpy(mac_info.macaddr, mac_address, ETH_ALEN);

				/* Is this a multicast address */
				if (0x01 & mac_info.macaddr[0])
					break;
			}

			for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath;
					vpath_idx++) {
				mac_info.vpath_no = vpath_idx;
				status = vxge_del_mac_addr(vdev, &mac_info);
			}
		}

		/* Enable all multicast */
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_assert(vpath->is_open);

			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			if (status != VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"%s:%d Enabling all multicasts failed",
					 __func__, __LINE__);
			}
			vdev->all_multi_flg = 1;
		}
		dev->flags |= IFF_ALLMULTI;
	}

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_set_mac_addr
 * @dev: pointer to the device structure
 *
 * Update entry "0" (default MAC addr)
 */
static int vxge_set_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	struct vxgedev *vdev;
	struct __vxge_hw_device  *hldev;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct macInfo mac_info_new, mac_info_old;
	int vpath_idx = 0;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = vdev->devh;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	memset(&mac_info_new, 0, sizeof(struct macInfo));
	memset(&mac_info_old, 0, sizeof(struct macInfo));

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d  Exiting...",
		__func__, __LINE__);

	/* Get the old address */
	memcpy(mac_info_old.macaddr, dev->dev_addr, dev->addr_len);

	/* Copy the new address */
	memcpy(mac_info_new.macaddr, addr->sa_data, dev->addr_len);

	/* First delete the old mac address from all the vpaths
	as we can't specify the index while adding new mac address */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		struct vxge_vpath *vpath = &vdev->vpaths[vpath_idx];
		if (!vpath->is_open) {
			/* This can happen when this interface is added/removed
			to the bonding interface. Delete this station address
			from the linked list */
			vxge_mac_list_del(vpath, &mac_info_old);

			/* Add this new address to the linked list
			for later restoring */
			vxge_mac_list_add(vpath, &mac_info_new);

			continue;
		}
		/* Delete the station address */
		mac_info_old.vpath_no = vpath_idx;
		status = vxge_del_mac_addr(vdev, &mac_info_old);
	}

	if (unlikely(!is_vxge_card_up(vdev))) {
		memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
		return VXGE_HW_OK;
	}

	/* Set this mac address to all the vpaths */
	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++) {
		mac_info_new.vpath_no = vpath_idx;
		mac_info_new.state = VXGE_LL_MAC_ADDR_IN_DA_TABLE;
		status = vxge_add_mac_addr(vdev, &mac_info_new);
		if (status != VXGE_HW_OK)
			return -EINVAL;
	}

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return status;
}

/*
 * vxge_vpath_intr_enable
 * @vdev: pointer to vdev
 * @vp_id: vpath for which to enable the interrupts
 *
 * Enables the interrupts for the vpath
*/
void vxge_vpath_intr_enable(struct vxgedev *vdev, int vp_id)
{
	struct vxge_vpath *vpath = &vdev->vpaths[vp_id];
	int msix_id = 0;
	int tim_msix_id[4] = {0, 1, 0, 0};
	int alarm_msix_id = VXGE_ALARM_MSIX_ID;

	vxge_hw_vpath_intr_enable(vpath->handle);

	if (vdev->config.intr_type == INTA)
		vxge_hw_vpath_inta_unmask_tx_rx(vpath->handle);
	else {
		vxge_hw_vpath_msix_set(vpath->handle, tim_msix_id,
			alarm_msix_id);

		msix_id = vpath->device_id * VXGE_HW_VPATH_MSIX_ACTIVE;
		vxge_hw_vpath_msix_unmask(vpath->handle, msix_id);
		vxge_hw_vpath_msix_unmask(vpath->handle, msix_id + 1);

		/* enable the alarm vector */
		msix_id = (vpath->handle->vpath->hldev->first_vp_id *
			VXGE_HW_VPATH_MSIX_ACTIVE) + alarm_msix_id;
		vxge_hw_vpath_msix_unmask(vpath->handle, msix_id);
	}
}

/*
 * vxge_vpath_intr_disable
 * @vdev: pointer to vdev
 * @vp_id: vpath for which to disable the interrupts
 *
 * Disables the interrupts for the vpath
*/
void vxge_vpath_intr_disable(struct vxgedev *vdev, int vp_id)
{
	struct vxge_vpath *vpath = &vdev->vpaths[vp_id];
	int msix_id;

	vxge_hw_vpath_intr_disable(vpath->handle);

	if (vdev->config.intr_type == INTA)
		vxge_hw_vpath_inta_mask_tx_rx(vpath->handle);
	else {
		msix_id = vpath->device_id * VXGE_HW_VPATH_MSIX_ACTIVE;
		vxge_hw_vpath_msix_mask(vpath->handle, msix_id);
		vxge_hw_vpath_msix_mask(vpath->handle, msix_id + 1);

		/* disable the alarm vector */
		msix_id = (vpath->handle->vpath->hldev->first_vp_id *
			VXGE_HW_VPATH_MSIX_ACTIVE) + VXGE_ALARM_MSIX_ID;
		vxge_hw_vpath_msix_mask(vpath->handle, msix_id);
	}
}

/*
 * vxge_reset_vpath
 * @vdev: pointer to vdev
 * @vp_id: vpath to reset
 *
 * Resets the vpath
*/
static int vxge_reset_vpath(struct vxgedev *vdev, int vp_id)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath = &vdev->vpaths[vp_id];
	int ret = 0;

	/* check if device is down already */
	if (unlikely(!is_vxge_card_up(vdev)))
		return 0;

	/* is device reset already scheduled */
	if (test_bit(__VXGE_STATE_RESET_CARD, &vdev->state))
		return 0;

	if (vpath->handle) {
		if (vxge_hw_vpath_reset(vpath->handle) == VXGE_HW_OK) {
			if (is_vxge_card_up(vdev) &&
				vxge_hw_vpath_recover_from_reset(vpath->handle)
					!= VXGE_HW_OK) {
				vxge_debug_init(VXGE_ERR,
					"vxge_hw_vpath_recover_from_reset"
					"failed for vpath:%d", vp_id);
				return status;
			}
		} else {
			vxge_debug_init(VXGE_ERR,
				"vxge_hw_vpath_reset failed for"
				"vpath:%d", vp_id);
				return status;
		}
	} else
		return VXGE_HW_FAIL;

	vxge_restore_vpath_mac_addr(vpath);
	vxge_restore_vpath_vid_table(vpath);

	/* Enable all broadcast */
	vxge_hw_vpath_bcast_enable(vpath->handle);

	/* Enable all multicast */
	if (vdev->all_multi_flg) {
		status = vxge_hw_vpath_mcast_enable(vpath->handle);
		if (status != VXGE_HW_OK)
			vxge_debug_init(VXGE_ERR,
				"%s:%d Enabling multicast failed",
				__func__, __LINE__);
	}

	/* Enable the interrupts */
	vxge_vpath_intr_enable(vdev, vp_id);

	smp_wmb();

	/* Enable the flow of traffic through the vpath */
	vxge_hw_vpath_enable(vpath->handle);

	smp_wmb();
	vxge_hw_vpath_rx_doorbell_init(vpath->handle);
	vpath->ring.last_status = VXGE_HW_OK;

	/* Vpath reset done */
	clear_bit(vp_id, &vdev->vp_reset);

	/* Start the vpath queue */
	vxge_wake_tx_queue(&vpath->fifo, NULL);

	return ret;
}

static int do_vxge_reset(struct vxgedev *vdev, int event)
{
	enum vxge_hw_status status;
	int ret = 0, vp_id, i;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_START_RESET)) {
		/* check if device is down already */
		if (unlikely(!is_vxge_card_up(vdev)))
			return 0;

		/* is reset already scheduled */
		if (test_and_set_bit(__VXGE_STATE_RESET_CARD, &vdev->state))
			return 0;
	}

	if (event == VXGE_LL_FULL_RESET) {
		/* wait for all the vpath reset to complete */
		for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
			while (test_bit(vp_id, &vdev->vp_reset))
				msleep(50);
		}

		/* if execution mode is set to debug, don't reset the adapter */
		if (unlikely(vdev->exec_mode)) {
			vxge_debug_init(VXGE_ERR,
				"%s: execution mode is debug, returning..",
				vdev->ndev->name);
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
			vxge_stop_all_tx_queue(vdev);
			return 0;
		}
	}

	if (event == VXGE_LL_FULL_RESET) {
		vxge_hw_device_intr_disable(vdev->devh);

		switch (vdev->cric_err_event) {
		case VXGE_HW_EVENT_UNKNOWN:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"unknown error",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_RESET_START:
			break;
		case VXGE_HW_EVENT_RESET_COMPLETE:
		case VXGE_HW_EVENT_LINK_DOWN:
		case VXGE_HW_EVENT_LINK_UP:
		case VXGE_HW_EVENT_ALARM_CLEARED:
		case VXGE_HW_EVENT_ECCERR:
		case VXGE_HW_EVENT_MRPCIM_ECCERR:
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_FIFO_ERR:
		case VXGE_HW_EVENT_VPATH_ERR:
			break;
		case VXGE_HW_EVENT_CRITICAL_ERR:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"serious error",
				vdev->ndev->name);
			/* SOP or device reset required */
			/* This event is not currently used */
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_SERR:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"serious error",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_SRPCIM_SERR:
		case VXGE_HW_EVENT_MRPCIM_SERR:
			ret = -EPERM;
			goto out;
		case VXGE_HW_EVENT_SLOT_FREEZE:
			vxge_stop_all_tx_queue(vdev);
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: Disabling device due to"
				"slot freeze",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		default:
			break;

		}
	}

	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_START_RESET))
		vxge_stop_all_tx_queue(vdev);

	if (event == VXGE_LL_FULL_RESET) {
		status = vxge_reset_all_vpaths(vdev);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"fatal: %s: can not reset vpaths",
				vdev->ndev->name);
			ret = -EPERM;
			goto out;
		}
	}

	if (event == VXGE_LL_COMPL_RESET) {
		for (i = 0; i < vdev->no_of_vpath; i++)
			if (vdev->vpaths[i].handle) {
				if (vxge_hw_vpath_recover_from_reset(
					vdev->vpaths[i].handle)
						!= VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
						"vxge_hw_vpath_recover_"
						"from_reset failed for vpath: "
						"%d", i);
					ret = -EPERM;
					goto out;
				}
				} else {
					vxge_debug_init(VXGE_ERR,
					"vxge_hw_vpath_reset failed for "
						"vpath:%d", i);
					ret = -EPERM;
					goto out;
				}
	}

	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_COMPL_RESET)) {
		/* Reprogram the DA table with populated mac addresses */
		for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
			vxge_restore_vpath_mac_addr(&vdev->vpaths[vp_id]);
			vxge_restore_vpath_vid_table(&vdev->vpaths[vp_id]);
		}

		/* enable vpath interrupts */
		for (i = 0; i < vdev->no_of_vpath; i++)
			vxge_vpath_intr_enable(vdev, i);

		vxge_hw_device_intr_enable(vdev->devh);

		smp_wmb();

		/* Indicate card up */
		set_bit(__VXGE_STATE_CARD_UP, &vdev->state);

		/* Get the traffic to flow through the vpaths */
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vxge_hw_vpath_enable(vdev->vpaths[i].handle);
			smp_wmb();
			vxge_hw_vpath_rx_doorbell_init(vdev->vpaths[i].handle);
		}

		vxge_wake_all_tx_queue(vdev);
	}

out:
	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);

	/* Indicate reset done */
	if ((event == VXGE_LL_FULL_RESET) || (event == VXGE_LL_COMPL_RESET))
		clear_bit(__VXGE_STATE_RESET_CARD, &vdev->state);
	return ret;
}

/*
 * vxge_reset
 * @vdev: pointer to ll device
 *
 * driver may reset the chip on events of serr, eccerr, etc
 */
int vxge_reset(struct vxgedev *vdev)
{
	return do_vxge_reset(vdev, VXGE_LL_FULL_RESET);
}

/**
 * vxge_poll - Receive handler when Receive Polling is used.
 * @dev: pointer to the device structure.
 * @budget: Number of packets budgeted to be processed in this iteration.
 *
 * This function comes into picture only if Receive side is being handled
 * through polling (called NAPI in linux). It mostly does what the normal
 * Rx interrupt handler does in terms of descriptor and packet processing
 * but not in an interrupt context. Also it will process a specified number
 * of packets at most in one iteration. This value is passed down by the
 * kernel as the function argument 'budget'.
 */
static int vxge_poll_msix(struct napi_struct *napi, int budget)
{
	struct vxge_ring *ring =
		container_of(napi, struct vxge_ring, napi);
	int budget_org = budget;
	int pkts_processed;

	spin_lock(&ring->poll_lock);
	ring->budget = budget;

	vxge_hw_vpath_poll_rx(ring->handle);

	if (ring->pkts_processed < budget_org) {
		napi_complete(napi);
		/* Re enable the Rx interrupts for the vpath */
		vxge_hw_channel_msix_unmask(
				(struct __vxge_hw_channel *)ring->handle,
				ring->rx_vector_no);
	}

	pkts_processed = ring->pkts_processed;
	spin_unlock(&ring->poll_lock);
	return pkts_processed;
}

static int vxge_poll_inta(struct napi_struct *napi, int budget)
{
	struct vxgedev *vdev = container_of(napi, struct vxgedev, napi);
	int pkts_processed = 0;
	int i;
	int budget_org = budget;
	struct vxge_ring *ring;

	struct __vxge_hw_device  *hldev = (struct __vxge_hw_device *)
		pci_get_drvdata(vdev->pdev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		spin_lock(&ring->poll_lock);
		ring->budget = budget;
		vxge_hw_vpath_poll_rx(ring->handle);
		pkts_processed += ring->pkts_processed;
		budget -= ring->pkts_processed;
		spin_unlock(&ring->poll_lock);
		if (budget <= 0)
			break;
	}

	VXGE_COMPLETE_ALL_TX(vdev);

	if (pkts_processed < budget_org) {
		napi_complete(napi);
		/* Re enable the Rx interrupts for the ring */
		vxge_hw_device_unmask_all(hldev);
		vxge_hw_device_flush_io(hldev);
	}

	return pkts_processed;
}

static inline int rhel_napi_poll_wrapper(int (*poll)(struct napi_struct*, int),
	struct napi_struct *napi, struct net_device *dummy_dev, int *budget)
{
	int to_do = min(*budget, dummy_dev->quota);
	int pkts_processed;

	pkts_processed = poll(napi, to_do);

	*budget -= pkts_processed;
	dummy_dev->quota -= pkts_processed;

	return (pkts_processed >= to_do);
}

static int rhel_vxge_poll_msix(struct net_device *dummy_dev, int *budget)
{
	struct vxge_ring *ring = dummy_dev->priv;
	return rhel_napi_poll_wrapper(vxge_poll_msix, &ring->napi, dummy_dev,
				      budget);
}

static int rhel_vxge_poll_inta(struct net_device *dummy_dev, int *budget)
{
	struct vxgedev *vdev = dummy_dev->priv;
	return rhel_napi_poll_wrapper(vxge_poll_inta, &vdev->napi, dummy_dev,
				      budget);
}

#ifdef CONFIG_NET_POLL_CONTROLLER
/**
 * vxge_netpoll - netpoll event handler entry point
 * @dev : pointer to the device structure.
 * Description:
 *      This function will be called by upper layer to check for events on the
 * interface in situations where interrupts are disabled. It is used for
 * specific in-kernel networking tasks, such as remote consoles and kernel
 * debugging over the network (example netdump in RedHat).
 */
static void vxge_netpoll(struct net_device *dev)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev;

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device  *)pci_get_drvdata(vdev->pdev);

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	if (pci_channel_offline(vdev->pdev))
		return;

	disable_irq(dev->irq);
	vxge_hw_device_clear_tx_rx(hldev);

	vxge_hw_device_clear_tx_rx(hldev);
	VXGE_COMPLETE_ALL_RX(vdev);
	VXGE_COMPLETE_ALL_TX(vdev);

	enable_irq(dev->irq);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}
#endif

/* RTH configuration */
static enum vxge_hw_status vxge_rth_configure(struct vxgedev *vdev)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_hw_rth_hash_types hash_types;
	u8 itable[256] = {0}; /* indirection table */
	u8 mtable[256] = {0}; /* CPU to vpath mapping  */
	int index;

	/*
	 * Filling
	 * 	- itable with bucket numbers
	 * 	- mtable with bucket-to-vpath mapping
	 */
	for (index = 0; index < (1 << vdev->config.rth_bkt_sz); index++) {
		itable[index] = index;
		mtable[index] = index % vdev->no_of_vpath;
	}

	/* Fill RTH hash types */
	hash_types.hash_type_tcpipv4_en   = vdev->config.rth_hash_type_tcpipv4;
	hash_types.hash_type_ipv4_en      = vdev->config.rth_hash_type_ipv4;
	hash_types.hash_type_tcpipv6_en   = vdev->config.rth_hash_type_tcpipv6;
	hash_types.hash_type_ipv6_en      = vdev->config.rth_hash_type_ipv6;
	hash_types.hash_type_tcpipv6ex_en =
					vdev->config.rth_hash_type_tcpipv6ex;
	hash_types.hash_type_ipv6ex_en    = vdev->config.rth_hash_type_ipv6ex;

	/* set indirection table, bucket-to-vpath mapping */
	status = vxge_hw_vpath_rts_rth_itable_set(vdev->vp_handles,
						vdev->no_of_vpath,
						mtable, itable,
						vdev->config.rth_bkt_sz);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"RTH indirection table configuration failed "
			"for vpath:%d", vdev->vpaths[0].device_id);
		return status;
	}

	/*
	* Because the itable_set() method uses the active_table field
	* for the target virtual path the RTH config should be updated
	* for all VPATHs. The h/w only uses the lowest numbered VPATH
	* when steering frames.
	*/
	 for (index = 0; index < vdev->no_of_vpath; index++) {
		status = vxge_hw_vpath_rts_rth_set(
				vdev->vpaths[index].handle,
				vdev->config.rth_algorithm,
				&hash_types,
				vdev->config.rth_bkt_sz);

		 if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"RTH configuration failed for vpath:%d",
				vdev->vpaths[index].device_id);
			return status;
		 }
	 }

	return status;
}

int vxge_mac_list_add(struct vxge_vpath *vpath, struct macInfo *mac)
{
	struct vxge_mac_addrs *new_mac_entry;
	u8 *mac_address = NULL;

	if (vpath->mac_addr_cnt >= VXGE_MAX_LEARN_MAC_ADDR_CNT)
		return TRUE;

	new_mac_entry = kzalloc(sizeof(struct vxge_mac_addrs), GFP_ATOMIC);
	if (!new_mac_entry) {
		vxge_debug_mem(VXGE_ERR,
			"%s: memory allocation failed",
			VXGE_DRIVER_NAME);
		return FALSE;
	}

	list_add(&new_mac_entry->item, &vpath->mac_addr_list);

	/* Copy the new mac address to the list */
	mac_address = (u8 *)&new_mac_entry->macaddr;
	memcpy(mac_address, mac->macaddr, ETH_ALEN);

	new_mac_entry->state = mac->state;
	vpath->mac_addr_cnt++;

	/* Is this a multicast address */
	if (0x01 & mac->macaddr[0])
		vpath->mcast_addr_cnt++;

	return TRUE;
}

/* Add a mac address to DA table */
enum vxge_hw_status vxge_add_mac_addr(struct vxgedev *vdev, struct macInfo *mac)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath;
	enum vxge_hw_vpath_mac_addr_add_mode duplicate_mode;

	if (0x01 & mac->macaddr[0]) /* multicast address */
		duplicate_mode = VXGE_HW_VPATH_MAC_ADDR_ADD_DUPLICATE;
	else
		duplicate_mode = VXGE_HW_VPATH_MAC_ADDR_REPLACE_DUPLICATE;

	vpath = &vdev->vpaths[mac->vpath_no];
	status = vxge_hw_vpath_mac_addr_add(vpath->handle, mac->macaddr,
						mac->macmask, duplicate_mode);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"DA config add entry failed for vpath:%d",
			vpath->device_id);
	} else
		if (FALSE == vxge_mac_list_add(vpath, mac))
			status = -EPERM;

	return status;
}

int vxge_mac_list_del(struct vxge_vpath *vpath, struct macInfo *mac)
{
	struct list_head *entry, *next;
	u64 del_mac = 0;
	u8 *mac_address = (u8 *) (&del_mac);

	/* Copy the mac address to delete from the list */
	memcpy(mac_address, mac->macaddr, ETH_ALEN);

	list_for_each_safe(entry, next, &vpath->mac_addr_list) {
		if (((struct vxge_mac_addrs *)entry)->macaddr == del_mac) {
			list_del(entry);
			kfree((struct vxge_mac_addrs *)entry);
			vpath->mac_addr_cnt--;

			/* Is this a multicast address */
			if (0x01 & mac->macaddr[0])
				vpath->mcast_addr_cnt--;
			return TRUE;
		}
	}

	return FALSE;
}
/* delete a mac address from DA table */
enum vxge_hw_status vxge_del_mac_addr(struct vxgedev *vdev, struct macInfo *mac)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath;

	vpath = &vdev->vpaths[mac->vpath_no];
	status = vxge_hw_vpath_mac_addr_delete(vpath->handle, mac->macaddr,
						mac->macmask);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"DA config delete entry failed for vpath:%d",
			vpath->device_id);
	} else
		vxge_mac_list_del(vpath, mac);
	return status;
}

/* list all mac addresses from DA table */
enum vxge_hw_status
static vxge_search_mac_addr_in_da_table(struct vxge_vpath *vpath,
					struct macInfo *mac)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	unsigned char macmask[ETH_ALEN];
	unsigned char macaddr[ETH_ALEN];

	status = vxge_hw_vpath_mac_addr_get(vpath->handle,
				macaddr, macmask);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"DA config list entry failed for vpath:%d",
			vpath->device_id);
		return status;
	}

	while (memcmp(mac->macaddr, macaddr, ETH_ALEN)) {

		status = vxge_hw_vpath_mac_addr_get_next(vpath->handle,
				macaddr, macmask);
		if (status != VXGE_HW_OK)
			break;
	}

	return status;
}

/* Store all vlan ids from the list to the vid table */
enum vxge_hw_status vxge_restore_vpath_vid_table(struct vxge_vpath *vpath)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxgedev *vdev = vpath->vdev;
	u16 vid;

	if (vdev->vlgrp && vpath->is_open) {

		for (vid = 0; vid < VLAN_GROUP_ARRAY_LEN; vid++) {
			if (!vlan_group_get_device(vdev->vlgrp, vid))
				continue;
			/* Add these vlan to the vid table */
			status = vxge_hw_vpath_vid_add(vpath->handle, vid);
		}
	}

	return status;
}

/* Store all mac addresses from the list to the DA table */
enum vxge_hw_status vxge_restore_vpath_mac_addr(struct vxge_vpath *vpath)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct macInfo mac_info;
	u8 *mac_address = NULL;
	struct list_head *entry, *next;

	memset(&mac_info, 0, sizeof(struct macInfo));

	if (vpath->is_open) {

		list_for_each_safe(entry, next, &vpath->mac_addr_list) {
			mac_address =
				(u8 *)&
				((struct vxge_mac_addrs *)entry)->macaddr;
			memcpy(mac_info.macaddr, mac_address, ETH_ALEN);
			((struct vxge_mac_addrs *)entry)->state =
				VXGE_LL_MAC_ADDR_IN_DA_TABLE;
			/* does this mac address already exist in da table? */
			status = vxge_search_mac_addr_in_da_table(vpath,
				&mac_info);
			if (status != VXGE_HW_OK) {
				/* Add this mac address to the DA table */
				status = vxge_hw_vpath_mac_addr_add(
					vpath->handle, mac_info.macaddr,
					mac_info.macmask,
				    VXGE_HW_VPATH_MAC_ADDR_ADD_DUPLICATE);
				if (status != VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
					    "DA add entry failed for vpath:%d",
					    vpath->device_id);
					((struct vxge_mac_addrs *)entry)->state
						= VXGE_LL_MAC_ADDR_IN_LIST;
				}
			}
		}
	}

	return status;
}

/* reset vpaths */
enum vxge_hw_status vxge_reset_all_vpaths(struct vxgedev *vdev)
{
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath;
	int i;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];
		if (vpath->handle) {
			if (vxge_hw_vpath_reset(vpath->handle) == VXGE_HW_OK) {
				if (is_vxge_card_up(vdev) &&
					vxge_hw_vpath_recover_from_reset(
						vpath->handle) != VXGE_HW_OK) {
					vxge_debug_init(VXGE_ERR,
						"vxge_hw_vpath_recover_"
						"from_reset failed for vpath: "
						"%d", i);
					return status;
				}
			} else {
				vxge_debug_init(VXGE_ERR,
					"vxge_hw_vpath_reset failed for "
					"vpath:%d", i);
					return status;
			}
		}
	}

	return status;
}

/* close vpaths */
void vxge_close_vpaths(struct vxgedev *vdev, int index)
{
	struct vxge_vpath *vpath;
	int i;

	for (i = index; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];

		if (vpath->handle && vpath->is_open) {
			vxge_hw_vpath_close(vpath->handle);
			vdev->stats.vpaths_open--;
		}
		vpath->is_open = 0;
		vpath->handle = NULL;
	}
}

/* open vpaths */
int vxge_open_vpaths(struct vxgedev *vdev)
{
	struct vxge_hw_vpath_attr attr;
	enum vxge_hw_status status;
	struct vxge_vpath *vpath;
	u32 vp_id = 0;
	int i;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];

		vxge_assert(vpath->is_configured);
		attr.vp_id = vpath->device_id;
		attr.fifo_attr.callback = vxge_xmit_compl;
		attr.fifo_attr.txdl_term = vxge_tx_term;
		attr.fifo_attr.per_txdl_space = sizeof(struct vxge_tx_priv);
		attr.fifo_attr.userdata = &vpath->fifo;

		attr.ring_attr.callback = vxge_rx_1b_compl;
		attr.ring_attr.rxd_init = vxge_rx_initial_replenish;
		attr.ring_attr.rxd_term = vxge_rx_term;
		attr.ring_attr.per_rxd_space = sizeof(struct vxge_rx_priv);
		attr.ring_attr.userdata = &vpath->ring;

		vpath->ring.ndev = vdev->ndev;
		vpath->ring.pdev = vdev->pdev;
		status = vxge_hw_vpath_open(vdev->devh, &attr, &vpath->handle);
		if (status == VXGE_HW_OK) {
			vpath->fifo.handle =
			    (struct __vxge_hw_fifo *)attr.fifo_attr.userdata;
			vpath->ring.handle =
			    (struct __vxge_hw_ring *)attr.ring_attr.userdata;
			vpath->fifo.tx_steering_type =
				vdev->config.tx_steering_type;
			vpath->fifo.ndev = vdev->ndev;
			vpath->fifo.pdev = vdev->pdev;
			vpath->fifo.indicate_max_pkts =
				vdev->config.fifo_indicate_max_pkts;
			vpath->ring.rx_vector_no = 0;
			vpath->ring.rx_csum = vdev->rx_csum;
			vpath->is_open = 1;
			vdev->vp_handles[i] = vpath->handle;
			vpath->ring.gro_enable = vdev->config.gro_enable;
			vpath->ring.vlan_tag_strip = vdev->vlan_tag_strip;
			vdev->stats.vpaths_open++;
		} else {
			vdev->stats.vpath_open_fail++;
			vxge_debug_init(VXGE_ERR,
				"%s: vpath: %d failed to open "
				"with status: %d",
			    vdev->ndev->name, vpath->device_id,
				status);
			vxge_close_vpaths(vdev, 0);
			return -EPERM;
		}

		vp_id = vpath->handle->vpath->vp_id;
		vdev->vpaths_deployed |= vxge_mBIT(vp_id);
	}
	return VXGE_HW_OK;
}

/*
 *  vxge_isr_napi
 *  @irq: the irq of the device.
 *  @dev_id: a void pointer to the hldev structure of the Titan device
 *  @ptregs: pointer to the registers pushed on the stack.
 *
 *  This function is the ISR handler of the device when napi is enabled. It
 *  identifies the reason for the interrupt and calls the relevant service
 *  routines.
 */
static irqreturn_t vxge_isr_napi(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev;
	struct __vxge_hw_device *hldev;
	u64 reason;
	enum vxge_hw_status status;
	struct vxgedev *vdev = (struct vxgedev *) dev_id;;

	vxge_debug_intr(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	dev = vdev->ndev;
	hldev = (struct __vxge_hw_device *)pci_get_drvdata(vdev->pdev);

	if (pci_channel_offline(vdev->pdev))
		return IRQ_NONE;

	if (unlikely(!is_vxge_card_up(vdev)))
		return IRQ_NONE;

	status = vxge_hw_device_begin_irq(hldev, vdev->exec_mode,
			&reason);
	if (status == VXGE_HW_OK) {
		vxge_hw_device_mask_all(hldev);

		if (reason &
			VXGE_HW_TITAN_GENERAL_INT_STATUS_VPATH_TRAFFIC_INT(
			vdev->vpaths_deployed >>
			(64 - VXGE_HW_MAX_VIRTUAL_PATHS))) {

			vxge_hw_device_clear_tx_rx(hldev);
			netif_rx_schedule(vdev->napi.dev);
			vxge_debug_intr(VXGE_TRACE,
				"%s:%d  Exiting...", __func__, __LINE__);
			return IRQ_HANDLED;
		} else
			vxge_hw_device_unmask_all(hldev);
	} else if (unlikely((status == VXGE_HW_ERR_VPATH) ||
		(status == VXGE_HW_ERR_CRITICAL) ||
		(status == VXGE_HW_ERR_FIFO))) {
		vxge_hw_device_mask_all(hldev);
		vxge_hw_device_flush_io(hldev);
		return IRQ_HANDLED;
	} else if (unlikely(status == VXGE_HW_ERR_SLOT_FREEZE))
		return IRQ_HANDLED;

	vxge_debug_intr(VXGE_TRACE, "%s:%d  Exiting...", __func__, __LINE__);
	return IRQ_NONE;
}

#ifdef CONFIG_PCI_MSI

static irqreturn_t
vxge_tx_msix_handle(int irq, void *dev_id, struct pt_regs *regs)
{
	struct vxge_fifo *fifo = (struct vxge_fifo *)dev_id;

	VXGE_COMPLETE_VPATH_TX(fifo);

	return IRQ_HANDLED;
}

static irqreturn_t
vxge_rx_msix_napi_handle(int irq, void *dev_id, struct pt_regs *regs)
{
	struct vxge_ring *ring = (struct vxge_ring *)dev_id;

	/* MSIX_IDX for Rx is 1 */
	vxge_hw_channel_msix_mask((struct __vxge_hw_channel *)ring->handle,
					ring->rx_vector_no);

	netif_rx_schedule(ring->napi.dev);
	return IRQ_HANDLED;
}

static irqreturn_t
vxge_alarm_msix_handle(int irq, void *dev_id, struct pt_regs *regs)
{
	int i;
	enum vxge_hw_status status;
	struct vxge_vpath *vpath = (struct vxge_vpath *)dev_id;
	struct vxgedev *vdev = vpath->vdev;
	int msix_id = (vpath->handle->vpath->vp_id *
		VXGE_HW_VPATH_MSIX_ACTIVE) + VXGE_ALARM_MSIX_ID;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vxge_hw_vpath_msix_mask(vdev->vpaths[i].handle, msix_id);

		status = vxge_hw_vpath_alarm_process(vdev->vpaths[i].handle,
			vdev->exec_mode);
		if (status == VXGE_HW_OK) {

			vxge_hw_vpath_msix_unmask(vdev->vpaths[i].handle,
					msix_id);
			continue;
		}
		vxge_debug_intr(VXGE_ERR,
			"%s: vxge_hw_vpath_alarm_process failed %x ",
			VXGE_DRIVER_NAME, status);
	}
	return IRQ_HANDLED;
}

static int vxge_alloc_msix(struct vxgedev *vdev)
{
	int j, i, ret = 0;
	int msix_intr_vect = 0, temp;
	vdev->intr_cnt = 0;

start:
	/* Tx/Rx MSIX Vectors count */
	vdev->intr_cnt = vdev->no_of_vpath * 2;

	/* Alarm MSIX Vectors count */
	vdev->intr_cnt++;

	vdev->entries = kzalloc(vdev->intr_cnt * sizeof(struct msix_entry),
						GFP_KERNEL);
	if (!vdev->entries) {
		vxge_debug_init(VXGE_ERR,
			"%s: memory allocation failed",
			VXGE_DRIVER_NAME);
		ret = -ENOMEM;
		goto alloc_entries_failed;
	}

	vdev->vxge_entries =
		kzalloc(vdev->intr_cnt * sizeof(struct vxge_msix_entry),
				GFP_KERNEL);
	if (!vdev->vxge_entries) {
		vxge_debug_init(VXGE_ERR, "%s: memory allocation failed",
			VXGE_DRIVER_NAME);
		ret = -ENOMEM;
		goto alloc_vxge_entries_failed;
	}

	for (i = 0, j = 0; i < vdev->no_of_vpath; i++) {

		msix_intr_vect = i * VXGE_HW_VPATH_MSIX_ACTIVE;

		/* Initialize the fifo vector */
		vdev->entries[j].entry = msix_intr_vect;
		vdev->vxge_entries[j].entry = msix_intr_vect;
		vdev->vxge_entries[j].in_use = 0;
		j++;

		/* Initialize the ring vector */
		vdev->entries[j].entry = msix_intr_vect + 1;
		vdev->vxge_entries[j].entry = msix_intr_vect + 1;
		vdev->vxge_entries[j].in_use = 0;
		j++;
	}

	/* Initialize the alarm vector */
	vdev->entries[j].entry = VXGE_ALARM_MSIX_ID;
	vdev->vxge_entries[j].entry = VXGE_ALARM_MSIX_ID;
	vdev->vxge_entries[j].in_use = 0;

	ret = pci_enable_msix(vdev->pdev, vdev->entries, vdev->intr_cnt);
	if (ret > 0) {
		vxge_debug_init(VXGE_ERR,
			"%s: MSI-X enable failed for %d vectors, ret: %d",
			VXGE_DRIVER_NAME, vdev->intr_cnt, ret);
		if ((max_config_vpath != VXGE_USE_DEFAULT) || (ret < 3)) {
			ret = -ENODEV;
			goto enable_msix_failed;
		}

		kfree(vdev->entries);
		kfree(vdev->vxge_entries);
		vdev->entries = NULL;
		vdev->vxge_entries = NULL;
		/* Try with less no of vector by reducing no of vpaths count */
		temp = (ret - 1)/2;
		vxge_close_vpaths(vdev, temp);
		vdev->no_of_vpath = temp;
		goto start;
	} else if (ret < 0) {
		ret = -ENODEV;
		goto enable_msix_failed;
	}
	return 0;

enable_msix_failed:
	kfree(vdev->vxge_entries);
alloc_vxge_entries_failed:
	kfree(vdev->entries);
alloc_entries_failed:
	return ret;
}

static int vxge_enable_msix(struct vxgedev *vdev)
{

	int i, ret = 0;
	/* 0 - Tx, 1 - Rx  */
	int tim_msix_id[4] = {0, 1, 0, 0};

	vdev->intr_cnt = 0;

	/* allocate msix vectors */
	ret = vxge_alloc_msix(vdev);
	if (!ret) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			struct vxge_vpath *vpath = &vdev->vpaths[i];

			/* If fifo or ring are not enabled, the MSIX vector for
			 * it should be set to 0.
			 */
			vpath->ring.rx_vector_no = (vpath->device_id *
						VXGE_HW_VPATH_MSIX_ACTIVE) + 1;

			vxge_hw_vpath_msix_set(vpath->handle, tim_msix_id,
					       VXGE_ALARM_MSIX_ID);
		}
	}

	return ret;
}

static void vxge_rem_msix_isr(struct vxgedev *vdev)
{
	int intr_cnt;

	for (intr_cnt = 0; intr_cnt < (vdev->no_of_vpath * 2 + 1);
		intr_cnt++) {
		if (vdev->vxge_entries[intr_cnt].in_use) {
			synchronize_irq(vdev->entries[intr_cnt].vector);
			free_irq(vdev->entries[intr_cnt].vector,
				vdev->vxge_entries[intr_cnt].arg);
			vdev->vxge_entries[intr_cnt].in_use = 0;
		}
	}

	kfree(vdev->entries);
	kfree(vdev->vxge_entries);
	vdev->entries = NULL;
	vdev->vxge_entries = NULL;

	if (vdev->config.intr_type == MSI_X)
		pci_disable_msix(vdev->pdev);
}
#endif

static void vxge_rem_isr(struct vxgedev *vdev)
{
	struct __vxge_hw_device  *hldev;
	hldev = (struct __vxge_hw_device  *) pci_get_drvdata(vdev->pdev);

#ifdef CONFIG_PCI_MSI
	if (vdev->config.intr_type == MSI_X) {
		vxge_rem_msix_isr(vdev);
	} else
#endif
	if (vdev->config.intr_type == INTA) {
			synchronize_irq(vdev->pdev->irq);
			free_irq(vdev->pdev->irq, vdev);
	}
}

static int vxge_add_isr(struct vxgedev *vdev)
{
	int ret = 0;
#ifdef CONFIG_PCI_MSI
	int vp_idx = 0, intr_idx = 0, intr_cnt = 0, msix_idx = 0, irq_req = 0;
	int pci_fun = PCI_FUNC(vdev->pdev->devfn);

	if (vdev->config.intr_type == MSI_X)
		ret = vxge_enable_msix(vdev);

	if (ret) {
		vxge_debug_init(VXGE_ERR,
			"%s: Enabling MSI-X Failed", VXGE_DRIVER_NAME);
		vxge_debug_init(VXGE_ERR,
			"%s: Defaulting to INTA", VXGE_DRIVER_NAME);
		vdev->config.intr_type = INTA;
	}

	if (vdev->config.intr_type == MSI_X) {
		for (intr_idx = 0;
		     intr_idx < (vdev->no_of_vpath *
			VXGE_HW_VPATH_MSIX_ACTIVE); intr_idx++) {

			msix_idx = intr_idx % VXGE_HW_VPATH_MSIX_ACTIVE;
			irq_req = 0;

			switch (msix_idx) {
			case 0:
				snprintf(vdev->desc[intr_cnt], VXGE_INTR_STRLEN,
				"%s:vxge:MSI-X %d - Tx - fn:%d vpath:%d",
					vdev->ndev->name,
					vdev->entries[intr_cnt].entry,
					pci_fun, vp_idx);
				ret = request_irq(
				    vdev->entries[intr_cnt].vector,
					vxge_tx_msix_handle, 0,
					vdev->desc[intr_cnt],
					&vdev->vpaths[vp_idx].fifo);
					vdev->vxge_entries[intr_cnt].arg =
						&vdev->vpaths[vp_idx].fifo;
				irq_req = 1;
				break;
			case 1:
				snprintf(vdev->desc[intr_cnt], VXGE_INTR_STRLEN,
				"%s:vxge:MSI-X %d - Rx - fn:%d vpath:%d",
					vdev->ndev->name,
					vdev->entries[intr_cnt].entry,
					pci_fun, vp_idx);
				ret = request_irq(
				    vdev->entries[intr_cnt].vector,
					vxge_rx_msix_napi_handle,
					0,
					vdev->desc[intr_cnt],
					&vdev->vpaths[vp_idx].ring);
					vdev->vxge_entries[intr_cnt].arg =
						&vdev->vpaths[vp_idx].ring;
				irq_req = 1;
				break;
			}

			if (ret) {
				vxge_debug_init(VXGE_ERR,
					"%s: MSIX - %d  Registration failed",
					vdev->ndev->name, intr_cnt);
				vxge_rem_msix_isr(vdev);
				vdev->config.intr_type = INTA;
				vxge_debug_init(VXGE_ERR,
					"%s: Defaulting to INTA"
					, vdev->ndev->name);
					goto INTA_MODE;
			}

			if (irq_req) {
				/* We requested for this msix interrupt */
				vdev->vxge_entries[intr_cnt].in_use = 1;
				msix_idx +=  vdev->vpaths[vp_idx].device_id *
					VXGE_HW_VPATH_MSIX_ACTIVE;
				vxge_hw_vpath_msix_unmask(
					vdev->vpaths[vp_idx].handle,
					msix_idx);
				intr_cnt++;
			}

			/* Point to next vpath handler */
			if (((intr_idx + 1) % VXGE_HW_VPATH_MSIX_ACTIVE == 0) &&
			    (vp_idx < (vdev->no_of_vpath - 1)))
				vp_idx++;
		}

		intr_cnt = vdev->no_of_vpath * 2;
		snprintf(vdev->desc[intr_cnt], VXGE_INTR_STRLEN,
			"%s:vxge:MSI-X %d - Alarm - fn:%d",
			 vdev->ndev->name,
			vdev->entries[intr_cnt].entry,
			pci_fun);
		/* For Alarm interrupts */
		ret = request_irq(vdev->entries[intr_cnt].vector,
					vxge_alarm_msix_handle, 0,
					vdev->desc[intr_cnt],
					&vdev->vpaths[0]);
		if (ret) {
			vxge_debug_init(VXGE_ERR,
				"%s: MSIX - %d Registration failed",
				vdev->ndev->name, intr_cnt);
			vxge_rem_msix_isr(vdev);
			vdev->config.intr_type = INTA;
			vxge_debug_init(VXGE_ERR,
				"%s: Defaulting to INTA",
				vdev->ndev->name);
				goto INTA_MODE;
		}

		msix_idx = (vdev->vpaths[0].handle->vpath->vp_id *
			VXGE_HW_VPATH_MSIX_ACTIVE) + VXGE_ALARM_MSIX_ID;
		vxge_hw_vpath_msix_unmask(vdev->vpaths[vp_idx].handle,
					msix_idx);
		vdev->vxge_entries[intr_cnt].in_use = 1;
		vdev->vxge_entries[intr_cnt].arg = &vdev->vpaths[0];
	}
INTA_MODE:
#endif

	if (vdev->config.intr_type == INTA) {
		snprintf(vdev->desc[0], VXGE_INTR_STRLEN,
			"%s:vxge:INTA", vdev->ndev->name);
		vxge_hw_device_set_intr_type(vdev->devh,
			VXGE_HW_INTR_MODE_IRQLINE);
		vxge_hw_vpath_tti_ci_set(vdev->devh,
			vdev->vpaths[0].device_id);
		ret = request_irq((int) vdev->pdev->irq,
			vxge_isr_napi,
			IRQF_SHARED, vdev->desc[0], vdev);
		if (ret) {
			vxge_debug_init(VXGE_ERR,
				"%s %s-%d: ISR registration failed",
				VXGE_DRIVER_NAME, "IRQ", vdev->pdev->irq);
			return -ENODEV;
		}
		vxge_debug_init(VXGE_TRACE,
			"new %s-%d line allocated",
			"IRQ", vdev->pdev->irq);
	}

	return VXGE_HW_OK;
}

static void vxge_poll_vp_reset(unsigned long data)
{
	struct vxgedev *vdev = (struct vxgedev *)data;
	int i, j = 0;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		if (test_bit(i, &vdev->vp_reset)) {
			vxge_reset_vpath(vdev, i);
			j++;
		}
	}
	if (j && (vdev->config.intr_type != MSI_X)) {
		vxge_hw_device_unmask_all(vdev->devh);
		vxge_hw_device_flush_io(vdev->devh);
	}

	mod_timer(&vdev->vp_reset_timer, jiffies + HZ / 2);
}

static void vxge_poll_vp_lockup(unsigned long data)
{
	struct vxgedev *vdev = (struct vxgedev *)data;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxge_vpath *vpath;
	struct vxge_ring *ring;
	int i;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		ring = &vdev->vpaths[i].ring;
		/* Did this vpath received any packets */
		if (ring->stats.prev_rx_frms == ring->stats.rx_frms) {
			status = vxge_hw_vpath_check_leak(ring->handle);

			/* Did it received any packets last time */
			if ((VXGE_HW_FAIL == status) &&
				(VXGE_HW_FAIL == ring->last_status)) {

				/* schedule vpath reset */
				if (!test_and_set_bit(i, &vdev->vp_reset)) {
					vpath = &vdev->vpaths[i];

					/* disable interrupts for this vpath */
					vxge_vpath_intr_disable(vdev, i);

					/* stop the queue for this vpath */
					vxge_stop_tx_queue(&vpath->fifo);
					continue;
				}
			}
		}
		ring->stats.prev_rx_frms = ring->stats.rx_frms;
		ring->last_status = status;
	}

	/* Check every 1 milli second */
	mod_timer(&vdev->vp_lockup_timer, jiffies + HZ / 1000);
}

static void vxge_napi_del_all(struct vxgedev *vdev)
{
	int i;
	if (vdev->config.intr_type != MSI_X) {
		free_netdev(vdev->napi.dev);
		vdev->napi.dev = NULL;
	} else {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			if (!vdev->vpaths[i].ring.napi.dev)
				break;
			free_netdev(vdev->vpaths[i].ring.napi.dev);
			vdev->vpaths[i].ring.napi.dev = NULL;
		}
	}
}

/**
 * vxge_open
 * @dev: pointer to the device structure.
 *
 * This function is the open entry point of the driver. It mainly calls a
 * function to allocate Rx buffers and inserts them into the buffer
 * descriptors and then enables the Rx part of the NIC.
 * Return value: '0' on success and an appropriate (-)ve integer as
 * defined in errno.h file on failure.
 */
int
vxge_open(struct net_device *dev)
{
	enum vxge_hw_status status;
	struct vxgedev *vdev;
	struct __vxge_hw_device *hldev;
	struct vxge_vpath *vpath;
	int ret = 0;
	int i;
	u64 val64, function_mode;
	struct net_device *napi_nd;
	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d", dev->name, __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);
	function_mode = vdev->config.device_hw_info.function_mode;

	/* make sure you have link off by default every time Nic is
	 * initialized */
	netif_carrier_off(dev);

	/* Open VPATHs */
	status = vxge_open_vpaths(vdev);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: fatal: Vpath open failed", vdev->ndev->name);
		ret = -EPERM;
		goto out0;
	}

	vdev->mtu = dev->mtu;

	status = vxge_add_isr(vdev);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: fatal: ISR add failed", dev->name);
		ret = -EPERM;
		goto out1;
	}


	if (vdev->config.intr_type != MSI_X) {
		napi_nd = alloc_netdev(0, "", ether_setup);
		if (!napi_nd) {
			ret = -ENOMEM;
			goto out2;
		}

		napi_nd->priv = vdev;
		napi_nd->weight = vdev->config.napi_weight;
		napi_nd->poll = rhel_vxge_poll_inta;
		set_bit(__LINK_STATE_START, &napi_nd->state);
		vdev->napi.dev = napi_nd;
		netif_poll_enable(napi_nd);
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vpath->ring.napi_p = &vdev->napi;
		}
	} else {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			napi_nd = alloc_netdev(0, "", ether_setup);
			if (!napi_nd) {
				ret = -ENOMEM;
				goto out3;
			}

			napi_nd->priv = &vpath->ring;
			napi_nd->weight = vdev->config.napi_weight;
			napi_nd->poll = rhel_vxge_poll_msix;
			set_bit(__LINK_STATE_START, &napi_nd->state);
			vpath->ring.napi.dev = napi_nd;
			netif_poll_enable(napi_nd);
			vpath->ring.napi_p = &vpath->ring.napi;
		}
	}

	/* configure RTH */
	if (vdev->config.rth_steering) {
		status = vxge_rth_configure(vdev);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s: fatal: RTH configuration failed",
				dev->name);
			ret = -EPERM;
			goto out3;
		}
	}

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];

		/* set initial mtu before enabling the device */
		status = vxge_hw_vpath_mtu_set(vpath->handle, vdev->mtu);
		if (status != VXGE_HW_OK) {
			vxge_debug_init(VXGE_ERR,
				"%s: fatal: can not set new MTU", dev->name);
			ret = -EPERM;
			goto out3;
		}
	}

	VXGE_DEVICE_DEBUG_LEVEL_SET(VXGE_TRACE, VXGE_COMPONENT_LL, vdev);
	vxge_debug_init(vdev->level_trace,
		"%s: MTU is %d", vdev->ndev->name, vdev->mtu);
	VXGE_DEVICE_DEBUG_LEVEL_SET(VXGE_ERR, VXGE_COMPONENT_LL, vdev);

	/* Restore the DA, VID table and also multicast and promiscuous mode
	 * states
	 */
	if (vdev->all_multi_flg) {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			vpath = &vdev->vpaths[i];
			vxge_restore_vpath_mac_addr(vpath);
			vxge_restore_vpath_vid_table(vpath);

			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR,
					"%s:%d Enabling multicast failed",
					__func__, __LINE__);
		}
	}

	/* Enable vpath to sniff all unicast/multicast traffic that not
	 * addressed to them. We allow promiscous mode for PF only
	 */

	val64 = 0;
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
		val64 |= VXGE_HW_RXMAC_AUTHORIZE_ALL_ADDR_VP(i);

	vxge_hw_mgmt_reg_write(vdev->devh,
		vxge_hw_mgmt_reg_type_mrpcim,
		0,
		(ulong)offsetof(struct vxge_hw_mrpcim_reg,
			rxmac_authorize_all_addr),
		val64);

	vxge_hw_mgmt_reg_write(vdev->devh,
		vxge_hw_mgmt_reg_type_mrpcim,
		0,
		(ulong)offsetof(struct vxge_hw_mrpcim_reg,
			rxmac_authorize_all_vid),
		val64);

	vxge_set_multicast(dev);

	/* Enabling Bcast and mcast for all vpath */
	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];
		status = vxge_hw_vpath_bcast_enable(vpath->handle);
		if (status != VXGE_HW_OK)
			vxge_debug_init(VXGE_ERR,
				"%s : Can not enable bcast for vpath "
				"id %d", dev->name, i);
		if (vdev->config.addr_learn_en) {
			status = vxge_hw_vpath_mcast_enable(vpath->handle);
			if (status != VXGE_HW_OK)
				vxge_debug_init(VXGE_ERR,
					"%s : Can not enable mcast for vpath "
					"id %d", dev->name, i);
		}
	}

	vxge_hw_device_setpause_data(vdev->devh, 0,
		vdev->config.tx_pause_enable,
		vdev->config.rx_pause_enable);

	if (vdev->vp_reset_timer.function == NULL)
		vxge_os_timer(vdev->vp_reset_timer,
			vxge_poll_vp_reset, vdev, (HZ/2));

	if (vdev->vp_lockup_timer.function == NULL)
		vxge_os_timer(vdev->vp_lockup_timer,
			vxge_poll_vp_lockup, vdev, (HZ/2));

	set_bit(__VXGE_STATE_CARD_UP, &vdev->state);

	smp_wmb();

	if (vxge_hw_device_link_state_get(vdev->devh) == VXGE_HW_LINK_UP) {
		netif_carrier_on(vdev->ndev);
		printk(KERN_NOTICE "%s: Link Up\n", vdev->ndev->name);
		vdev->stats.link_up++;
	}

	vxge_hw_device_intr_enable(vdev->devh);

	smp_wmb();

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vpath = &vdev->vpaths[i];

		vxge_hw_vpath_enable(vpath->handle);
		smp_wmb();
		vxge_hw_vpath_rx_doorbell_init(vpath->handle);
	}

	vxge_start_all_tx_queue(vdev);
	goto out0;

out3:
	/* Disable napi */
	if (vdev->config.intr_type != MSI_X)
		netif_poll_disable(vdev->napi.dev);
	else {
		for (i = 0; i < vdev->no_of_vpath; i++) {
			if (!vdev->vpaths[i].ring.napi.dev)
				break;
			netif_poll_disable(vdev->vpaths[i].ring.napi.dev);
		}
	}
	vxge_napi_del_all(vdev);
out2:
	vxge_rem_isr(vdev);
out1:
	vxge_close_vpaths(vdev, 0);
out0:
	vxge_debug_entryexit(VXGE_TRACE,
				"%s: %s:%d  Exiting...",
				dev->name, __func__, __LINE__);
	return ret;
}

/* Loop throught the mac address list and delete all the entries */
void vxge_free_mac_add_list(struct vxge_vpath *vpath)
{

	struct list_head *entry, *next;
	if (list_empty(&vpath->mac_addr_list))
		return;

	list_for_each_safe(entry, next, &vpath->mac_addr_list) {
		list_del(entry);
		kfree((struct vxge_mac_addrs *)entry);
	}
}

int do_vxge_close(struct net_device *dev, int do_io)
{
	enum vxge_hw_status status;
	struct vxgedev *vdev;
	struct __vxge_hw_device *hldev;
	int i;
	u64 val64, vpath_vector;
	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d",
		dev->name, __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);
	hldev = (struct __vxge_hw_device *) pci_get_drvdata(vdev->pdev);

	if (unlikely(!is_vxge_card_up(vdev)))
		return 0;

	/* If vxge_handle_crit_err task is executing,
	 * wait till it completes. */
	while (test_and_set_bit(__VXGE_STATE_RESET_CARD, &vdev->state))
		msleep(50);

	clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
	if (do_io) {
		/* Put the vpath back in normal mode */
		vpath_vector = vxge_mBIT(vdev->vpaths[0].device_id);
		status = vxge_hw_mgmt_reg_read(vdev->devh,
				vxge_hw_mgmt_reg_type_mrpcim,
				0,
				(ulong)offsetof(
					struct vxge_hw_mrpcim_reg,
					rts_mgr_cbasin_cfg),
				&val64);

		if (status == VXGE_HW_OK) {
			val64 &= ~vpath_vector;
			status = vxge_hw_mgmt_reg_write(vdev->devh,
					vxge_hw_mgmt_reg_type_mrpcim,
					0,
					(ulong)offsetof(
						struct vxge_hw_mrpcim_reg,
						rts_mgr_cbasin_cfg),
					val64);
		}

		/* Remove the function 0 from promiscous mode */
		vxge_hw_mgmt_reg_write(vdev->devh,
			vxge_hw_mgmt_reg_type_mrpcim,
			0,
			(ulong)offsetof(struct vxge_hw_mrpcim_reg,
				rxmac_authorize_all_addr),
			0);

		vxge_hw_mgmt_reg_write(vdev->devh,
			vxge_hw_mgmt_reg_type_mrpcim,
			0,
			(ulong)offsetof(struct vxge_hw_mrpcim_reg,
				rxmac_authorize_all_vid),
			0);

		smp_wmb();
	}
	del_timer_sync(&vdev->vp_lockup_timer);

	del_timer_sync(&vdev->vp_reset_timer);

	/* Disable napi */
	if (vdev->config.intr_type != MSI_X)
		netif_poll_disable(vdev->napi.dev);
	else {
		for (i = 0; i < vdev->no_of_vpath; i++)
			netif_poll_disable(vdev->vpaths[i].ring.napi.dev);
	}

	netif_carrier_off(vdev->ndev);
	printk(KERN_NOTICE "%s: Link Down\n", vdev->ndev->name);
	vxge_stop_all_tx_queue(vdev);

	/* Note that at this point xmit() is stopped by upper layer */
	if (do_io)
		vxge_hw_device_intr_disable(vdev->devh);

	mdelay(1000);

	vxge_rem_isr(vdev);

	vxge_napi_del_all(vdev);

	if (do_io)
		vxge_reset_all_vpaths(vdev);

	vxge_close_vpaths(vdev, 0);

	vxge_debug_entryexit(VXGE_TRACE,
		"%s: %s:%d  Exiting...", dev->name, __func__, __LINE__);

	clear_bit(__VXGE_STATE_RESET_CARD, &vdev->state);

	return 0;
}

/**
 * vxge_close
 * @dev: device pointer.
 *
 * This is the stop entry point of the driver. It needs to undo exactly
 * whatever was done by the open entry point, thus it's usually referred to
 * as the close function.Among other things this function mainly stops the
 * Rx side of the NIC and frees all the Rx buffers in the Rx rings.
 * Return value: '0' on success and an appropriate (-)ve integer as
 * defined in errno.h file on failure.
 */
int
vxge_close(struct net_device *dev)
{
	do_vxge_close(dev, 1);
	return 0;
}

/**
 * vxge_change_mtu
 * @dev: net device pointer.
 * @new_mtu :the new MTU size for the device.
 *
 * A driver entry point to change MTU size for the device. Before changing
 * the MTU the device must be stopped.
 */
static int vxge_change_mtu(struct net_device *dev, int new_mtu)
{
	struct vxgedev *vdev = netdev_priv(dev);

	vxge_debug_entryexit(vdev->level_trace,
		"%s:%d", __func__, __LINE__);
	if ((new_mtu < VXGE_HW_MIN_MTU) || (new_mtu > VXGE_HW_MAX_MTU)) {
		vxge_debug_init(vdev->level_err,
			"%s: mtu size is invalid", dev->name);
		return -EPERM;
	}

	/* check if device is down already */
	if (unlikely(!is_vxge_card_up(vdev))) {
		/* just store new value, will use later on open() */
		dev->mtu = new_mtu;
		vxge_debug_init(vdev->level_err,
			"%s", "device is down on MTU change");
		return 0;
	}

	vxge_debug_init(vdev->level_trace,
		"trying to apply new MTU %d", new_mtu);

	if (vxge_close(dev))
		return -EIO;

	dev->mtu = new_mtu;
	vdev->mtu = new_mtu;

	if (vxge_open(dev))
		return -EIO;

	vxge_debug_init(vdev->level_trace,
		"%s: MTU changed to %d", vdev->ndev->name, new_mtu);

	vxge_debug_entryexit(vdev->level_trace,
		"%s:%d  Exiting...", __func__, __LINE__);

	return 0;
}

/**
 * vxge_get_stats
 * @dev: pointer to the device structure
 *
 * Updates the device statistics structure. This function updates the device
 * statistics structure in the net_device structure and returns a pointer
 * to the same.
 */
static struct net_device_stats *
vxge_get_stats(struct net_device *dev)
{
	struct vxgedev *vdev;
	struct net_device_stats *net_stats;
	int k;

	vdev = netdev_priv(dev);

	net_stats = &vdev->stats.net_stats;

	memset(net_stats, 0, sizeof(struct net_device_stats));

	for (k = 0; k < vdev->no_of_vpath; k++) {
		net_stats->rx_packets += vdev->vpaths[k].ring.stats.rx_frms;
		net_stats->rx_bytes += vdev->vpaths[k].ring.stats.rx_bytes;
		net_stats->rx_errors += vdev->vpaths[k].ring.stats.rx_errors;
		net_stats->multicast += vdev->vpaths[k].ring.stats.rx_mcast;
		net_stats->rx_dropped +=
			vdev->vpaths[k].ring.stats.rx_dropped;

		net_stats->tx_packets += vdev->vpaths[k].fifo.stats.tx_frms;
		net_stats->tx_bytes += vdev->vpaths[k].fifo.stats.tx_bytes;
		net_stats->tx_errors += vdev->vpaths[k].fifo.stats.tx_errors;
	}

	return net_stats;
}

/**
 * vxge_ioctl
 * @dev: Device pointer.
 * @ifr: An IOCTL specific structure, that can contain a pointer to
 *       a proprietary structure used to pass information to the driver.
 * @cmd: This is used to distinguish between the different commands that
 *       can be passed to the IOCTL functions.
 *
 * Entry point for the Ioctl.
 */
static int vxge_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	return -EOPNOTSUPP;
}

/**
 * vxge_tx_watchdog
 * @dev: pointer to net device structure
 *
 * Watchdog for transmit side.
 * This function is triggered if the Tx Queue is stopped
 * for a pre-defined amount of time when the Interface is still up.
 */
static void
vxge_tx_watchdog(struct net_device *dev)
{
	struct vxgedev *vdev;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);

	vdev->cric_err_event = VXGE_HW_EVENT_RESET_START;

	vxge_reset(vdev);
	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_vlan_rx_register
 * @dev: net device pointer.
 * @grp: vlan group
 *
 * Vlan group registration
 */
static void
vxge_vlan_rx_register(struct net_device *dev, struct vlan_group *grp)
{
	struct vxgedev *vdev;
	struct vxge_vpath *vpath;
	int vp;
	u64 vid;
	enum vxge_hw_status status;
	int i;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);

	vpath = &vdev->vpaths[0];
	if ((NULL == grp) && (vpath->is_open)) {
		/* Get the first vlan */
		status = vxge_hw_vpath_vid_get(vpath->handle, &vid);

		while (status == VXGE_HW_OK) {

			/* Delete this vlan from the vid table */
			for (vp = 0; vp < vdev->no_of_vpath; vp++) {
				vpath = &vdev->vpaths[vp];
				if (!vpath->is_open)
					continue;

				vxge_hw_vpath_vid_delete(vpath->handle, vid);
			}

			/* Get the next vlan to be deleted */
			vpath = &vdev->vpaths[0];
			status = vxge_hw_vpath_vid_get(vpath->handle, &vid);
		}
	}

	vdev->vlgrp = grp;

	for (i = 0; i < vdev->no_of_vpath; i++) {
		if (vdev->vpaths[i].is_configured)
			vdev->vpaths[i].ring.vlgrp = grp;
	}

	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

/**
 * vxge_vlan_rx_add_vid
 * @dev: net device pointer.
 * @vid: vid
 *
 * Add the vlan id to the devices vlan id table
 */
static void
vxge_vlan_rx_add_vid(struct net_device *dev, unsigned short vid)
{
	struct vxgedev *vdev;
	struct vxge_vpath *vpath;
	int vp_id;

	vdev = (struct vxgedev *)netdev_priv(dev);

	/* Add these vlan to the vid table */
	for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
		vpath = &vdev->vpaths[vp_id];
		if (!vpath->is_open)
			continue;
		vxge_hw_vpath_vid_add(vpath->handle, vid);
	}
}

/**
 * vxge_vlan_rx_add_vid
 * @dev: net device pointer.
 * @vid: vid
 *
 * Remove the vlan id from the device's vlan id table
 */
static void
vxge_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct vxgedev *vdev;
	struct vxge_vpath *vpath;
	int vp_id;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);

	vdev = (struct vxgedev *)netdev_priv(dev);

	vlan_group_set_device(vdev->vlgrp, vid, NULL);

	/* Delete this vlan from the vid table */
	for (vp_id = 0; vp_id < vdev->no_of_vpath; vp_id++) {
		vpath = &vdev->vpaths[vp_id];
		if (!vpath->is_open)
			continue;
		vxge_hw_vpath_vid_delete(vpath->handle, vid);
	}
	vxge_debug_entryexit(VXGE_TRACE,
		"%s:%d  Exiting...", __func__, __LINE__);
}

int __devinit vxge_device_register(struct __vxge_hw_device *hldev,
				   struct vxge_config *config,
				   int high_dma, int no_of_vpath,
				   struct vxgedev **vdev_out)
{
	struct net_device *ndev;
	enum vxge_hw_status status = VXGE_HW_OK;
	struct vxgedev *vdev;
	int i, ret = 0, no_of_queue = 1;
	u64 stat;

	*vdev_out = NULL;
	if (config->tx_steering_type == TX_MULTIQ_STEERING)
		no_of_queue = no_of_vpath;

	ndev = alloc_etherdev_mq(sizeof(struct vxgedev),
			no_of_queue);
	if (ndev == NULL) {
		vxge_debug_init(
			vxge_hw_device_trace_level_get(hldev),
		"%s : device allocation failed", __func__);
		ret = -ENODEV;
		goto _out0;
	}

	vxge_debug_entryexit(
		vxge_hw_device_trace_level_get(hldev),
		"%s: %s:%d  Entering...",
		ndev->name, __func__, __LINE__);

	vdev = netdev_priv(ndev);
	memset(vdev, 0, sizeof(struct vxgedev));

	vdev->ndev = ndev;
	vdev->devh = hldev;
	vdev->pdev = hldev->pdev;
	memcpy(&vdev->config, config, sizeof(struct vxge_config));
	vdev->rx_csum = 1;	/* Enable Rx CSUM by default. */

	SET_NETDEV_DEV(ndev, &vdev->pdev->dev);

	ndev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX |
				NETIF_F_HW_VLAN_FILTER;
	/*  Driver entry points */
	ndev->irq = vdev->pdev->irq;
	ndev->base_addr = (unsigned long) hldev->bar0;

	ndev->open = vxge_open;
	ndev->stop = vxge_close;
	ndev->hard_start_xmit = vxge_xmit;
	ndev->set_mac_address = vxge_set_mac_addr;
	ndev->get_stats = vxge_get_stats;
	ndev->set_multicast_list = vxge_set_multicast;
	ndev->change_mtu = vxge_change_mtu;
	ndev->vlan_rx_register = vxge_vlan_rx_register;
	ndev->vlan_rx_add_vid = vxge_vlan_rx_add_vid;
	ndev->vlan_rx_kill_vid = vxge_vlan_rx_kill_vid;
	ndev->tx_timeout = vxge_tx_watchdog;
	ndev->do_ioctl = vxge_ioctl;
#ifdef CONFIG_NET_POLL_CONTROLLER
	ndev->poll_controller = vxge_netpoll;
#endif
	ndev->watchdog_timeo = VXGE_LL_WATCH_DOG_TIMEOUT;

	initialize_ethtool_ops(ndev);

	/* Allocate memory for vpath */
	vdev->vpaths = kzalloc((sizeof(struct vxge_vpath)) *
				no_of_vpath, GFP_KERNEL);
	if (!vdev->vpaths) {
		vxge_debug_init(VXGE_ERR,
			"%s: vpath memory allocation failed",
			vdev->ndev->name);
		ret = -ENODEV;
		goto _out1;
	}

	ndev->features |= NETIF_F_SG;

	ndev->features |= NETIF_F_HW_CSUM;
	vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
		"%s : checksuming enabled", __func__);

	if (high_dma) {
		ndev->features |= NETIF_F_HIGHDMA;
		vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
			"%s : using High DMA", __func__);
	}

	ndev->features |= NETIF_F_TSO | NETIF_F_TSO6;

	if (vdev->config.gro_enable)
		ndev->features |= NETIF_F_GRO;

#if 0 /* MQ not in RHEL5 */
	if (vdev->config.tx_steering_type == TX_MULTIQ_STEERING)
		ndev->real_num_tx_queues = no_of_vpath;
#endif

#ifdef NETIF_F_LLTX
	ndev->features |= NETIF_F_LLTX;
#endif

	for (i = 0; i < no_of_vpath; i++) {
		spin_lock_init(&vdev->vpaths[i].fifo.tx_lock);
		spin_lock_init(&vdev->vpaths[i].ring.poll_lock);
	}

	if (register_netdev(ndev)) {
		vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
			"%s: %s : device registration failed!",
			ndev->name, __func__);
		ret = -ENODEV;
		goto _out2;
	}

	/*  Set the factory defined MAC address initially */
	ndev->addr_len = ETH_ALEN;

	/* Make Link state as off at this point, when the Link change
	 * interrupt comes the state will be automatically changed to
	 * the right state.
	 */
	netif_carrier_off(ndev);

	vxge_debug_init(vxge_hw_device_trace_level_get(hldev),
		"%s: Ethernet device registered",
		ndev->name);

	*vdev_out = vdev;

	/* Resetting the Device stats */
	status = vxge_hw_mrpcim_stats_access(
				hldev,
				VXGE_HW_STATS_OP_CLEAR_ALL_STATS,
				0,
				0,
				&stat);

	if (status == VXGE_HW_ERR_PRIVILAGED_OPEARATION)
		vxge_debug_init(
			vxge_hw_device_trace_level_get(hldev),
			"%s: device stats clear returns"
			"VXGE_HW_ERR_PRIVILAGED_OPEARATION", ndev->name);

	vxge_debug_entryexit(vxge_hw_device_trace_level_get(hldev),
		"%s: %s:%d  Exiting...",
		ndev->name, __func__, __LINE__);

	return ret;
_out2:
	kfree(vdev->vpaths);
_out1:
	free_netdev(ndev);
_out0:
	return ret;
}

/*
 * vxge_device_unregister
 *
 * This function will unregister and free network device
 */
void
vxge_device_unregister(struct __vxge_hw_device *hldev)
{
	struct vxgedev *vdev;
	struct net_device *dev;
	char buf[IFNAMSIZ];
#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	u32 level_trace;
#endif

	dev = hldev->ndev;
	vdev = netdev_priv(dev);
#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	level_trace = vdev->level_trace;
#endif
	vxge_debug_entryexit(level_trace,
		"%s: %s:%d", vdev->ndev->name, __func__, __LINE__);

	memcpy(buf, vdev->ndev->name, IFNAMSIZ);

	/* in 2.6 will call stop() if device is up */
	unregister_netdev(dev);

	flush_scheduled_work();

	vxge_debug_init(level_trace, "%s: ethernet device unregistered", buf);
	vxge_debug_entryexit(level_trace,
		"%s: %s:%d  Exiting...", buf, __func__, __LINE__);
}

/*
 * vxge_callback_crit_err
 *
 * This function is called by the alarm handler in interrupt context.
 * Driver must analyze it based on the event type.
 */
static void
vxge_callback_crit_err(struct __vxge_hw_device *hldev,
			enum vxge_hw_event type, u64 vp_id)
{
	struct net_device *dev = hldev->ndev;
	struct vxgedev *vdev = (struct vxgedev *)netdev_priv(dev);
	int vpath_idx;

	vxge_debug_entryexit(vdev->level_trace,
		"%s: %s:%d", vdev->ndev->name, __func__, __LINE__);

	/* Note: This event type should be used for device wide
	 * indications only - Serious errors, Slot freeze and critical errors
	 */
	vdev->cric_err_event = type;

	for (vpath_idx = 0; vpath_idx < vdev->no_of_vpath; vpath_idx++)
		if (vdev->vpaths[vpath_idx].device_id == vp_id)
			break;

	if (!test_bit(__VXGE_STATE_RESET_CARD, &vdev->state)) {
		if (type == VXGE_HW_EVENT_SLOT_FREEZE) {
			vxge_debug_init(VXGE_ERR,
				"%s: Slot is frozen", vdev->ndev->name);
		} else if (type == VXGE_HW_EVENT_SERR) {
			vxge_debug_init(VXGE_ERR,
				"%s: Encountered Serious Error",
				vdev->ndev->name);
		} else if (type == VXGE_HW_EVENT_CRITICAL_ERR)
			vxge_debug_init(VXGE_ERR,
				"%s: Encountered Critical Error",
				vdev->ndev->name);
	}

	if ((type == VXGE_HW_EVENT_SERR) ||
		(type == VXGE_HW_EVENT_SLOT_FREEZE)) {
		if (unlikely(vdev->exec_mode))
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
	} else if (type == VXGE_HW_EVENT_CRITICAL_ERR) {
		vxge_hw_device_mask_all(hldev);
		if (unlikely(vdev->exec_mode))
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
	} else if ((type == VXGE_HW_EVENT_FIFO_ERR) ||
		  (type == VXGE_HW_EVENT_VPATH_ERR)) {

		if (unlikely(vdev->exec_mode))
			clear_bit(__VXGE_STATE_CARD_UP, &vdev->state);
		else {
			/* check if this vpath is already set for reset */
			if (!test_and_set_bit(vpath_idx, &vdev->vp_reset)) {

				/* disable interrupts for this vpath */
				vxge_vpath_intr_disable(vdev, vpath_idx);

				/* stop the queue for this vpath */
				vxge_stop_tx_queue(&vdev->vpaths[vpath_idx].
							fifo);
			}
		}
	}

	vxge_debug_entryexit(vdev->level_trace,
		"%s: %s:%d  Exiting...",
		vdev->ndev->name, __func__, __LINE__);
}

static void verify_bandwidth(void)
{
	int i, band_width, total = 0, equal_priority = 0;

	/* 1. If user enters 0 for some fifo, give equal priority to all */
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (bw_percentage[i] == 0) {
			equal_priority = 1;
			break;
		}
	}

	if (!equal_priority) {
		/* 2. If sum exceeds 100, give equal priority to all */
		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
			if (bw_percentage[i] == 0xFF)
				break;

			total += bw_percentage[i];
			if (total > VXGE_HW_VPATH_BANDWIDTH_MAX) {
				equal_priority = 1;
				break;
			}
		}
	}

	if (!equal_priority) {
		/* Is all the bandwidth consumed? */
		if (total < VXGE_HW_VPATH_BANDWIDTH_MAX) {
			if (i < VXGE_HW_MAX_VIRTUAL_PATHS) {
				/* Split rest of bw equally among next VPs*/
				band_width =
				  (VXGE_HW_VPATH_BANDWIDTH_MAX  - total) /
					(VXGE_HW_MAX_VIRTUAL_PATHS - i);
				if (band_width < 2) /* min of 2% */
					equal_priority = 1;
				else {
					for (; i < VXGE_HW_MAX_VIRTUAL_PATHS;
						i++)
						bw_percentage[i] =
							band_width;
				}
			}
		} else if (i < VXGE_HW_MAX_VIRTUAL_PATHS)
			equal_priority = 1;
	}

	if (equal_priority) {
		vxge_debug_init(VXGE_ERR,
			"%s: Assigning equal bandwidth to all the vpaths",
			VXGE_DRIVER_NAME);
		bw_percentage[0] = VXGE_HW_VPATH_BANDWIDTH_MAX /
					VXGE_HW_MAX_VIRTUAL_PATHS;
		for (i = 1; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
			bw_percentage[i] = bw_percentage[0];
	}
}

/*
 * Vpath configuration
 */
static int __devinit vxge_config_vpaths(
			struct vxge_hw_device_config *device_config,
			u64 vpath_mask, struct vxge_config *config_param)
{
	int i, no_of_vpaths = 0, default_no_vpath = 0, temp;
	u32 txdl_size, txdl_per_memblock;

	temp = driver_config->vpath_per_dev;
	if ((driver_config->vpath_per_dev == VXGE_USE_DEFAULT) &&
		(max_config_dev == VXGE_MAX_CONFIG_DEV)) {
		/* No more CPU. Return vpath number as zero.*/
		if (driver_config->g_no_cpus == -1)
			return 0;

		if (!driver_config->g_no_cpus)
			driver_config->g_no_cpus = num_online_cpus();

		driver_config->vpath_per_dev = driver_config->g_no_cpus >> 1;
		if (!driver_config->vpath_per_dev)
			driver_config->vpath_per_dev = 1;

		for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
			if (!vxge_bVALn(vpath_mask, i, 1))
				continue;
			else
				default_no_vpath++;
		if (default_no_vpath < driver_config->vpath_per_dev)
			driver_config->vpath_per_dev = default_no_vpath;

		driver_config->g_no_cpus = driver_config->g_no_cpus -
				(driver_config->vpath_per_dev * 2);
		if (driver_config->g_no_cpus <= 0)
			driver_config->g_no_cpus = -1;
	}

	if (driver_config->vpath_per_dev == 1) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: Disable tx and rx steering, "
			"as single vpath is configured", VXGE_DRIVER_NAME);
		config_param->rth_steering = NO_STEERING;
		config_param->tx_steering_type = NO_STEERING;
		device_config->rth_en = 0;
	}

	/* configure bandwidth */
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++)
		device_config->vp_config[i].min_bandwidth = bw_percentage[i];

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		device_config->vp_config[i].vp_id = i;
		device_config->vp_config[i].mtu = VXGE_HW_DEFAULT_MTU;
		if (no_of_vpaths < driver_config->vpath_per_dev) {
			if (!vxge_bVALn(vpath_mask, i, 1)) {
				vxge_debug_ll_config(VXGE_TRACE,
					"%s: vpath: %d is not available",
					VXGE_DRIVER_NAME, i);
				continue;
			} else {
				vxge_debug_ll_config(VXGE_TRACE,
					"%s: vpath: %d available",
					VXGE_DRIVER_NAME, i);
				no_of_vpaths++;
			}
		} else {
			vxge_debug_ll_config(VXGE_TRACE,
				"%s: vpath: %d is not configured, "
				"max_config_vpath exceeded",
				VXGE_DRIVER_NAME, i);
			break;
		}

		/* Configure Tx fifo's */
		device_config->vp_config[i].fifo.enable =
						VXGE_HW_FIFO_ENABLE;
		device_config->vp_config[i].fifo.max_frags =
				MAX_SKB_FRAGS + 1;
		device_config->vp_config[i].fifo.memblock_size =
			VXGE_HW_MIN_FIFO_MEMBLOCK_SIZE;

		txdl_size = device_config->vp_config[i].fifo.max_frags *
				sizeof(struct vxge_hw_fifo_txd);
		txdl_per_memblock = VXGE_HW_MIN_FIFO_MEMBLOCK_SIZE / txdl_size;

		device_config->vp_config[i].fifo.fifo_blocks =
			((VXGE_DEF_FIFO_LENGTH - 1) / txdl_per_memblock) + 1;

		device_config->vp_config[i].fifo.intr =
				VXGE_HW_FIFO_QUEUE_INTR_DISABLE;

		/* Configure tti properties */
		device_config->vp_config[i].tti.intr_enable =
					VXGE_HW_TIM_INTR_ENABLE;

		device_config->vp_config[i].tti.btimer_val =
			(VXGE_TTI_BTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].tti.timer_ac_en =
				VXGE_HW_TIM_TIMER_AC_ENABLE;

		/* For msi-x with napi (each vector
		has a handler of its own) -
		Set CI to OFF for all vpaths */
		device_config->vp_config[i].tti.timer_ci_en =
			VXGE_HW_TIM_TIMER_CI_DISABLE;

		device_config->vp_config[i].tti.timer_ri_en =
				VXGE_HW_TIM_TIMER_RI_DISABLE;

		device_config->vp_config[i].tti.util_sel =
			VXGE_HW_TIM_UTIL_SEL_LEGACY_TX_NET_UTIL;

		device_config->vp_config[i].tti.ltimer_val =
			(VXGE_TTI_LTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].tti.rtimer_val =
			(VXGE_TTI_RTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].tti.urange_a = TTI_TX_URANGE_A;
		device_config->vp_config[i].tti.urange_b = TTI_TX_URANGE_B;
		device_config->vp_config[i].tti.urange_c = TTI_TX_URANGE_C;
		device_config->vp_config[i].tti.uec_a = TTI_TX_UFC_A;
		device_config->vp_config[i].tti.uec_b = TTI_TX_UFC_B;
		device_config->vp_config[i].tti.uec_c = TTI_TX_UFC_C;
		device_config->vp_config[i].tti.uec_d = TTI_TX_UFC_D;

		/* Configure Rx rings */
		device_config->vp_config[i].ring.enable  =
						VXGE_HW_RING_ENABLE;

		device_config->vp_config[i].ring.ring_blocks  =
						VXGE_HW_DEF_RING_BLOCKS;
		device_config->vp_config[i].ring.buffer_mode =
			VXGE_HW_RING_RXD_BUFFER_MODE_1;
		device_config->vp_config[i].ring.rxds_limit  =
				VXGE_HW_DEF_RING_RXDS_LIMIT;
		device_config->vp_config[i].ring.scatter_mode =
					VXGE_HW_RING_SCATTER_MODE_A;

		/* Configure rti properties */
		device_config->vp_config[i].rti.intr_enable =
					VXGE_HW_TIM_INTR_ENABLE;

		device_config->vp_config[i].rti.btimer_val =
			(VXGE_RTI_BTIMER_VAL * 1000)/272;

		device_config->vp_config[i].rti.timer_ac_en =
						VXGE_HW_TIM_TIMER_AC_ENABLE;

		device_config->vp_config[i].rti.timer_ci_en =
						VXGE_HW_TIM_TIMER_CI_DISABLE;

		device_config->vp_config[i].rti.timer_ri_en =
						VXGE_HW_TIM_TIMER_RI_DISABLE;

		device_config->vp_config[i].rti.util_sel =
				VXGE_HW_TIM_UTIL_SEL_LEGACY_RX_NET_UTIL;

		device_config->vp_config[i].rti.urange_a =
						RTI_RX_URANGE_A;
		device_config->vp_config[i].rti.urange_b =
						RTI_RX_URANGE_B;
		device_config->vp_config[i].rti.urange_c =
						RTI_RX_URANGE_C;
		device_config->vp_config[i].rti.uec_a = RTI_RX_UFC_A;
		device_config->vp_config[i].rti.uec_b = RTI_RX_UFC_B;
		device_config->vp_config[i].rti.uec_c = RTI_RX_UFC_C;
		device_config->vp_config[i].rti.uec_d = RTI_RX_UFC_D;

		device_config->vp_config[i].rti.rtimer_val =
			(VXGE_RTI_RTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].rti.ltimer_val =
			(VXGE_RTI_LTIMER_VAL * 1000) / 272;

		device_config->vp_config[i].rpa_strip_vlan_tag =
			vlan_tag_strip;
	}

	driver_config->vpath_per_dev = temp;
	return no_of_vpaths;
}

/* initialize device configuratrions */
static void __devinit vxge_device_config_init(
				struct vxge_hw_device_config *device_config,
				int *intr_type)
{
	/* Used for CQRQ/SRQ. */
	device_config->dma_blockpool_initial =
			VXGE_HW_INITIAL_DMA_BLOCK_POOL_SIZE;

	device_config->dma_blockpool_max =
			VXGE_HW_MAX_DMA_BLOCK_POOL_SIZE;

	if (max_mac_vpath > VXGE_MAX_MAC_ADDR_COUNT)
		max_mac_vpath = VXGE_MAX_MAC_ADDR_COUNT;

#ifndef CONFIG_PCI_MSI
	vxge_debug_init(VXGE_ERR,
		"%s: This Kernel does not support "
		"MSI-X. Defaulting to INTA", VXGE_DRIVER_NAME);
	*intr_type = INTA;
#endif

	/* Configure whether MSI-X or IRQL. */
	switch (*intr_type) {
	case INTA:
		device_config->intr_mode = VXGE_HW_INTR_MODE_IRQLINE;
		break;

	case MSI_X:
		device_config->intr_mode = VXGE_HW_INTR_MODE_MSIX;
		break;
	}
	/* Timer period between device poll */
	device_config->device_poll_millis = VXGE_TIMER_DELAY;

	/* Configure mac based steering. */
	device_config->rts_mac_en = addr_learn_en;

	/* Configure Vpaths */
	device_config->rth_it_type = VXGE_HW_RTH_IT_TYPE_MULTI_IT;

	vxge_debug_ll_config(VXGE_TRACE, "%s : Device Config Params ",
			__func__);
	vxge_debug_ll_config(VXGE_TRACE, "dma_blockpool_initial : %d",
			device_config->dma_blockpool_initial);
	vxge_debug_ll_config(VXGE_TRACE, "dma_blockpool_max : %d",
			device_config->dma_blockpool_max);
	vxge_debug_ll_config(VXGE_TRACE, "intr_mode : %d",
			device_config->intr_mode);
	vxge_debug_ll_config(VXGE_TRACE, "device_poll_millis : %d",
			device_config->device_poll_millis);
	vxge_debug_ll_config(VXGE_TRACE, "rts_mac_en : %d",
			device_config->rts_mac_en);
	vxge_debug_ll_config(VXGE_TRACE, "rth_en : %d",
			device_config->rth_en);
	vxge_debug_ll_config(VXGE_TRACE, "rth_it_type : %d",
			device_config->rth_it_type);
}

static void __devinit vxge_print_parm(struct vxgedev *vdev, u64 vpath_mask)
{
	int i;

	vxge_debug_init(VXGE_TRACE,
		"%s: %d Vpath(s) opened",
		vdev->ndev->name, vdev->no_of_vpath);

	switch (vdev->config.intr_type) {
	case INTA:
		vxge_debug_init(VXGE_TRACE,
			"%s: Interrupt type INTA", vdev->ndev->name);
		break;

	case MSI_X:
		vxge_debug_init(VXGE_TRACE,
			"%s: Interrupt type MSI-X", vdev->ndev->name);
		break;
	}

	if (vdev->config.rth_steering) {
		vxge_debug_init(VXGE_TRACE,
			"%s: RTH steering enabled for TCP_IPV4",
			vdev->ndev->name);
	} else {
		vxge_debug_init(VXGE_TRACE,
			"%s: RTH steering disabled", vdev->ndev->name);
	}

	switch (vdev->config.tx_steering_type) {
	case NO_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		break;
	case TX_PRIORITY_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Unsupported tx steering option",
			vdev->ndev->name);
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		vdev->config.tx_steering_type = 0;
		break;
	case TX_VLAN_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Unsupported tx steering option",
			vdev->ndev->name);
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		vdev->config.tx_steering_type = 0;
		break;
	case TX_MULTIQ_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx multiqueue steering enabled",
			vdev->ndev->name);
		break;
	case TX_PORT_STEERING:
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx port steering enabled",
			vdev->ndev->name);
		break;
	default:
		vxge_debug_init(VXGE_ERR,
			"%s: Unsupported tx steering type",
			vdev->ndev->name);
		vxge_debug_init(VXGE_TRACE,
			"%s: Tx steering disabled", vdev->ndev->name);
		vdev->config.tx_steering_type = 0;
	}

	if (vdev->config.gro_enable) {
		vxge_debug_init(VXGE_ERR,
			"%s: Generic receive offload enabled",
			vdev->ndev->name);
	} else
		vxge_debug_init(VXGE_TRACE,
			"%s: Generic receive offload disabled",
			vdev->ndev->name);

	if (vdev->config.addr_learn_en)
		vxge_debug_init(VXGE_TRACE,
			"%s: MAC Address learning enabled", vdev->ndev->name);

	vxge_debug_init(VXGE_TRACE,
		"%s: Rx doorbell mode enabled", vdev->ndev->name);

	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!vxge_bVALn(vpath_mask, i, 1))
			continue;
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: MTU size - %d", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].mtu);
		vxge_debug_init(VXGE_TRACE,
			"%s: VLAN tag stripping %s", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].rpa_strip_vlan_tag
			? "Enabled" : "Disabled");
		vxge_debug_init(VXGE_TRACE,
			"%s: Ring blocks : %d", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].ring.ring_blocks);
		vxge_debug_init(VXGE_TRACE,
			"%s: Fifo blocks : %d", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].fifo.fifo_blocks);
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: Max frags : %d", vdev->ndev->name,
			((struct __vxge_hw_device  *)(vdev->devh))->
				config.vp_config[i].fifo.max_frags);
		break;
	}
}

#ifdef CONFIG_PM
/**
 * vxge_pm_suspend - vxge power management suspend entry point
 *
 */
static int vxge_pm_suspend(struct pci_dev *pdev, pm_message_t state)
{
	return -ENOSYS;
}
/**
 * vxge_pm_resume - vxge power management resume entry point
 *
 */
static int vxge_pm_resume(struct pci_dev *pdev)
{
	return -ENOSYS;
}

#endif

/**
 * vxge_io_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
static pci_ers_result_t vxge_io_error_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	netif_device_detach(netdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	if (netif_running(netdev)) {
		/* Bring down the card, while avoiding PCI I/O */
		do_vxge_close(netdev, 0);
	}

	pci_disable_device(pdev);

	return PCI_ERS_RESULT_NEED_RESET;
}

/**
 * vxge_io_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot.
 * At this point, the card has exprienced a hard reset,
 * followed by fixups by BIOS, and has its config space
 * set up identically to what it was at cold boot.
 */
static pci_ers_result_t vxge_io_slot_reset(struct pci_dev *pdev)
{
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	struct vxgedev *vdev = netdev_priv(netdev);

	if (pci_enable_device(pdev)) {
		printk(KERN_ERR "%s: "
			"Cannot re-enable device after reset\n",
			VXGE_DRIVER_NAME);
		return PCI_ERS_RESULT_DISCONNECT;
	}

	pci_set_master(pdev);
	vxge_reset(vdev);

	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * vxge_io_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells
 * us that its OK to resume normal operation.
 */
static void vxge_io_resume(struct pci_dev *pdev)
{
	struct __vxge_hw_device  *hldev =
		(struct __vxge_hw_device  *) pci_get_drvdata(pdev);
	struct net_device *netdev = hldev->ndev;

	if (netif_running(netdev)) {
		if (vxge_open(netdev)) {
			printk(KERN_ERR "%s: "
				"Can't bring device back up after reset\n",
				VXGE_DRIVER_NAME);
			return;
		}
	}

	netif_device_attach(netdev);
}

static inline u32 vxge_get_num_vfs(u64 function_mode)
{
	u32 num_functions = 0;

	switch (function_mode) {
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION:
	case VXGE_HW_FUNCTION_MODE_SRIOV_8:
		num_functions = 8;
		break;
	case VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION:
		num_functions = 1;
		break;
	case VXGE_HW_FUNCTION_MODE_SRIOV:
	case VXGE_HW_FUNCTION_MODE_MRIOV:
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_17:
		num_functions = 17;
		break;
	case VXGE_HW_FUNCTION_MODE_SRIOV_4:
		num_functions = 4;
		break;
	case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION_2:
		num_functions = 2;
		break;
	case VXGE_HW_FUNCTION_MODE_MRIOV_8:
		num_functions = 8; /* TODO */
		break;
	}
	return num_functions;
}

/**
 * vxge_probe
 * @pdev : structure containing the PCI related information of the device.
 * @pre: List of PCI devices supported by the driver listed in vxge_id_table.
 * Description:
 * This function is called when a new PCI device gets detected and initializes
 * it.
 * Return value:
 * returns 0 on success and negative on failure.
 *
 */
static int __devinit
vxge_probe(struct pci_dev *pdev, const struct pci_device_id *pre)
{
	struct __vxge_hw_device  *hldev;
	enum vxge_hw_status status;
	int ret;
	int high_dma = 0;
	u64 vpath_mask = 0;
	struct vxgedev *vdev;
	struct vxge_config *ll_config = NULL;
	struct vxge_hw_device_config *device_config = NULL;
	struct vxge_hw_device_attr attr;
	int i, j, no_of_vpath = 0, max_vpath_supported = 0;
	u8 *macaddr;
	struct vxge_mac_addrs *entry;
	static int bus = -1, device = -1;
	u32 host_type;
	u8 new_device = 0;
	enum vxge_hw_status is_privileged;
	u32 function_mode;
	u32 num_vfs = 0;

	vxge_debug_entryexit(VXGE_TRACE, "%s:%d", __func__, __LINE__);
	attr.pdev = pdev;

	/* In SRIOV-17 mode, functions of the same adapter
	 * can be deployed on different buses */
	if ((!pdev->is_virtfn) && ((bus != pdev->bus->number) ||
		(device != PCI_SLOT(pdev->devfn))))
		new_device = 1;

	bus = pdev->bus->number;
	device = PCI_SLOT(pdev->devfn);

	if (new_device) {
		if (driver_config->config_dev_cnt &&
		   (driver_config->config_dev_cnt !=
			driver_config->total_dev_cnt))
			vxge_debug_init(VXGE_ERR,
				"%s: Configured %d of %d devices",
				VXGE_DRIVER_NAME,
				driver_config->config_dev_cnt,
				driver_config->total_dev_cnt);
		driver_config->config_dev_cnt = 0;
		driver_config->total_dev_cnt = 0;
	}
	/* Now making the CPU based no of vpath calculation
	 * applicable for individual functions as well.
	 */
	driver_config->g_no_cpus = 0;
	driver_config->vpath_per_dev = max_config_vpath;

	driver_config->total_dev_cnt++;
	if (++driver_config->config_dev_cnt > max_config_dev) {
		ret = 0;
		goto _exit0;
	}

	device_config = kzalloc(sizeof(struct vxge_hw_device_config),
		GFP_KERNEL);
	if (!device_config) {
		ret = -ENOMEM;
		vxge_debug_init(VXGE_ERR,
			"device_config : malloc failed %s %d",
			__FILE__, __LINE__);
		goto _exit0;
	}

	ll_config = kzalloc(sizeof(*ll_config), GFP_KERNEL);
	if (!ll_config) {
		ret = -ENOMEM;
		vxge_debug_init(VXGE_ERR,
			"ll_config : malloc failed %s %d",
			__FILE__, __LINE__);
		goto _exit0;
	}
#if 0 /* MQ not in RHEL5 */
	ll_config->tx_steering_type = TX_MULTIQ_STEERING;
#else
	ll_config->tx_steering_type = TX_PORT_STEERING;
#endif
	ll_config->intr_type = MSI_X;
	ll_config->napi_weight = NEW_NAPI_WEIGHT;
	ll_config->rth_steering = RTH_STEERING;

	/* get the default configuration parameters */
	vxge_hw_device_config_default_get(device_config);

	/* initialize configuration parameters */
	vxge_device_config_init(device_config, &ll_config->intr_type);

	ret = pci_enable_device(pdev);
	if (ret) {
		vxge_debug_init(VXGE_ERR,
			"%s : can not enable PCI device", __func__);
		goto _exit0;
	}

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s : using 64bit DMA", __func__);

		high_dma = 1;

		if (pci_set_consistent_dma_mask(pdev,
						DMA_BIT_MASK(64))) {
			vxge_debug_init(VXGE_ERR,
				"%s : unable to obtain 64bit DMA for "
				"consistent allocations", __func__);
			ret = -ENOMEM;
			goto _exit1;
		}
	} else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s : using 32bit DMA", __func__);
	} else {
		ret = -ENOMEM;
		goto _exit1;
	}

	if (pci_request_regions(pdev, VXGE_DRIVER_NAME)) {
		vxge_debug_init(VXGE_ERR,
			"%s : request regions failed", __func__);
		ret = -ENODEV;
		goto _exit1;
	}

	pci_set_master(pdev);

	attr.bar0 = pci_ioremap_bar(pdev, 0);
	if (!attr.bar0) {
		vxge_debug_init(VXGE_ERR,
			"%s : cannot remap io memory bar0", __func__);
		ret = -ENODEV;
		goto _exit2;
	}
	vxge_debug_ll_config(VXGE_TRACE,
		"pci ioremap bar0: %p:0x%llx",
		attr.bar0,
		(unsigned long long)pci_resource_start(pdev, 0));

	status = vxge_hw_device_hw_info_get(attr.bar0,
			&ll_config->device_hw_info);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: Reading of hardware info failed."
			"Please try upgrading the firmware.", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit3;
	}

	if (ll_config->device_hw_info.fw_version.major !=
		VXGE_DRIVER_FW_VERSION_MAJOR) {
		vxge_debug_init(VXGE_ERR,
			"%s: Incorrect firmware version."
			"Please upgrade the firmware to version 1.x.x",
			VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit3;
	}

	vpath_mask = ll_config->device_hw_info.vpath_mask;
	if (vpath_mask == 0) {
		vxge_debug_ll_config(VXGE_TRACE,
			"%s: No vpaths available in device", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit3;
	}

	vxge_debug_ll_config(VXGE_TRACE,
		"%s:%d  Vpath mask = %llx", __func__, __LINE__,
		(unsigned long long)vpath_mask);

	function_mode = ll_config->device_hw_info.function_mode;
	host_type = ll_config->device_hw_info.host_type;
	is_privileged = __vxge_hw_device_is_privilaged(host_type,
		ll_config->device_hw_info.func_id);

	/* Check how many vpaths are available */
	for (i = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!((vpath_mask) & vxge_mBIT(i)))
			continue;
		max_vpath_supported++;
	}

	if (new_device)
		num_vfs = vxge_get_num_vfs(function_mode) - 1;

	/* Enable SRIOV mode, if firmware has SRIOV support and if it is a PF */
	if (is_sriov(function_mode) && (max_config_dev > 1) &&
		(ll_config->intr_type != INTA) &&
		(is_privileged == VXGE_HW_OK)) {
		ret = pci_enable_sriov(pdev, ((max_config_dev - 1) < num_vfs)
			? (max_config_dev - 1) : num_vfs);
		if (ret)
			vxge_debug_ll_config(VXGE_ERR,
				"Failed in enabling SRIOV mode: %d\n", ret);
	}

	/*
	 * Configure vpaths and get driver configured number of vpaths
	 * which is less than or equal to the maximum vpaths per function.
	 */
	no_of_vpath = vxge_config_vpaths(device_config, vpath_mask, ll_config);
	if (!no_of_vpath) {
		vxge_debug_ll_config(VXGE_ERR,
			"%s: No more vpaths to configure", VXGE_DRIVER_NAME);
		ret = 0;
		goto _exit3;
	}

	/* Setting driver callbacks */
	attr.uld_callbacks.link_up = vxge_callback_link_up;
	attr.uld_callbacks.link_down = vxge_callback_link_down;
	attr.uld_callbacks.crit_err = vxge_callback_crit_err;

	status = vxge_hw_device_initialize(&hldev, &attr, device_config);
	if (status != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"Failed to initialize device (%d)", status);
			ret = -EINVAL;
			goto _exit3;
	}

	/* if FCS stripping is not disabled in MAC fail driver load */
	if (vxge_hw_vpath_strip_fcs_check(hldev, vpath_mask) != VXGE_HW_OK) {
		vxge_debug_init(VXGE_ERR,
			"%s: FCS stripping is not disabled in MAC"
			" failing driver load", VXGE_DRIVER_NAME);
		ret = -EINVAL;
		goto _exit4;
	}

	vxge_hw_device_debug_set(hldev, VXGE_ERR, VXGE_COMPONENT_LL);

	/* set private device info */
	pci_set_drvdata(pdev, hldev);

	ll_config->gro_enable = VXGE_GRO_ALWAYS_AGGREGATE;
	ll_config->fifo_indicate_max_pkts = VXGE_FIFO_INDICATE_MAX_PKTS;
	ll_config->addr_learn_en = addr_learn_en;
	ll_config->rth_algorithm = RTH_ALG_JENKINS;
	ll_config->rth_hash_type_tcpipv4 = VXGE_HW_RING_HASH_TYPE_TCP_IPV4;
	ll_config->rth_hash_type_ipv4 = VXGE_HW_RING_HASH_TYPE_NONE;
	ll_config->rth_hash_type_tcpipv6 = VXGE_HW_RING_HASH_TYPE_NONE;
	ll_config->rth_hash_type_ipv6 = VXGE_HW_RING_HASH_TYPE_NONE;
	ll_config->rth_hash_type_tcpipv6ex = VXGE_HW_RING_HASH_TYPE_NONE;
	ll_config->rth_hash_type_ipv6ex = VXGE_HW_RING_HASH_TYPE_NONE;
	ll_config->rth_bkt_sz = RTH_BUCKET_SIZE;
	ll_config->tx_pause_enable = VXGE_PAUSE_CTRL_ENABLE;
	ll_config->rx_pause_enable = VXGE_PAUSE_CTRL_ENABLE;

	if (vxge_device_register(hldev, ll_config, high_dma, no_of_vpath,
		&vdev)) {
		ret = -EINVAL;
		goto _exit4;
	}

	vxge_hw_device_debug_set(hldev, VXGE_TRACE, VXGE_COMPONENT_LL);
	VXGE_COPY_DEBUG_INFO_TO_LL(vdev, vxge_hw_device_error_level_get(hldev),
		vxge_hw_device_trace_level_get(hldev));

	/* set private HW device info */
	hldev->ndev = vdev->ndev;
	vdev->mtu = VXGE_HW_DEFAULT_MTU;
	vdev->bar0 = attr.bar0;
	vdev->max_vpath_supported = max_vpath_supported;
	vdev->no_of_vpath = no_of_vpath;

	/* Virtual Path count */
	for (i = 0, j = 0; i < VXGE_HW_MAX_VIRTUAL_PATHS; i++) {
		if (!vxge_bVALn(vpath_mask, i, 1))
			continue;
		if (j >= vdev->no_of_vpath)
			break;

		vdev->vpaths[j].is_configured = 1;
		vdev->vpaths[j].device_id = i;
		vdev->vpaths[j].fifo.driver_id = j;
		vdev->vpaths[j].ring.driver_id = j;
		vdev->vpaths[j].vdev = vdev;
		vdev->vpaths[j].max_mac_addr_cnt = max_mac_vpath;
		memcpy((u8 *)vdev->vpaths[j].macaddr,
				ll_config->device_hw_info.mac_addrs[i],
				ETH_ALEN);

		/* Initialize the mac address list header */
		INIT_LIST_HEAD(&vdev->vpaths[j].mac_addr_list);

		vdev->vpaths[j].mac_addr_cnt = 0;
		vdev->vpaths[j].mcast_addr_cnt = 0;
		j++;
	}
	vdev->exec_mode = VXGE_EXEC_MODE_DISABLE;
	vdev->max_config_port = max_config_port;

	vdev->vlan_tag_strip = vlan_tag_strip;

	/* map the hashing selector table to the configured vpaths */
	for (i = 0; i < vdev->no_of_vpath; i++)
		vdev->vpath_selector[i] = vpath_selector[i];

	macaddr = (u8 *)vdev->vpaths[0].macaddr;

	ll_config->device_hw_info.serial_number[VXGE_HW_INFO_LEN - 1] = '\0';
	ll_config->device_hw_info.product_desc[VXGE_HW_INFO_LEN - 1] = '\0';
	ll_config->device_hw_info.part_number[VXGE_HW_INFO_LEN - 1] = '\0';

	vxge_debug_init(VXGE_TRACE, "%s: SERIAL NUMBER: %s",
		vdev->ndev->name, ll_config->device_hw_info.serial_number);

	vxge_debug_init(VXGE_TRACE, "%s: PART NUMBER: %s",
		vdev->ndev->name, ll_config->device_hw_info.part_number);

	vxge_debug_init(VXGE_TRACE, "%s: Neterion %s Server Adapter",
		vdev->ndev->name, ll_config->device_hw_info.product_desc);

	vxge_debug_init(VXGE_TRACE,
		"%s: MAC ADDR: %02X:%02X:%02X:%02X:%02X:%02X",
		vdev->ndev->name, macaddr[0], macaddr[1], macaddr[2],
		macaddr[3], macaddr[4], macaddr[5]);

	vxge_debug_init(VXGE_TRACE, "%s: Link Width x%d",
		vdev->ndev->name, vxge_hw_device_link_width_get(hldev));

	vxge_debug_init(VXGE_TRACE,
		"%s: Firmware version : %s Date : %s", vdev->ndev->name,
		ll_config->device_hw_info.fw_version.version,
		ll_config->device_hw_info.fw_date.date);

	if (new_device) {
		switch (ll_config->device_hw_info.function_mode) {
		case VXGE_HW_FUNCTION_MODE_SINGLE_FUNCTION:
			vxge_debug_init(VXGE_TRACE,
			"%s: Single Function Mode Enabled", vdev->ndev->name);
		break;
		case VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION:
			vxge_debug_init(VXGE_TRACE,
			"%s: Multi Function Mode Enabled", vdev->ndev->name);
		break;
		case VXGE_HW_FUNCTION_MODE_SRIOV:
			vxge_debug_init(VXGE_TRACE,
			"%s: Single Root IOV Mode Enabled", vdev->ndev->name);
		break;
		case VXGE_HW_FUNCTION_MODE_MRIOV:
			vxge_debug_init(VXGE_TRACE,
			"%s: Multi Root IOV Mode Enabled", vdev->ndev->name);
		break;
		}
	}

	vxge_print_parm(vdev, vpath_mask);

	/* Store the fw version for ethttool option */
	strcpy(vdev->fw_version, ll_config->device_hw_info.fw_version.version);
	memcpy(vdev->ndev->dev_addr, (u8 *)vdev->vpaths[0].macaddr, ETH_ALEN);
	memcpy(vdev->ndev->perm_addr, vdev->ndev->dev_addr, ETH_ALEN);

	/* Copy the station mac address to the list */
	for (i = 0; i < vdev->no_of_vpath; i++) {
		entry =	(struct vxge_mac_addrs *)
				kzalloc(sizeof(struct vxge_mac_addrs),
					GFP_KERNEL);
		if (NULL == entry) {
			vxge_debug_init(VXGE_ERR,
				"%s: mac_addr_list : memory allocation failed",
				vdev->ndev->name);
			ret = -EPERM;
			goto _exit5;
		}
		macaddr = (u8 *)&entry->macaddr;
		memcpy(macaddr, vdev->ndev->dev_addr, ETH_ALEN);
		list_add(&entry->item, &vdev->vpaths[i].mac_addr_list);
		vdev->vpaths[i].mac_addr_cnt = 1;
	}

	kfree(device_config);

	/*
	 * INTA is shared in multi-function mode. This is unlike the INTA
	 * implementation in MR mode, where each VH has its own INTA message.
	 * - INTA is masked (disabled) as long as at least one function sets
	 * its TITAN_MASK_ALL_INT.ALARM bit.
	 * - INTA is unmasked (enabled) when all enabled functions have cleared
	 * their own TITAN_MASK_ALL_INT.ALARM bit.
	 * The TITAN_MASK_ALL_INT ALARM & TRAFFIC bits are cleared on power up.
	 * Though this driver leaves the top level interrupts unmasked while
	 * leaving the required module interrupt bits masked on exit, there
	 * could be a rougue driver around that does not follow this procedure
	 * resulting in a failure to generate interrupts. The following code is
	 * present to prevent such a failure.
	 */

	if (ll_config->device_hw_info.function_mode ==
		VXGE_HW_FUNCTION_MODE_MULTI_FUNCTION)
		if (vdev->config.intr_type == INTA)
			vxge_hw_device_unmask_all(hldev);

	vxge_debug_entryexit(VXGE_TRACE, "%s: %s:%d  Exiting...",
		vdev->ndev->name, __func__, __LINE__);

	vxge_hw_device_debug_set(hldev, VXGE_ERR, VXGE_COMPONENT_LL);
	VXGE_COPY_DEBUG_INFO_TO_LL(vdev, vxge_hw_device_error_level_get(hldev),
		vxge_hw_device_trace_level_get(hldev));

	kfree(ll_config);
	return 0;

_exit5:
	for (i = 0; i < vdev->no_of_vpath; i++)
		vxge_free_mac_add_list(&vdev->vpaths[i]);

	vxge_device_unregister(hldev);
_exit4:
	pci_disable_sriov(pdev);
	vxge_hw_device_terminate(hldev);
_exit3:
	iounmap(attr.bar0);
_exit2:
	pci_release_regions(pdev);
_exit1:
	pci_disable_device(pdev);
_exit0:
	kfree(ll_config);
	kfree(device_config);
	driver_config->config_dev_cnt--;
	pci_set_drvdata(pdev, NULL);
	return ret;
}

/**
 * vxge_rem_nic - Free the PCI device
 * @pdev: structure containing the PCI related information of the device.
 * Description: This function is called by the Pci subsystem to release a
 * PCI device and free up all resource held up by the device.
 */
static void __devexit
vxge_remove(struct pci_dev *pdev)
{
	struct __vxge_hw_device  *hldev;
	struct vxgedev *vdev = NULL;
	struct net_device *dev;
	int i = 0;
#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	u32 level_trace;
#endif

	hldev = (struct __vxge_hw_device  *) pci_get_drvdata(pdev);

	if (hldev == NULL)
		return;
	dev = hldev->ndev;
	vdev = netdev_priv(dev);

#if ((VXGE_DEBUG_INIT & VXGE_DEBUG_MASK) || \
	(VXGE_DEBUG_ENTRYEXIT & VXGE_DEBUG_MASK))
	level_trace = vdev->level_trace;
#endif
	vxge_debug_entryexit(level_trace,
		"%s:%d", __func__, __LINE__);

	vxge_debug_init(level_trace,
		"%s : removing PCI device...", __func__);
	vxge_device_unregister(hldev);

	for (i = 0; i < vdev->no_of_vpath; i++) {
		vxge_free_mac_add_list(&vdev->vpaths[i]);
		vdev->vpaths[i].mcast_addr_cnt = 0;
		vdev->vpaths[i].mac_addr_cnt = 0;
	}

	kfree(vdev->vpaths);

	iounmap(vdev->bar0);

	pci_disable_sriov(pdev);

	/* we are safe to free it now */
	free_netdev(dev);

	vxge_debug_init(level_trace,
		"%s:%d  Device unregistered", __func__, __LINE__);

	vxge_hw_device_terminate(hldev);

	pci_disable_device(pdev);
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
	vxge_debug_entryexit(level_trace,
		"%s:%d  Exiting...", __func__, __LINE__);
}

static struct pci_error_handlers vxge_err_handler = {
	.error_detected = vxge_io_error_detected,
	.slot_reset = vxge_io_slot_reset,
	.resume = vxge_io_resume,
};

static struct pci_driver vxge_driver = {
	.name = VXGE_DRIVER_NAME,
	.id_table = vxge_id_table,
	.probe = vxge_probe,
	.remove = __devexit_p(vxge_remove),
#ifdef CONFIG_PM
	.suspend = vxge_pm_suspend,
	.resume = vxge_pm_resume,
#endif
	.err_handler = &vxge_err_handler,
};

static int __init
vxge_starter(void)
{
	int ret = 0;
	char version[32];
	snprintf(version, 32, "%s", DRV_VERSION);

	printk(KERN_INFO "%s: Copyright(c) 2002-2009 Neterion Inc\n",
		VXGE_DRIVER_NAME);
	printk(KERN_INFO "%s: Driver version: %s\n",
			VXGE_DRIVER_NAME, version);

	verify_bandwidth();

	driver_config = kzalloc(sizeof(struct vxge_drv_config), GFP_KERNEL);
	if (!driver_config)
		return -ENOMEM;

	ret = pci_register_driver(&vxge_driver);

	if (driver_config->config_dev_cnt &&
	   (driver_config->config_dev_cnt != driver_config->total_dev_cnt))
		vxge_debug_init(VXGE_ERR,
			"%s: Configured %d of %d devices",
			VXGE_DRIVER_NAME, driver_config->config_dev_cnt,
			driver_config->total_dev_cnt);

	if (ret)
		kfree(driver_config);

	return ret;
}

static void __exit
vxge_closer(void)
{
	pci_unregister_driver(&vxge_driver);
	kfree(driver_config);
}
module_init(vxge_starter);
module_exit(vxge_closer);
