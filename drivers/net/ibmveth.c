/**************************************************************************/
/*                                                                        */
/* IBM eServer i/pSeries Virtual Ethernet Device Driver                   */
/* Copyright (C) 2003 IBM Corp.                                           */
/*  Originally written by Dave Larson (larson1@us.ibm.com)                */
/*  Maintained by Santiago Leon (santil@us.ibm.com)                       */
/*                                                                        */
/*  This program is free software; you can redistribute it and/or modify  */
/*  it under the terms of the GNU General Public License as published by  */
/*  the Free Software Foundation; either version 2 of the License, or     */
/*  (at your option) any later version.                                   */
/*                                                                        */
/*  This program is distributed in the hope that it will be useful,       */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/*  GNU General Public License for more details.                          */
/*                                                                        */
/*  You should have received a copy of the GNU General Public License     */
/*  along with this program; if not, write to the Free Software           */
/*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  */
/*                                                                   USA  */
/*                                                                        */
/* This module contains the implementation of a virtual ethernet device   */
/* for use with IBM i/pSeries LPAR Linux.  It utilizes the logical LAN    */
/* option of the RS/6000 Platform Architechture to interface with virtual */
/* ethernet NICs that are presented to the partition by the hypervisor.   */
/*                                                                        */
/**************************************************************************/
/*
  TODO:
  - add support for sysfs
  - possibly remove procfs support
*/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/ethtool.h>
#include <linux/proc_fs.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <asm/semaphore.h>
#include <asm/hvcall.h>
#include <asm/atomic.h>
#include <asm/iommu.h>
#include <asm/vio.h>
#include <linux/seq_file.h>

#include "ibmveth.h"

#undef DEBUG

#define ibmveth_printk(fmt, args...) \
  printk(KERN_DEBUG "%s: " fmt, __FILE__, ## args)

#define ibmveth_error_printk(fmt, args...) \
  printk(KERN_ERR "(%s:%3.3d ua:%x) ERROR: " fmt, __FILE__, __LINE__ , adapter->vdev->unit_address, ## args)

#ifdef DEBUG
#define ibmveth_debug_printk_no_adapter(fmt, args...) \
  printk(KERN_DEBUG "(%s:%3.3d): " fmt, __FILE__, __LINE__ , ## args)
#define ibmveth_debug_printk(fmt, args...) \
  printk(KERN_DEBUG "(%s:%3.3d ua:%x): " fmt, __FILE__, __LINE__ , adapter->vdev->unit_address, ## args)
#else
#define ibmveth_debug_printk_no_adapter(fmt, args...)
#define ibmveth_debug_printk(fmt, args...)
#endif

static void ibmveth_proc_register_driver(void);
static void ibmveth_proc_unregister_driver(void);
static void ibmveth_proc_register_adapter(struct ibmveth_adapter *adapter);
static void ibmveth_proc_unregister_adapter(struct ibmveth_adapter *adapter);
static irqreturn_t ibmveth_interrupt(int irq, void *dev_instance, struct pt_regs *regs);
static inline void ibmveth_rxq_harvest_buffer(struct ibmveth_adapter *adapter);
static struct kobj_type ktype_veth_pool;

#ifdef CONFIG_PROC_FS
#define IBMVETH_PROC_DIR "net/ibmveth"
static struct proc_dir_entry *ibmveth_proc_dir;
#endif

static const char ibmveth_driver_name[] = "ibmveth";
static const char ibmveth_driver_string[] = "IBM i/pSeries Virtual Ethernet Driver";
#define ibmveth_driver_version "1.03-1"

MODULE_AUTHOR("Santiago Leon <santil@us.ibm.com>");
MODULE_DESCRIPTION("IBM i/pSeries Virtual Ethernet Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(ibmveth_driver_version);

static unsigned int tx_copybreak __read_mostly = 128;
module_param(tx_copybreak, uint, 0644);
MODULE_PARM_DESC(tx_copybreak,
	"Maximum size of packet that is copied to a new buffer on transmit");

static unsigned int rx_copybreak __read_mostly = 128;
module_param(rx_copybreak, uint, 0644);
MODULE_PARM_DESC(rx_copybreak,
	"Maximum size of packet that is copied to a new buffer on receive");

static unsigned int rx_flush __read_mostly = 0;
module_param(rx_flush, uint, 0644);
MODULE_PARM_DESC(rx_flush, "Flush receive buffers before use");

struct ibmveth_stat {
	char name[ETH_GSTRING_LEN];
	int offset;
};

#define IBMVETH_STAT_OFF(stat) offsetof(struct ibmveth_adapter, stat)
#define IBMVETH_GET_STAT(a, off) *((u64 *)(((unsigned long)(a)) + off))

struct ibmveth_stat ibmveth_stats[] = {
	{ "replenish_task_cycles", IBMVETH_STAT_OFF(replenish_task_cycles) },
	{ "replenish_no_mem", IBMVETH_STAT_OFF(replenish_no_mem) },
	{ "replenish_add_buff_failure", IBMVETH_STAT_OFF(replenish_add_buff_failure) },
	{ "replenish_add_buff_success", IBMVETH_STAT_OFF(replenish_add_buff_success) },
	{ "rx_invalid_buffer", IBMVETH_STAT_OFF(rx_invalid_buffer) },
	{ "rx_no_buffer", IBMVETH_STAT_OFF(rx_no_buffer) },
	{ "tx_map_failed", IBMVETH_STAT_OFF(tx_map_failed) },
	{ "tx_send_failed", IBMVETH_STAT_OFF(tx_send_failed) },
};

/* simple methods of getting data from the current rxq entry */
static inline u32 ibmveth_rxq_flags(struct ibmveth_adapter *adapter)
{
	return adapter->rx_queue.queue_addr[adapter->rx_queue.index].flags_off;
}

static inline int ibmveth_rxq_toggle(struct ibmveth_adapter *adapter)
{
	return (ibmveth_rxq_flags(adapter) & IBMVETH_RXQ_TOGGLE) >> IBMVETH_RXQ_TOGGLE_SHIFT;
}

static inline int ibmveth_rxq_pending_buffer(struct ibmveth_adapter *adapter)
{
	return (ibmveth_rxq_toggle(adapter) == adapter->rx_queue.toggle);
}

static inline int ibmveth_rxq_buffer_valid(struct ibmveth_adapter *adapter)
{
	return (ibmveth_rxq_flags(adapter) & IBMVETH_RXQ_VALID);
}

static inline int ibmveth_rxq_frame_offset(struct ibmveth_adapter *adapter)
{
	return (ibmveth_rxq_flags(adapter) & IBMVETH_RXQ_OFF_MASK);
}

static inline int ibmveth_rxq_frame_length(struct ibmveth_adapter *adapter)
{
	return (adapter->rx_queue.queue_addr[adapter->rx_queue.index].length);
}

static inline int ibmveth_rxq_csum_good(struct ibmveth_adapter *adapter)
{
	return (ibmveth_rxq_flags(adapter) & IBMVETH_RXQ_CSUM_GOOD);
}

/* setup the initial settings for a buffer pool */
static void ibmveth_init_buffer_pool(struct ibmveth_buff_pool *pool, u32 pool_index, u32 pool_size, u32 buff_size, u32 pool_active)
{
	pool->size = pool_size;
	pool->index = pool_index;
	pool->buff_size = buff_size;
	pool->threshold = pool_size * 7 / 8;
	pool->active = pool_active;
}

/* allocate and setup an buffer pool - called during open */
static int ibmveth_alloc_buffer_pool(struct ibmveth_buff_pool *pool)
{
	int i;

	pool->free_map = kmalloc(sizeof(u16) * pool->size, GFP_KERNEL);

	if(!pool->free_map) {
		return -1;
	}

	pool->dma_addr = kmalloc(sizeof(dma_addr_t) * pool->size, GFP_KERNEL);
	if(!pool->dma_addr) {
		kfree(pool->free_map);
		pool->free_map = NULL;
		return -1;
	}

	pool->skbuff = kmalloc(sizeof(void*) * pool->size, GFP_KERNEL);

	if(!pool->skbuff) {
		kfree(pool->dma_addr);
		pool->dma_addr = NULL;

		kfree(pool->free_map);
		pool->free_map = NULL;
		return -1;
	}

	memset(pool->skbuff, 0, sizeof(void*) * pool->size);
	memset(pool->dma_addr, 0, sizeof(dma_addr_t) * pool->size);

	for(i = 0; i < pool->size; ++i) {
		pool->free_map[i] = i;
	}

	atomic_set(&pool->available, 0);
	pool->producer_index = 0;
	pool->consumer_index = 0;

	return 0;
}

static inline void ibmveth_flush_buffer(void *addr, unsigned long length)
{
	unsigned long offset;

	for (offset = 0; offset < length; offset += SMP_CACHE_BYTES)
		asm("dcbfl %0,%1" :: "b" (addr), "r" (offset));
}

/* replenish the buffers for a pool.  note that we don't need to
 * skb_reserve these since they are used for incoming...
 */
static void ibmveth_replenish_buffer_pool(struct ibmveth_adapter *adapter, struct ibmveth_buff_pool *pool)
{
	u32 i;
	u32 count = pool->size - atomic_read(&pool->available);
	u32 buffers_added = 0;

	mb();

	for(i = 0; i < count; ++i) {
		struct sk_buff *skb;
		unsigned int free_index, index;
		u64 correlator;
		union ibmveth_buf_desc desc;
		unsigned long lpar_rc;
		dma_addr_t dma_addr;

		skb = netdev_alloc_skb(adapter->netdev, pool->buff_size);

		if(!skb) {
			ibmveth_debug_printk("replenish: unable to allocate skb\n");
			adapter->replenish_no_mem++;
			break;
		}

		free_index = pool->consumer_index;
		pool->consumer_index++;
		if (pool->consumer_index >= pool->size)
			pool->consumer_index = 0;
		index = pool->free_map[free_index];

		BUG_ON(index == IBM_VETH_INVALID_MAP);
		BUG_ON(pool->skbuff[index] != NULL);

		dma_addr = dma_map_single(&adapter->vdev->dev, skb->data,
				pool->buff_size, DMA_FROM_DEVICE);

		pool->free_map[free_index] = IBM_VETH_INVALID_MAP;
		pool->dma_addr[index] = dma_addr;
		pool->skbuff[index] = skb;

		correlator = ((u64)pool->index << 32) | index;
		*(u64*)skb->data = correlator;

		desc.fields.flags_len = IBMVETH_BUF_VALID | pool->buff_size;
		desc.fields.address = dma_addr;

		if (rx_flush) {
			unsigned int len = min(pool->buff_size,
						adapter->netdev->mtu +
						IBMVETH_BUFF_OH);
			ibmveth_flush_buffer(skb->data, len);
		}
		lpar_rc = h_add_logical_lan_buffer(adapter->vdev->unit_address, desc.desc);

		if(lpar_rc != H_SUCCESS) {
			pool->free_map[free_index] = index;
			pool->skbuff[index] = NULL;
			if (pool->consumer_index == 0)
				pool->consumer_index = pool->size - 1;
			else
				pool->consumer_index--;
			dma_unmap_single(&adapter->vdev->dev,
					pool->dma_addr[index], pool->buff_size,
					DMA_FROM_DEVICE);
			dev_kfree_skb_any(skb);
			adapter->replenish_add_buff_failure++;
			break;
		} else {
			buffers_added++;
			adapter->replenish_add_buff_success++;
		}
	}

	mb();
	atomic_add(buffers_added, &(pool->available));
}

/* replenish routine */
static void ibmveth_replenish_task(struct ibmveth_adapter *adapter)
{
	int i;

	adapter->replenish_task_cycles++;

	for(i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++) {
		struct ibmveth_buff_pool *pool = &adapter->rx_buff_pool[i];

		if (pool->active &&
		    (atomic_read(&pool->available) < pool->threshold))
			ibmveth_replenish_buffer_pool(adapter, pool);
	}

	adapter->rx_no_buffer = *(u64*)(((char*)adapter->buffer_list_addr) + 4096 - 8);
}

/* empty and free ana buffer pool - also used to do cleanup in error paths */
static void ibmveth_free_buffer_pool(struct ibmveth_adapter *adapter, struct ibmveth_buff_pool *pool)
{
	int i;

	kfree(pool->free_map);
	pool->free_map = NULL;

	if(pool->skbuff && pool->dma_addr) {
		for(i = 0; i < pool->size; ++i) {
			struct sk_buff *skb = pool->skbuff[i];
			if(skb) {
				dma_unmap_single(&adapter->vdev->dev,
						 pool->dma_addr[i],
						 pool->buff_size,
						 DMA_FROM_DEVICE);
				dev_kfree_skb_any(skb);
				pool->skbuff[i] = NULL;
			}
		}
	}

	if(pool->dma_addr) {
		kfree(pool->dma_addr);
		pool->dma_addr = NULL;
	}

	if(pool->skbuff) {
		kfree(pool->skbuff);
		pool->skbuff = NULL;
	}
}

/* remove a buffer from a pool */
static void ibmveth_remove_buffer_from_pool(struct ibmveth_adapter *adapter, u64 correlator)
{
	unsigned int pool  = correlator >> 32;
	unsigned int index = correlator & 0xffffffffUL;
	unsigned int free_index;
	struct sk_buff *skb;

	BUG_ON(pool >= IBMVETH_NUM_BUFF_POOLS);
	BUG_ON(index >= adapter->rx_buff_pool[pool].size);

	skb = adapter->rx_buff_pool[pool].skbuff[index];

	BUG_ON(skb == NULL);

	adapter->rx_buff_pool[pool].skbuff[index] = NULL;

	dma_unmap_single(&adapter->vdev->dev,
			 adapter->rx_buff_pool[pool].dma_addr[index],
			 adapter->rx_buff_pool[pool].buff_size,
			 DMA_FROM_DEVICE);

	free_index = adapter->rx_buff_pool[pool].producer_index;
	adapter->rx_buff_pool[pool].producer_index++;
	if (adapter->rx_buff_pool[pool].producer_index >=
	    adapter->rx_buff_pool[pool].size)
		adapter->rx_buff_pool[pool].producer_index = 0;
	adapter->rx_buff_pool[pool].free_map[free_index] = index;

	mb();

	atomic_dec(&(adapter->rx_buff_pool[pool].available));
}

/* get the current buffer on the rx queue */
static inline struct sk_buff *ibmveth_rxq_get_buffer(struct ibmveth_adapter *adapter)
{
	u64 correlator = adapter->rx_queue.queue_addr[adapter->rx_queue.index].correlator;
	unsigned int pool = correlator >> 32;
	unsigned int index = correlator & 0xffffffffUL;

	BUG_ON(pool >= IBMVETH_NUM_BUFF_POOLS);
	BUG_ON(index >= adapter->rx_buff_pool[pool].size);

	return adapter->rx_buff_pool[pool].skbuff[index];
}

/* recycle the current buffer on the rx queue */
static void ibmveth_rxq_recycle_buffer(struct ibmveth_adapter *adapter)
{
	u32 q_index = adapter->rx_queue.index;
	u64 correlator = adapter->rx_queue.queue_addr[q_index].correlator;
	unsigned int pool = correlator >> 32;
	unsigned int index = correlator & 0xffffffffUL;
	union ibmveth_buf_desc desc;
	unsigned long lpar_rc;

	BUG_ON(pool >= IBMVETH_NUM_BUFF_POOLS);
	BUG_ON(index >= adapter->rx_buff_pool[pool].size);

	if(!adapter->rx_buff_pool[pool].active) {
		ibmveth_rxq_harvest_buffer(adapter);
		ibmveth_free_buffer_pool(adapter, &adapter->rx_buff_pool[pool]);
		return;
	}

	desc.fields.flags_len = IBMVETH_BUF_VALID |
		adapter->rx_buff_pool[pool].buff_size;
	desc.fields.address = adapter->rx_buff_pool[pool].dma_addr[index];

	lpar_rc = h_add_logical_lan_buffer(adapter->vdev->unit_address, desc.desc);

	if(lpar_rc != H_SUCCESS) {
		ibmveth_debug_printk("h_add_logical_lan_buffer failed during recycle rc=%ld", lpar_rc);
		ibmveth_remove_buffer_from_pool(adapter, adapter->rx_queue.queue_addr[adapter->rx_queue.index].correlator);
	}

	if(++adapter->rx_queue.index == adapter->rx_queue.num_slots) {
		adapter->rx_queue.index = 0;
		adapter->rx_queue.toggle = !adapter->rx_queue.toggle;
	}
}

static inline void ibmveth_rxq_harvest_buffer(struct ibmveth_adapter *adapter)
{
	ibmveth_remove_buffer_from_pool(adapter, adapter->rx_queue.queue_addr[adapter->rx_queue.index].correlator);

	if(++adapter->rx_queue.index == adapter->rx_queue.num_slots) {
		adapter->rx_queue.index = 0;
		adapter->rx_queue.toggle = !adapter->rx_queue.toggle;
	}
}

static void ibmveth_cleanup(struct ibmveth_adapter *adapter)
{
	int i;

	if(adapter->buffer_list_addr != NULL) {
		if(!dma_mapping_error(adapter->buffer_list_dma)) {
			dma_unmap_single(&adapter->vdev->dev,
					adapter->buffer_list_dma, 4096,
					DMA_BIDIRECTIONAL);
			adapter->buffer_list_dma = DMA_ERROR_CODE;
		}
		free_page((unsigned long)adapter->buffer_list_addr);
		adapter->buffer_list_addr = NULL;
	}

	if(adapter->filter_list_addr != NULL) {
		if(!dma_mapping_error(adapter->filter_list_dma)) {
			dma_unmap_single(&adapter->vdev->dev,
					adapter->filter_list_dma, 4096,
					DMA_BIDIRECTIONAL);
			adapter->filter_list_dma = DMA_ERROR_CODE;
		}
		free_page((unsigned long)adapter->filter_list_addr);
		adapter->filter_list_addr = NULL;
	}

	if(adapter->rx_queue.queue_addr != NULL) {
		if(!dma_mapping_error(adapter->rx_queue.queue_dma)) {
			dma_unmap_single(&adapter->vdev->dev,
					adapter->rx_queue.queue_dma,
					adapter->rx_queue.queue_len,
					DMA_BIDIRECTIONAL);
			adapter->rx_queue.queue_dma = DMA_ERROR_CODE;
		}
		kfree(adapter->rx_queue.queue_addr);
		adapter->rx_queue.queue_addr = NULL;
	}

	for(i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++)
		if (adapter->rx_buff_pool[i].active)
			ibmveth_free_buffer_pool(adapter,
						 &adapter->rx_buff_pool[i]);

	if (adapter->bounce_buffer != NULL) {
		if (!dma_mapping_error(adapter->bounce_buffer_dma)) {
			dma_unmap_single(&adapter->vdev->dev,
					 adapter->bounce_buffer_dma,
					 adapter->netdev->mtu + IBMVETH_BUFF_OH,
					 DMA_BIDIRECTIONAL);
			adapter->bounce_buffer_dma = DMA_ERROR_CODE;
		}
		kfree(adapter->bounce_buffer);
		adapter->bounce_buffer = NULL;
	}
}

static int ibmveth_register_logical_lan(struct ibmveth_adapter *adapter,
        union ibmveth_buf_desc rxq_desc, u64 mac_address)
{
	int rc, try_again = 1;

	/* After a kexec the adapter will still be open, so our attempt to
	* open it will fail. So if we get a failure we free the adapter and
	* try again, but only once. */
retry:
	rc = h_register_logical_lan(adapter->vdev->unit_address,
				    adapter->buffer_list_dma, rxq_desc.desc,
				    adapter->filter_list_dma, mac_address);

	if (rc != H_SUCCESS && try_again) {
		do {
			rc = h_free_logical_lan(adapter->vdev->unit_address);
		} while (H_IS_LONG_BUSY(rc) || (rc == H_BUSY));

		try_again = 0;
		goto retry;
	}

	return rc;
}

static int ibmveth_open(struct net_device *netdev)
{
	struct ibmveth_adapter *adapter = netdev->priv;
	u64 mac_address = 0;
	int rxq_entries = 1;
	unsigned long lpar_rc;
	int rc;
	union ibmveth_buf_desc rxq_desc;
	int i;

	ibmveth_debug_printk("open starting\n");

	for(i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++)
		rxq_entries += adapter->rx_buff_pool[i].size;

	adapter->buffer_list_addr = (void*) get_zeroed_page(GFP_KERNEL);
	adapter->filter_list_addr = (void*) get_zeroed_page(GFP_KERNEL);

	if(!adapter->buffer_list_addr || !adapter->filter_list_addr) {
		ibmveth_error_printk("unable to allocate filter or buffer list pages\n");
		goto err_nomem;
	}

	adapter->rx_queue.queue_len = sizeof(struct ibmveth_rx_q_entry) * rxq_entries;
	adapter->rx_queue.queue_addr = kmalloc(adapter->rx_queue.queue_len, GFP_KERNEL);

	if(!adapter->rx_queue.queue_addr) {
		ibmveth_error_printk("unable to allocate rx queue pages\n");
		goto err_nomem;
	}

	adapter->buffer_list_dma = dma_map_single(&adapter->vdev->dev,
			adapter->buffer_list_addr, 4096, DMA_BIDIRECTIONAL);
	adapter->filter_list_dma = dma_map_single(&adapter->vdev->dev,
			adapter->filter_list_addr, 4096, DMA_BIDIRECTIONAL);
	adapter->rx_queue.queue_dma = dma_map_single(&adapter->vdev->dev,
			adapter->rx_queue.queue_addr,
			adapter->rx_queue.queue_len, DMA_BIDIRECTIONAL);

	if((dma_mapping_error(adapter->buffer_list_dma) ) ||
	   (dma_mapping_error(adapter->filter_list_dma)) ||
	   (dma_mapping_error(adapter->rx_queue.queue_dma))) {
		ibmveth_error_printk("unable to map filter or buffer list pages\n");
		goto err_nomem;
	}

	adapter->rx_queue.index = 0;
	adapter->rx_queue.num_slots = rxq_entries;
	adapter->rx_queue.toggle = 1;

	memcpy(&mac_address, netdev->dev_addr, netdev->addr_len);
	mac_address = mac_address >> 16;

	rxq_desc.fields.flags_len = IBMVETH_BUF_VALID | adapter->rx_queue.queue_len;
	rxq_desc.fields.address = adapter->rx_queue.queue_dma;

	ibmveth_debug_printk("buffer list @ 0x%p\n", adapter->buffer_list_addr);
	ibmveth_debug_printk("filter list @ 0x%p\n", adapter->filter_list_addr);
	ibmveth_debug_printk("receive q   @ 0x%p\n", adapter->rx_queue.queue_addr);

	h_vio_signal(adapter->vdev->unit_address, VIO_IRQ_DISABLE);

	lpar_rc = ibmveth_register_logical_lan(adapter, rxq_desc, mac_address);

	if(lpar_rc != H_SUCCESS) {
		ibmveth_error_printk("h_register_logical_lan failed with %ld\n", lpar_rc);
		ibmveth_error_printk("buffer TCE:0x%lx filter TCE:0x%lx rxq desc:0x%lx MAC:0x%lx\n",
				     adapter->buffer_list_dma,
				     adapter->filter_list_dma,
				     rxq_desc.desc,
				     mac_address);
		rc = -ENONET;
		goto err_out;
	}

	for(i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++) {
		if(!adapter->rx_buff_pool[i].active)
			continue;
		if (ibmveth_alloc_buffer_pool(&adapter->rx_buff_pool[i])) {
			ibmveth_error_printk("unable to alloc pool\n");
			adapter->rx_buff_pool[i].active = 0;
			goto err_nomem;
		}
	}

	ibmveth_debug_printk("registering irq 0x%x\n", netdev->irq);
	if((rc = request_irq(netdev->irq, &ibmveth_interrupt, 0, netdev->name, netdev)) != 0) {
		ibmveth_error_printk("unable to request irq 0x%x, rc %d\n", netdev->irq, rc);
		do {
			rc = h_free_logical_lan(adapter->vdev->unit_address);
		} while (H_IS_LONG_BUSY(rc) || (rc == H_BUSY));

		goto err_out;
	}

	adapter->bounce_buffer =
	    kmalloc(netdev->mtu + IBMVETH_BUFF_OH, GFP_KERNEL);
	if (!adapter->bounce_buffer) {
		ibmveth_error_printk("unable to allocate bounce buffer\n");
		goto err_out_free_irq;
	}
	adapter->bounce_buffer_dma =
	    dma_map_single(&adapter->vdev->dev, adapter->bounce_buffer,
			   netdev->mtu + IBMVETH_BUFF_OH, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(adapter->bounce_buffer_dma)) {
		ibmveth_error_printk("unable to map bounce buffer\n");
		goto err_out_free_irq;
	}

	ibmveth_debug_printk("initial replenish cycle\n");
	ibmveth_interrupt(netdev->irq, netdev, NULL);

	netif_start_queue(netdev);

	ibmveth_debug_printk("open complete\n");

	return 0;

err_out_free_irq:
	free_irq(netdev->irq, netdev);
err_nomem:
	rc = -ENOMEM;
err_out:
	ibmveth_cleanup(adapter);
	return rc;
}

static int ibmveth_close(struct net_device *netdev)
{
	struct ibmveth_adapter *adapter = netdev->priv;
	long lpar_rc;

	ibmveth_debug_printk("close starting\n");

	if (!adapter->pool_config)
		netif_stop_queue(netdev);

	h_vio_signal(adapter->vdev->unit_address, VIO_IRQ_DISABLE);

	do {
		lpar_rc = h_free_logical_lan(adapter->vdev->unit_address);
	} while (H_IS_LONG_BUSY(lpar_rc) || (lpar_rc == H_BUSY));

	if(lpar_rc != H_SUCCESS)
	{
		ibmveth_error_printk("h_free_logical_lan failed with %lx, continuing with close\n",
				     lpar_rc);
	}

	free_irq(netdev->irq, netdev);

	adapter->rx_no_buffer = *(u64*)(((char*)adapter->buffer_list_addr) + 4096 - 8);

	ibmveth_cleanup(adapter);

	ibmveth_debug_printk("close complete\n");

	return 0;
}

static int netdev_get_settings(struct net_device *dev, struct ethtool_cmd *cmd) {
	cmd->supported = (SUPPORTED_1000baseT_Full | SUPPORTED_Autoneg | SUPPORTED_FIBRE);
	cmd->advertising = (ADVERTISED_1000baseT_Full | ADVERTISED_Autoneg | ADVERTISED_FIBRE);
	cmd->speed = SPEED_1000;
	cmd->duplex = DUPLEX_FULL;
	cmd->port = PORT_FIBRE;
	cmd->phy_address = 0;
	cmd->transceiver = XCVR_INTERNAL;
	cmd->autoneg = AUTONEG_ENABLE;
	cmd->maxtxpkt = 0;
	cmd->maxrxpkt = 1;
	return 0;
}

static void netdev_get_drvinfo (struct net_device *dev, struct ethtool_drvinfo *info) {
	strncpy(info->driver, ibmveth_driver_name, sizeof(info->driver) - 1);
	strncpy(info->version, ibmveth_driver_version, sizeof(info->version) - 1);
}

static u32 netdev_get_link(struct net_device *dev) {
	return 1;
}

static void ibmveth_set_rx_csum_flags(struct net_device *dev, u32 data)
{
	struct ibmveth_adapter *adapter = dev->priv;

	if (data)
		adapter->rx_csum = 1;
	else {
		/*
		 * Since the ibmveth firmware interface does not have the concept of
		 * separate tx/rx checksum offload enable, if rx checksum is disabled
		 * we also have to disable tx checksum offload. Once we disable rx
		 * checksum offload, we are no longer allowed to send tx buffers that
		 * are not properly checksummed.
		 */
		adapter->rx_csum = 0;
		dev->features &= ~NETIF_F_IP_CSUM;
	}
}

static void ibmveth_set_tx_csum_flags(struct net_device *dev, u32 data)
{
	struct ibmveth_adapter *adapter = dev->priv;

	if (data) {
		dev->features |= NETIF_F_IP_CSUM;
		adapter->rx_csum = 1;
	} else
		dev->features &= ~NETIF_F_IP_CSUM;
}

static int ibmveth_set_csum_offload(struct net_device *dev, u32 data,
				    void (*done) (struct net_device *, u32))
{
	struct ibmveth_adapter *adapter = dev->priv;
	u64 set_attr, clr_attr, ret_attr;
	long ret;
	int rc1 = 0, rc2 = 0;
	int restart = 0;

	if (netif_running(dev)) {
		restart = 1;
		adapter->pool_config = 1;
		ibmveth_close(dev);
		adapter->pool_config = 0;
	}

	set_attr = 0;
	clr_attr = 0;

	if (data)
		set_attr = IBMVETH_ILLAN_IPV4_TCP_CSUM;
	else
		clr_attr = IBMVETH_ILLAN_IPV4_TCP_CSUM;

	ret = h_illan_attributes(adapter->vdev->unit_address, 0, 0, &ret_attr);

	if (ret == H_SUCCESS && !(ret_attr & IBMVETH_ILLAN_ACTIVE_TRUNK) &&
	    !(ret_attr & IBMVETH_ILLAN_TRUNK_PRI_MASK) &&
	    (ret_attr & IBMVETH_ILLAN_PADDED_PKT_CSUM)) {
		ret = h_illan_attributes(adapter->vdev->unit_address, clr_attr,
					 set_attr, &ret_attr);

		if (ret != H_SUCCESS) {
			rc1 = -EIO;
			ibmveth_error_printk("unable to change checksum offload settings."
					     " %d rc=%ld\n", data, ret);

			ret = h_illan_attributes(adapter->vdev->unit_address,
						 set_attr, clr_attr, &ret_attr);
		} else
			done(dev, data);
	} else {
		rc1 = -EIO;
		ibmveth_error_printk("unable to change checksum offload settings."
				     " %d rc=%ld ret_attr=%lx\n", data, ret, ret_attr);
	}

	if (restart)
		rc2 = ibmveth_open(dev);

	return rc1 ? rc1 : rc2;
}

static int ibmveth_set_rx_csum(struct net_device *dev, u32 data)
{
	struct ibmveth_adapter *adapter = dev->priv;

	if ((data && adapter->rx_csum) || (!data && !adapter->rx_csum))
		return 0;

	return ibmveth_set_csum_offload(dev, data, ibmveth_set_rx_csum_flags);
}

static int ibmveth_set_tx_csum(struct net_device *dev, u32 data)
{
	struct ibmveth_adapter *adapter = dev->priv;
	int rc = 0;

	if (data && (dev->features & NETIF_F_IP_CSUM))
		return 0;
	if (!data && !(dev->features & NETIF_F_IP_CSUM))
		return 0;

	if (data && !adapter->rx_csum)
		rc = ibmveth_set_csum_offload(dev, data, ibmveth_set_tx_csum_flags);
	else
		ibmveth_set_tx_csum_flags(dev, data);

	return rc;
}

static u32 ibmveth_get_rx_csum(struct net_device *dev)
{
	struct ibmveth_adapter *adapter = dev->priv;
	return adapter->rx_csum;
}

static void ibmveth_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	for (i = 0; i < ARRAY_SIZE(ibmveth_stats); i++, data += ETH_GSTRING_LEN)
		memcpy(data, ibmveth_stats[i].name, ETH_GSTRING_LEN);
}

static int ibmveth_get_stats_count(struct net_device *dev)
{
	return ARRAY_SIZE(ibmveth_stats);
}

static void ibmveth_get_ethtool_stats(struct net_device *dev,
				      struct ethtool_stats *stats, u64 *data)
{
	int i;
	struct ibmveth_adapter *adapter = dev->priv;

	for (i = 0; i < ARRAY_SIZE(ibmveth_stats); i++)
		data[i] = IBMVETH_GET_STAT(adapter, ibmveth_stats[i].offset);
}

static struct ethtool_ops netdev_ethtool_ops = {
	.get_drvinfo		= netdev_get_drvinfo,
	.get_settings		= netdev_get_settings,
	.get_link		= netdev_get_link,
	.get_sg			= ethtool_op_get_sg,
	.get_tx_csum		= ethtool_op_get_tx_csum,
	.set_tx_csum		= ibmveth_set_tx_csum,
	.get_rx_csum		= ibmveth_get_rx_csum,
	.set_rx_csum		= ibmveth_set_rx_csum,
	.get_tso			= ethtool_op_get_tso,
	.get_ufo			= ethtool_op_get_ufo,
	.get_strings		= ibmveth_get_strings,
	.get_stats_count		= ibmveth_get_stats_count,
	.get_ethtool_stats	= ibmveth_get_ethtool_stats,
	.set_sg			= ethtool_op_set_sg,
};

static int ibmveth_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	return -EOPNOTSUPP;
}

#define page_offset(v) ((unsigned long)(v) & ((1 << 12) - 1))

static int ibmveth_send(struct ibmveth_adapter *adapter,
			union ibmveth_buf_desc *descs)
{
	unsigned long correlator;
	unsigned int retry_count;
	unsigned long ret;

	/*
	* The retry count sets a maximum for the number of broadcast and
	* multicast destinations within the system.
	*/
	retry_count = 1024;
	correlator = 0;
	do {
		ret = h_send_logical_lan(adapter->vdev->unit_address,
					 descs[0].desc, descs[1].desc,
					 descs[2].desc, descs[3].desc,
					 descs[4].desc, descs[5].desc,
					 correlator);
	} while ((ret == H_BUSY) && (retry_count--));

	if (ret != H_SUCCESS && ret != H_DROPPED) {
		ibmveth_error_printk("tx: h_send_logical_lan failed with "
				     "rc=%ld\n", ret);
	return 1;
	}

	return 0;
}

static int ibmveth_start_xmit(struct sk_buff *skb,
				      struct net_device *netdev)
{
	struct ibmveth_adapter *adapter = netdev_priv(netdev);
	unsigned int desc_flags;
	union ibmveth_buf_desc descs[6];
	int last, i;
	int force_bounce = 0;

	/*
	* veth handles a maximum of 6 segments including the header, so
	* we have to linearize the skb if there are more than this.
	*/
	if (skb_shinfo(skb)->nr_frags > 5 && __skb_linearize(skb)) {
		adapter->stats.tx_dropped++;
		goto out;
	}
	/* veth can't checksum offload UDP */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    skb->nh.iph->protocol != IPPROTO_TCP && skb_checksum_help(skb, 0)) {
		ibmveth_error_printk("tx: failed to checksum packet\n");
		adapter->stats.tx_dropped++;
		goto out;
	}

	desc_flags = IBMVETH_BUF_VALID;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		unsigned char *buf = skb_transport_header(skb) +
					skb->csum;

		desc_flags |= (IBMVETH_BUF_NO_CSUM | IBMVETH_BUF_CSUM_GOOD);

		/* Need to zero out the checksum */
		buf[0] = 0;
		buf[1] = 0;
	}

retry_bounce:
	memset(descs, 0, sizeof(descs));

	/*
	* If a linear packet is below the rx threshold then
	* copy it into the static bounce buffer. This avoids the
	* cost of a TCE insert and remove.
	*/
	if (force_bounce || (!skb_is_nonlinear(skb) &&
				(skb->len < tx_copybreak))) {
		skb_copy_from_linear_data(skb, adapter->bounce_buffer,
					  skb->len);

		descs[0].fields.flags_len = desc_flags | skb->len;
		descs[0].fields.address = adapter->bounce_buffer_dma;

		if (ibmveth_send(adapter, descs)) {
			adapter->tx_send_failed++;
			adapter->stats.tx_dropped++;
		} else {
			adapter->stats.tx_packets++;
			adapter->stats.tx_bytes += skb->len;
		}
 
		goto out;
	}
 
	/* Map the header */
	descs[0].fields.address = dma_map_single(&adapter->vdev->dev, skb->data,
						 skb_headlen(skb),
						 DMA_TO_DEVICE);
	if (dma_mapping_error(descs[0].fields.address))
		goto map_failed;
 
	descs[0].fields.flags_len = desc_flags | skb_headlen(skb);
 
	/* Map the frags */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		unsigned long dma_addr;
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		dma_addr = dma_map_page(&adapter->vdev->dev, frag->page,
					frag->page_offset, frag->size,
					DMA_TO_DEVICE);

		if (dma_mapping_error(dma_addr))
			goto map_failed_frags;

		descs[i+1].fields.flags_len = desc_flags | frag->size;
		descs[i+1].fields.address = dma_addr;
	}

	if (ibmveth_send(adapter, descs)) {
		adapter->tx_send_failed++;
		adapter->stats.tx_dropped++;
	} else {
		adapter->stats.tx_packets++;
		adapter->stats.tx_bytes += skb->len;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags + 1; i++)
		dma_unmap_page(&adapter->vdev->dev, descs[i].fields.address,
			       descs[i].fields.flags_len & IBMVETH_BUF_LEN_MASK,
			       DMA_TO_DEVICE);

out:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;


map_failed_frags:
	last = i+1;
	for (i = 0; i < last; i++)
		dma_unmap_page(&adapter->vdev->dev, descs[i].fields.address,
			       descs[i].fields.flags_len & IBMVETH_BUF_LEN_MASK,
			       DMA_TO_DEVICE);

map_failed:
	ibmveth_error_printk("tx: unable to map xmit buffer\n");
	adapter->tx_map_failed++;
	skb_linearize(skb);
	force_bounce = 1;
	goto retry_bounce;
}

static int ibmveth_poll(struct net_device *netdev, int *budget)
{
	struct ibmveth_adapter *adapter = netdev->priv;
	int max_frames_to_process = netdev->quota;
	int frames_processed = 0;
	int more_work = 1;
	unsigned long lpar_rc;

 restart_poll:
	do {
		struct net_device *netdev = adapter->netdev;

		if(ibmveth_rxq_pending_buffer(adapter)) {

			rmb();

			if(!ibmveth_rxq_buffer_valid(adapter)) {
				wmb(); /* suggested by larson1 */
				adapter->rx_invalid_buffer++;
				ibmveth_debug_printk("recycling invalid buffer\n");
				ibmveth_rxq_recycle_buffer(adapter);
			} else {
				struct sk_buff *skb, *new_skb;
				int length = ibmveth_rxq_frame_length(adapter);
				int offset = ibmveth_rxq_frame_offset(adapter);
				int csum_good = ibmveth_rxq_csum_good(adapter);

				skb = ibmveth_rxq_get_buffer(adapter);

				new_skb = NULL;
				if (length < rx_copybreak)
					new_skb = netdev_alloc_skb(netdev,
								   length);

				if (new_skb) {
					skb_copy_to_linear_data(new_skb,
								skb->data +
								offset, length);
					if (rx_flush)
						ibmveth_flush_buffer(skb->data,
							length + offset);
					skb = new_skb;
					ibmveth_rxq_recycle_buffer(adapter);
				} else {
					ibmveth_rxq_harvest_buffer(adapter);
					skb_reserve(skb, offset);
				}

				skb_put(skb, length);
				skb->dev = netdev;
				skb->protocol = eth_type_trans(skb, netdev);

				if (csum_good)
					skb->ip_summed = CHECKSUM_UNNECESSARY;

				netif_receive_skb(skb);	/* send it up */

				adapter->stats.rx_packets++;
				adapter->stats.rx_bytes += length;
				frames_processed++;
				netdev->last_rx = jiffies;
			}
		} else {
			more_work = 0;
		}
	} while(more_work && (frames_processed < max_frames_to_process));

	ibmveth_replenish_task(adapter);

	if(more_work) {
		/* more work to do - return that we are not done yet */
		netdev->quota -= frames_processed;
		*budget -= frames_processed;
		return 1;
	}

	/* we think we are done - reenable interrupts, then check once more to make sure we are done */
	lpar_rc = h_vio_signal(adapter->vdev->unit_address, VIO_IRQ_ENABLE);

	BUG_ON(lpar_rc != H_SUCCESS);

	netif_rx_complete(netdev);

	if(ibmveth_rxq_pending_buffer(adapter) && netif_rx_reschedule(netdev, frames_processed))
	{
		lpar_rc = h_vio_signal(adapter->vdev->unit_address, VIO_IRQ_DISABLE);
		BUG_ON(lpar_rc != H_SUCCESS);
		more_work = 1;
		goto restart_poll;
	}

	netdev->quota -= frames_processed;
	*budget -= frames_processed;

	/* we really are done */
	return 0;
}

static irqreturn_t ibmveth_interrupt(int irq, void *dev_instance, struct pt_regs *regs)
{
	struct net_device *netdev = dev_instance;
	struct ibmveth_adapter *adapter = netdev->priv;
	unsigned long lpar_rc;

	if(netif_rx_schedule_prep(netdev)) {
		lpar_rc = h_vio_signal(adapter->vdev->unit_address, VIO_IRQ_DISABLE);
		BUG_ON(lpar_rc != H_SUCCESS);
		__netif_rx_schedule(netdev);
	}
	return IRQ_HANDLED;
}

static struct net_device_stats *ibmveth_get_stats(struct net_device *dev)
{
	struct ibmveth_adapter *adapter = dev->priv;
	return &adapter->stats;
}

static void ibmveth_set_multicast_list(struct net_device *netdev)
{
	struct ibmveth_adapter *adapter = netdev->priv;
	unsigned long lpar_rc;

	if((netdev->flags & IFF_PROMISC) || (netdev->mc_count > adapter->mcastFilterSize)) {
		lpar_rc = h_multicast_ctrl(adapter->vdev->unit_address,
					   IbmVethMcastEnableRecv |
					   IbmVethMcastDisableFiltering,
					   0);
		if(lpar_rc != H_SUCCESS) {
			ibmveth_error_printk("h_multicast_ctrl rc=%ld when entering promisc mode\n", lpar_rc);
		}
	} else {
		struct dev_mc_list *mclist = netdev->mc_list;
		int i;
		/* clear the filter table & disable filtering */
		lpar_rc = h_multicast_ctrl(adapter->vdev->unit_address,
					   IbmVethMcastEnableRecv |
					   IbmVethMcastDisableFiltering |
					   IbmVethMcastClearFilterTable,
					   0);
		if(lpar_rc != H_SUCCESS) {
			ibmveth_error_printk("h_multicast_ctrl rc=%ld when attempting to clear filter table\n", lpar_rc);
		}
		/* add the addresses to the filter table */
		for(i = 0; i < netdev->mc_count; ++i, mclist = mclist->next) {
			// add the multicast address to the filter table
			unsigned long mcast_addr = 0;
			memcpy(((char *)&mcast_addr)+2, mclist->dmi_addr, 6);
			lpar_rc = h_multicast_ctrl(adapter->vdev->unit_address,
						   IbmVethMcastAddFilter,
						   mcast_addr);
			if(lpar_rc != H_SUCCESS) {
				ibmveth_error_printk("h_multicast_ctrl rc=%ld when adding an entry to the filter table\n", lpar_rc);
			}
		}

		/* re-enable filtering */
		lpar_rc = h_multicast_ctrl(adapter->vdev->unit_address,
					   IbmVethMcastEnableFiltering,
					   0);
		if(lpar_rc != H_SUCCESS) {
			ibmveth_error_printk("h_multicast_ctrl rc=%ld when enabling filtering\n", lpar_rc);
		}
	}
}

static int ibmveth_change_mtu(struct net_device *dev, int new_mtu)
{
	struct ibmveth_adapter *adapter = dev->priv;
	int new_mtu_oh = new_mtu + IBMVETH_BUFF_OH;
	int reinit = 0;
	int i, rc;

	if (new_mtu < IBMVETH_MIN_MTU)
		return -EINVAL;

	for (i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++)
		if (new_mtu_oh < adapter->rx_buff_pool[i].buff_size)
			break;

	if (i == IBMVETH_NUM_BUFF_POOLS)
		return -EINVAL;

	/* Look for an active buffer pool that can hold the new MTU */
	for(i = 0; i<IBMVETH_NUM_BUFF_POOLS; i++) {
		if (!adapter->rx_buff_pool[i].active) {
			adapter->rx_buff_pool[i].active = 1;
			reinit = 1;
		}

		if (new_mtu_oh < adapter->rx_buff_pool[i].buff_size) {
			if (reinit && netif_running(adapter->netdev)) {
				adapter->pool_config = 1;
				ibmveth_close(adapter->netdev);
				adapter->pool_config = 0;
				dev->mtu = new_mtu;
				if ((rc = ibmveth_open(adapter->netdev)))
					return rc;
			} else
				dev->mtu = new_mtu;
			return 0;
		}
	}
	return -EINVAL;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void ibmveth_poll_controller(struct net_device *dev)
{
	ibmveth_replenish_task(dev->priv);
	ibmveth_interrupt(dev->irq, dev, NULL);
}
#endif

static int __devinit ibmveth_probe(struct vio_dev *dev, const struct vio_device_id *id)
{
	int rc, i;
	struct net_device *netdev;
	struct ibmveth_adapter *adapter = NULL;

	unsigned char *mac_addr_p;
	unsigned int *mcastFilterSize_p;


	ibmveth_debug_printk_no_adapter("entering ibmveth_probe for UA 0x%x\n",
					dev->unit_address);

	mac_addr_p = (unsigned char *) vio_get_attribute(dev, VETH_MAC_ADDR, 0);
	if(!mac_addr_p) {
		printk(KERN_ERR "(%s:%3.3d) ERROR: Can't find VETH_MAC_ADDR "
				"attribute\n", __FILE__, __LINE__);
		return -EIO;
	}

	mcastFilterSize_p= (unsigned int *) vio_get_attribute(dev, VETH_MCAST_FILTER_SIZE, 0);
	if(!mcastFilterSize_p) {
		printk(KERN_ERR "(%s:%3.3d) ERROR: Can't find "
				"VETH_MCAST_FILTER_SIZE attribute\n",
				__FILE__, __LINE__);
		return -EIO;
	}

	netdev = alloc_etherdev(sizeof(struct ibmveth_adapter));

	if(!netdev)
		return -ENOMEM;

	SET_MODULE_OWNER(netdev);

	adapter = netdev->priv;
	memset(adapter, 0, sizeof(adapter));
	dev->dev.driver_data = netdev;

	adapter->vdev = dev;
	adapter->netdev = netdev;
	adapter->mcastFilterSize= *mcastFilterSize_p;
	adapter->pool_config = 0;

	/* 	Some older boxes running PHYP non-natively have an OF that
		returns a 8-byte local-mac-address field (and the first
		2 bytes have to be ignored) while newer boxes' OF return
		a 6-byte field. Note that IEEE 1275 specifies that
		local-mac-address must be a 6-byte field.
		The RPA doc specifies that the first byte must be 10b, so
		we'll just look for it to solve this 8 vs. 6 byte field issue */

	if ((*mac_addr_p & 0x3) != 0x02)
		mac_addr_p += 2;

	adapter->mac_addr = 0;
	memcpy(&adapter->mac_addr, mac_addr_p, 6);

	adapter->liobn = dev->iommu_table->it_index;

	netdev->irq = dev->irq;
	netdev->open               = ibmveth_open;
	netdev->poll               = ibmveth_poll;
	netdev->weight             = 16;
	netdev->stop               = ibmveth_close;
	netdev->hard_start_xmit    = ibmveth_start_xmit;
	netdev->get_stats          = ibmveth_get_stats;
	netdev->set_multicast_list = ibmveth_set_multicast_list;
	netdev->do_ioctl           = ibmveth_ioctl;
	netdev->ethtool_ops           = &netdev_ethtool_ops;
	netdev->change_mtu         = ibmveth_change_mtu;
	SET_NETDEV_DEV(netdev, &dev->dev);
	netdev->features |= NETIF_F_SG;
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = ibmveth_poll_controller;
#endif

	memcpy(&netdev->dev_addr, &adapter->mac_addr, netdev->addr_len);

	for(i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++) {
		struct kobject *kobj = &adapter->rx_buff_pool[i].kobj;
		ibmveth_init_buffer_pool(&adapter->rx_buff_pool[i], i,
					 pool_count[i], pool_size[i],
					 pool_active[i]);
		kobj->parent = &dev->dev.kobj;
		sprintf(kobj->name, "pool%d", i);
		kobj->ktype = &ktype_veth_pool;
		kobject_register(kobj);
	}

	ibmveth_debug_printk("adapter @ 0x%p\n", adapter);

	adapter->buffer_list_dma = DMA_ERROR_CODE;
	adapter->filter_list_dma = DMA_ERROR_CODE;
	adapter->rx_queue.queue_dma = DMA_ERROR_CODE;

	ibmveth_debug_printk("registering netdev...\n");

	ibmveth_set_csum_offload(netdev, 1, ibmveth_set_tx_csum_flags);

	rc = register_netdev(netdev);

	if(rc) {
		ibmveth_debug_printk("failed to register netdev rc=%d\n", rc);
		free_netdev(netdev);
		return rc;
	}

	ibmveth_debug_printk("registered\n");

	ibmveth_proc_register_adapter(adapter);

	return 0;
}

static int __devexit ibmveth_remove(struct vio_dev *dev)
{
	struct net_device *netdev = dev->dev.driver_data;
	struct ibmveth_adapter *adapter = netdev->priv;
	int i;

	for(i = 0; i<IBMVETH_NUM_BUFF_POOLS; i++)
		kobject_unregister(&adapter->rx_buff_pool[i].kobj);

	unregister_netdev(netdev);

	ibmveth_proc_unregister_adapter(adapter);

	free_netdev(netdev);
	return 0;
}

#ifdef CONFIG_PROC_FS
static void ibmveth_proc_register_driver(void)
{
	ibmveth_proc_dir = proc_mkdir(IBMVETH_PROC_DIR, NULL);
	if (ibmveth_proc_dir) {
		SET_MODULE_OWNER(ibmveth_proc_dir);
	}
}

static void ibmveth_proc_unregister_driver(void)
{
	remove_proc_entry(IBMVETH_PROC_DIR, NULL);
}

static void *ibmveth_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos == 0) {
		return (void *)1;
	} else {
		return NULL;
	}
}

static void *ibmveth_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void ibmveth_seq_stop(struct seq_file *seq, void *v)
{
}

static int ibmveth_seq_show(struct seq_file *seq, void *v)
{
	struct ibmveth_adapter *adapter = seq->private;
	char *current_mac = ((char*) &adapter->netdev->dev_addr);
	char *firmware_mac = ((char*) &adapter->mac_addr) ;

	seq_printf(seq, "%s %s\n\n", ibmveth_driver_string, ibmveth_driver_version);

	seq_printf(seq, "Unit Address:    0x%x\n", adapter->vdev->unit_address);
	seq_printf(seq, "LIOBN:           0x%lx\n", adapter->liobn);
	seq_printf(seq, "Current MAC:     %02X:%02X:%02X:%02X:%02X:%02X\n",
		   current_mac[0], current_mac[1], current_mac[2],
		   current_mac[3], current_mac[4], current_mac[5]);
	seq_printf(seq, "Firmware MAC:    %02X:%02X:%02X:%02X:%02X:%02X\n",
		   firmware_mac[0], firmware_mac[1], firmware_mac[2],
		   firmware_mac[3], firmware_mac[4], firmware_mac[5]);

	seq_printf(seq, "\nAdapter Statistics:\n");
	seq_printf(seq, "  TX:  vio_map_single failres:      %ld\n", adapter->tx_map_failed);
	seq_printf(seq, "       send failures:               %ld\n", adapter->tx_send_failed);
	seq_printf(seq, "  RX:  replenish task cycles:       %ld\n", adapter->replenish_task_cycles);
	seq_printf(seq, "       alloc_skb_failures:          %ld\n", adapter->replenish_no_mem);
	seq_printf(seq, "       add buffer failures:         %ld\n", adapter->replenish_add_buff_failure);
	seq_printf(seq, "       invalid buffers:             %ld\n", adapter->rx_invalid_buffer);
	seq_printf(seq, "       no buffers:                  %ld\n", adapter->rx_no_buffer);

	return 0;
}
static struct seq_operations ibmveth_seq_ops = {
	.start = ibmveth_seq_start,
	.next  = ibmveth_seq_next,
	.stop  = ibmveth_seq_stop,
	.show  = ibmveth_seq_show,
};

static int ibmveth_proc_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct proc_dir_entry *proc;
	int rc;

	rc = seq_open(file, &ibmveth_seq_ops);
	if (!rc) {
		/* recover the pointer buried in proc_dir_entry data */
		seq = file->private_data;
		proc = PDE(inode);
		seq->private = proc->data;
	}
	return rc;
}

static struct file_operations ibmveth_proc_fops = {
	.owner	 = THIS_MODULE,
	.open    = ibmveth_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void ibmveth_proc_register_adapter(struct ibmveth_adapter *adapter)
{
	struct proc_dir_entry *entry;
	if (ibmveth_proc_dir) {
		char u_addr[10];
		sprintf(u_addr, "%x", adapter->vdev->unit_address);
		entry = create_proc_entry(u_addr, S_IFREG, ibmveth_proc_dir);
		if (!entry) {
			ibmveth_error_printk("Cannot create adapter proc entry");
		} else {
			entry->data = (void *) adapter;
			entry->proc_fops = &ibmveth_proc_fops;
			SET_MODULE_OWNER(entry);
		}
	}
	return;
}

static void ibmveth_proc_unregister_adapter(struct ibmveth_adapter *adapter)
{
	if (ibmveth_proc_dir) {
		char u_addr[10];
		sprintf(u_addr, "%x", adapter->vdev->unit_address);
		remove_proc_entry(u_addr, ibmveth_proc_dir);
	}
}

#else /* CONFIG_PROC_FS */
static void ibmveth_proc_register_adapter(struct ibmveth_adapter *adapter)
{
}

static void ibmveth_proc_unregister_adapter(struct ibmveth_adapter *adapter)
{
}
static void ibmveth_proc_register_driver(void)
{
}

static void ibmveth_proc_unregister_driver(void)
{
}
#endif /* CONFIG_PROC_FS */

static struct attribute veth_active_attr;
static struct attribute veth_num_attr;
static struct attribute veth_size_attr;

static ssize_t veth_pool_show(struct kobject * kobj,
                              struct attribute * attr, char * buf)
{
	struct ibmveth_buff_pool *pool = container_of(kobj,
						      struct ibmveth_buff_pool,
						      kobj);

	if (attr == &veth_active_attr)
		return sprintf(buf, "%d\n", pool->active);
	else if (attr == &veth_num_attr)
		return sprintf(buf, "%d\n", pool->size);
	else if (attr == &veth_size_attr)
		return sprintf(buf, "%d\n", pool->buff_size);
	return 0;
}

static ssize_t veth_pool_store(struct kobject * kobj, struct attribute * attr,
const char * buf, size_t count)
{
	struct ibmveth_buff_pool *pool = container_of(kobj,
						      struct ibmveth_buff_pool,
						      kobj);
	struct net_device *netdev =
	    container_of(kobj->parent, struct device, kobj)->driver_data;
	struct ibmveth_adapter *adapter = netdev->priv;
	long value = simple_strtol(buf, NULL, 10);
	long rc;

	if (attr == &veth_active_attr) {
		if (value && !pool->active) {
			if (netif_running(netdev)) {
				if(ibmveth_alloc_buffer_pool(pool)) {
					ibmveth_error_printk("unable to alloc pool\n");
					return -ENOMEM;
				}
				pool->active = 1;
				adapter->pool_config = 1;
				ibmveth_close(netdev);
				adapter->pool_config = 0;
				if ((rc = ibmveth_open(netdev)))
					return rc;
			} else
				pool->active = 1;
		} else if (!value && pool->active) {
			int mtu = netdev->mtu + IBMVETH_BUFF_OH;
			int i;
			/* Make sure there is a buffer pool with buffers that
			   can hold a packet of the size of the MTU */
			for (i = 0; i < IBMVETH_NUM_BUFF_POOLS; i++) {
				if (pool == &adapter->rx_buff_pool[i])
					continue;
				if (!adapter->rx_buff_pool[i].active)
					continue;
				if (mtu <= adapter->rx_buff_pool[i].buff_size)
					break;
			}

			if (i == IBMVETH_NUM_BUFF_POOLS) {
				ibmveth_error_printk("no active pool >= MTU\n");
				return -EPERM;
			}

			pool->active = 0;
			if (netif_running(netdev)) {
				adapter->pool_config = 1;
				ibmveth_close(netdev);
				adapter->pool_config = 0;
				if ((rc = ibmveth_open(netdev)))
					return rc;
			}
		}
	} else if (attr == &veth_num_attr) {
		if (value <= 0 || value > IBMVETH_MAX_POOL_COUNT)
			return -EINVAL;
		else {
			if (netif_running(netdev)) {
				adapter->pool_config = 1;
				ibmveth_close(netdev);
				adapter->pool_config = 0;
				pool->size = value;
				if ((rc = ibmveth_open(netdev)))
					return rc;
			} else
				pool->size = value;
		}
	} else if (attr == &veth_size_attr) {
		if (value <= IBMVETH_BUFF_OH || value > IBMVETH_MAX_BUF_SIZE)
			return -EINVAL;
		else {
			if (netif_running(netdev)) {
				adapter->pool_config = 1;
				ibmveth_close(netdev);
				adapter->pool_config = 0;
				pool->buff_size = value;
				if ((rc = ibmveth_open(netdev)))
					return rc;
			} else
				pool->buff_size = value;
		}
	}

	/* kick the interrupt handler to allocate/deallocate pools */
	ibmveth_interrupt(netdev->irq, netdev, NULL);
	return count;
}


#define ATTR(_name, _mode)      \
        struct attribute veth_##_name##_attr = {               \
        .name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE \
        };

static ATTR(active, 0644);
static ATTR(num, 0644);
static ATTR(size, 0644);

static struct attribute * veth_pool_attrs[] = {
	&veth_active_attr,
	&veth_num_attr,
	&veth_size_attr,
	NULL,
};

static struct sysfs_ops veth_pool_ops = {
	.show   = veth_pool_show,
	.store  = veth_pool_store,
};

static struct kobj_type ktype_veth_pool = {
	.release        = NULL,
	.sysfs_ops      = &veth_pool_ops,
	.default_attrs  = veth_pool_attrs,
};

static int ibmveth_resume(struct device *dev)
{
	struct net_device *netdev = dev_get_drvdata(dev);
	ibmveth_interrupt(netdev->irq, netdev, NULL);
	return 0;
}

static struct vio_device_id ibmveth_device_table[] __devinitdata= {
	{ "network", "IBM,l-lan"},
	{ "", "" }
};
MODULE_DEVICE_TABLE(vio, ibmveth_device_table);

static struct vio_driver ibmveth_driver = {
	.id_table	= ibmveth_device_table,
	.probe		= ibmveth_probe,
	.remove		= ibmveth_remove,
	.driver		= {
		.name	= ibmveth_driver_name,
		.owner	= THIS_MODULE,
		.resume	= ibmveth_resume,
	}
};

static int __init ibmveth_module_init(void)
{
	ibmveth_printk("%s: %s %s\n", ibmveth_driver_name, ibmveth_driver_string, ibmveth_driver_version);

	ibmveth_proc_register_driver();

	return vio_register_driver(&ibmveth_driver);
}

static void __exit ibmveth_module_exit(void)
{
	vio_unregister_driver(&ibmveth_driver);
	ibmveth_proc_unregister_driver();
}

module_init(ibmveth_module_init);
module_exit(ibmveth_module_exit);
