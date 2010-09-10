/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/


/* Linux PRO/1000 Ethernet Driver main header file */

#ifndef _IGB_H_
#define _IGB_H_

#include "igb_compat.h"
#include "e1000_api.h"
#include "e1000_82575.h"

struct igb_adapter;

#define IGB_ERR(args...) printk(KERN_ERR "igb: " args)

#define PFX "igb: "
#define DPRINTK(nlevel, klevel, fmt, args...) \
	(void)((NETIF_MSG_##nlevel & adapter->msg_enable) && \
	printk(KERN_##klevel PFX "%s: %s: " fmt, adapter->netdev->name, \
		__FUNCTION__ , ## args))

/* Interrupt defines */
#define IGB_MAX_TX_CLEAN 72

#define IGB_MIN_DYN_ITR 3000
#define IGB_MAX_DYN_ITR 96000
#define IGB_START_ITR 6000

#define IGB_DYN_ITR_PACKET_THRESHOLD 2
#define IGB_DYN_ITR_LENGTH_LOW 200
#define IGB_DYN_ITR_LENGTH_HIGH 1000

/* TX/RX descriptor defines */
#define IGB_DEFAULT_TXD                  256
#define IGB_MIN_TXD                       80
#define IGB_MAX_TXD                     4096

#define IGB_DEFAULT_RXD                  256
#define IGB_MIN_RXD                       80
#define IGB_MAX_RXD                     4096

/* Transmit and receive queues */
#define IGB_MAX_RX_QUEUES                  4
#define IGB_MAX_TX_QUEUES                  4

/* RX descriptor control thresholds.
 * PTHRESH - MAC will consider prefetch if it has fewer than this number of
 *           descriptors available in its onboard memory.
 *           Setting this to 0 disables RX descriptor prefetch.
 * HTHRESH - MAC will only prefetch if there are at least this many descriptors
 *           available in host memory.
 *           If PTHRESH is 0, this should also be 0.
 * WTHRESH - RX descriptor writeback threshold - MAC will delay writing back
 *           descriptors until either it has this many to write back, or the
 *           ITR timer expires.
 */
#define IGB_RX_PTHRESH                    16
#define IGB_RX_HTHRESH                     8
#define IGB_RX_WTHRESH                     1

/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522

/* Supported Rx Buffer Sizes */
#define IGB_RXBUFFER_128   128    /* Used for packet split */
#define IGB_RXBUFFER_256   256    /* Used for packet split */
#define IGB_RXBUFFER_512   512
#define IGB_RXBUFFER_1024  1024
#define IGB_RXBUFFER_2048  2048
#define IGB_RXBUFFER_4096  4096
#define IGB_RXBUFFER_8192  8192
#define IGB_RXBUFFER_16384 16384

/* Packet Buffer allocations */
#define IGB_PBA_BYTES_SHIFT 0xA
#define IGB_TX_HEAD_ADDR_SHIFT 7
#define IGB_PBA_TX_MASK 0xFFFF0000

#define IGB_FC_PAUSE_TIME 0x0680 /* 858 usec */

/* How many Tx Descriptors do we need to call netif_wake_queue ? */
#define IGB_TX_QUEUE_WAKE	16
/* How many Rx Buffers do we bundle into one write to the hardware ? */
#define IGB_RX_BUFFER_WRITE	16	/* Must be power of 2 */

#define AUTO_ALL_MODES            0
#define IGB_EEPROM_APME         0x0400

#ifndef IGB_MASTER_SLAVE
/* Switch to override PHY master/slave setting */
#define IGB_MASTER_SLAVE	e1000_ms_hw_default
#endif

#define IGB_MNG_VLAN_NONE -1

/* wrapper around a pointer to a socket buffer,
 * so a DMA handle can be stored along with the buffer */
struct igb_buffer {
	struct sk_buff *skb;
	dma_addr_t dma;

	union {
		/* TX */
		struct {
			unsigned long time_stamp;
			u32 length;
		};
		/* RX */
		struct {
			struct page *page;
			u64 page_dma;
		};
	};
};

struct igb_queue_stats {
	u64 packets;
	u64 bytes;
};

struct igb_ring {
	struct igb_adapter *adapter; /* backlink */
	void *desc;         /* pointer to the descriptor ring memory */
	dma_addr_t dma;     /* physical address of the descriptor ring */
	unsigned int size;  /* length of descriptor ring in bytes */
	u16 count;          /* number of descriptors in the ring */
	u16 next_to_use;    /* index to next free descriptor */
	u16 next_to_clean;  /* index to next processed descriptor */
	u16 head, tail;     /* indices to ring head/tail */

	u16 itr_register;
	u32 itr_val;
	u32 eims_value;

	struct igb_buffer *buffer_info;

	union {
		/* TX */
		struct {
			spinlock_t tx_clean_lock;
			bool detect_tx_hung;
			char name[IFNAMSIZ + 5];
		};
		/* RX */
		struct {
			struct sk_buff *pending_skb;
			int pending_skb_page;
			struct net_device *netdev;
			struct igb_ring *buddy;
		};
	};

	int cpu;

	unsigned int total_bytes;
	unsigned int total_packets;
};

#define IGB_DESC_UNUSED(R) \
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

#define E1000_RX_DESC_ADV(R, i)	    \
	(&(((union e1000_adv_rx_desc *)((R).desc))[i]))
#define E1000_TX_DESC_ADV(R, i)	    \
	(&(((union e1000_adv_tx_desc *)((R).desc))[i]))
#define E1000_TX_CTXTDESC_ADV(R, i)	    \
	(&(((struct e1000_adv_tx_context_desc *)((R).desc))[i]))
#define E1000_GET_DESC(R, i, type)	(&(((struct type *)((R).desc))[i]))
#define E1000_TX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_tx_desc)
#define E1000_RX_DESC(R, i)		E1000_GET_DESC(R, i, e1000_rx_desc)

#define MAX_MSIX_COUNT 10
/* board specific private data structure */

struct igb_adapter {
	/* TX */
	struct igb_ring *tx_ring;        /* One per active queue */
	int num_tx_queues;
	unsigned int restart_queue;
	unsigned long tx_queue_len;
	u32 txd_cmd;
	u32 gotcl;
	u64 gotcl_old;
	u64 tpt_old;
	u64 colc_old;
	u32 tx_timeout_count;
	unsigned int total_tx_bytes;
	unsigned int total_tx_packets;

	/* RX */
	struct igb_ring *rx_ring;        /* One per active queue */
	int num_rx_queues;
	u32 alloc_rx_buff_failed;
	u64 hw_csum_err;
	u64 hw_csum_good;
	u64 rx_hdr_split;
	u64 gorcl_old;
	u32 gorcl;
	u16 rx_ps_hdr_size;
	bool rx_csum;
	unsigned int total_rx_bytes;
	unsigned int total_rx_packets;

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;
	struct net_device_stats net_stats;

	/* structs defined in e1000_hw.h */
	struct e1000_hw hw;
	struct e1000_hw_stats stats;
	struct e1000_phy_info phy_info;
	struct e1000_phy_stats phy_stats;

	/* timers, tasks */
	struct timer_list watchdog_timer;
	struct timer_list phy_info_timer;
	struct timer_list blink_timer;

	struct work_struct reset_task;
	struct work_struct watchdog_task;

	struct vlan_group *vlgrp;
	u16 mng_vlan_id;
	u32 bd_number;
	u32 rx_buffer_len;
	u32 wol;
	u32 en_mng_pt;
	u16 link_speed;
	u16 link_duplex;
	/* Interrupt Throttle Rate */
	u32 itr;
	u32 itr_setting;
	u16 tx_itr;
	u16 rx_itr;
	int set_itr;

	u8 fc_autoneg;
	u8 tx_timeout_factor;
	unsigned long led_status;


	u32 test_icr;
	struct igb_ring test_tx_ring;
	struct igb_ring test_rx_ring;

	int msg_enable;
	struct msix_entry *msix_entries;
	u32 eims_enable_mask;
	u32 lli_port;
	u32 lli_size;

	/* to not mess up cache alignment, always add to the bottom */
	unsigned long state;
	unsigned int flags;
	u32 eeprom_wol;
};

enum e1000_state_t {
	__IGB_TESTING,
	__IGB_RESETTING,
	__IGB_DOWN
};

#define FLAG_IGB_HAS_MSI     (1 << 0)
#define FLAG_IGB_LLI_PUSH    (1 << 1)
#define FLAG_IGB_IN_NETPOLL  (1 << 2)

extern char igb_driver_name[];
extern const char igb_driver_version[];

extern int igb_up(struct igb_adapter *);
extern void igb_down(struct igb_adapter *);
extern void igb_reinit_locked(struct igb_adapter *);
extern void igb_reset(struct igb_adapter *);
extern int igb_set_spd_dplx(struct igb_adapter *, u16 );
extern int igb_setup_tx_resources(struct igb_adapter *, struct igb_ring *);
extern int igb_setup_rx_resources(struct igb_adapter *, struct igb_ring *);
extern void igb_update_stats(struct igb_adapter *);

#endif /* _IGB_H_ */
