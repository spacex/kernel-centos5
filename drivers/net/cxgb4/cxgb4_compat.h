/*
 * This file is part of the Chelsio T4 Ethernet driver for Linux.
 *
 * Copyright (c) 2003-2010 Chelsio Communications, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __CXGB4_COMPAT_H__
#define __CXGB4_COMPAT_H__

#include <linux/ethtool.h>
#include <linux/in6.h>
#include <linux/ctype.h>


typedef int netdev_tx_t;

static inline void skb_set_queue_mapping(struct sk_buff *skb, int mapping)
{
	skb->priority = mapping;
}

#define __devnet(nd)				\
	((nd)					\
	 ? ((nd)->class_dev.parent		\
	    ? ((nd)->class_dev.parent->dev ?: 0)\
	    : 0)				\
	 : 0)

#define netdev_uc_count(netdev)			0
#define netdev_for_each_uc_addr(ha, dev)	if (0)

/*
 * Fake this.  uc_count is zero and netdev_for_each_uc_addr will do nothing,
 * but we still want it to compile.
 */
struct netdev_hw_addr {
	u8	*addr;
};

#define dev_addr_list	dev_mc_list	

#define	netif_tx_start_all_queues(dev)	netif_start_queue(dev)
#define	netif_tx_stop_all_queues(dev)	netif_stop_queue(dev)
#define	netif_tx_wake_queue(dev)	netif_wake_queue(dev)

/*
 * No multiqueue support, so we collapse the netdev_queue back
 * to the net_device.
 */
#define netdev_queue	net_device
#define netdev_get_tx_queue(dev, j)	(dev)
#define netif_tx_stop_queue(txq)	netif_stop_queue(txq)
#define skb_get_queue_mapping(skb) 	0	
#define skb_record_rx_queue(a, b)	do {;} while (0)


/*
 * no mdio_support field in ethtool_cmd struct.
 * we'll place it in the last reserved field, where it will stay out of the way.
 * It is set by the driver, and ignored by all.
 */

#define mdio_support	reserved[3]

#include <linux/delay.h>

#define PCI_VPD_INFO_FLD_HDR_SIZE    3
#define PCI_VPD_MAX_POLL	40
#define PCI_VPD_LEN		(1 + PCI_VPD_ADDR_MASK)
#define PCI_EXP_LNKSTA_CLS_2_5GB 0x01
#define PCI_EXP_LNKSTA_CLS_5_0GB 0x02

#define PCI_VPD_INFO_FLD_HDR_SIZE       3

#define PCI_VPD_LRDT                    0x80    /* Large Resource Data Type */
#define PCI_VPD_LRDT_ID(x)              (x | PCI_VPD_LRDT)

/* Large Resource Data Type Tag Item Names */
#define PCI_VPD_LTIN_ID_STRING          0x02    /* Identifier String */
#define PCI_VPD_LTIN_RO_DATA            0x10    /* Read-Only Data */
#define PCI_VPD_LTIN_RW_DATA            0x11    /* Read-Write Data */

#define PCI_VPD_LRDT_ID_STRING          PCI_VPD_LRDT_ID(PCI_VPD_LTIN_ID_STRING)
#define PCI_VPD_LRDT_RO_DATA            PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RO_DATA)
#define PCI_VPD_LRDT_RW_DATA            PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RW_DATA)

/* Small Resource Data Type Tag Item Names */
#define PCI_VPD_STIN_END                0x78    /* End */

#define PCI_VPD_SRDT_END                PCI_VPD_STIN_END

#define PCI_VPD_SRDT_TIN_MASK           0x78
#define PCI_VPD_SRDT_LEN_MASK           0x07

#define PCI_VPD_LRDT_TAG_SIZE           3
#define PCI_VPD_SRDT_TAG_SIZE           1

/*
 * pci_read_vpd - used by eeprom_rd_pyhs
 */
static inline ssize_t pci_read_vpd(struct pci_dev *dev,
				   loff_t pos, size_t count, void *arg)
{
	loff_t	end = pos + count;
	u8	*buf = arg;
	u16	v16;
	u32	v32;
	int	attempts = PCI_VPD_MAX_POLL;
	int	ret;

	static struct cache {
		struct pci_dev *dev;
		u8	cap;
	} cache = {0,0};

	if (pos < 0 || pos > PCI_VPD_LEN || end > PCI_VPD_LEN)
		return -EINVAL;
 
	if (cache.dev != dev) {
		cache.cap = pci_find_capability(dev, PCI_CAP_ID_VPD);
		cache.dev = dev;
	}
 
	while (pos < end) {
		unsigned int i, skip;
 
		ret = pci_write_config_word(dev, cache.cap + PCI_VPD_ADDR,
					    pos & ~3);
		if (ret < 0)
			return ret;

		attempts = PCI_VPD_MAX_POLL;
		do {
			udelay(10);
			pci_read_config_word(dev, cache.cap + PCI_VPD_ADDR, &v16);
		} while (!(v16 & PCI_VPD_ADDR_F) && --attempts);

		if (attempts <= 0)
			return -ETIMEDOUT;

		ret = pci_read_config_dword(dev, cache.cap + PCI_VPD_DATA, &v32);
		if (ret < 0)
			break;
 
		skip = pos & 3;
		for (i = 0;  i < sizeof (u32); ++i) {
			if (i >= skip) {
				*buf++ = v32;
				if (++pos == end)
					break;
			}
			v32 >>= 8;
		}
	}

	return count;
}

static inline ssize_t pci_write_vpd(struct pci_dev *dev,
				    loff_t pos, size_t count, const void *arg)
{
	const u8	*buf = arg;
	loff_t		end = pos + count;
	int		ret = 0;
	u16		v16;
	u32		v32;
	int		attempts = PCI_VPD_MAX_POLL;

	static struct cache {
		struct pci_dev *dev;
		u8	cap;
	} cache = {0,0};

	if (pos < 0 || (pos & 3) || (count & 3) || end > PCI_VPD_LEN)
		return -EINVAL;

	if (cache.dev != dev) {
		cache.cap = pci_find_capability(dev, PCI_CAP_ID_VPD);
		cache.dev = dev;
	}

	attempts = PCI_VPD_MAX_POLL;
	do {
		udelay(10);
		pci_read_config_word(dev, cache.cap + PCI_VPD_ADDR, &v16);
	} while (!(v16 & PCI_VPD_ADDR_F) && --attempts);

	if (attempts <= 0)
		return -ETIMEDOUT;

	while (pos < end) {
		v32  = *buf++ <<  0;
		v32 |= *buf++ <<  8;
		v32 |= *buf++ << 16;
		v32 |= *buf++ << 24;

		ret = pci_write_config_dword(dev, cache.cap + PCI_VPD_DATA, v32);
		if (ret < 0)
			return ret;
		ret = pci_write_config_word(dev, cache.cap + PCI_VPD_ADDR,
					    pos | PCI_VPD_ADDR_F);
		if (ret < 0)
			return ret;

		attempts = PCI_VPD_MAX_POLL;
		do {
			udelay(10);
			pci_read_config_word(dev, cache.cap + PCI_VPD_ADDR, &v16);
		} while (!(v16 & PCI_VPD_ADDR_F) && --attempts);

		if (attempts <= 0)
			return -ETIMEDOUT;

		pos += sizeof (u32);
	}
	return count;
}

static inline u32 pci_pcie_cap(struct pci_dev *pci)
{
	return pci_find_capability(pci, PCI_CAP_ID_EXP);
}

#define COMPAT_ETHTOOL_FLASH_MAX_FILENAME	128
struct compat_ethtool_flash {
	__u32   cmd;
	__u32   region;
	char    data[COMPAT_ETHTOOL_FLASH_MAX_FILENAME];
};

#define ethtool_flash	compat_ethtool_flash

#define ethtool_op_set_tx_ipv6_csum compat_ethtool_op_set_tx_ipv6_csum

static inline int compat_ethtool_op_set_tx_ipv6_csum(struct net_device *dev, u32 data)
{
	if (data)
		dev->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
	else
		dev->features &= ~(NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);
	return 0;
}

typedef unsigned long uintptr_t;

static inline long IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((unsigned long)ptr);
}

#define dev_alert(dev, format, arg...)		\
	dev_printk(KERN_ALERT , dev , format , ## arg)

#define printk_once(x...) ({			\
	static bool __print_once;		\
						\
	if (!__print_once) {			\
		__print_once = true;		\
		printk(x);			\
	}					\
})

#define alloc_etherdev_mq(a, b)	alloc_etherdev(a)

#define pr_warning(fmt, ...)				\
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)

static inline char *skip_spaces(const char *str)
{
	while (isspace(*str))
		++str;
	return (char *)str;
}

static inline char *strim(char *s)
{
	size_t size;
	char *end;

	s = skip_spaces(s);
	size = strlen(s);
	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	return s;
}

#define __netdev_alloc_page(a, b)		\
	alloc_pages_node(-1, (b), 0)

#define netdev_free_page(a, b)			\
	__free_pages((b), 0)

static inline void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
				  int (*poll)(struct net_device *, int *), int weight)
{
        BUG_ON(dev->atalk_ptr);

        INIT_LIST_HEAD(&napi->poll_list);
        napi->gro_count = 0;
        napi->gro_list = NULL;
        napi->skb = NULL;

        napi->weight = weight;
        napi->dev = dev;

        dev->poll = poll;

}

static inline void netif_napi_del(struct napi_struct *napi)
{
        struct sk_buff *skb, *next;

        kfree_skb(napi->skb);

        for (skb = napi->gro_list; skb; skb = next) {
                next = skb->next;
                skb->next = NULL;
                kfree_skb(skb);
        }

        napi->gro_list = NULL;
        napi->gro_count = 0;


}
static inline void napi_schedule(struct net_device *dev)
{
	netif_rx_schedule(dev);
}

static inline void compat_napi_complete(struct net_device *dev)
{
        netif_rx_complete(dev);
}
#define napi_complete(x)        compat_napi_complete(x)

static inline int napi_reschedule(struct napi_struct *napi)
{
	netif_rx_schedule(napi->dev);
	return 1;
}

static inline int __netif_tx_trylock(struct net_device *txq)
{
	return netif_tx_trylock(txq);
}

static inline void __netif_tx_unlock(struct net_device *txq)
{
	netif_tx_unlock(txq);
}

static inline void napi_enable(struct net_device *dev)
{
        if (dev)
                netif_poll_enable(dev);
}

static inline void napi_disable(struct net_device *dev)
{
        if (dev)
                netif_poll_disable(dev);
}

#define netif_tx_start_all_queues(dev)  netif_start_queue(dev)
#define netif_tx_stop_all_queues(dev)   netif_stop_queue(dev)
#define netif_tx_wake_queue(dev)        netif_wake_queue(dev)

#ifndef BIT
#define BIT(n)          (1 << (n))
#endif


#endif /* __CXGB4_COMPAT_H__ */
