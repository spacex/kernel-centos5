/*
 * QLogic qlge NIC HBA Driver
 * Copyright (c)  2003-2008 QLogic Corporation
 * See LICENSE.qlge for copyright and licensing details.
 * Author:     Linux qlge network device driver by
 *                      Ron Mercer <ron.mercer@qlogic.com>
 */

#ifndef _KCOMPAT_H_
#define _KCOMPAT_H_

#include <linux/version.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/mii.h>
#include <asm/io.h>

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18))
#ifndef NETIF_F_GRO
#define vlan_gro_receive(_napi, _vlgrp, _vlan, _skb) \
		vlan_hwaccel_receive_skb(_skb, _vlgrp, _vlan)
#define napi_gro_receive(_napi, _skb) netif_receive_skb(_skb)
#endif

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#ifndef IRQF_SHARED
#define IRQF_SHARED SA_SHIRQ
#endif

#ifndef netdev_alloc_skb
#define netdev_alloc_skb _kc_netdev_alloc_skb
static inline struct sk_buff *_kc_netdev_alloc_skb(struct net_device *dev,
						unsigned int length)
{
	struct sk_buff *skb;
	skb = alloc_skb(length + 16, GFP_ATOMIC);
	if (likely(skb != NULL)) {
		skb_reserve(skb, 16);
		skb->dev = dev;
	}
	return skb;
}
#endif

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
	return skb->h.raw;
}
static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}

#define pci_channel_offline(pdev) (pdev->error_state && \
	pdev->error_state != pci_channel_io_normal)

#endif /* < 2.6.18 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19))

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif
#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b) 0
#endif
#if !defined(__USE_COMPAT_LAYER_2_6_18_PLUS__)
#if (!((RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(4, 4)) && \
	(RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(5, 0)) || \
	(RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(5, 0))))
typedef irqreturn_t (*irq_handler_t)(int, void*, struct pt_regs *);
#endif
#endif /* !defined(__USE_COMPAT_LAYER_2_6_18_PLUS__) */
typedef irqreturn_t (*new_handler_t)(int, void*);
static inline irqreturn_t _kc_request_irq(unsigned int irq,
			new_handler_t handler, unsigned long flags,
			const char *devname, void *dev_id)
{
	irq_handler_t new_handler = (irq_handler_t) handler;
	return request_irq(irq, new_handler, flags, devname, dev_id);
}
#if defined(__COMPAT_LAYER_2_6_18_PLUS__)
#undef irq_handler_t
#endif

#undef request_irq
#define request_irq(irq, handler, flags, devname, dev_id) \
		_kc_request_irq((irq), (handler), (flags), (devname), (dev_id))

#define irq_handler_t new_handler_t

#if !defined(__USE_COMPAT_LAYER_2_6_18_PLUS__)
#undef INIT_WORK
#define INIT_WORK(_work, _func) \
do { \
	INIT_LIST_HEAD(&(_work)->entry); \
	(_work)->pending = 0; \
	(_work)->func = (void (*)(void *))_func; \
	(_work)->data = _work; \
	init_timer(&(_work)->timer); \
} while (0)
#define INIT_DELAYED_WORK INIT_WORK
#endif

#define tcp_hdr(skb) (skb->h.th)
#define tcp_hdrlen(skb) (skb->h.th->doff << 2)
#define skb_transport_offset(skb) (skb->h.raw - skb->data)
#define skb_transport_header(skb) (skb->h.raw)
#define ipv6_hdr(skb) (skb->nh.ipv6h)
#define ip_hdr(skb) (skb->nh.iph)
#define skb_network_offset(skb) (skb->nh.raw - skb->data)
#define skb_network_header(skb) (skb->nh.raw)
#define skb_network_header_len(skb) (skb->h.raw - skb->nh.raw)

#define cancel_delayed_work_sync(x) cancel_delayed_work(x)

#endif /* < 2.6.19 */

/*****************************************************************************/
#if (LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 16))
typedef __u16 __bitwise __sum16;
#endif /* > 2.6.18 */

#endif /* _KCOMPAT_H_ */
