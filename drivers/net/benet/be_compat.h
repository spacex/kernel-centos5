/*
 * Copyright (C) 2005 - 2009 ServerEngines
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.  The full GNU General
 * Public License is included in this distribution in the file called COPYING.
 *
 * Contact Information:
 * linux-drivers@serverengines.com
 *
 * ServerEngines
 * 209 N. Fair Oaks Ave
 * Sunnyvale, CA 94085
 */

#ifndef BE_COMPAT_H
#define BE_COMPAT_H


#define ETH_FCS_LEN			4

#define DEFINE_PCI_DEVICE_TABLE(_table) struct pci_device_id _table[] 	\
						__devinitdata

/* Backport of request_irq */
typedef irqreturn_t(*backport_irq_handler_t) (int, void *);
static inline int
backport_request_irq(unsigned int irq, irqreturn_t(*handler) (int, void *),
		unsigned long flags, const char *dev_name, void *dev_id)
{
	return request_irq(irq,
			(irqreturn_t(*) (int, void *, struct pt_regs *))handler,
			flags, dev_name, dev_id);
}
#define request_irq 			backport_request_irq

/*
 * Backport of netdev ops struct
 */
struct net_device_ops {
	int	(*ndo_init)(struct net_device *dev);
	void	(*ndo_uninit)(struct net_device *dev);
	int	(*ndo_open)(struct net_device *dev);
	int	(*ndo_stop)(struct net_device *dev);
	int	(*ndo_start_xmit) (struct sk_buff *skb, struct net_device *dev);
	u16	(*ndo_select_queue)(struct net_device *dev,
				    struct sk_buff *skb);
	void	(*ndo_change_rx_flags)(struct net_device *dev, int flags);
	void	(*ndo_set_rx_mode)(struct net_device *dev);
	void	(*ndo_set_multicast_list)(struct net_device *dev);
	int	(*ndo_set_mac_address)(struct net_device *dev, void *addr);
	int	(*ndo_validate_addr)(struct net_device *dev);
	int	(*ndo_do_ioctl)(struct net_device *dev,
				struct ifreq *ifr, int cmd);
	int	(*ndo_set_config)(struct net_device *dev, struct ifmap *map);
	int	(*ndo_change_mtu)(struct net_device *dev, int new_mtu);
	int	(*ndo_neigh_setup)(struct net_device *dev,
				struct neigh_parms *);
	void	(*ndo_tx_timeout) (struct net_device *dev);

	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	void	(*ndo_vlan_rx_register)(struct net_device *dev,
				struct vlan_group *grp);
	void	(*ndo_vlan_rx_add_vid)(struct net_device *dev,
			       unsigned short vid);
	void	(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
				unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
#define HAVE_NETDEV_POLL
	void	(*ndo_poll_controller)(struct net_device *dev);
#endif
};
extern void be_netdev_ops_init(struct net_device *netdev,
			struct net_device_ops *ops);
extern int eth_validate_addr(struct net_device *);

/*
 * Back port of new NAPI: simulate polling on multiple napi instances
 * using tasklets
 */

extern int be_poll(struct napi_struct *, int);
extern int be_poll_compat(struct net_device *netdev, int *budget);

static inline void napi_schedule(struct napi_struct *napi)
{
	netif_rx_schedule(napi->dev);
}

static inline void netif_napi_add(struct net_device *netdev,
		  struct napi_struct *napi,
		  int (*poll) (struct napi_struct *, int), int weight)
{
	netdev->weight = weight;
	netdev->poll = be_poll_compat;

	napi->dev = netdev;
}

static inline void napi_enable(struct napi_struct *napi)
{
	netif_poll_enable(napi->dev);
}

static inline void napi_disable(struct napi_struct *napi)
{
	netif_poll_disable(napi->dev);
}

static inline void vlan_group_set_device(struct vlan_group *vg,
					u16 vlan_id,
					struct net_device *dev)
{
	struct net_device **array;
	if (!vg)
		return;
	array = vg->vlan_devices;
	array[vlan_id] = dev;
}


/************** Backport of Delayed work queues interface ****************/
struct delayed_work {
	struct work_struct work;
};

#define INIT_DELAYED_WORK(_work, _func)				\
		INIT_WORK(&(_work)->work, (void (*)(void *))_func, &(_work)->work)

static inline int backport_cancel_delayed_work_sync(struct delayed_work *work)
{
	cancel_rearming_delayed_work(&work->work);
	return 0;
}
#define cancel_delayed_work_sync backport_cancel_delayed_work_sync

static inline int backport_schedule_delayed_work(struct delayed_work *work,
		unsigned long delay)
{
	if (unlikely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}
#define schedule_delayed_work backport_schedule_delayed_work
/* backport delayed workqueue */

#if !defined(NETIF_F_IPV6_CSUM)
#define NETIF_F_IPV6_CSUM       NETIF_F_HW_CSUM
#endif

#endif				/* BE_COMPAT_H */
