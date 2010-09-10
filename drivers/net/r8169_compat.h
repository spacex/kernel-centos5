#ifndef __R8169_COMPAT_H__
#define __R8169_COMPAT_H__

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/workqueue.h>
#include <linux/pci.h>

static inline __be16 backport_eth_type_trans(struct sk_buff *skb,
					     struct net_device *dev)
{
	skb->dev = dev;
	return eth_type_trans(skb, dev);
}

#define eth_type_trans backport_eth_type_trans

typedef void (*work_func_t)(struct work_struct *work);

struct delayed_work {
	struct work_struct work;
};

static inline void backport_INIT_WORK(struct work_struct *work, void *func)
{
	INIT_WORK(work, func, work);
}

static inline void backport_PREPARE_WORK(struct work_struct *work, void *func)
{
	PREPARE_WORK(work, func, work);
}

static inline int backport_schedule_delayed_work(struct delayed_work *work,
						 unsigned long delay)
{
	if (likely(!delay))
		return schedule_work(&work->work);
	else
		return schedule_delayed_work(&work->work, delay);
}


#undef INIT_WORK
#define INIT_WORK(_work, _func) backport_INIT_WORK(_work, _func)
#define INIT_DELAYED_WORK(_work,_func) INIT_WORK(&(_work)->work, _func)

#undef PREPARE_WORK
#define PREPARE_WORK(_work, _func) backport_PREPARE_WORK(_work, _func)
#define PREPARE_DELAYED_WORK(_work, _func) PREPARE_WORK(&(_work)->work, _func)

#define schedule_delayed_work backport_schedule_delayed_work

#define PCI_VENDOR_ID_GIGABYTE	0x1458

static inline int pci_wake_from_d3(struct pci_dev *dev, bool enable)
{
	if (pci_enable_wake(dev, PCI_D3cold, enable))
		return pci_enable_wake(dev, PCI_D3hot, enable);
	return 0;
}

#undef NETDEV_TX_OK
#undef NETDEV_TX_BUSY
#undef NETDEV_TX_LOCKED

enum netdev_tx {
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY,
	NETDEV_TX_LOCKED = -1,
};
typedef enum netdev_tx netdev_tx_t;

static inline void napi_enable(struct napi_struct *napi)
{
	netif_poll_enable(napi->dev);
}

static inline void napi_disable(struct napi_struct *napi)
{
	netif_poll_disable(napi->dev);
}

static inline void __napi_schedule(struct napi_struct *napi)
{
	__netif_rx_schedule(napi->dev);
}

static inline void napi_schedule(struct napi_struct *napi)
{
	netif_rx_schedule(napi->dev);
}

static inline int napi_schedule_prep(struct napi_struct *napi)
{
	return netif_rx_schedule_prep(napi->dev);
}

static int rtl8169_poll_compat(struct net_device *, int *);

static inline void netif_napi_add(struct net_device *netdev,
				  struct napi_struct *napi,
				  int (*poll)(struct napi_struct *, int),
				  int weight)
{
	netdev->weight = weight;
	netdev->poll = rtl8169_poll_compat;

	napi->dev = netdev;
	napi->poll = poll;
}

/*
 * net_device_ops backport
 */
#define eth_validate_addr NULL

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
	void	(*ndo_poll_controller)(struct net_device *dev);
#endif
};

static void dev_netdev_ops(struct net_device *netdev,
			   const struct net_device_ops *ops)
{
	netdev->open = ops->ndo_open;
	netdev->stop = ops->ndo_stop;
	netdev->hard_start_xmit = ops->ndo_start_xmit;
	netdev->set_mac_address = ops->ndo_set_mac_address;
	netdev->get_stats = ops->ndo_get_stats;
	netdev->set_multicast_list = ops->ndo_set_multicast_list;
	netdev->change_mtu = ops->ndo_change_mtu;
	netdev->vlan_rx_register = ops->ndo_vlan_rx_register;
	netdev->vlan_rx_add_vid = ops->ndo_vlan_rx_add_vid;
	netdev->tx_timeout = ops->ndo_tx_timeout;
	netdev->do_ioctl = ops->ndo_do_ioctl;
#ifdef CONFIG_NET_POLL_CONTROLLER
	netdev->poll_controller = ops->ndo_poll_controller;
#endif
}

static inline int backport_request_irq(unsigned int irq,
				       irqreturn_t (*h)(int, void *),
				       unsigned long flags,
				       const char *dev_name, void *dev_id)
{
	return request_irq(irq,
			   (irqreturn_t (*)(int, void *, struct pt_regs *))h,
			   flags, dev_name, dev_id);
}
#define request_irq backport_request_irq

#define ETH_FCS_LEN	4

#elif !defined(__R8169_COMPAT2_H__)
#define __R8169_COMPAT2_H__

static int rtl8169_poll_compat(struct net_device *netdev, int *budget)
{
	struct rtl8169_private *tp = netdev_priv(netdev);
	u32 work_done, can_do;

	can_do = min(*budget, netdev->quota);
	work_done = tp->napi.poll(&tp->napi, can_do);
	*budget -= work_done;
	netdev->quota -= work_done;

	return (work_done < can_do) ? 0 : 1;
}

#define ETH_FCS_LEN 4
#endif
