#ifndef __SFC_COMPAT_H__
#define __SFC_COMPAT_H__

#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <linux/workqueue.h>

#define delayed_work work_struct
#define INIT_DELAYED_WORK INIT_WORK
typedef void (*work_func_old_t)(void *);

static inline int sfc_pci_dma_mapping_error(struct pci_dev *pdev,
					    dma_addr_t dma_addr)
{
	return pci_dma_mapping_error(dma_addr);
}
#define pci_dma_mapping_error(pdev, dma_addr) \
	sfc_pci_dma_mapping_error(pdev, dma_addr)

static inline void skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{
}

typedef int netdev_tx_t;

/*
 * net_device_ops copied from upstream, but only the members actually
 * used by the sfc driver.
 */
struct net_device_ops {
	int			(*ndo_open)(struct net_device *dev);
	int			(*ndo_stop)(struct net_device *dev);
	netdev_tx_t		(*ndo_start_xmit) (struct sk_buff *skb,
						   struct net_device *dev);
	void			(*ndo_set_multicast_list)(struct net_device *dev);
	int			(*ndo_set_mac_address)(struct net_device *dev,
						       void *addr);
	int			(*ndo_validate_addr)(struct net_device *dev);
	int			(*ndo_do_ioctl)(struct net_device *dev,
					        struct ifreq *ifr, int cmd);
	int			(*ndo_change_mtu)(struct net_device *dev,
						  int new_mtu);
	void			(*ndo_tx_timeout) (struct net_device *dev);
	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);
#ifdef CONFIG_NET_POLL_CONTROLLER
	void                    (*ndo_poll_controller)(struct net_device *dev);
#endif
};

#define eth_validate_addr NULL

static inline void sfc_set_netdev_ops(struct net_device *ndev,
	const struct net_device_ops *ndo)
{
	ndev->open               = ndo->ndo_open;
	ndev->stop               = ndo->ndo_stop;
	ndev->hard_start_xmit    = ndo->ndo_start_xmit;
	ndev->set_multicast_list = ndo->ndo_set_multicast_list;
	ndev->set_mac_address    = ndo->ndo_set_mac_address;
	BUG_ON(ndo->ndo_validate_addr != eth_validate_addr);
	ndev->do_ioctl           = ndo->ndo_do_ioctl;
	ndev->change_mtu         = ndo->ndo_change_mtu;
	ndev->tx_timeout         = ndo->ndo_tx_timeout;
	ndev->get_stats          = ndo->ndo_get_stats;
#ifdef CONFIG_NET_POLL_CONTROLLER
	ndev->poll_controller    = ndo->ndo_poll_controller;
#endif
}

#endif /* __SFC_COMPAT_H__ */
