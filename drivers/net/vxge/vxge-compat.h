#ifndef __VXGE_COMPAT_H
#define __VXGE_COMPAT_H

#include <linux/if_vlan.h>

#define ETH_FCS_LEN	4	/* Octets in the FCS */

static inline int vxge_pci_dma_mapping_error(struct pci_dev *pdev,
					     dma_addr_t dma_addr)
{
	return pci_dma_mapping_error(dma_addr);
}
#define pci_dma_mapping_error(pdev, dma_addr) vxge_pci_dma_mapping_error(pdev, dma_addr)

/*
 * VLAN group compat functions
 */

static inline void vlan_group_set_device(struct vlan_group *vg,
					 u16 vid,
					 struct net_device *dev)
{
	if (vg)
		vg->vlan_devices[vid] = dev;
}

static inline struct net_device *vlan_group_get_device(struct vlan_group *vg,
						       u16 vid)
{
	return vg ? vg->vlan_devices[vid] : NULL;
}

/*
 * Multiqueue function wrappers for single-queue devices
 */

static inline struct net_device *alloc_etherdev_mq(int sizeof_priv,
						   unsigned int queue_count)
{
	WARN_ON(queue_count != 1);
	return alloc_etherdev(sizeof_priv);
}

struct netdev_queue; /* not instantiated anywhere */

static inline void netif_tx_stop_all_queues(struct net_device *dev)
{
	netif_stop_queue(dev);
}

static inline void netif_tx_stop_queue(struct netdev_queue *txq)
{
	netif_stop_queue((struct net_device *)txq);
}

static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	netif_start_queue(dev);
}

static inline void netif_tx_wake_all_queues(struct net_device *dev)
{
	netif_wake_queue(dev);
}

static inline void netif_tx_wake_queue(struct netdev_queue *txq)
{
	netif_wake_queue((struct net_device *)txq);
}

static inline int netif_tx_queue_stopped(const struct netdev_queue *txq)
{
	return netif_queue_stopped((struct net_device *)txq);
}

static inline struct netdev_queue *netdev_get_tx_queue(struct net_device *dev,
						       int n)
{
	WARN_ON(n != 0);
	return (struct netdev_queue*)dev;
}

static inline void skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{
}

/*
 * Partial new NAPI to old NAPI mapping
 * napi->dev is the dummy net_device for the old NAPI.
 */

static inline void napi_enable(struct napi_struct *napi)
{
	netif_poll_enable(napi->dev);
}

static inline void napi_disable(struct napi_struct *napi)
{
	netif_poll_disable(napi->dev);
}

static inline void napi_schedule(struct napi_struct *napi)
{
	netif_rx_schedule(napi->dev);
}

/* Unlike upstream netif_napi_add(), ours may fail with -ENOMEM */
static inline int vxge_netif_napi_add(void *nd_priv,
	struct napi_struct *napi, int (*poll)(struct net_device *, int *),
	int weight)
{
	struct net_device *nd;

	nd = alloc_netdev(0, "", ether_setup);
	if (!nd)
		return -ENOMEM;

	nd->priv = nd_priv;
	nd->weight = weight;
	nd->poll = poll;
	set_bit(__LINK_STATE_START, &nd->state);
	napi->dev = nd;
	return 0;
}

static inline void netif_napi_del(struct napi_struct *napi)
{
	free_netdev(napi->dev);
	napi->dev = NULL;
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

/*
 * These are only used with TX_MULTIQ_STEERING,
 * and so should never be called in RHEL5.
 */

static inline u16 skb_get_queue_mapping(const struct sk_buff *skb)
{
	WARN_ON(1);
	return 0;
}

static inline int netif_subqueue_stopped(const struct net_device *dev,
					 struct sk_buff *skb)
{
	WARN_ON(1);
	return netif_queue_stopped(dev);
}

typedef int netdev_tx_t;

/*
 * net_device_ops copied from upstream, but only the members actually
 * used by the vxge driver.
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

	void			(*ndo_vlan_rx_register)(struct net_device *dev,
						        struct vlan_group *grp);
	void			(*ndo_vlan_rx_add_vid)(struct net_device *dev,
						       unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
	void                    (*ndo_poll_controller)(struct net_device *dev);
#endif
};

#define eth_validate_addr NULL

static inline void vxge_set_netdev_ops(struct net_device *ndev,
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
	ndev->vlan_rx_register   = ndo->ndo_vlan_rx_register;
	ndev->vlan_rx_add_vid    = ndo->ndo_vlan_rx_add_vid;
#ifdef CONFIG_NET_POLL_CONTROLLER
	ndev->poll_controller    = ndo->ndo_poll_controller;
#endif
}

#endif /* __VXGE_COMPAT_H */
