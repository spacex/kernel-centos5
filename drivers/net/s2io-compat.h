#ifndef __S2IO_COMPAT_H
#define __S2IO_COMPAT_H

typedef __u16 __bitwise __sum16;

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_BUF_SIZE 18
#define DECLARE_MAC_BUF(var) char var[MAC_BUF_SIZE]
static inline char *print_mac(char *buf, const unsigned char *addr)
{
	sprintf(buf, MAC_FMT,
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}

static inline int s2io_pci_dma_mapping_error(struct pci_dev *pdev,
					     dma_addr_t dma_addr)
{
	return pci_dma_mapping_error(dma_addr);
}
#define pci_dma_mapping_error(pdev, dma_addr) s2io_pci_dma_mapping_error(pdev, dma_addr)

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

/*
 * delayer work compat
 */
typedef void (*work_func_old_t)(void *);
typedef void (*work_func_t)(struct work_struct *work);

struct delayed_work {
	struct work_struct work;
};

static inline void compat_INIT_WORK(struct work_struct *work, work_func_t func)
{
	INIT_WORK(work, (work_func_old_t)func, work);
}

static inline int compat_queue_delayed_work(struct workqueue_struct *wq,
					    struct delayed_work *work,
					    unsigned long delay)
{
	if (!delay)
		return queue_work(wq, &work->work);
	else
		return queue_delayed_work(wq, &work->work, delay);
}

static inline int compat_cancel_delayed_work(struct delayed_work *work)
{
	return cancel_delayed_work(&work->work);
}

#undef INIT_WORK
#define INIT_WORK(_work, _func) compat_INIT_WORK(_work, _func)
#define INIT_DELAYED_WORK(_work,_func) INIT_WORK(&(_work)->work, _func)

#define queue_delayed_work compat_queue_delayed_work
#define cancel_delayed_work compat_cancel_delayed_work

/*
 * Multiqueue stubs and function wrappers for single-queue devices
 */
static inline struct net_device *alloc_etherdev_mq(int sizeof_priv,
				     unsigned int queue_count)
{
	BUG_ON(queue_count != 1);
	return alloc_etherdev(sizeof_priv);
}

static inline void netif_tx_stop_all_queues(struct net_device *dev)
{
	netif_stop_queue(dev);
}

static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	netif_start_queue(dev);
}

static inline void netif_tx_wake_all_queues(struct net_device *dev)
{
	netif_wake_queue(dev);
}

static inline int __netif_subqueue_stopped(struct net_device *dev,
					   int fifo_no)
{
	WARN_ON(1);
	return netif_queue_stopped(dev);
}

static void netif_wake_subqueue(struct net_device *dev, int fifo_no)
{
	WARN_ON(1);
	netif_wake_queue(dev);
}

static inline void skb_record_rx_queue(struct sk_buff *skb, u16 rx_queue)
{
}

typedef int netdev_tx_t;

/*
 * net_device_ops copied from upstream, but only the members actually
 * used by the s2io driver.
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
#ifdef CONFIG_NET_POLL_CONTROLLER
	void                    (*ndo_poll_controller)(struct net_device *dev);
#endif
};

#define eth_validate_addr NULL

static inline void s2io_set_netdev_ops(struct net_device *ndev,
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
#ifdef CONFIG_NET_POLL_CONTROLLER
	ndev->poll_controller    = ndo->ndo_poll_controller;
#endif
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
static inline int rhel_netif_napi_add(void *nd_priv,
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


#endif /* __S2IO_COMPAT_H */
