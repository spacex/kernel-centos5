/*
 *  Bogus Network Driver for PowerPC Full System Simulator
 *
 *  (C) Copyright IBM Corporation 2003-2005
 *
 *  Bogus Network Driver
 * 
 *  Author: JimiX <jimix@watson.ibm.com>
 *  Maintained By: Eric Van Hensbergen <ericvh@gmail.com>
 *
 * 	inspired by drivers/net/ibmveth.c
 *	written by Dave Larson 
 *
 *  Some code is from the IBM Full System Simulator Group in ARL
 *  Author: Patrick Bohrer <IBM Austin Research Lab>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *  
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/init.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/if_ether.h>	/* For the statistics structure. */
#include <linux/if_arp.h>	/* For ARPHRD_ETHER */
#include <linux/workqueue.h>
#include <asm/prom.h>
#include <asm/systemsim.h>

#define MAMBO_BOGUS_NET_PROBE   119
#define MAMBO_BOGUS_NET_SEND    120
#define MAMBO_BOGUS_NET_RECV    121

static inline int MamboBogusNetProbe(int devno, void *buf)
{
	return callthru2(MAMBO_BOGUS_NET_PROBE,
			 (unsigned long)devno, (unsigned long)buf);
}

static inline int MamboBogusNetSend(int devno, void *buf, ulong size)
{
	return callthru3(MAMBO_BOGUS_NET_SEND,
			 (unsigned long)devno,
			 (unsigned long)buf, (unsigned long)size);
}

static inline int MamboBogusNetRecv(int devno, void *buf, ulong size)
{
	return callthru3(MAMBO_BOGUS_NET_RECV,
			 (unsigned long)devno,
			 (unsigned long)buf, (unsigned long)size);
}

static irqreturn_t
mambonet_interrupt(int irq, void *dev_instance, struct pt_regs *regs);

#define INIT_BOTTOM_HALF(x,y,z) INIT_WORK(x, y, (void*)z)
#define SCHEDULE_BOTTOM_HALF(x) schedule_delayed_work(x, 1)
#define KILL_BOTTOM_HALF(x) cancel_delayed_work(x); flush_scheduled_work()

#define MAMBO_MTU 1500

struct netdev_private {
	int devno;
	int closing;
	struct work_struct poll_task;
	struct net_device_stats stats;
};

static int mambonet_probedev(int devno, void *buf)
{
	struct device_node *mambo;
	struct device_node *net;
	unsigned int *reg;

	mambo = find_path_device("/mambo");

	if (mambo == NULL) {
		return -1;
	}
	net = find_path_device("/mambo/bogus-net@0");
	if (net == NULL) {
		return -1;
	}
	reg = (unsigned int *)get_property(net, "reg", 0);

	if (*reg != devno) {
		return -1;
	}

	return MamboBogusNetProbe(devno, buf);
}

static int mambonet_send(int devno, void *buf, ulong size)
{
	return MamboBogusNetSend(devno, buf, size);
}

static int mambonet_recv(int devno, void *buf, ulong size)
{
	return MamboBogusNetRecv(devno, buf, size);
}

static int mambonet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct netdev_private *priv = (struct netdev_private *)dev->priv;
	int devno = priv->devno;

	skb->dev = dev;

	/* we might need to checksum or something */
	mambonet_send(devno, skb->data, skb->len);

	dev->last_rx = jiffies;
	priv->stats.rx_bytes += skb->len;
	priv->stats.tx_bytes += skb->len;
	priv->stats.rx_packets++;
	priv->stats.tx_packets++;

	dev_kfree_skb(skb);

	return (0);
}

static int mambonet_poll(struct net_device *dev, int *budget)
{
	struct netdev_private *np = dev->priv;
	int devno = np->devno;
	char buffer[1600];
	int ns;
	struct sk_buff *skb;
	int frames = 0;
	int max_frames = min(*budget, dev->quota);
	int ret = 0;

	while ((ns = mambonet_recv(devno, buffer, 1600)) > 0) {
		if ((skb = dev_alloc_skb(ns + 2)) != NULL) {
			skb->dev = dev;
			skb_reserve(skb, 2);	/* 16 byte align the IP
						 * header */
#ifdef HAS_IP_COPYSUM
			eth_copy_and_sum(skb, buffer, ns, 0);
			skb_put(skb, ns);
#else
			memcpy(skb_put(skb, ns), buffer, ns);
#endif
			skb->protocol = eth_type_trans(skb, dev);

			if (dev->irq)
				netif_receive_skb(skb);
			else
				netif_rx(skb);

			dev->last_rx = jiffies;
			np->stats.rx_packets++;
			np->stats.rx_bytes += ns;
		} else {
			printk("Failed to allocated skbuff, "
			       "dropping packet\n");
			np->stats.rx_dropped++;
			/* wait for another cycle */
			return 1;
		}
		++frames;
		if (frames > max_frames) {
			ret = 1;
			break;
		}
	}
	*budget -= frames;
	dev->quota -= frames;

	if ((!ret) && (dev->irq))
		netif_rx_complete(dev);

	return ret;
}

static void mambonet_timer(struct net_device *dev)
{
	int budget = 16;
	struct netdev_private *priv = (struct netdev_private *)dev->priv;

	mambonet_poll(dev, &budget);

	if (!priv->closing) {
		SCHEDULE_BOTTOM_HALF(&priv->poll_task);
	}
}

static struct net_device_stats *get_stats(struct net_device *dev)
{
	struct netdev_private *priv = (struct netdev_private *)dev->priv;
	return (struct net_device_stats *)&(priv->stats);
}

static irqreturn_t
mambonet_interrupt(int irq, void *dev_instance, struct pt_regs *regs)
{
	struct net_device *dev = dev_instance;
	if (netif_rx_schedule_prep(dev)) {
		__netif_rx_schedule(dev);
	}
	return IRQ_HANDLED;
}

static int mambonet_open(struct net_device *dev)
{
	struct netdev_private *priv;
	int ret = 0;

	priv = dev->priv;

	/*
	 * we can't start polling in mambonet_init, because I don't think
	 * workqueues are usable that early. so start polling now.
	 */

	if (dev->irq) {
		ret = request_irq(dev->irq, &mambonet_interrupt, 0,
				  dev->name, dev);

		if (ret == 0) {
			netif_start_queue(dev);
		} else {
			printk(KERN_ERR "mambonet: request irq failed\n");
		}

		MamboBogusNetProbe(priv->devno, NULL);	/* probe with NULL to activate interrupts */
	} else {
		mambonet_timer(dev);
	}

	return ret;
}

static int mambonet_close(struct net_device *dev)
{
	struct netdev_private *priv;

	netif_stop_queue(dev);

	if (dev->irq)
		free_irq(dev->irq, dev);

	priv = dev->priv;
	priv->closing = 1;
	if (dev->irq == 0) {
		KILL_BOTTOM_HALF(&priv->poll_task);
	}

	kfree(priv);

	return 0;
}

static struct net_device_stats mambonet_stats;

static struct net_device_stats *mambonet_get_stats(struct net_device *dev)
{
	return &mambonet_stats;
}

static int mambonet_set_mac_address(struct net_device *dev, void *p)
{
	return -EOPNOTSUPP;
}
static int mambonet_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	return -EOPNOTSUPP;
}
static int nextdevno = 0;	/* running count of device numbers */

/* Initialize the rest of the device. */
int __init do_mambonet_probe(struct net_device *dev)
{
	struct netdev_private *priv;
	int devno = nextdevno++;
	int irq;

	printk("eth%d: bogus network driver initialization\n", devno);

	irq = mambonet_probedev(devno, dev->dev_addr);

	if (irq < 0) {
		printk("No IRQ retreived\n");
		return (-ENODEV);
	}

	printk("%s: %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n", dev->name,
	       dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2],
	       dev->dev_addr[3], dev->dev_addr[4], dev->dev_addr[5]);

	SET_MODULE_OWNER(dev);

	dev->irq = irq;
	dev->mtu = MAMBO_MTU;
	dev->open = mambonet_open;
	dev->poll = mambonet_poll;
	dev->weight = 16;
	dev->stop = mambonet_close;
	dev->hard_start_xmit = mambonet_start_xmit;
	dev->get_stats = mambonet_get_stats;
	dev->set_mac_address = mambonet_set_mac_address;
	dev->do_ioctl = mambonet_ioctl;

	dev->priv = kmalloc(sizeof(struct netdev_private), GFP_KERNEL);
	if (dev->priv == NULL)
		return -ENOMEM;
	memset(dev->priv, 0, sizeof(struct netdev_private));

	priv = dev->priv;
	priv->devno = devno;
	priv->closing = 0;
	dev->get_stats = get_stats;

	if (dev->irq == 0) {
		INIT_BOTTOM_HALF(&priv->poll_task, (void *)mambonet_timer,
				 (void *)dev);
	}

	return (0);
};

struct net_device *__init mambonet_probe(int unit)
{
	struct net_device *dev = alloc_etherdev(0);
	int err;

	if (!dev)
		return ERR_PTR(-ENODEV);

	sprintf(dev->name, "eth%d", unit);
	netdev_boot_setup_check(dev);

	err = do_mambonet_probe(dev);

	if (err)
		goto out;

	err = register_netdev(dev);
	if (err)
		goto out;

	return dev;

      out:
	free_netdev(dev);
	return ERR_PTR(err);
}

int __init init_mambonet(void)
{
	mambonet_probe(0);
	return 0;
}

module_init(init_mambonet);
MODULE_LICENSE("GPL");
