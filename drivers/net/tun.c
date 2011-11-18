/*
 *  TUN - Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2002 Maxim Krasnyansky <maxk@qualcomm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: tun.c,v 1.15 2002/03/01 02:44:24 maxk Exp $
 */

/*
 *  Changes:
 *
 *  Mike Kershaw <dragorn@kismetwireless.net> 2005/08/14
 *    Add TUNSETLINK ioctl to set the link encapsulation
 *
 *  Mark Smith <markzzzsmith@yahoo.com.au>
 *   Use random_ether_addr() for tap MAC address.
 *
 *  Harald Roelle <harald.roelle@ifi.lmu.de>  2004/04/20
 *    Fixes in packet dropping, queue length setting and queue wakeup.
 *    Increased default tx queue length.
 *    Added ethtool API.
 *    Minor cleanups
 *
 *  Daniel Podlejski <underley@underley.eu.org>
 *    Modifications for 2.3.99-pre5 kernel.
 */

#define DRV_NAME	"tun"
#define DRV_VERSION	"1.6"
#define DRV_DESCRIPTION	"Universal TUN/TAP device driver"
#define DRV_COPYRIGHT	"(C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>"

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/crc32.h>
#include <linux/virtio_net.h>
#include <net/sock.h>

#include <asm/system.h>
#include <asm/uaccess.h>

/* Uncomment to enable debugging */
/* #define TUN_DEBUG 1 */

#ifdef TUN_DEBUG
static int debug;

#define DBG  if(tun->debug)printk
#define DBG1 if(debug==2)printk
#else
#define DBG( a... )
#define DBG1( a... )
#endif

#define FLT_EXACT_COUNT 8
struct tap_filter {
	unsigned int    count;    /* Number of addrs. Zero means disabled */
	u32             mask[2];  /* Mask of the hashed addrs */
	unsigned char	addr[FLT_EXACT_COUNT][ETH_ALEN];
};

struct tun_file {
	atomic_t count;
	struct tun_struct *tun;
	struct net *net;
};

struct tun_sock;

struct tun_sock {
	struct sock		sk;
	struct tun_struct	*tun;
};

static inline struct tun_sock *tun_sk(struct sock *sk)
{
	return container_of(sk, struct tun_sock, sk);
}

static int tun_attach(struct tun_struct *tun, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	int err;

	ASSERT_RTNL();

	netif_tx_lock_bh(tun->dev);

	err = -EINVAL;
	if (tfile->tun)
		goto out;

	err = -EBUSY;
	if (tun->tfile)
		goto out;

	err = 0;
	tfile->tun = tun;
	tun->tfile = tfile;
	tun->socket.file = file;
	netif_carrier_on(tun->dev);
	dev_hold(tun->dev);
	sock_hold(tun->socket.sk);
	atomic_inc(&tfile->count);

out:
	netif_tx_unlock_bh(tun->dev);
	return err;
}

static void __tun_detach(struct tun_struct *tun)
{
	/* Detach from net device */
	netif_tx_lock_bh(tun->dev);
	netif_carrier_off(tun->dev);
	tun->tfile = NULL;
	tun->socket.file = NULL;
	netif_tx_unlock_bh(tun->dev);

	/* Drop read queue */
	skb_queue_purge(&tun->readq);

	/* Drop the extra count on the net device */
	dev_put(tun->dev);
}

static void tun_detach(struct tun_struct *tun)
{
	rtnl_lock();
	__tun_detach(tun);
	rtnl_unlock();
}

static struct tun_struct *__tun_get(struct tun_file *tfile)
{
	struct tun_struct *tun = NULL;

	if (atomic_inc_not_zero(&tfile->count))
		tun = tfile->tun;

	return tun;
}

static struct tun_struct *tun_get(struct file *file)
{
	return __tun_get(file->private_data);
}

static void tun_put(struct tun_struct *tun)
{
	struct tun_file *tfile = tun->tfile;

	if (atomic_dec_and_test(&tfile->count))
		tun_detach(tfile->tun);
}

/* Network device part of the driver */

static struct ethtool_ops tun_ethtool_ops;

/* Net device detach from fd. */
static void tun_net_uninit(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_file *tfile = tun->tfile;

	/* Inform the methods they need to stop using the dev.
	 */
	if (tfile) {
		wake_up_all(&tun->read_wait);
		if (atomic_dec_and_test(&tfile->count))
			__tun_detach(tun);
	}
}

static void tun_free_netdev(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	sock_put(tun->socket.sk);
}

/* Net device open. */
static int tun_net_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

/* Net device close. */
static int tun_net_close(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

/* Net device start xmit */
static int tun_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	DBG(KERN_INFO "%s: tun_net_xmit %d\n", tun->dev->name, skb->len);

	/* Drop packet if interface is not attached */
	if (!tun->tfile)
		goto drop;

	/* Packet dropping */
	if (skb_queue_len(&tun->readq) >= dev->tx_queue_len) {
		if (!(tun->flags & TUN_ONE_QUEUE)) {
			/* Normal queueing mode. */
			/* Packet scheduler handles dropping of further packets. */
			netif_stop_queue(dev);

			/* We won't see all dropped packets individually, so overrun
			 * error is more appropriate. */
			tun->stats.tx_fifo_errors++;
		} else {
			/* Single queue mode.
			 * Driver handles dropping of all packets itself. */
			goto drop;
		}
	}

       /* Orphan the skb - required as we might hang on to it
        * for indefinite time. */
	skb_orphan(skb);

	/* Queue packet */
	skb_queue_tail(&tun->readq, skb);
	dev->trans_start = jiffies;

	/* Notify and wake up reader process */
	if (tun->flags & TUN_FASYNC)
		kill_fasync(&tun->fasync, SIGIO, POLL_IN);
	wake_up_interruptible(&tun->read_wait);
	return 0;

drop:
	tun->stats.tx_dropped++;
	kfree_skb(skb);
	return 0;
}

/** Add the specified Ethernet address to this multicast filter. */
static void
add_multi(u32* filter, const u8* addr)
{
	int bit_nr = ether_crc(ETH_ALEN, addr) >> 26;
	filter[bit_nr >> 5] |= 1 << (bit_nr & 31);
}

/** Remove the specified Ethernet addres from this multicast filter. */
static void
del_multi(u32* filter, const u8* addr)
{
	int bit_nr = ether_crc(ETH_ALEN, addr) >> 26;
	filter[bit_nr >> 5] &= ~(1 << (bit_nr & 31));
}

/** Update the list of multicast groups to which the network device belongs.
 * This list is used to filter packets being sent from the character device to
 * the network device. */
static void
tun_net_mclist(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	const struct dev_mc_list *mclist;
	int i;
	DBG(KERN_DEBUG "%s: tun_net_mclist: mc_count %d\n",
			dev->name, dev->mc_count);
	memset(tun->chr_filter, 0, sizeof tun->chr_filter);
	for (i = 0, mclist = dev->mc_list; i < dev->mc_count && mclist != NULL;
			i++, mclist = mclist->next) {
		add_multi(tun->net_filter, mclist->dmi_addr);
		DBG(KERN_DEBUG "%s: tun_net_mclist: %x:%x:%x:%x:%x:%x\n",
				dev->name,
				mclist->dmi_addr[0], mclist->dmi_addr[1], mclist->dmi_addr[2],
				mclist->dmi_addr[3], mclist->dmi_addr[4], mclist->dmi_addr[5]);
	}
}

static struct net_device_stats *tun_net_stats(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	return &tun->stats;
}

#define MIN_MTU 68
#define MAX_MTU 65535

static int
tun_net_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < MIN_MTU || new_mtu + dev->hard_header_len > MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

/* Initialize net device. */
static void tun_net_init(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
   
	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		/* Point-to-Point TUN Device */
		dev->hard_header_len = 0;
		dev->addr_len = 0;
		dev->mtu = 1500;
		dev->change_mtu = tun_net_change_mtu;

		/* Zero header length */
		dev->type = ARPHRD_NONE; 
		dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
		dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
		break;

	case TUN_TAP_DEV:
		/* Ethernet TAP Device */
		ether_setup(dev);
		dev->change_mtu         = tun_net_change_mtu;
		dev->set_multicast_list = tun_net_mclist;

		random_ether_addr(dev->dev_addr);
		dev->tx_queue_len = TUN_READQ_SIZE;  /* We prefer our own queue length */
		break;
	}
}

/* Character device part */

/* Poll */
static unsigned int tun_chr_poll(struct file *file, poll_table * wait)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	struct sock *sk;
	unsigned int mask = 0;

	if (!tun)
		return -EBADFD;

	sk = tun->socket.sk;

	DBG(KERN_INFO "%s: tun_chr_poll\n", tun->dev->name);

	poll_wait(file, &tun->read_wait, wait);
 
	if (!skb_queue_empty(&tun->readq))
		mask |= POLLIN | POLLRDNORM;

	if (sock_writeable(sk) ||
	    (!test_and_set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
	     sock_writeable(sk)))
		mask |= POLLOUT | POLLWRNORM;

	if (tun->dev->reg_state != NETREG_REGISTERED)
		mask = POLLERR;

	tun_put(tun);
	return mask;
}

/* prepad is the amount to reserve at front.  len is length after that.
 * linear is a hint as to how much to copy (usually headers). */
static inline struct sk_buff *tun_alloc_skb(struct tun_struct *tun,
					    size_t prepad, size_t len,
					    size_t linear, int noblock)
{
	struct sock *sk = tun->socket.sk;
	struct sk_buff *skb;
	int err;

	/* Under a page?  Don't bother with paged skb. */
	if (prepad + len < PAGE_SIZE || !linear)
		linear = len;

	skb = sock_alloc_send_pskb(sk, prepad + linear, len - linear, noblock,
				   &err);
	if (!skb)
		return ERR_PTR(err);

	skb_reserve(skb, prepad);
	skb_put(skb, linear);
	skb->data_len = len - linear;
	skb->len += len - linear;

	return skb;
}

/* Get packet from user space buffer */
static __inline__ ssize_t tun_get_user(struct tun_struct *tun,
				       struct iovec *iv, size_t count,
				       int noblock)
{
	struct tun_pi pi = { 0, __constant_htons(ETH_P_IP) };
	struct sk_buff *skb;
	size_t len = count, align = 0;
	struct virtio_net_hdr gso = { 0 };

	if (!(tun->flags & TUN_NO_PI)) {
		if ((len -= sizeof(pi)) > count)
			return -EINVAL;

		if(memcpy_fromiovec((void *)&pi, iv, sizeof(pi)))
			return -EFAULT;
	}

	if (tun->flags & TUN_VNET_HDR) {
		if ((len -= sizeof(gso)) > count)
			return -EINVAL;

		if (memcpy_fromiovec((void *)&gso, iv, sizeof(gso)))
			return -EFAULT;

		if ((gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    gso.csum_start + gso.csum_offset + 2 > gso.hdr_len)
			gso.hdr_len = gso.csum_start + gso.csum_offset + 2;

		if (gso.hdr_len > len)
			return -EINVAL;
	}

	if ((tun->flags & TUN_TYPE_MASK) == TUN_TAP_DEV)
		align = NET_IP_ALIGN;
 
	skb = tun_alloc_skb(tun, align, len, gso.hdr_len, noblock);
	if (IS_ERR(skb)) {
		if (PTR_ERR(skb) != -EAGAIN)
			tun->stats.rx_dropped++;
		return PTR_ERR(skb);
	}

	if (skb_copy_datagram_from_iovec(skb, 0, iv, len)) {
		tun->stats.rx_dropped++;
		kfree_skb(skb);
		return -EFAULT;
	}

	if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		if (gso.csum_start + gso.csum_offset > len - 2) {
			if (net_ratelimit())
				printk(KERN_WARNING
				       "bad partial csum: csum=%u/%u len=%zu\n",
				       gso.csum_start, gso.csum_offset, len);
			tun->stats.rx_dropped++;
			kfree_skb(skb);
			return -EINVAL;
		}

		skb->ip_summed = CHECKSUM_HW;
		skb->csum = gso.csum_offset;
		skb->h.raw = skb->data + gso.csum_start;
		skb_checksum_help(skb, 0);
	} else if (tun->flags & TUN_NOCHECKSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb->dev = tun->dev;
	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		skb->mac.raw = skb->data;
		skb->protocol = pi.proto;
		break;
	case TUN_TAP_DEV:
		skb->protocol = eth_type_trans(skb, tun->dev);
		break;
	};

	if (gso.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		pr_debug("GSO!\n");
		switch (gso.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
			break;
		default:
			tun->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		if (gso.gso_type & VIRTIO_NET_HDR_GSO_ECN)
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

		skb_shinfo(skb)->gso_size = gso.gso_size;
		if (skb_shinfo(skb)->gso_size == 0) {
			tun->stats.rx_frame_errors++;
			kfree_skb(skb);
			return -EINVAL;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	netif_rx_ni(skb);
	tun->dev->last_rx = jiffies;
   
	tun->stats.rx_packets++;
	tun->stats.rx_bytes += len;

	return count;
} 

static inline size_t iov_total(const struct iovec *iv, unsigned long count)
{
	unsigned long i;
	size_t len;

	for (i = 0, len = 0; i < count; i++) 
		len += iv[i].iov_len;

	return len;
}

/* Writev */
static ssize_t tun_chr_writev(struct file * file, const struct iovec *iv, 
			      unsigned long count, loff_t *pos)
{
	struct tun_struct *tun = tun_get(file);
	int ret;

	if (!tun)
		return -EBADFD;

	DBG(KERN_INFO "%s: tun_chr_write %ld\n", tun->dev->name, count);

	ret = tun_get_user(tun, (struct iovec *) iv, iov_total(iv, count),
			   file->f_flags & O_NONBLOCK);

	tun_put(tun);
	return ret;
}

/* Write */
static ssize_t tun_chr_write(struct file * file, const char __user * buf, 
			     size_t count, loff_t *pos)
{
	struct iovec iv = { (void __user *) buf, count };
	return tun_chr_writev(file, &iv, 1, pos);
}

/* Put packet to the user space buffer */
static __inline__ ssize_t tun_put_user(struct tun_struct *tun,
				       struct sk_buff *skb,
				       struct iovec *iv, int len)
{
	struct tun_pi pi = { 0, skb->protocol };
	ssize_t total = 0;

	if (!(tun->flags & TUN_NO_PI)) {
		if ((len -= sizeof(pi)) < 0)
			return -EINVAL;

		if (len < skb->len) {
			/* Packet will be striped */
			pi.flags |= TUN_PKT_STRIP;
		}
 
		if (memcpy_toiovec(iv, (void *) &pi, sizeof(pi)))
			return -EFAULT;
		total += sizeof(pi);
	}       

	if (tun->flags & TUN_VNET_HDR) {
		struct virtio_net_hdr gso = { 0 }; /* no info leak */
		if ((len -= sizeof(gso)) < 0)
			return -EINVAL;

		if (skb_is_gso(skb)) {
			struct skb_shared_info *sinfo = skb_shinfo(skb);

			/* This is a hint as to how much should be linear. */
			gso.hdr_len = skb_headlen(skb);
			gso.gso_size = sinfo->gso_size;
			if (sinfo->gso_type & SKB_GSO_TCPV4)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
			else if (sinfo->gso_type & SKB_GSO_TCPV6)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
			else
				BUG();
			if (sinfo->gso_type & SKB_GSO_TCP_ECN)
				gso.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
		} else
			gso.gso_type = VIRTIO_NET_HDR_GSO_NONE;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			gso.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			gso.csum_start = skb->h.raw - skb->data;
			gso.csum_offset = skb->csum;
		} /* else everything is zero */

		if (unlikely(memcpy_toiovec(iv, (void *)&gso, sizeof(gso))))
			return -EFAULT;
		total += sizeof(gso);
	}

	len = min_t(int, skb->len, len);

	skb_copy_datagram_iovec(skb, 0, iv, len);
	total += len;

	tun->stats.tx_packets++;
	tun->stats.tx_bytes += len;

	return total;
}

/* Readv */
static ssize_t tun_chr_readv(struct file *file, const struct iovec *iv,
			    unsigned long count, loff_t *pos)
{
	struct tun_struct *tun = tun_get(file);
	DECLARE_WAITQUEUE(wait, current);
	struct sk_buff *skb;
	ssize_t len, ret = 0;

	if (!tun)
		return -EBADFD;

	DBG(KERN_INFO "%s: tun_chr_read\n", tun->dev->name);

	len = iov_total(iv, count);
	if (len < 0) {
		ret = -EINVAL;
		goto err;
	}

	add_wait_queue(&tun->read_wait, &wait);
	while (len) {
		const u8 ones[ ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
		u8 addr[ ETH_ALEN];
		int bit_nr;

		current->state = TASK_INTERRUPTIBLE;

		/* Read frames from the queue */
		if (!(skb=skb_dequeue(&tun->readq))) {
			if (file->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
			if (signal_pending(current)) {
				ret = -ERESTARTSYS;
				break;
			}

			/* Nothing to read, let's sleep */
			schedule();
			continue;
		}
		netif_wake_queue(tun->dev);

		/** Decide whether to accept this packet. This code is designed to
		 * behave identically to an Ethernet interface. Accept the packet if
		 * - we are promiscuous.
		 * - the packet is addressed to us.
		 * - the packet is broadcast.
		 * - the packet is multicast and
		 *   - we are multicast promiscous.
		 *   - we belong to the multicast group.
		 */
		memcpy(addr, skb->data,
		       min_t(size_t, sizeof addr, skb->len));
		bit_nr = ether_crc(sizeof addr, addr) >> 26;
		if ((tun->if_flags & IFF_PROMISC) ||
				memcmp(addr, tun->dev_addr, sizeof addr) == 0 ||
				memcmp(addr, ones, sizeof addr) == 0 ||
				(((addr[0] == 1 && addr[1] == 0 && addr[2] == 0x5e) ||
				  (addr[0] == 0x33 && addr[1] == 0x33)) &&
				 ((tun->if_flags & IFF_ALLMULTI) ||
				  (tun->chr_filter[bit_nr >> 5] & (1 << (bit_nr & 31)))))) {
			DBG(KERN_DEBUG "%s: tun_chr_readv: accepted: %x:%x:%x:%x:%x:%x\n",
					tun->dev->name, addr[0], addr[1], addr[2],
					addr[3], addr[4], addr[5]);
			ret = tun_put_user(tun, skb, (struct iovec *) iv, len);
			kfree_skb(skb);
			break;
		} else {
			DBG(KERN_DEBUG "%s: tun_chr_readv: rejected: %x:%x:%x:%x:%x:%x\n",
					tun->dev->name, addr[0], addr[1], addr[2],
					addr[3], addr[4], addr[5]);
			kfree_skb(skb);
			continue;
		}
	}

	current->state = TASK_RUNNING;
	remove_wait_queue(&tun->read_wait, &wait);

err:
	tun_put(tun);
	return ret;
}

/* Read */
static ssize_t tun_chr_read(struct file * file, char __user * buf, 
			    size_t count, loff_t *pos)
{
	struct iovec iv = { buf, count };
	return tun_chr_readv(file, &iv, 1, pos);
}

static void tun_setup(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	skb_queue_head_init(&tun->readq);
	init_waitqueue_head(&tun->read_wait);

	tun->owner = -1;
	tun->group = -1;

	SET_MODULE_OWNER(dev);
	dev->open = tun_net_open;
	dev->uninit = tun_net_uninit;
	dev->hard_start_xmit = tun_net_xmit;
	dev->stop = tun_net_close;
	dev->get_stats = tun_net_stats;
	dev->ethtool_ops = &tun_ethtool_ops;
	dev->destructor = tun_free_netdev;
}

static void tun_sock_write_space(struct sock *sk)
{
	struct tun_struct *tun;

	if (!sock_writeable(sk))
		return;

	if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags))
		return;

	if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
		wake_up_interruptible_sync(sk->sk_sleep);

	tun = container_of(sk, struct tun_sock, sk)->tun;
	kill_fasync(&tun->fasync, SIGIO, POLL_OUT);
}

static void tun_sock_destruct(struct sock *sk)
{
	free_netdev(tun_sk(sk)->tun->dev);
}

static struct proto tun_proto = {
	.name		= "tun",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tun_sock),
};

static int tun_set_iff(struct file *file, struct ifreq *ifr)
{
	struct sock *sk;
	struct tun_struct *tun;
	struct net_device *dev;
	int err;

	dev = __dev_get_by_name(ifr->ifr_name);
	if (dev) {
		if ((ifr->ifr_flags & IFF_TUN) && dev->open == tun_net_open)
			tun = netdev_priv(dev);
		else if ((ifr->ifr_flags & IFF_TAP) && dev->open == tun_net_open)
			tun = netdev_priv(dev);
		else
			return -EINVAL;

		if (((tun->owner != -1 && current->euid != tun->owner) ||
		     (tun->group != -1 && !in_egroup_p(tun->group))) &&
		    !capable(CAP_NET_ADMIN))
			return -EPERM;
		err = tun_attach(tun, file);
		if (err < 0)
			return err;
	}
	else {
		char *name;
		unsigned long flags = 0;

		if (!capable(CAP_NET_ADMIN))
			return -EPERM;

		/* Set dev type */
		if (ifr->ifr_flags & IFF_TUN) {
			/* TUN device */
			flags |= TUN_TUN_DEV;
			name = "tun%d";
		} else if (ifr->ifr_flags & IFF_TAP) {
			/* TAP device */
			flags |= TUN_TAP_DEV;
			name = "tap%d";
		} else
			return -EINVAL;

		if (*ifr->ifr_name)
			name = ifr->ifr_name;

		dev = alloc_netdev(sizeof(struct tun_struct), name,
				   tun_setup);
		if (!dev)
			return -ENOMEM;

		tun = netdev_priv(dev);
		tun->dev = dev;
		tun->flags = flags;
		/* Be promiscuous by default to maintain previous behaviour. */
		tun->if_flags = IFF_PROMISC;
		/* Generate random Ethernet address. */
		*(u16 *)tun->dev_addr = htons(0x00FF);
		get_random_bytes(tun->dev_addr + sizeof(u16), 4);
		memset(tun->chr_filter, 0, sizeof tun->chr_filter);

		err = -ENOMEM;
		sk = sk_alloc(AF_UNSPEC, GFP_KERNEL, &tun_proto, 1);
		if (!sk)
			goto err_free_dev;

		sock_init_data(&tun->socket, sk);
		sk->sk_write_space = tun_sock_write_space;
		sk->sk_sndbuf = INT_MAX;
		sk->sk_sleep = &tun->read_wait;

		tun_sk(sk)->tun = tun;

		tun_net_init(dev);

		if (strchr(dev->name, '%')) {
			err = dev_alloc_name(dev, dev->name);
			if (err < 0)
				goto err_free_sk;
		}

		err = register_netdevice(tun->dev);
		if (err < 0)
			goto err_free_sk;

		sk->sk_destruct = tun_sock_destruct;

		err = tun_attach(tun, file);
		if (err < 0)
			goto failed;
	}

	DBG(KERN_INFO "%s: tun_set_iff\n", tun->dev->name);

	if (ifr->ifr_flags & IFF_NO_PI)
		tun->flags |= TUN_NO_PI;

	if (ifr->ifr_flags & IFF_ONE_QUEUE)
		tun->flags |= TUN_ONE_QUEUE;

	if (ifr->ifr_flags & IFF_VNET_HDR)
		tun->flags |= TUN_VNET_HDR;
	else
		tun->flags &= ~TUN_VNET_HDR;

	strcpy(ifr->ifr_name, tun->dev->name);
	return 0;

 err_free_sk:
	sock_put(sk);
 err_free_dev:
	free_netdev(dev);
 failed:
	return err;
}

static int tun_get_iff(struct tun_struct *tun, struct ifreq *ifr)
{
	DBG(KERN_INFO "%s: tun_get_iff\n", tun->dev->name);

	strcpy(ifr->ifr_name, tun->dev->name);

	ifr->ifr_flags = 0;

	if (ifr->ifr_flags & TUN_TUN_DEV)
		ifr->ifr_flags |= IFF_TUN;
	else
		ifr->ifr_flags |= IFF_TAP;

	if (tun->flags & TUN_NO_PI)
		ifr->ifr_flags |= IFF_NO_PI;

	if (tun->flags & TUN_ONE_QUEUE)
		ifr->ifr_flags |= IFF_ONE_QUEUE;

	if (tun->flags & TUN_VNET_HDR)
		ifr->ifr_flags |= IFF_VNET_HDR;

	return 0;
}

/* This is like a cut-down ethtool ops, except done via tun fd so no
 * privs required. */
static int set_offload(struct net_device *dev, unsigned long arg)
{
	unsigned int old_features, features;

	old_features = dev->features;
	/* Unset features, set them as we chew on the arg. */
	features = (old_features & ~(NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST
				    |NETIF_F_TSO_ECN|NETIF_F_TSO|NETIF_F_TSO6));

	if (arg & TUN_F_CSUM) {
		features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;
		arg &= ~TUN_F_CSUM;

		if (arg & (TUN_F_TSO4|TUN_F_TSO6)) {
			if (arg & TUN_F_TSO_ECN) {
				features |= NETIF_F_TSO_ECN;
				arg &= ~TUN_F_TSO_ECN;
			}
			if (arg & TUN_F_TSO4)
				features |= NETIF_F_TSO;
			if (arg & TUN_F_TSO6)
				features |= NETIF_F_TSO6;
			arg &= ~(TUN_F_TSO4|TUN_F_TSO6);
		}
	}

	/* This gives the user a way to test for new features in future by
	 * trying to set them. */
	if (arg)
		return -EINVAL;

	dev->features = features;
	if (old_features != dev->features)
		netdev_features_change(dev);

	return 0;
}

static int tun_chr_ioctl(struct inode *inode, struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;
	void __user* argp = (void __user*)arg;
	struct ifreq ifr;
	int sndbuf;
	int ret;

	if (cmd == TUNSETIFF || _IOC_TYPE(cmd) == 0x89)
		if (copy_from_user(&ifr, argp, sizeof ifr))
			return -EFAULT;

	if (cmd == TUNGETFEATURES) {
		/* Currently this just means: "what IFF flags are valid?".
		 * This is needed because we never checked for invalid flags on
		 * TUNSETIFF. */
		return put_user(IFF_TUN | IFF_TAP | IFF_NO_PI | IFF_ONE_QUEUE |
				IFF_VNET_HDR,
				(unsigned int __user*)argp);
	}

	rtnl_lock();

	tun = __tun_get(tfile);
	if (cmd == TUNSETIFF && !tun) {
		ifr.ifr_name[IFNAMSIZ-1] = '\0';

		ret = tun_set_iff(file, &ifr);

		if (ret)
			goto unlock;

		if (copy_to_user(argp, &ifr, sizeof ifr))
			ret = -EFAULT;
		goto unlock;
	}

	ret = -EBADFD;
	if (!tun)
		goto unlock;

	DBG(KERN_INFO "%s: tun_chr_ioctl cmd %d\n", tun->dev->name, cmd);

	ret = 0;
	switch (cmd) {
	case TUNGETIFF:
		ret = tun_get_iff(tun, &ifr);
		if (ret)
			break;

		if (copy_to_user(argp, &ifr, sizeof(ifr)))
			ret = -EFAULT;
		break;

	case TUNSETNOCSUM:
		/* Disable/Enable checksum */
		if (arg)
			tun->flags |= TUN_NOCHECKSUM;
		else
			tun->flags &= ~TUN_NOCHECKSUM;

		DBG(KERN_INFO "%s: checksum %s\n",
		    tun->dev->name, arg ? "disabled" : "enabled");
		break;

	case TUNSETPERSIST:
		/* Disable/Enable persist mode */
		if (arg)
			tun->flags |= TUN_PERSIST;
		else
			tun->flags &= ~TUN_PERSIST;

		DBG(KERN_INFO "%s: persist %s\n",
		    tun->dev->name, arg ? "disabled" : "enabled");
		break;

	case TUNSETOWNER:
		/* Set owner of the device */
		tun->owner = (uid_t) arg;

		DBG(KERN_INFO "%s: owner set to %d\n", tun->dev->name, tun->owner);
		break;

	case TUNSETGROUP:
		/* Set group of the device */
		tun->group= (gid_t) arg;

		DBG(KERN_INFO "%s: group set to %d\n", tun->dev->name, tun->group);
		break;

	case TUNSETLINK:
		/* Only allow setting the type when the interface is down */
		if (tun->dev->flags & IFF_UP) {
			DBG(KERN_INFO "%s: Linktype set failed because interface is up\n",
				tun->dev->name);
			ret = -EBUSY;
		} else {
			tun->dev->type = (int) arg;
			DBG(KERN_INFO "%s: linktype set to %d\n", tun->dev->name, tun->dev->type);
			ret = 0;
		}
		break;

#ifdef TUN_DEBUG
	case TUNSETDEBUG:
		tun->debug = arg;
		break;
#endif

	case TUNSETOFFLOAD:
		ret = set_offload(tun->dev, arg);
		break;

	case SIOCGIFFLAGS:
		ifr.ifr_flags = tun->if_flags;
		if (copy_to_user( argp, &ifr, sizeof ifr))
			ret = -EFAULT;
		break;

	case SIOCSIFFLAGS:
		/** Set the character device's interface flags. Currently only
		 * IFF_PROMISC and IFF_ALLMULTI are used. */
		tun->if_flags = ifr.ifr_flags;
		DBG(KERN_INFO "%s: interface flags 0x%lx\n",
				tun->dev->name, tun->if_flags);
		break;

	case SIOCGIFHWADDR:
		memcpy(ifr.ifr_hwaddr.sa_data, tun->dev_addr,
				min(sizeof ifr.ifr_hwaddr.sa_data, sizeof tun->dev_addr));
		if (copy_to_user( argp, &ifr, sizeof ifr))
			ret = -EFAULT;
		break;

	case SIOCSIFHWADDR:
		/** Set the character device's hardware address. This is used when
		 * filtering packets being sent from the network device to the character
		 * device. */
		memcpy(tun->dev_addr, ifr.ifr_hwaddr.sa_data,
				min(sizeof ifr.ifr_hwaddr.sa_data, sizeof tun->dev_addr));
		DBG(KERN_DEBUG "%s: set hardware address: %x:%x:%x:%x:%x:%x\n",
				tun->dev->name,
				tun->dev_addr[0], tun->dev_addr[1], tun->dev_addr[2],
				tun->dev_addr[3], tun->dev_addr[4], tun->dev_addr[5]);
		break;

	case SIOCADDMULTI:
		/** Add the specified group to the character device's multicast filter
		 * list. */
		add_multi(tun->chr_filter, ifr.ifr_hwaddr.sa_data);
		DBG(KERN_DEBUG "%s: add multi: %x:%x:%x:%x:%x:%x\n",
				tun->dev->name,
				(u8)ifr.ifr_hwaddr.sa_data[0], (u8)ifr.ifr_hwaddr.sa_data[1],
				(u8)ifr.ifr_hwaddr.sa_data[2], (u8)ifr.ifr_hwaddr.sa_data[3],
				(u8)ifr.ifr_hwaddr.sa_data[4], (u8)ifr.ifr_hwaddr.sa_data[5]);
		break;

	case SIOCDELMULTI:
		/** Remove the specified group from the character device's multicast
		 * filter list. */
		del_multi(tun->chr_filter, ifr.ifr_hwaddr.sa_data);
		DBG(KERN_DEBUG "%s: del multi: %x:%x:%x:%x:%x:%x\n",
				tun->dev->name,
				(u8)ifr.ifr_hwaddr.sa_data[0], (u8)ifr.ifr_hwaddr.sa_data[1],
				(u8)ifr.ifr_hwaddr.sa_data[2], (u8)ifr.ifr_hwaddr.sa_data[3],
				(u8)ifr.ifr_hwaddr.sa_data[4], (u8)ifr.ifr_hwaddr.sa_data[5]);
		break;

	case TUNGETSNDBUF:
		sndbuf = tun->socket.sk->sk_sndbuf;
		if (copy_to_user(argp, &sndbuf, sizeof(sndbuf)))
			ret = -EFAULT;
		break;

	case TUNSETSNDBUF:
		if (copy_from_user(&sndbuf, argp, sizeof(sndbuf))) {
			ret = -EFAULT;
			break;
		}

		tun->socket.sk->sk_sndbuf = sndbuf;
		break;

	default:
		ret = -EINVAL;
		break;
	}

unlock:
	rtnl_unlock();
	if (tun)
		tun_put(tun);
	return ret;
}

static int tun_chr_fasync(int fd, struct file *file, int on)
{
	struct tun_struct *tun = tun_get(file);
	int ret;

	if (!tun)
		return -EBADFD;

	DBG(KERN_INFO "%s: tun_chr_fasync %d\n", tun->dev->name, on);

	if ((ret = fasync_helper(fd, file, on, &tun->fasync)) < 0)
		goto out;

	if (on) {
		ret = f_setown(file, current->pid, 0);
		if (ret)
			goto out;
		tun->flags |= TUN_FASYNC;
	} else 
		tun->flags &= ~TUN_FASYNC;
	ret = 0;
out:
	tun_put(tun);
	return ret;
}

static int tun_chr_open(struct inode *inode, struct file * file)
{
	struct tun_file *tfile;

	DBG1(KERN_INFO "tunX: tun_chr_open\n");

	tfile = kmalloc(sizeof(*tfile), GFP_KERNEL);
	if (!tfile)
		return -ENOMEM;
	atomic_set(&tfile->count, 0);
	tfile->tun = NULL;
	file->private_data = tfile;
	return 0;
}

static int tun_chr_close(struct inode *inode, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;

	tun = __tun_get(tfile);
	if (tun) {
		struct net_device *dev = tun->dev;

		DBG(KERN_INFO "%s: tun_chr_close\n", dev->name);

		__tun_detach(tun);

		/* If desirable, unregister the netdevice. */
		if (!(tun->flags & TUN_PERSIST)) {
			rtnl_lock();
			if (dev->reg_state == NETREG_REGISTERED)
				unregister_netdevice(dev);
			rtnl_unlock();
		}
	}

	tun = tfile->tun;
	if (tun)
		sock_put(tun->socket.sk);

	kfree(tfile);

	return 0;
}

static struct file_operations tun_fops = {
	.owner	= THIS_MODULE,	
	.llseek = no_llseek,
	.read	= tun_chr_read,
	.readv	= tun_chr_readv,
	.write	= tun_chr_write,
	.writev = tun_chr_writev,
	.poll	= tun_chr_poll,
	.ioctl	= tun_chr_ioctl,
	.open	= tun_chr_open,
	.release = tun_chr_close,
	.fasync = tun_chr_fasync		
};

static struct miscdevice tun_miscdev = {
	.minor = TUN_MINOR,
	.name = "tun",
	.fops = &tun_fops,
};

/* ethtool interface */

static int tun_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported		= 0;
	cmd->advertising	= 0;
	cmd->speed		= SPEED_10;
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void tun_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct tun_struct *tun = netdev_priv(dev);

	strcpy(info->driver, DRV_NAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->fw_version, "N/A");

	switch (tun->flags & TUN_TYPE_MASK) {
	case TUN_TUN_DEV:
		strcpy(info->bus_info, "tun");
		break;
	case TUN_TAP_DEV:
		strcpy(info->bus_info, "tap");
		break;
	}
}

static u32 tun_get_msglevel(struct net_device *dev)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	return tun->debug;
#else
	return -EOPNOTSUPP;
#endif
}

static void tun_set_msglevel(struct net_device *dev, u32 value)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	tun->debug = value;
#endif
}

static u32 tun_get_rx_csum(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	return (tun->flags & TUN_NOCHECKSUM) == 0;
}

static int tun_set_rx_csum(struct net_device *dev, u32 data)
{
	struct tun_struct *tun = netdev_priv(dev);
	if (data)
		tun->flags &= ~TUN_NOCHECKSUM;
	else
		tun->flags |= TUN_NOCHECKSUM;
	return 0;
}

static struct ethtool_ops tun_ethtool_ops = {
	.get_settings	= tun_get_settings,
	.get_drvinfo	= tun_get_drvinfo,
	.get_msglevel	= tun_get_msglevel,
	.set_msglevel	= tun_set_msglevel,
	.get_link	= ethtool_op_get_link,
	.get_rx_csum	= tun_get_rx_csum,
	.set_rx_csum	= tun_set_rx_csum
};

static int __init tun_init(void)
{
	int ret = 0;

	printk(KERN_INFO "tun: %s, %s\n", DRV_DESCRIPTION, DRV_VERSION);
	printk(KERN_INFO "tun: %s\n", DRV_COPYRIGHT);

	ret = misc_register(&tun_miscdev);
	if (ret) {
		printk(KERN_ERR "tun: Can't register misc device %d\n", TUN_MINOR);
		goto err_misc;
	}
	return  0;
err_misc:
	return ret;
}

static void tun_cleanup(void)
{
	misc_deregister(&tun_miscdev);
}

module_init(tun_init);
module_exit(tun_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(TUN_MINOR);
