/* A simple network driver using virtio.
 *
 * Copyright 2007 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
//#define DEBUG
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/scatterlist.h>
#include <linux/timer.h>
#include <net/esp.h> /* for skb_to_sgvec() */

static int napi_weight = 128;
module_param(napi_weight, int, 0444);

static int csum = 1, gso = 1;
module_param(csum, bool, 0444);
module_param(gso, bool, 0444);

/* FIXME: MTU in config. */
#define MAX_PACKET_LEN (ETH_HLEN+ETH_DATA_LEN)
#define GOOD_COPY_LEN	128

struct virtnet_info
{
	struct virtio_device *vdev;
	struct virtqueue *rvq, *svq;
	struct net_device *dev;
	unsigned int status;

	/* The skb we couldn't send because buffers were full. */
	struct sk_buff *last_xmit_skb;

	/* If we need to free in a timer, this is it. */
	struct timer_list xmit_free_timer;

	/* Number of input buffers, and max we've ever had. */
	unsigned int num, max;

	/* For cleaning up after transmission. */
	struct tasklet_struct tasklet;
	bool free_in_tasklet;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Timer for refilling if we run low on memory. */
	struct timer_list refill;

	/* Chain pages by the private ptr. */
	struct page *pages;

	struct net_device_stats stats;
};

struct skb_vnet_hdr {
	union {
		struct virtio_net_hdr hdr;
		struct virtio_net_hdr_mrg_rxbuf mhdr;
	};
};

struct padded_vnet_hdr {
	struct virtio_net_hdr hdr;
	/*
	 * virtio_net_hdr should be in a separated sg buffer because of a
	 * QEMU bug, and data sg buffer shares same page with this header sg.
	 * This padding makes next sg 16 byte aligned after virtio_net_hdr.
	 */
	char padding[6];
};

static inline struct skb_vnet_hdr *skb_vnet_hdr(struct sk_buff *skb)
{
	return (struct skb_vnet_hdr *)skb->cb;
}

/*
 * private is used to chain pages for big packets, put the whole
 * most recent used list in the beginning for reuse
 */
static void give_pages(struct virtnet_info *vi, struct page *page)
{
	struct page *end;

	/* Find end of list, sew whole thing into vi->pages. */
	for (end = page; end->private; end = (struct page *)end->private);
	end->private = (unsigned long)vi->pages;
	vi->pages = page;
}


static struct page *get_a_page(struct virtnet_info *vi, gfp_t gfp_mask)
{
	struct page *p = vi->pages;

	if (p) {
		vi->pages = (struct page *)p->private;
		/* clear private here, it is used to chain pages */
		p->private = 0;
	} else
		p = alloc_page(gfp_mask);
	return p;
}

static void skb_xmit_done(struct virtqueue *svq)
{
	struct virtnet_info *vi = svq->vdev->priv;

	/* Suppress further interrupts. */
	svq->vq_ops->disable_cb(svq);

	/* We were probably waiting for more output buffers. */
	netif_wake_queue(vi->dev);

	/* Make sure we re-xmit last_xmit_skb: if there are no more packets
	 * queued, start_xmit won't be called. */
	tasklet_schedule(&vi->tasklet);
}

static void set_skb_frag(struct sk_buff *skb, struct page *page,
			 unsigned int offset, unsigned int *len)
{
	int i = skb_shinfo(skb)->nr_frags;
	skb_frag_t *f;

	f = &skb_shinfo(skb)->frags[i];
	f->size = min((unsigned)PAGE_SIZE - offset, *len);
	f->page_offset = offset;
	f->page = page;

	skb->data_len += f->size;
	skb->len += f->size;
	skb_shinfo(skb)->nr_frags++;
	*len -= f->size;
}

static struct sk_buff *page_to_skb(struct virtnet_info *vi,
				   struct page *page, unsigned int len)
{
	struct sk_buff *skb;
	struct skb_vnet_hdr *hdr;
	unsigned int copy, hdr_len, offset;
	char *p;

	p = page_address(page);

	/* copy small packet so we can reuse these pages for small data */
	skb = netdev_alloc_skb(vi->dev, GOOD_COPY_LEN + NET_IP_ALIGN);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, NET_IP_ALIGN);

	hdr = skb_vnet_hdr(skb);

	if (vi->mergeable_rx_bufs) {
		hdr_len = sizeof hdr->mhdr;
		offset = hdr_len;
	} else {
		hdr_len = sizeof hdr->hdr;
		offset = sizeof(struct padded_vnet_hdr);
	}

	memcpy(hdr, p, hdr_len);

	len -= hdr_len;
	p += offset;

	copy = len;
	if (copy > skb_tailroom(skb))
		copy = skb_tailroom(skb);
	memcpy(skb_put(skb, copy), p, copy);

	len -= copy;
	offset += copy;

	while (len) {
		set_skb_frag(skb, page, offset, &len);
		page = (struct page *)page->private;
		offset = 0;
	}

	if (page)
		give_pages(vi, page);

	return skb;
}

static int receive_mergeable(struct virtnet_info *vi, struct sk_buff *skb)
{
	struct skb_vnet_hdr *hdr = skb_vnet_hdr(skb);
	struct page *page;
	int num_buf, i, len;

	num_buf = hdr->mhdr.num_buffers;
	while (--num_buf) {
		i = skb_shinfo(skb)->nr_frags;
		if (i >= MAX_SKB_FRAGS) {
			pr_debug("%s: packet too long\n", skb->dev->name);
			vi->stats.rx_length_errors++;
			return -EINVAL;
		}

		page = vi->rvq->vq_ops->get_buf(vi->rvq, &len);
		if (!page) {
			pr_debug("%s: rx error: %d buffers missing\n",
				 skb->dev->name, hdr->mhdr.num_buffers);
			vi->stats.rx_length_errors++;
			return -EINVAL;
		}
		if (len > PAGE_SIZE)
			len = PAGE_SIZE;

		set_skb_frag(skb, page, 0, &len);

		--vi->num;
	}
	return 0;
}

static void receive_buf(struct net_device *dev, void *buf, unsigned int len)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct sk_buff *skb;
	struct page *page;
	struct skb_vnet_hdr *hdr;

	if (unlikely(len < sizeof(struct virtio_net_hdr) + ETH_HLEN)) {
		pr_debug("%s: short packet %i\n", dev->name, len);
		vi->stats.rx_length_errors++;
		if (vi->mergeable_rx_bufs || vi->big_packets)
			give_pages(vi, buf);
		else
			dev_kfree_skb(buf);
		return;
	}

	if (!vi->mergeable_rx_bufs && !vi->big_packets) {
		skb = buf;
		len -= sizeof(struct virtio_net_hdr);
		skb_trim(skb, len);
	} else {
		page = buf;
		skb = page_to_skb(vi, page, len);
		if (unlikely(!skb)) {
			vi->stats.rx_dropped++;
			give_pages(vi, page);
			return;
		}
		if (vi->mergeable_rx_bufs)
			if (receive_mergeable(vi, skb)) {
				dev_kfree_skb(skb);
				return;
			}
	}

	hdr = skb_vnet_hdr(skb);
	skb->truesize += skb->data_len;
	vi->stats.rx_bytes += skb->len;
	vi->stats.rx_packets++;

	if (hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	skb->protocol = eth_type_trans(skb, dev);
	pr_debug("Receiving skb proto 0x%04x len %i type %i\n",
		 ntohs(skb->protocol), skb->len, skb->pkt_type);

	if (hdr->hdr.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		pr_debug("GSO!\n");
		switch (hdr->hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
			break;
		case VIRTIO_NET_HDR_GSO_UDP:
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
			break;
		default:
			if (net_ratelimit())
				printk(KERN_WARNING "%s: bad gso type %u.\n",
				       dev->name, hdr->hdr.gso_type);
			goto frame_err;
		}

		if (hdr->hdr.gso_type & VIRTIO_NET_HDR_GSO_ECN)
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

		skb_shinfo(skb)->gso_size = hdr->hdr.gso_size;
		if (skb_shinfo(skb)->gso_size == 0) {
			if (net_ratelimit())
				printk(KERN_WARNING "%s: zero gso size.\n",
				       dev->name);
			goto frame_err;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	netif_receive_skb(skb);
	return;

frame_err:
	vi->stats.rx_frame_errors++;
	dev_kfree_skb(skb);
}

static inline void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
	memset(sgl, 0, sizeof(*sgl) * nents);
}

static int add_recvbuf_small(struct virtnet_info *vi, gfp_t gfp)
{
	struct sk_buff *skb;
	struct skb_vnet_hdr *hdr;
	struct scatterlist sg[2];
	int err;

	sg_init_table(sg, 2);
	skb = netdev_alloc_skb(vi->dev, MAX_PACKET_LEN + NET_IP_ALIGN);
	if (unlikely(!skb))
		return -ENOMEM;
	
	skb_reserve(skb, NET_IP_ALIGN);
	skb_put(skb, MAX_PACKET_LEN);

	hdr = skb_vnet_hdr(skb);

	sg_init_one(sg, &hdr->hdr, sizeof hdr->hdr);
	skb_to_sgvec(skb, sg + 1, 0, skb->len);

	err = vi->rvq->vq_ops->add_buf(vi->rvq, sg, 0, 2, skb);
	if (err < 0)
		dev_kfree_skb(skb);

	return err;
}

static int add_recvbuf_big(struct virtnet_info *vi, gfp_t gfp)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	struct page *first, *list = NULL;
	char *p;
	int i, err, offset;

	sg_init_table(sg, MAX_SKB_FRAGS + 2);
	/* page in sg[MAX_SKB_FRAGS + 1] is list tail */
	for (i = MAX_SKB_FRAGS + 1; i > 1; --i) {
		first = get_a_page(vi, gfp);
		if (!first) {
			if (list)
				give_pages(vi, list);
			return -ENOMEM;
		}
		sg_init_one(&sg[i], page_address(first), PAGE_SIZE);

		/* chain new page in list head to match sg */
		first->private = (unsigned long)list;
		list = first;
	}

	first = get_a_page(vi, gfp);
	if (!first) {
		give_pages(vi, list);
		return -ENOMEM;
	}
	p = page_address(first);

	/* sg[0], sg[1] share the same page */
	/* a separated sg[0] for  virtio_net_hdr only during to QEMU bug*/
	sg_init_one(&sg[0], p, sizeof(struct virtio_net_hdr));

	/* sg[1] for data packet, from offset */
	offset = sizeof(struct padded_vnet_hdr);
	sg_init_one(&sg[1], p + offset, PAGE_SIZE - offset);

	/* chain first in list head */
	first->private = (unsigned long)list;
	err = vi->rvq->vq_ops->add_buf(vi->rvq, sg, 0, MAX_SKB_FRAGS + 2,
				       first);
	if (err < 0)
		give_pages(vi, first);

	return err;
}

static int add_recvbuf_mergeable(struct virtnet_info *vi, gfp_t gfp)
{
	struct page *page;
	struct scatterlist sg;
	int err;

	page = get_a_page(vi, gfp);
	if (!page)
		return -ENOMEM;

	sg_init_one(&sg, page_address(page), PAGE_SIZE);

	err = vi->rvq->vq_ops->add_buf(vi->rvq, &sg, 0, 1, page);
	if (err < 0)
		give_pages(vi, page);

	return err;
}

/* Returns false if we couldn't fill entirely (OOM). */
static bool try_fill_recv(struct virtnet_info *vi, gfp_t gfp)
{
	int err;
	bool oom = false;

	do {
		if (vi->mergeable_rx_bufs)
			err = add_recvbuf_mergeable(vi, gfp);
		else if (vi->big_packets)
			err = add_recvbuf_big(vi, gfp);
		else
			err = add_recvbuf_small(vi, gfp);

		if (err < 0) {
			oom = true;
			break;
		}
		++vi->num;
	} while (err > 0);

	if (unlikely(vi->num > vi->max))
		vi->max = vi->num;
	vi->rvq->vq_ops->kick(vi->rvq);
	return !oom;
}

static void skb_recv_done(struct virtqueue *rvq)
{
	struct virtnet_info *vi = rvq->vdev->priv;
	/* Schedule NAPI, Suppress further interrupts if successful. */
	if (netif_rx_schedule_prep(vi->dev)) {
		rvq->vq_ops->disable_cb(rvq);
		__netif_rx_schedule(vi->dev);
	}
}

static void refill_timer(unsigned long data)
{
	struct virtnet_info *vi = (void *)data;
	skb_recv_done(vi->rvq);
}

static int virtnet_poll(struct net_device *dev, int *budget)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int max_received = min(dev->quota, *budget);
	bool no_work;
	void *buf = NULL;
	unsigned int len, received = 0;

again:
	while (received < max_received &&
	       (buf = vi->rvq->vq_ops->get_buf(vi->rvq, &len)) != NULL) {
		receive_buf(vi->dev, buf, len);
		vi->num--;
		received++;
	}

	if (vi->num < vi->max / 2) {
		if (!try_fill_recv(vi, GFP_ATOMIC))
			mod_timer(&vi->refill, jiffies + HZ/2);
	}

	/* Out of packets? */
	if (buf) {
		*budget -= received;
		dev->quota -= received;
		return 1;
	}

	netif_rx_complete(vi->dev);
	no_work = vi->rvq->vq_ops->enable_cb(vi->rvq);

	if (!no_work && netif_rx_schedule_prep(vi->dev)) {
		vi->rvq->vq_ops->disable_cb(vi->rvq);
		__netif_rx_schedule(vi->dev);
		dev_put(vi->dev);
		goto again;
	}

	dev->quota -= received;
	*budget -= received;

	return 0;
}

static void free_old_xmit_skbs(struct virtnet_info *vi)
{
	struct sk_buff *skb;
	unsigned int len;

	while ((skb = vi->svq->vq_ops->get_buf(vi->svq, &len)) != NULL) {
		pr_debug("Sent skb %p\n", skb);
		vi->stats.tx_bytes += skb->len;
		vi->stats.tx_packets++;
		kfree_skb(skb);
	}
}

/* If the virtio transport doesn't always notify us when all in-flight packets
 * are consumed, we fall back to using this function on a timer to free them. */
static void xmit_free(unsigned long data)
{
	struct virtnet_info *vi = (void *)data;

	netif_tx_lock(vi->dev);
	free_old_xmit_skbs(vi);
	netif_tx_unlock(vi->dev);
}

static int xmit_skb(struct virtnet_info *vi, struct sk_buff *skb)
{
	int num, err;
	struct scatterlist sg[2+MAX_SKB_FRAGS];
	struct skb_vnet_hdr *hdr = skb_vnet_hdr(skb);

#ifdef DEBUG
	const unsigned char *dest = ((struct ethhdr *)skb->data)->h_dest;

	pr_debug("%s: xmit %p " MAC_FMT "\n", vi->dev->name, skb,
		 dest[0], dest[1], dest[2],
		 dest[3], dest[4], dest[5]);
#endif

	if (skb->ip_summed == CHECKSUM_HW) {
		hdr->hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		hdr->hdr.csum_start = skb->h.raw - skb->data;
		hdr->hdr.csum_offset = skb->csum;
	} else {
		hdr->hdr.flags = 0;
		hdr->hdr.csum_offset = hdr->hdr.csum_start = 0;
	}

	if (skb_is_gso(skb)) {
		hdr->hdr.hdr_len = skb->h.raw - skb->data;
		hdr->hdr.gso_size = skb_shinfo(skb)->gso_size;
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV4)
			hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_TCPV6)
			hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
			hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_UDP;
		else
			BUG();
		if (skb_shinfo(skb)->gso_type & SKB_GSO_TCP_ECN)
			hdr->hdr.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
	} else {
		hdr->hdr.gso_type = VIRTIO_NET_HDR_GSO_NONE;
		hdr->hdr.gso_size = hdr->hdr.hdr_len = 0;
	}

	hdr->mhdr.num_buffers = 0;

	/* Encode metadata header at front. */
	if (vi->mergeable_rx_bufs)
		sg_init_one(sg, &hdr->mhdr, sizeof(hdr->mhdr));
	else
		sg_init_one(sg, &hdr->hdr, sizeof(hdr->hdr));

	num = skb_to_sgvec(skb, sg+1, 0, skb->len) + 1;

	err = vi->svq->vq_ops->add_buf(vi->svq, sg, num, 0, skb);
	if (err >= 0 && !vi->free_in_tasklet)
		mod_timer(&vi->xmit_free_timer, jiffies + (HZ/10));

	return err;
}

static void xmit_tasklet(unsigned long data)
{
	struct virtnet_info *vi = (void *)data;

	netif_tx_lock_bh(vi->dev);
	if (vi->last_xmit_skb && xmit_skb(vi, vi->last_xmit_skb) >= 0) {
		vi->svq->vq_ops->kick(vi->svq);
		vi->last_xmit_skb = NULL;
	}
	if (vi->free_in_tasklet) {
		free_old_xmit_skbs(vi);
		netif_wake_queue(vi->dev);
	}
	netif_tx_unlock_bh(vi->dev);
}

static int start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);

again:
	/* Free up any pending old buffers before queueing new ones. */
	free_old_xmit_skbs(vi);

	/* If we has a buffer left over from last time, send it now. */
	if (unlikely(vi->last_xmit_skb) &&
	    xmit_skb(vi, vi->last_xmit_skb) < 0)
		goto stop_queue;

	vi->last_xmit_skb = NULL;

	/* Put new one in send queue and do transmit */
	if (likely(skb)) {
		if (xmit_skb(vi, skb) < 0) {
			vi->last_xmit_skb = skb;
			skb = NULL;
			goto stop_queue;
		}
	}
done:
	vi->svq->vq_ops->kick(vi->svq);
	vi->dev->trans_start = jiffies;
	return NETDEV_TX_OK;

stop_queue:
	pr_debug("%s: virtio not prepared to send\n", dev->name);
	netif_stop_queue(dev);

	/* Activate callback for using skbs: if this returns false it
	 * means some were used in the meantime. */
	if (unlikely(!vi->svq->vq_ops->enable_cb(vi->svq))) {
		vi->svq->vq_ops->disable_cb(vi->svq);
		netif_start_queue(dev);
		goto again;
	}
	if (skb) {
		/* Drop this skb: we only queue one. */
		vi->stats.tx_dropped++;
		kfree_skb(skb);
	}
	goto done;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void virtnet_netpoll(struct net_device *dev)
{
	netif_rx_schedule(dev);
}
#endif

struct net_device_stats *virtnet_get_stats(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);

	return &vi->stats;
}

static int virtnet_open(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);

	memset(&vi->stats, 0, sizeof(vi->stats));

	netif_poll_enable(dev);

	/* If all buffers were filled by other side before we napi_enabled, we
	 * won't get another interrupt, so process any outstanding packets
	 * now.  virtnet_poll wants re-enable the queue, so we disable here.
	 * We synchronize against interrupts via NAPI_STATE_SCHED */
	if (netif_rx_schedule_prep(dev)) {
		vi->rvq->vq_ops->disable_cb(vi->rvq);
		__netif_rx_schedule(vi->dev);
	}
	return 0;
}

static int virtnet_close(struct net_device *dev)
{
	netif_poll_disable(dev);

	return 0;
}

static int virtnet_set_tx_csum(struct net_device *dev, u32 data)
{
	struct virtnet_info *vi = netdev_priv(dev);
	struct virtio_device *vdev = vi->vdev;

	if (data && !virtio_has_feature(vdev, VIRTIO_NET_F_CSUM))
		return -ENOSYS;

	return ethtool_op_set_tx_hw_csum(dev, data);
}

static void virtnet_get_drvinfo(struct net_device *dev,
				struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "virtio_net");
	strcpy(info->bus_info, dev->class_dev.dev->bus_id);
}

static struct ethtool_ops virtnet_ethtool_ops = {
	.get_drvinfo = virtnet_get_drvinfo,

	.set_tx_csum = virtnet_set_tx_csum,
	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_sg = ethtool_op_set_sg,
	.get_sg = ethtool_op_get_sg,
	.set_tso = ethtool_op_set_tso,
	.get_tso = ethtool_op_get_tso,
	.get_link = ethtool_op_get_link,
};

#define MIN_MTU 68
#define MAX_MTU 65535

static int virtnet_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < MIN_MTU || new_mtu > MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static void virtnet_mclist(struct net_device *dev)
{
}

static void virtnet_update_status(struct virtnet_info *vi)
{
	u16 v;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS))
		return;

	vi->vdev->config->get(vi->vdev,
			      offsetof(struct virtio_net_config, status),
			      &v, sizeof(v));

	/* Ignore unknown (future) status bits */
	v &= VIRTIO_NET_S_LINK_UP;

	if (vi->status == v)
		return;

	vi->status = v;

	if (vi->status & VIRTIO_NET_S_LINK_UP) {
		netif_carrier_on(vi->dev);
		netif_wake_queue(vi->dev);
	} else {
		netif_carrier_off(vi->dev);
		netif_stop_queue(vi->dev);
	}
}

static void virtnet_config_changed(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	virtnet_update_status(vi);
}

static int virtnet_probe(struct virtio_device *vdev)
{
	int err;
	struct net_device *dev;
	struct virtnet_info *vi;
	struct virtqueue *vqs[2];
	vq_callback_t *callbacks[] = { skb_recv_done, skb_xmit_done};
	const char *names[] = { "input", "output" };
	int nvqs;

	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev(sizeof(struct virtnet_info));
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->open = virtnet_open;
	dev->stop = virtnet_close;
	dev->hard_start_xmit = start_xmit;
	dev->get_stats = virtnet_get_stats;
	dev->change_mtu = virtnet_change_mtu;
	dev->set_multicast_list = virtnet_mclist;
	dev->features = NETIF_F_HIGHDMA;
#ifdef CONFIG_NET_POLL_CONTROLLER
	dev->poll_controller = virtnet_netpoll;
#endif
	SET_ETHTOOL_OPS(dev, &virtnet_ethtool_ops);
	SET_NETDEV_DEV(dev, &vdev->dev);

	/* Do we support "hardware" checksums? */
	if (csum && virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
		/* This opens up the world of extra features. */
		dev->features |= NETIF_F_HW_CSUM|NETIF_F_SG|NETIF_F_FRAGLIST;
		if (gso && virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
			dev->features |= NETIF_F_TSO | NETIF_F_UFO
				| NETIF_F_TSO_ECN | NETIF_F_TSO6;
		}
		/* Individual feature bits: what can host handle? */
		if (gso && virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
			dev->features |= NETIF_F_TSO;
		if (gso && virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
			dev->features |= NETIF_F_TSO6;
		if (gso && virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
			dev->features |= NETIF_F_TSO_ECN;
		if (gso && virtio_has_feature(vdev, VIRTIO_NET_F_HOST_UFO))
			dev->features |= NETIF_F_UFO;
	}

	/* Configuration may specify what MAC to use.  Otherwise random. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC)) {
		vdev->config->get(vdev,
				  offsetof(struct virtio_net_config, mac),
				  dev->dev_addr, dev->addr_len);
	} else
		random_ether_addr(dev->dev_addr);

	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	dev->poll = virtnet_poll;
	dev->weight = napi_weight;
	vi->dev = dev;
	vi->vdev = vdev;
	vdev->priv = vi;
	vi->pages = NULL;
	setup_timer(&vi->refill, refill_timer, (unsigned long)vi);

	/* If they give us a callback when all buffers are done, we don't need
	 * the timer. */
	vi->free_in_tasklet = virtio_has_feature(vdev,VIRTIO_F_NOTIFY_ON_EMPTY);

	/* If we can receive ANY GSO packets, we must allocate large ones. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4)
	    || virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6)
	    || virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN))
		vi->big_packets = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
		vi->mergeable_rx_bufs = true;

	/* We expect two virtqueues, receive then send. */
	nvqs = 2;

	err = vdev->config->find_vqs(vdev, nvqs, vqs, callbacks, names);
	if (err)
		goto free;

	vi->rvq = vqs[0];
	vi->svq = vqs[1];

	tasklet_init(&vi->tasklet, xmit_tasklet, (unsigned long)vi);

	if (!vi->free_in_tasklet)
		setup_timer(&vi->xmit_free_timer, xmit_free, (unsigned long)vi);

	err = register_netdev(dev);
	if (err) {
		pr_debug("virtio_net: registering device failed\n");
		goto free_vqs;
	}

	/* Last of all, set up some receive buffers. */
	try_fill_recv(vi, GFP_KERNEL);

	/* If we didn't even get one input buffer, we're useless. */
	if (vi->num == 0) {
		err = -ENOMEM;
		goto unregister;
	}

	/* Assume link up if device can't report link status,
	   otherwise get link status from config. */
	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
		netif_carrier_off(dev);
		virtnet_update_status(vi);
	} else {
		vi->status = VIRTIO_NET_S_LINK_UP;
		netif_carrier_on(dev);
	}

	pr_debug("virtnet: registered device %s\n", dev->name);
	return 0;

unregister:
	unregister_netdev(dev);
	del_timer_sync(&vi->refill);
free_vqs:
	vdev->config->del_vqs(vdev);
free:
	free_netdev(dev);
	return err;
}

static void free_unused_bufs(struct virtnet_info *vi)
{
	void *buf;
	while (1) {
		buf = vi->svq->vq_ops->detach_unused_buf(vi->svq);
		if (!buf)
			break;
		dev_kfree_skb(buf);
	}
	while (1) {
		buf = vi->rvq->vq_ops->detach_unused_buf(vi->rvq);
		if (!buf)
			break;
		if (vi->mergeable_rx_bufs || vi->big_packets)
			give_pages(vi, buf);
		else
			dev_kfree_skb(buf);
		--vi->num;
	}
	BUG_ON(vi->num != 0);
}

static void virtnet_remove(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	if (!vi->free_in_tasklet)
		del_timer_sync(&vi->xmit_free_timer);

	unregister_netdev(vi->dev);
	del_timer_sync(&vi->refill);

	/* Free unused buffers in both send and recv, if any. */
	free_unused_bufs(vi);

	vdev->config->del_vqs(vi->vdev);

	while (vi->pages)
		__free_pages(get_a_page(vi, GFP_KERNEL), 0);

	free_netdev(vi->dev);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
	VIRTIO_NET_F_GSO, VIRTIO_NET_F_MAC,
	VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_HOST_TSO6,
	VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6,
	VIRTIO_NET_F_GUEST_ECN, /* We don't yet handle UFO input. */
	VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS,
	VIRTIO_F_NOTIFY_ON_EMPTY,
};

static struct virtio_driver virtio_net = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.probe =	virtnet_probe,
	.remove =	__devexit_p(virtnet_remove),
	.config_changed = virtnet_config_changed,
};

static int __init init(void)
{
	return register_virtio_driver(&virtio_net);
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_net);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_ALIAS("virtio:d00000001v*");
MODULE_DESCRIPTION("Virtio network driver");
MODULE_LICENSE("GPL");
