/*
 * xfrm6_noutput.c - Common IPsec encapsulation code for IPv6.
 * Copyright (C) 2002 USAGI/WIDE Project
 * Copyright (c) 2004 Herbert Xu <herbert@gondor.apana.org.au>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/icmpv6.h>
#include <linux/module.h>
#include <linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <net/xfrm.h>

static int xfrm6_output_finish2(struct sk_buff *skb);

static int xfrm6_tunnel_check_size(struct sk_buff *skb)
{
	int mtu, ret = 0;
	struct dst_entry *dst = skb->dst;

	mtu = dst_mtu(dst);
	if (mtu < IPV6_MIN_MTU)
		mtu = IPV6_MIN_MTU;

	if (skb->len > mtu) {
		skb->dev = dst->dev;
		icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu, skb->dev);
		ret = -EMSGSIZE;
	}

	return ret;
}

static int xfrm6_output_one(struct sk_buff *skb, int err)
{
	struct dst_entry *dst = skb->dst;
	struct xfrm_state *x = dst->xfrm;
	
	if (skb->ip_summed == CHECKSUM_HW) {
		err = skb_checksum_help(skb, 0);
		if (err)
			goto error_nolock;
	}

	if (x->props.mode) {
		err = xfrm6_tunnel_check_size(skb);
		if (err)
			goto error_nolock;
	}

	do {
		spin_lock_bh(&x->lock);
		err = xfrm_state_check(x, skb);
		if (err)
			goto error;

		err = x->mode->output(skb);
		if (err)
			goto error;

		err = x->type->output(x, skb);
		if (err)
			goto error;

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock_bh(&x->lock);

		skb->nh.raw = skb->data;
		
		if (!(skb->dst = dst_pop(dst))) {
			err = -EHOSTUNREACH;
			goto error_nolock;
		}
		dst = skb->dst;
		x = dst->xfrm;
	} while (x && !x->props.mode);

	IP6CB(skb)->flags |= IP6SKB_XFRM_TRANSFORMED;
	err = 0;

out_exit:
	return err;
error:
	spin_unlock_bh(&x->lock);
	if (err == -EINPROGRESS)
		goto out_exit;
error_nolock:
	kfree_skb(skb);
	goto out_exit;
}

int xfrm6_output_resume(struct sk_buff *skb, int err)
{
	while (likely((err = xfrm6_output_one(skb, err)) == 0)) {
		nf_reset(skb);
	
		err = nf_hook(PF_INET6, NF_IP6_LOCAL_OUT, &skb, NULL,
			      skb->dst->dev, dst_output);
		if (unlikely(err != 1))
			goto out;

		if (!skb->dst->xfrm)
			return dst_output(skb);

		err = nf_hook(PF_INET6, NF_IP6_POST_ROUTING, &skb, NULL,
			      skb->dst->dev, xfrm6_output_finish2);
		if (unlikely(err != 1))
			goto out;
	}

	if (err == -EINPROGRESS)
		err = 0;

out:
	return err;
}
EXPORT_SYMBOL_GPL(xfrm6_output_resume);

static int xfrm6_output_finish2(struct sk_buff *skb)
{
	return xfrm6_output_resume(skb, 1);
}

static void xfrm6_noutput_exit(void)
{
}

module_exit(xfrm6_noutput_exit);
MODULE_LICENSE("GPL");
