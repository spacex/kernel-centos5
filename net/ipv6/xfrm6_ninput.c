/*
 * xfrm6_ninput.c: based on net/ipv4/xfrm4_input.c
 *
 * Authors:
 *	Mitsuru KANDA @USAGI
 * 	Kazunori MIYAZAWA @USAGI
 * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
 *	YOSHIFUJI Hideaki @USAGI
 *		IPv6 support
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <net/xfrm.h>

int xfrm6_input_resume(struct sk_buff *skb, int nexthdr)
{
	int err;
	int spi;
	u32 seq;
	struct xfrm_state *x;
	int decaps = 0;
	unsigned int nhoff;

	nhoff = IP6CB(skb)->nhoff;
	x = skb->sp->xvec[skb->sp->len - 1];
	seq = XFRM_SKB_CB(skb)->seq;
	spin_lock(&x->lock);
	goto resume;

	do {
		struct ipv6hdr *iph = skb->nh.ipv6h;

		if (skb->sp->len == XFRM_MAX_DEPTH)
			goto drop;

		x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, spi, nexthdr, AF_INET6);
		if (x == NULL) {
			xfrm_naudit_state_notfound(skb, AF_INET6, spi, seq);
			goto drop;
		}

		skb->sp->xvec[skb->sp->len++] = x;

		spin_lock(&x->lock);
		if (unlikely(x->km.state != XFRM_STATE_VALID))
			goto drop_unlock;

		if (x->props.replay_window && xfrm_replay_check(x, seq)) {
			xfrm_naudit_state_replay(x, skb, seq);
			goto drop_unlock;
		}

		if (xfrm_state_check_expire(x))
			goto drop_unlock;

		XFRM_SKB_CB(skb)->seq = seq;

		nexthdr = x->type->input(x, skb);

resume:
		if (nexthdr <= 0)
			goto drop_unlock;

		skb->nh.raw[nhoff] = nexthdr;

		if (x->props.replay_window)
			xfrm_replay_advance(x, seq);

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock(&x->lock);

		if (x->mode->input(x, skb))
			goto drop;

		if (x->props.mode) { /* XXX */
			decaps = 1;
			break;
		}

		if ((err = xfrm_parse_spi(skb, nexthdr, &spi, &seq)) < 0)
			goto drop;
	} while (!err);

	skb->ip_summed = CHECKSUM_NONE;

	nf_reset(skb);

	if (decaps) {
		if (!(skb->dev->flags&IFF_LOOPBACK)) {
			dst_release(skb->dst);
			skb->dst = NULL;
		}
		netif_rx(skb);
		return -1;
	} else {
		skb->nh.ipv6h->payload_len = htons(skb->len);
		__skb_push(skb, skb->data - skb->nh.raw);

		NF_HOOK(PF_INET6, NF_IP6_PRE_ROUTING, skb, skb->dev, NULL,
		        dst_input);
		return -1;
	}

drop_unlock:
	spin_unlock(&x->lock);
	if (nexthdr == -EINPROGRESS)
		return -1;
drop:
	kfree_skb(skb);
	return -1;
}
EXPORT_SYMBOL(xfrm6_input_resume);
