/*
 * xfrm4_ninput.c
 *
 * Changes:
 *	YOSHIFUJI Hideaki @USAGI
 *		Split up af-specific portion
 *	Derek Atkins <derek@ihtfp.com>
 *		Add Encapsulation support
 * 	
 */

#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/xfrm.h>

static int xfrm4_rcv_encap_finish(struct sk_buff *skb)
{
	struct iphdr *iph = skb->nh.iph;

	if (skb->dst == NULL) {
		if (ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
		                   skb->dev))
			goto drop;
	}
	return dst_input(skb);
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

int xfrm4_input_resume(struct sk_buff *skb, int err)
{
	u32 spi, seq;
	struct xfrm_state *x;
	int decaps = 0;

	x = skb->sp->xvec[skb->sp->len - 1];
	seq = XFRM_SKB_CB(skb)->seq;
	spin_lock(&x->lock);
	goto resume;

	do {
		struct iphdr *iph = skb->nh.iph;

		if (skb->sp->len == XFRM_MAX_DEPTH)
			goto drop;

		x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, spi, iph->protocol, AF_INET);
		if (x == NULL) {
			xfrm_naudit_state_notfound(skb, AF_INET, spi, seq);
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

		err = x->type->input(x, skb);

resume:
		if (err)
			goto drop_unlock;

		if (x->props.replay_window)
			xfrm_replay_advance(x, seq);

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock(&x->lock);

		if (x->mode->input(x, skb))
			goto drop;

		if (x->props.mode) {
			decaps = 1;
			break;
		}

		if ((err = xfrm_parse_spi(skb, skb->nh.iph->protocol, &spi, &seq)) < 0)
			goto drop;
	} while (!err);

	nf_reset(skb);

	if (decaps) {
		if (!(skb->dev->flags&IFF_LOOPBACK)) {
			dst_release(skb->dst);
			skb->dst = NULL;
		}
		netif_rx(skb);
		return 0;
	} else {
		__skb_push(skb, skb->data - skb->nh.raw);
		skb->nh.iph->tot_len = htons(skb->len);
		ip_send_check(skb->nh.iph);

		NF_HOOK(PF_INET, NF_IP_PRE_ROUTING, skb, skb->dev, NULL,
		        xfrm4_rcv_encap_finish);
		return 0;
	}

drop_unlock:
	spin_unlock(&x->lock);
	if (err == -EINPROGRESS)
		return 0;
drop:
	kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL(xfrm4_input_resume);
