/*
 * This is a module which is used for rejecting packets.
 * Added support for customized reject packets (Jozsef Kadlecsik).
 * Added support for ICMP type-3-code-13 (Maciej Soltysiak). [RFC 1812]
 */

/* (C) 1999-2001 Paul `Rusty' Russell
 * (C) 2002-2004 Netfilter Core Team <coreteam@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_REJECT.h>
#ifdef CONFIG_BRIDGE_NETFILTER
#include <linux/netfilter_bridge.h>
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables REJECT target module");

#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, args...)
#endif

/* Backported 'ip_route_me_harder' that allows to use explicit address type */
static int ip_route_me_harder_compat(struct sk_buff *skb, unsigned addr_type)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	struct flowi fl = {};
	struct dst_entry *odst;
	unsigned int hh_len;

	if (addr_type == RTN_UNSPEC)
		addr_type = inet_addr_type(iph->saddr);

	/* some non-standard hacks like ipt_REJECT.c:send_reset() can cause
	 * packets with foreign saddr to appear on the NF_INET_LOCAL_OUT hook.
	 */
	if (addr_type == RTN_LOCAL) {
		fl.nl_u.ip4_u.daddr = iph->daddr;
		fl.nl_u.ip4_u.saddr = iph->saddr;
		fl.nl_u.ip4_u.tos = RT_TOS(iph->tos);
		fl.oif = skb->sk ? skb->sk->sk_bound_dev_if : 0;
#ifdef CONFIG_IP_ROUTE_FWMARK
		fl.nl_u.ip4_u.fwmark = skb->nfmark;
#endif
		if (ip_route_output_key(&rt, &fl) != 0)
			return -1;

		/* Drop old route. */
		dst_release(skb->dst);
		skb->dst = &rt->u.dst;
	} else {
		/* non-local src, find valid iif to satisfy
		 * rp-filter when calling ip_route_input. */
		fl.nl_u.ip4_u.daddr = iph->saddr;
		if (ip_route_output_key(&rt, &fl) != 0)
			return -1;

		odst = skb->dst;
		if (ip_route_input(skb, iph->daddr, iph->saddr,
				   RT_TOS(iph->tos), rt->u.dst.dev) != 0) {
			dst_release(&rt->u.dst);
			return -1;
		}
		dst_release(&rt->u.dst);
		dst_release(odst);
	}

	if (skb->dst->error)
		return -1;

#ifdef CONFIG_XFRM
	if (!(IPCB(skb)->flags & IPSKB_XFRM_TRANSFORMED) &&
	    xfrm_decode_session(skb, &fl, AF_INET) == 0)
		if (xfrm_lookup(&skb->dst, &fl, skb->sk, 0))
			return -1;
#endif

	/* Change in oif may mean change in hh_len. */
	hh_len = skb->dst->dev->hard_header_len;
	if (skb_headroom(skb) < hh_len &&
	    pskb_expand_head(skb, hh_len - skb_headroom(skb), 0, GFP_ATOMIC))
		return -1;

	return 0;
}

/* Send RST reply */
static void send_reset(struct sk_buff *oldskb, int hook)
{
	struct sk_buff *nskb;
	struct iphdr *oiph, *niph;
	struct tcphdr _otcph, *oth, *tcph;
	unsigned int addr_type;

	/* IP header checks: fragment. */
	if (ip_hdr(oldskb)->frag_off & htons(IP_OFFSET))
		return;

	oth = skb_header_pointer(oldskb, ip_hdrlen(oldskb),
				 sizeof(_otcph), &_otcph);
	if (oth == NULL)
 		return;

	/* No RST for RST. */
	if (oth->rst)
		return;

	/* Check checksum */
	if (nf_ip_checksum(oldskb, hook, ip_hdrlen(oldskb), IPPROTO_TCP))
		return;
	oiph = ip_hdr(oldskb);

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 LL_MAX_HEADER, GFP_ATOMIC);
	if (!nskb)
		return;

	/* This packet will not be the same as the other: clear nf fields */
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_reset_network_header(nskb);
	niph = (struct iphdr *)skb_put(nskb, sizeof(struct iphdr));
	niph->version	= 4;
	niph->ihl	= sizeof(struct iphdr) / 4;
	niph->tos	= 0;
	niph->id	= 0;
	niph->frag_off	= htons(IP_DF);
	niph->protocol	= IPPROTO_TCP;
	niph->check	= 0;
	niph->saddr	= oiph->daddr;
	niph->daddr	= oiph->saddr;

	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(*tcph));
	tcph->source	= oth->dest;
	tcph->dest	= oth->source;
	tcph->doff	= sizeof(struct tcphdr) / 4;

	if (oth->ack)
		tcph->seq = oth->ack_seq;
	else {
		tcph->ack_seq = htonl(ntohl(oth->seq) + oth->syn + oth->fin +
				      oldskb->len - ip_hdrlen(oldskb) -
				      (oth->doff << 2));
		tcph->ack = 1;
	}

	tcph->rst	= 1;
	tcph->check	= tcp_v4_check(tcph, sizeof(struct tcphdr),
				       niph->saddr, niph->daddr,
				       csum_partial((char *)tcph,
						    sizeof(struct tcphdr), 0));

	addr_type = RTN_UNSPEC;
	if (hook != NF_IP_FORWARD
#ifdef CONFIG_BRIDGE_NETFILTER
	    || (nskb->nf_bridge && nskb->nf_bridge->mask & BRNF_BRIDGED)
#endif
	   )
		addr_type = RTN_LOCAL;

	/* ip_route_me_harder expects skb->dst to be set */
	dst_hold(oldskb->dst);
	nskb->dst = oldskb->dst;

	if (ip_route_me_harder_compat(nskb, addr_type))
		goto free_nskb;

	niph->ttl	= dst_metric(nskb->dst, RTAX_HOPLIMIT);
	nskb->ip_summed	= CHECKSUM_NONE;

	/* "Never happens" */
	if (nskb->len > dst_mtu(nskb->dst))
		goto free_nskb;

	nf_ct_attach(nskb, oldskb);

	niph->tot_len = htons(nskb->len);
	ip_send_check(niph);
	NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, nskb, NULL, nskb->dst->dev,
		dst_output);
	return;

 free_nskb:
	kfree_skb(nskb);
}

static inline void send_unreach(struct sk_buff *skb_in, int code)
{
	icmp_send(skb_in, ICMP_DEST_UNREACH, code, 0);
}	

static unsigned int reject(struct sk_buff **pskb,
			   const struct net_device *in,
			   const struct net_device *out,
			   unsigned int hooknum,
			   const struct xt_target *target,
			   const void *targinfo,
			   void *userinfo)
{
	const struct ipt_reject_info *reject = targinfo;

	/* Our naive response construction doesn't deal with IP
           options, and probably shouldn't try. */
	if (ip_hdrlen(*pskb) != sizeof(struct iphdr))
		return NF_DROP;

	/* WARNING: This code causes reentry within iptables.
	   This means that the iptables jump stack is now crap.  We
	   must return an absolute verdict. --RR */
    	switch (reject->with) {
    	case IPT_ICMP_NET_UNREACHABLE:
    		send_unreach(*pskb, ICMP_NET_UNREACH);
    		break;
    	case IPT_ICMP_HOST_UNREACHABLE:
    		send_unreach(*pskb, ICMP_HOST_UNREACH);
    		break;
    	case IPT_ICMP_PROT_UNREACHABLE:
    		send_unreach(*pskb, ICMP_PROT_UNREACH);
    		break;
    	case IPT_ICMP_PORT_UNREACHABLE:
    		send_unreach(*pskb, ICMP_PORT_UNREACH);
    		break;
    	case IPT_ICMP_NET_PROHIBITED:
    		send_unreach(*pskb, ICMP_NET_ANO);
    		break;
	case IPT_ICMP_HOST_PROHIBITED:
    		send_unreach(*pskb, ICMP_HOST_ANO);
    		break;
    	case IPT_ICMP_ADMIN_PROHIBITED:
		send_unreach(*pskb, ICMP_PKT_FILTERED);
		break;
	case IPT_TCP_RESET:
		send_reset(*pskb, hooknum);
	case IPT_ICMP_ECHOREPLY:
		/* Doesn't happen. */
		break;
	}

	return NF_DROP;
}

static int check(const char *tablename,
		 const void *e_void,
		 const struct xt_target *target,
		 void *targinfo,
		 unsigned int targinfosize,
		 unsigned int hook_mask)
{
 	const struct ipt_reject_info *rejinfo = targinfo;
	const struct ipt_entry *e = e_void;

	if (rejinfo->with == IPT_ICMP_ECHOREPLY) {
		printk("REJECT: ECHOREPLY no longer supported.\n");
		return 0;
	} else if (rejinfo->with == IPT_TCP_RESET) {
		/* Must specify that it's a TCP packet */
		if (e->ip.proto != IPPROTO_TCP
		    || (e->ip.invflags & IPT_INV_PROTO)) {
			DEBUGP("REJECT: TCP_RESET invalid for non-tcp\n");
			return 0;
		}
	}
	return 1;
}

static struct ipt_target ipt_reject_reg = {
	.name		= "REJECT",
	.target		= reject,
	.targetsize	= sizeof(struct ipt_reject_info),
	.table		= "filter",
	.hooks		= (1 << NF_IP_LOCAL_IN) | (1 << NF_IP_FORWARD) |
			  (1 << NF_IP_LOCAL_OUT),
	.checkentry	= check,
	.me		= THIS_MODULE,
};

static int __init ipt_reject_init(void)
{
	return ipt_register_target(&ipt_reject_reg);
}

static void __exit ipt_reject_fini(void)
{
	ipt_unregister_target(&ipt_reject_reg);
}

module_init(ipt_reject_init);
module_exit(ipt_reject_fini);
