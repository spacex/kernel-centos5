/* x_tables module for setting the IPv4/IPv6 DSCP field, Version 1.8
 *
 * (C) 2002 by Harald Welte <laforge@netfilter.org>
 * based on ipt_FTOS.c (C) 2000 by Matthew G. Marsh <mgm@paktronix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See RFC2474 for a description of the DSCP field within the IP Header.
*/

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/dsfield.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_DSCP.h>

MODULE_AUTHOR("Harald Welte <laforge@netfilter.org>");
MODULE_DESCRIPTION("Xtables: DSCP field modification");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_DSCP");
MODULE_ALIAS("ip6t_DSCP");

static unsigned int
dscp_tg(struct sk_buff **pskb, const struct net_device *in,
       const struct net_device *out, unsigned int hooknum,
       const struct xt_target *target, const void *targinfo,
       void *userinfo)
{
	const struct xt_DSCP_info *dinfo = targinfo;
	u_int8_t dscp = ipv4_get_dsfield(ip_hdr(*pskb)) >> XT_DSCP_SHIFT;

	if (dscp != dinfo->dscp) {
		if (!skb_make_writable(pskb, sizeof(struct iphdr)))
			return NF_DROP;

		ipv4_change_dsfield(ip_hdr(*pskb), (__u8)(~XT_DSCP_MASK),
				    dinfo->dscp << XT_DSCP_SHIFT);

	}
	return XT_CONTINUE;
}

static unsigned int
dscp_tg6(struct sk_buff **pskb, const struct net_device *in,
	 const struct net_device *out, unsigned int hooknum,
	 const struct xt_target *target, const void *targinfo,
	 void *userinfo)
{
	const struct xt_DSCP_info *dinfo = targinfo;
	u_int8_t dscp = ipv6_get_dsfield(ipv6_hdr(*pskb)) >> XT_DSCP_SHIFT;

	if (dscp != dinfo->dscp) {
		if (!skb_make_writable(pskb, sizeof(struct ipv6hdr)))
			return NF_DROP;

		ipv6_change_dsfield(ipv6_hdr(*pskb), (__u8)(~XT_DSCP_MASK),
				    dinfo->dscp << XT_DSCP_SHIFT);
	}
	return XT_CONTINUE;
}

static int dscp_tg_check(const char *tablename, const void *inf,
			 const struct xt_target *target, void *targetinfo,
			 unsigned int targetinfosize, unsigned int hook_mask)
{
	const struct xt_DSCP_info *info = targetinfo;

	if (info->dscp > XT_DSCP_MAX) {
		printk(KERN_WARNING "DSCP: dscp %x out of range\n", info->dscp);
		return 0;
	}

	return 1;
}

static struct xt_target dscp_reg __read_mostly = {
	.name		= "DSCP",
	.family		= AF_INET,
	.checkentry	= dscp_tg_check,
	.target		= dscp_tg,
	.targetsize	= sizeof(struct xt_DSCP_info),
	.table		= "mangle",
	.me		= THIS_MODULE,
};

static struct xt_target dscp6_reg __read_mostly = {
	.name		= "DSCP",
	.family		= AF_INET6,
	.checkentry	= dscp_tg_check,
	.target		= dscp_tg6,
	.targetsize	= sizeof(struct xt_DSCP_info),
	.table		= "mangle",
	.me		= THIS_MODULE,
};

static int __init dscp_tg_init(void)
{
	int ret;

	ret = xt_register_target(&dscp_reg);
	if (ret)
		return ret;

	ret = xt_register_target(&dscp6_reg);
	if (ret)
		xt_unregister_target(&dscp_reg);

	return ret;
}

static void __exit dscp_tg_exit(void)
{
	xt_unregister_target(&dscp6_reg);
	xt_unregister_target(&dscp_reg);
}

module_init(dscp_tg_init);
module_exit(dscp_tg_exit);
