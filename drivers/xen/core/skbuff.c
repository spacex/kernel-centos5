/*
 * clalance: In the bare-metal kernel __dev_alloc_skb is an inline function.
 * Unfortunately, in the Xen kernel, it's a regular function, and somehow
 * found it's way onto the Xen kernel kABI whitelist.  We just maintain a
 * copy of the bare-metal version here to maintain kABI.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/hypervisor.h>

/*static*/ kmem_cache_t *skbuff_cachep;
EXPORT_SYMBOL(skbuff_cachep);

struct sk_buff *__dev_alloc_skb(unsigned int length, gfp_t gfp_mask)
{
	struct sk_buff *skb = alloc_skb(length + NET_SKB_PAD, gfp_mask);
	if (likely(skb))
		skb_reserve(skb, NET_SKB_PAD);
	return skb;
}

EXPORT_SYMBOL(__dev_alloc_skb);
