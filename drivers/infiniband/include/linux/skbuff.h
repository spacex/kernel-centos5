#ifndef LINUX_SKBUFF_H_BACKPORT
#define LINUX_SKBUFF_H_BACKPORT

#include_next <linux/skbuff.h>

#define CHECKSUM_PARTIAL CHECKSUM_HW 
#define CHECKSUM_COMPLETE CHECKSUM_HW 

#endif
#ifndef __BACKPORT_LINUX_SKBUFF_H_TO_2_6_21__
#define __BACKPORT_LINUX_SKBUFF_H_TO_2_6_21__

#include_next <linux/skbuff.h>

#define transport_header h.raw
#define network_header nh.raw

static inline int skb_csum_unnecessary(const struct sk_buff *skb)
{
	return skb->ip_summed & CHECKSUM_UNNECESSARY;
}

#endif
