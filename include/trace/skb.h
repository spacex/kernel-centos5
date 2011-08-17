#ifndef _TRACE_SKB_H_
#define _TRACE_SKB_H_

#include <linux/tracepoint.h>

DEFINE_TRACE(kfree_skb,
	TPPROTO(struct sk_buff *skb, void *location),
	TPARGS(skb, location));

DEFINE_TRACE(consume_skb,
	TPPROTO(struct sk_buff *skb),
	TPARGS(skb));

#endif
