#ifndef _TRACE_NET_H_
#define _TRACE_NET_H_

#include <linux/tracepoint.h>

DEFINE_TRACE(net_dev_xmit,
	TPPROTO(struct sk_buff *skb, int rc),
	TPARGS(skb, rc));

DEFINE_TRACE(net_dev_receive,
	TPPROTO(struct sk_buff *skb),
	TPARGS(skb));
#endif
