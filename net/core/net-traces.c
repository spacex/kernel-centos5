/*
 * consolidates trace point definitions
 *
 * Copyright (C) 2009 Neil Horman <nhorman@tuxdriver.com>
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/interrupt.h>
#include <linux/netpoll.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/netlink.h>
#include <linux/net_dropmon.h>
#include <trace/skb.h>
#include <trace/napi.h>
#include <trace/net.h>

#include <asm/unaligned.h>
#include <asm/bitops.h>


DEFINE_TRACE(kfree_skb);
EXPORT_TRACEPOINT_SYMBOL_GPL(kfree_skb);

DEFINE_TRACE(napi_poll);
EXPORT_TRACEPOINT_SYMBOL_GPL(napi_poll);

DEFINE_TRACE(net_dev_xmit);
EXPORT_TRACEPOINT_SYMBOL_GPL(net_dev_xmit);

DEFINE_TRACE(net_dev_receive);
EXPORT_TRACEPOINT_SYMBOL_GPL(net_dev_receive);

DEFINE_TRACE(net_dev_queue);
EXPORT_TRACEPOINT_SYMBOL_GPL(net_dev_queue);

DEFINE_TRACE(netif_rx);
EXPORT_TRACEPOINT_SYMBOL_GPL(netif_rx);

DEFINE_TRACE(consume_skb);
EXPORT_TRACEPOINT_SYMBOL_GPL(consume_skb);

