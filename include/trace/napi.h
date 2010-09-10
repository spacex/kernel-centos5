#ifndef _TRACE_NAPI_H_
#define _TRACE_NAPI_H_

#include <linux/netdevice.h>
#include <linux/tracepoint.h>

DEFINE_TRACE(napi_poll,
	TPPROTO(struct net_device *napi),
	TPARGS(napi));

#endif
