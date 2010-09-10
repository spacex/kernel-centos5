#if !defined(_TRACE_SUNRPC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SUNRPC_H

#include <linux/tracepoint.h>
#include <linux/sunrpc/sched.h>

DEFINE_TRACE(rpc_call_status,
	TPPROTO(struct rpc_task *task), TPARGS(task));

DEFINE_TRACE(rpc_bind_status,
	TPPROTO(struct rpc_task *task), TPARGS(task));

DEFINE_TRACE(rpc_connect_status,
	TPPROTO(struct rpc_task *task, int status), TPARGS(task, status));

#endif /* __TRACE_SUNRPC_H */
