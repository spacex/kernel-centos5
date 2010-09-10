#ifndef _TRACE_SOCKET_H
#define _TRACE_SOCKET_H

#include <net/sock.h>
#include <linux/tracepoint.h>

DEFINE_TRACE(socket_sendmsg,
	TPPROTO(struct socket *sock, struct msghdr *msg, size_t size, int ret),
	TPARGS(sock, msg, size, ret));
DEFINE_TRACE(socket_recvmsg,
	TPPROTO(struct socket *sock, struct msghdr *msg, size_t size, int flags,
		int ret),
	TPARGS(sock, msg, size, flags, ret));
DEFINE_TRACE(socket_sendpage,
	TPPROTO(struct socket *sock, struct page *page, int offset, size_t size,
		int flags, int ret),
	TPARGS(sock, page, offset, size, flags, ret));
#endif
