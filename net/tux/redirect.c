/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * redirect.c: redirect requests to other server sockets (such as Apache).
 */

#include <net/tux.h>
#include <linux/module.h>
#include <linux/init.h>

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

static void nop_destructor(struct request_sock *req)
{
}

static struct request_sock_ops tux_req =
{
	.destructor = &nop_destructor,
};

static int redirect_sock (tux_req_t *req, const int port)
{
	struct socket *sock = req->sock;
	struct request_sock *tcpreq;
	struct sock *sk, *oldsk;
	int err = -1;

	/*
	 * Look up (optional) listening user-space socket.
	 */
	local_bh_disable();
	sk = inet_lookup_listener(&tcp_hashinfo, INADDR_ANY, port, 0);
	/*
	 * Look up localhost listeners as well.
	 */
	if (!sk) {
		u32 daddr;
		((unsigned char *)&daddr)[0] = 127;
		((unsigned char *)&daddr)[1] = 0;
		((unsigned char *)&daddr)[2] = 0;
		((unsigned char *)&daddr)[3] = 1;
		sk = inet_lookup_listener(&tcp_hashinfo, daddr, port, 0);
	}
	local_bh_enable();

	/* No secondary server found */
	if (!sk)
		goto out;
	if (sk->sk_family != AF_INET) {
		sock_put(sk);
		goto out;
	}

	/*
	 * Requeue the 'old' socket as an accept-socket of
	 * the listening socket. This way we can shuffle
	 * a socket around. Since we've read the input data
	 * via the non-destructive MSG_PEEK, the secondary
	 * server can be used transparently.
	 */
	oldsk = sock->sk;
	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN)
		goto out_unlock;

	tcpreq = reqsk_alloc(&tux_req);
	if (!tcpreq)
		goto out_unlock;

	unlink_tux_socket(req);

	sock->sk = NULL;
	sock->state = SS_UNCONNECTED;

	write_lock_irq(&oldsk->sk_callback_lock);
	oldsk->sk_socket = NULL;
        oldsk->sk_sleep = NULL;
	write_unlock_irq(&oldsk->sk_callback_lock);

	tcp_sk(oldsk)->nonagle = 0;

	inet_csk_reqsk_queue_add(sk, tcpreq, oldsk);

	sk->sk_data_ready(sk, 0);

	/*
	 * It's now completely up to the secondary
	 * server to handle this request.
	 */
	if (req->fd != -1) {
		tux_close(req->fd);
		req->fd = -1;
	} else
		sock_release(req->sock);
	req->sock = NULL;
	req->parsed_len = 0;
	err = 0;
	Dprintk("req %p redirected to secondary server!\n", req);

out_unlock:
	release_sock(sk);
	sock_put(sk);
out:
	if (err)
		Dprintk("NO secondary server for req %p!\n", req);
	return err;
}

void redirect_request (tux_req_t *req, int cachemiss)
{
	if (tux_TDprintk && (req->status != 304)) {
		TDprintk("trying to redirect req %p, req->error: %d, req->status: %d.\n", req, req->error, req->status);
		print_req(req);
	}

	if (cachemiss)
		TUX_BUG();
	if (req->error == TUX_ERROR_CONN_CLOSE)
		goto out_flush;
	if (!req->sock)
		TUX_BUG();

	if (!req->status)
		req->status = -1;
	if (!req->proto->can_redirect || (req->status == 304) || redirect_sock(req, tux_clientport)) {
		if (req->parsed_len)
			trunc_headers(req);
		req->proto->illegal_request(req, cachemiss);
		return;
	} else {
		if (req->data_sock)
			BUG();
	}
out_flush:
	clear_keepalive(req);
	if (!tux_redirect_logging)
		req->status = 0;
	flush_request(req, cachemiss);
}

int init_tux_request_slabs(void)
{
	tux_req.slab = kmem_cache_create("tux-request",
			sizeof(struct request_sock), 0, SLAB_HWCACHE_ALIGN,
			NULL, NULL);

	return tux_req.slab == NULL;
}

void free_tux_request_slabs(void)
{
	kmem_cache_destroy(tux_req.slab);
}
