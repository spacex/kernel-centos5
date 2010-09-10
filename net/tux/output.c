/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * output.c: Send data to clients
 */

#include <net/tux.h>

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

int send_sync_buf (tux_req_t *req, struct socket *sock, const char *buf, const size_t length, unsigned long flags)
{
	struct msghdr msg;
	struct iovec iov;
	int len, written = 0, left = length;
	struct tcp_sock *tp = tcp_sk(sock->sk);

	tp->nonagle = 2;

	msg.msg_name     = NULL;
	msg.msg_namelen  = 0;
	msg.msg_iov	 = &iov;
	msg.msg_iovlen   = 1;
	msg.msg_control  = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags    = flags | MSG_NOSIGNAL;
repeat_send:
	msg.msg_iov->iov_len = left;
	msg.msg_iov->iov_base = (char *) buf + written;

	len = sock_sendmsg(sock, &msg, left);

	Dprintk("sendmsg ret: %d, written: %d, left: %d.\n", len,written,left);
	if ((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) &&
			 (len == -EAGAIN))) {
		flush_all_signals();
		goto repeat_send;
	}
	if (len > 0) {
		written += len;
		left -= len;
		if (left)
			goto repeat_send;
	}
	if (len >= 0) {
		if (written != length)
			TUX_BUG();
		if (left)
			TUX_BUG();
	}
	if (req && (written > 0))
		req->bytes_sent += written;
	Dprintk("sendmsg FINAL ret: %d, written: %d, left: %d.\n", len,written,left);
	return written ? written : len;
}

unsigned int tux_zerocopy_sendfile = 1;

typedef struct sock_send_desc
{
	struct socket *sock;
	tux_req_t *req;
} sock_send_desc_t;

static int sock_send_actor (read_descriptor_t * desc, struct page *page,
				unsigned long offset, unsigned long orig_size)
{
	sock_send_desc_t *sock_desc = (sock_send_desc_t *)desc->arg.buf;
	struct socket *sock = sock_desc->sock;
	tux_req_t *req = sock_desc->req;
	unsigned int flags;
	ssize_t written;
	char *buf = NULL;
	unsigned int size;

	flags = MSG_DONTWAIT | MSG_NOSIGNAL;
	if (desc->count < orig_size)
		orig_size = desc->count;
	if (desc->count > orig_size)
		flags |= MSG_MORE;
	Dprintk("sock_send_actor(), page: %p, offset: %ld, orig_size: %ld, sock: %p, desc->count: %d, desc->written: %d, MSG_MORE: %d.\n", page, offset, orig_size, sock, desc->count, desc->written, flags & MSG_MORE);

	if (req->content_gzipped >= 2) {
		unsigned int gzip_left;
		struct msghdr msg;
		struct iovec iov;
		mm_segment_t oldmm;
		char *kaddr = kmap(page);
		__u32 in_len, out_len;
		out_len = orig_size*101/100 + 12;
		buf = tux_kmalloc(out_len);
		in_len = orig_size;
		size = out_len;
		gzip_left = 0;
// 8b1f 0808 fdc4 3bd8 0300 79
buf[1] = 0x8b; buf[0] = 0x1f; buf[3] = 0x08; buf[2] = 0x08;
buf[5] = 0xfd; buf[4] = 0xc4; buf[7] = 0x3b; buf[6] = 0xd8;
buf[9] = 0x03; buf[8] = 0x00; buf[10] = 0x79;
		size += 11;
		Dprintk("pre-compress: in_len: %d, out_len: %d, gzip_left: %d, uncompressed size: %d.\n", in_len, out_len, gzip_left, size);
		gzip_left = tux_gzip_compress(req, kaddr, buf+11, &in_len, &out_len);
		size -= out_len;
 buf[11] = 0x79; buf[12] = 0x00;

		Dprintk("post-compress: in_len: %d, out_len: %d, gzip_left: %d, compressed size: %d.\n", in_len, out_len, gzip_left, size);
		kunmap(page);
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		flags &= ~MSG_DONTWAIT;
		msg.msg_flags = flags;
		iov.iov_base = buf;
		iov.iov_len = size;

		oldmm = get_fs(); set_fs(KERNEL_DS);
		written = sock_sendmsg(sock, &msg, size);
		set_fs(oldmm);

		Dprintk("buf: %p, offset: %ld, size: %d, written: %d.\n", buf, offset, size, written);
		if (written == size)
			written = orig_size;
		else
			written = size;

	} else {
		size = orig_size;
		if (tux_zerocopy_sendfile && sock->ops->sendpage &&
		    (sock->sk->sk_route_caps&NETIF_F_SG)) {
			written = sock->ops->sendpage(sock, page, offset, size, flags);
		} else {
			struct msghdr msg;
			struct iovec iov;
			char *kaddr;
			mm_segment_t oldmm;

			if (offset+size > PAGE_SIZE)
				return -EFAULT;

			kaddr = kmap(page);

			msg.msg_name = NULL;
			msg.msg_namelen = 0;
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = NULL;
			msg.msg_controllen = 0;
			msg.msg_flags = flags;
			iov.iov_base = kaddr + offset;
			iov.iov_len = size;

			oldmm = get_fs(); set_fs(KERNEL_DS);
			written = sock_sendmsg(sock, &msg, size);
			set_fs(oldmm);

			Dprintk("kaddr: %p, offset: %ld, size: %d, written: %d.\n", kaddr, offset, size, written);
			kunmap(page);
		}
	}
	if (written < 0) {
		desc->error = written;
		written = 0;
	}
	Dprintk("desc->count: %d, desc->written: %d, written: %d.\n", desc->count, desc->written, written);
	desc->count -= written;
	if ((int)desc->count < 0)
		TUX_BUG();
	desc->written += written;

	if (buf)
		kfree(buf);

	return written;
}

/*
 * Return 1 if the output space condition went away
 * before adding the handler.
 */
int add_output_space_event (tux_req_t *req, struct socket *sock)
{
	struct sock *sk = sock->sk;
	/*
	 * blocked due to socket IO?
	 */
	spin_lock_irq(&req->ti->work_lock);
	add_keepalive_timer(req);
	if (test_and_set_bit(0,&req->wait_output_space))
		TUX_BUG();
	INC_STAT(nr_output_space_pending);

	if ((sk->sk_state == TCP_ESTABLISHED) && enough_wspace(sk)) {
		if (test_and_clear_bit(0, &req->wait_output_space)) {
			DEC_STAT(nr_output_space_pending);
			del_keepalive_timer(req);
			spin_unlock_irq(&req->ti->work_lock);
			return 1;
		}
	}
	spin_unlock_irq(&req->ti->work_lock);

	return 0;
}

#define SEND_BLOCKSIZE (164*1024)

int generic_send_file (tux_req_t *req, struct socket *sock, int cachemiss)
{
	sock_send_desc_t sock_desc;
	int len, want, nonblock = !cachemiss;
	struct tcp_sock *tp = tcp_sk(sock->sk);

	tp->nonagle = 2;

	sock_desc.sock = sock;
	sock_desc.req = req;

repeat:
	Dprintk("generic_send_file(%p,%d,%p) called, f_pos: %Ld, output_len: %Ld.\n", req, nonblock, sock, req->in_file->f_pos, req->output_len);

	if (req->proto->check_req_err(req, cachemiss))
		return -1;
	if (connection_too_fast(req) == 2) {
		len = -5;
		goto out;
	}
	if (req->total_file_len < req->in_file->f_pos)
		TUX_BUG();

	req->desc.written = 0;
	/*
	 * Careful, output_len can be 64-bit, while 'want' can be 32-bit.
	 */
	if (req->output_len > SEND_BLOCKSIZE)
		want = SEND_BLOCKSIZE;
	else
		want = req->output_len;
	req->desc.count = want;
	req->desc.arg.buf = (char *) &sock_desc;
	req->desc.error = 0;
	Dprintk("sendfile(), desc.count: %d.\n", req->desc.count);
	do_generic_file_read(req->in_file, &req->in_file->f_pos, &req->desc, sock_send_actor, nonblock);
	if (req->desc.written > 0) {
		req->bytes_sent += req->desc.written;
		req->output_len -= req->desc.written;
	}
	if (!nonblock && (req->desc.error == -EWOULDBLOCKIO))
		TUX_BUG();
	Dprintk("sendfile() wrote: %d bytes.\n", req->desc.written);
	if (req->output_len && !req->desc.written && !req->desc.error) {
#ifdef CONFIG_TUX_DEBUG
		req->bytes_expected = 0;
#endif
		req->in_file->f_pos = 0;
		req->error = TUX_ERROR_CONN_CLOSE;
		zap_request(req, cachemiss);
		return -1;
	}

	switch (req->desc.error) {

	case -EWOULDBLOCKIO:
		len = -3;
		break;
	case -EAGAIN:
no_write_space:
		Dprintk("sk->wmem_queued: %d, sk->sndbuf: %d.\n",
			sock->sk->sk_wmem_queued, sock->sk->sk_sndbuf);
		len = -4;
		break;
	default:
		len = req->desc.written;
#ifdef CONFIG_TUX_DEBUG
		if (req->desc.error)
			TDprintk("TUX: sendfile() returned error %d (signals pending: %08lx)!\n", req->desc.error, current->pending.signal.sig[0]);
#endif
		if (!req->desc.error) {
			if (req->output_len < 0)
				BUG();
			if (req->output_len) {
				if (test_bit(SOCK_NOSPACE, &sock->flags))
					goto no_write_space;
				goto repeat;
			}
		}
#ifdef CONFIG_TUX_DEBUG
		if (req->desc.written != want)
			TDprintk("TUX: sendfile() wrote %d bytes, wanted %d! (pos %Ld) (signals pending: %08lx).\n", req->desc.written, want, req->in_file->f_pos, current->pending.signal.sig[0]);
		else
			Dprintk("TUX: sendfile() FINISHED for req %p, wrote %d bytes.\n", req, req->desc.written);
		req->bytes_expected = 0;
#endif
		break;
	}

out:
	Dprintk("sendfile() wrote %d bytes.\n", len);

	return len;
}

static int file_fetch_actor (read_descriptor_t * desc, struct page *page,
				unsigned long offset, unsigned long size)
{
	if (desc->count < size)
		size = desc->count;

	desc->count -= size;
	desc->written += size;

	return size;
}

int tux_fetch_file (tux_req_t *req, int nonblock)
{
	int len;

	req->desc.written = 0;
	req->desc.count = req->output_len;
	req->desc.arg.buf = NULL;
	req->desc.error = 0;

	do_generic_file_read(req->in_file, &req->in_file->f_pos, &req->desc,
					file_fetch_actor, nonblock);
	if (nonblock && (req->desc.error == -EWOULDBLOCKIO))
		return 1;
	len = req->desc.written;
	if (req->desc.error)
		Dprintk("fetchfile() returned %d error!\n", req->desc.error);
	Dprintk("fetchfile() fetched %d bytes.\n", len);
	return 0;
}

