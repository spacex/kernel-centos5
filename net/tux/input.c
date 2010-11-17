/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * input.c: handle requests arriving on accepted connections
 */

#include <net/tux.h>
#include <linux/kmod.h>

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

void zap_request (tux_req_t *req, int cachemiss)
{
	if (!req->error)
		TUX_BUG();
	if (req->error == TUX_ERROR_CONN_TIMEOUT) {
		if (req->proto->request_timeout) {
			clear_keepalive(req);
			req->proto->request_timeout(req, cachemiss);
		} else {
			clear_keepalive(req);
			if (!cachemiss)
				flush_request(req, 0);
			else {
				add_tux_atom(req, flush_request);
				add_req_to_workqueue(req);
			}
		}
		return;
	}

	if (!cachemiss && (req->error == TUX_ERROR_CONN_CLOSE)) {
		/*
		 * Zap connection as fast as possible, there is
		 * no valid client connection anymore:
		 */
		clear_keepalive(req);
		flush_request(req, 0);
	} else {
		if (req->error == TUX_ERROR_CONN_CLOSE) {
			clear_keepalive(req);
			add_tux_atom(req, flush_request);
		} else
			/*
			 * Potentially redirect to the secondary server:
			 */
			add_tux_atom(req, redirect_request);
		add_req_to_workqueue(req);
	}
}

void __switch_docroot(tux_req_t *req)
{
	if (!req->docroot_dentry || !req->docroot_mnt)
		TUX_BUG();
	set_fs_root(current->fs, req->docroot_mnt, req->docroot_dentry);
}

struct dentry * __tux_lookup (tux_req_t *req, const char *filename,
			 struct nameidata *base, struct vfsmount **mnt)
{
	int err;

	err = path_walk(filename, base);
	if (err) {
		Dprintk("path_walk() returned with %d!\n", err);
		return ERR_PTR(err);
	}
	if (*mnt)
		TUX_BUG();
	*mnt = base->mnt;

	return base->dentry;
}

int tux_permission (struct inode *inode)
{
	umode_t mode;
	int err;

	mode = inode->i_mode;
	Dprintk("URL inode mode: %08x.\n", mode);

	if (mode & tux_mode_forbidden)
		return -2;
	/*
	 * at least one bit in the 'allowed' set has to
	 * be present to allow access.
	 */
	if (!(mode & tux_mode_allowed))
		return -3;
	err = permission(inode,MAY_READ,NULL);
	return err;
}

struct dentry * tux_lookup (tux_req_t *req, const char *filename,
			const unsigned int flag, struct vfsmount **mnt)
{
	struct dentry *dentry;
	struct nameidata base = { };

	Dprintk("tux_lookup(%p, %s, %d, virtual: %d, host: %s (%d).)\n", req, filename, flag, req->virtual, req->host, req->host_len);

	base.flags = LOOKUP_FOLLOW|flag;
	base.last_type = LAST_ROOT;
	if (req->objectname[0] == '/') {
		base.dentry = dget(req->docroot_dentry);
		base.mnt = mntget(req->docroot_mnt);
	} else {
		if (!req->cwd_dentry) {
			req->cwd_dentry = dget(req->docroot_dentry);
			req->cwd_mnt = mntget(req->docroot_mnt);
		}
		base.dentry = req->cwd_dentry;
		dget(base.dentry);
		base.mnt = mntget(req->cwd_mnt);
	}

	switch_docroot(req);
	dentry = __tux_lookup (req, filename, &base, mnt);

	Dprintk("looked up {%s} == dentry %p.\n", filename, dentry);

	if (dentry && !IS_ERR(dentry) && !dentry->d_inode)
		TUX_BUG();
	return dentry;
}

int lookup_object (tux_req_t *req, const unsigned int flag)
{
	struct vfsmount *mnt = NULL;
	struct dentry *dentry = NULL;
	int perm;

	dentry = tux_lookup(req, req->objectname, flag, &mnt);
	if (!dentry || IS_ERR(dentry)) {
		if (PTR_ERR(dentry) == -EWOULDBLOCKIO)
			goto cachemiss;
		goto abort;
	}
	perm = tux_permission(dentry->d_inode);
	/*
	 * Only regular files allowed.
	 */
	if ((perm < 0) || !S_ISREG(dentry->d_inode->i_mode)) {
		req->status = 403;
		goto abort;
	}
	req->total_file_len = i_size_read(dentry->d_inode);
out:
	install_req_dentry(req, dentry, mnt);
	return 0;
cachemiss:
	return 1;
abort:
	if (dentry) {
		if (!IS_ERR(dentry))
			dput(dentry);
		dentry = NULL;
	}
	if (mnt) {
		if (!IS_ERR(mnt))
			mntput(mnt);
		mnt = NULL;
	}
	req_err(req);
	goto out;
}

void install_req_dentry (tux_req_t *req, struct dentry *dentry, struct vfsmount *mnt)
{
	if (req->dentry)
		TUX_BUG();
	req->dentry = dentry;
	if (req->mnt)
		TUX_BUG();
	req->mnt = mnt;
	if (req->in_file && req->in_file->f_dentry)
		TUX_BUG();
	if (dentry)
		req->in_file = dentry_open(dget(dentry), NULL, O_RDONLY);
}

void release_req_dentry (tux_req_t *req)
{
	if (!req->dentry) {
		if (req->in_file && req->in_file->f_dentry)
			TUX_BUG();
		return;
	}

	fput(req->in_file);
	req->in_file = NULL;
	dput(req->dentry);
	req->dentry = NULL;
	mntput(req->mnt);
	req->mnt = NULL;
}

int __connection_too_fast (tux_req_t *req)
{
	unsigned long curr_bw, delta, bytes;

	bytes = req->total_bytes + req->bytes_sent;
	if (!bytes)
		return 1;

	delta = jiffies - req->first_timestamp;
	if (!delta)
		delta++;
	curr_bw = bytes * HZ / delta;

	if (curr_bw > tux_max_output_bandwidth)
		return 2;
	return 0;
}

void unidle_req (tux_req_t *req)
{
	threadinfo_t *ti = req->ti;

	Dprintk("UNIDLE req %p <%p> (sock %p, sk %p) (keepalive: %d, status: %d)\n", req, __builtin_return_address(0), req->sock, req->sock->sk, req->keep_alive, req->status);
	spin_lock_irq(&ti->work_lock);
	if (req->magic != TUX_MAGIC)
		TUX_BUG();
	if (!test_and_clear_bit(0, &req->idle_input)) {
		Dprintk("unidling %p, wasnt idle!\n", req);
		if (list_empty(&req->work))
			TUX_BUG();
		list_del(&req->work);
		DEBUG_DEL_LIST(&req->work);
		DEC_STAT(nr_work_pending);
	} else {
		del_keepalive_timer(req);
		DEC_STAT(nr_idle_input_pending);
		Dprintk("unidled %p.\n", req);
	}
	if (req->idle_input)
		TUX_BUG();
	spin_unlock_irq(&ti->work_lock);
}

#define GOTO_INCOMPLETE do { Dprintk("incomplete at %s:%d.\n", __FILE__, __LINE__); goto incomplete; } while (0)
#define GOTO_REDIRECT do { TDprintk("redirect at %s:%d.\n", __FILE__, __LINE__); goto redirect; } while (0)
#define GOTO_REDIRECT_NONIDLE do { TDprintk("redirect at %s:%d.\n", __FILE__, __LINE__); goto redirect_nonidle; } while (0)

static int read_request (struct socket *sock, char *buf, int max_size)
{
	mm_segment_t oldmm;
	struct kiocb iocb;
	struct msghdr msg;
	struct iovec iov;

	int len;

	msg.msg_name     = NULL;
	msg.msg_namelen  = 0;
	msg.msg_iov	 = &iov;
	msg.msg_iovlen   = 1;
	msg.msg_control  = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags    = 0;

	msg.msg_iov->iov_base = buf;
	msg.msg_iov->iov_len  = max_size;

	oldmm = get_fs(); set_fs(KERNEL_DS);

read_again:
	init_sync_kiocb(&iocb, NULL);
	len = sock->sk->sk_prot->recvmsg(&iocb, sock->sk, &msg, max_size,
						MSG_DONTWAIT, MSG_PEEK, NULL);
	if (-EIOCBQUEUED == len)
		len = wait_on_sync_kiocb(&iocb);

	/*
	 * We must not get a signal inbetween
	 */
	if ((len == -EAGAIN) || (len == -ERESTARTSYS)) {
		if (!signal_pending(current)) {
			len = 0;
			goto out;
		}
		flush_all_signals();
		goto read_again;
	}
out:
	set_fs(oldmm);
	return len;
}

/*
 * We inline URG data so it's at the head of the normal receive queue.
 */
static int zap_urg_data (struct socket *sock)
{
	mm_segment_t oldmm;
	struct msghdr msg;
	struct iovec iov;
	struct kiocb iocb;
	int len;
	char buf[10];

	oldmm = get_fs(); set_fs(KERNEL_DS);

	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	msg.msg_iov		= &iov;
	msg.msg_iovlen		= 1;
	msg.msg_control		= NULL;
	msg.msg_controllen	= 0;
	msg.msg_flags		= 0;

	msg.msg_iov->iov_base = buf;
	msg.msg_iov->iov_len  = 2;

read_again:
	init_sync_kiocb(&iocb, NULL);
	len = sock->sk->sk_prot->recvmsg(&iocb, sock->sk, &msg, 2,
						MSG_DONTWAIT, 0, NULL);
	if (-EIOCBQUEUED == len)
		len = wait_on_sync_kiocb(&iocb);
	Dprintk("recvmsg(MSG_OOB) returned %d.\n", len);

	/*
	 * We must not get a signal inbetween
	 */
	if ((len == -EAGAIN) || (len == -ERESTARTSYS)) {
		if (!signal_pending(current)) {
			len = 0;
			goto out;
		}
		flush_all_signals();
		goto read_again;
	}
out:
	set_fs(oldmm);

	Dprintk("in out:.. and will return %d.!\n", len);

	return len;
}

void trunc_headers (tux_req_t *req)
{
	struct sock *sk = req->sock->sk;
	int len, addr_len = 0;
	struct kiocb iocb;

	if (!req->parsed_len)
		TUX_BUG();
repeat_trunc:
	init_sync_kiocb(&iocb, NULL);
	len = sk->sk_prot->recvmsg(&iocb, sk, NULL, req->parsed_len, 1, MSG_TRUNC, &addr_len);
	if (-EIOCBQUEUED == len)
		len = wait_on_sync_kiocb(&iocb);
	if ((len == -ERESTARTSYS) || (len == -EAGAIN)) {
		flush_all_signals();
		goto repeat_trunc;
	}
	Dprintk("truncated (TRUNC) %d bytes at %p. (wanted: %d.)\n", len, __builtin_return_address(0), req->parsed_len);



	req->parsed_len = 0;
}

void print_req (tux_req_t *req)
{
	struct sock *sk;

	printk("PRINT req %p <%p>, sock %p\n",
			req, __builtin_return_address(0), req->sock);
	printk("... idx: %d\n", req->atom_idx);
	if (req->sock) {
		sk = req->sock->sk;
		printk("... sock %p, sk %p, sk->state: %d, sk->err: %d\n", req->sock, sk, sk->sk_state, sk->sk_err);
		printk("... write_queue: %d, receive_queue: %d, error_queue: %d, keepalive: %d, status: %d\n", !skb_queue_empty(&sk->sk_write_queue), !skb_queue_empty(&sk->sk_receive_queue), !skb_queue_empty(&sk->sk_error_queue), req->keep_alive, req->status);
		printk("...tp->send_head: %p\n", sk->sk_send_head);
		printk("...tp->snd_una: %08x\n", tcp_sk(sk)->snd_una);
		printk("...tp->snd_nxt: %08x\n", tcp_sk(sk)->snd_nxt);
		printk("...tp->packets_out: %08x\n", tcp_sk(sk)->packets_out);
	}
	printk("... meth:{%s}, uri:{%s}, query:{%s}, ver:{%s}\n", req->method_str ? req->method_str : "<null>", req->uri_str ? req->uri_str : "<null>", req->query_str ? req->query_str : "<null>", req->version_str ? req->version_str : "<null>");
	printk("... post_data:{%s}(%d).\n", req->post_data_str, req->post_data_len);
	printk("... headers: {%s}\n", req->headers);
}
/*
 * parse_request() reads all available TCP/IP data and prepares
 * the request if the TUX request is complete. (we can get TUX
 * requests in several packets.) Invalid requests are redirected
 * to the secondary server.
 */

void parse_request (tux_req_t *req, int cachemiss)
{
	int len, parsed_len;
	struct sock *sk = req->sock->sk;
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int was_keepalive = req->keep_alive;

	if (req->magic != TUX_MAGIC)
		TUX_BUG();

	SET_TIMESTAMP(req->parse_timestamp);

	spin_lock_irq(&req->ti->work_lock);
	add_keepalive_timer(req);
	if (test_and_set_bit(0, &req->idle_input))
		TUX_BUG();
	INC_STAT(nr_idle_input_pending);
	spin_unlock_irq(&req->ti->work_lock);

	Dprintk("idled request %p.\n", req);

restart:

	if (tp->urg_data && !(tp->urg_data & TCP_URG_READ)) {
		len = zap_urg_data(req->sock);
		if (tp->urg_data && !(tp->urg_data & TCP_URG_READ)) {
			req->error = TUX_ERROR_CONN_CLOSE;
			goto redirect_error;
		}
	}

	INC_STAT(input_slowpath);

	if (!req->headers)
		req->headers = tux_kmalloc(tux_max_header_len);

	/* First, read the data */
	len = read_request(req->sock, (char *)req->headers, tux_max_header_len-1);
	if (len < 0) {
		req->error = TUX_ERROR_CONN_CLOSE;
		goto redirect_error;
	}
	if (!len)
		GOTO_INCOMPLETE;

	/*
	 * Make it a zero-delimited string to automatically get
	 * protection against various buffer overflow situations.
	 * Then pass it to the TUX application protocol stack.
	 */
	((char *)req->headers)[len] = 0;
	req->headers_len = len;

	parsed_len = req->proto->parse_message(req, len);

	/*
	 * Is the request fully read? (or is there any error)
	 */
	if (parsed_len < 0)
		GOTO_REDIRECT;
	if (!parsed_len) {
		/*
		 * Push pending ACK which was delayed due to the
		 * pingpong optimization:
		 */
		if (was_keepalive) {
			lock_sock(sk);
			icsk->icsk_ack.pingpong = 0;
			icsk->icsk_ack.pending |= ICSK_ACK_PUSHED;
			tcp_cleanup_rbuf(sk, 1);
			release_sock(sk);
		}
		if (len >= tux_max_header_len-1)
			GOTO_REDIRECT;
		GOTO_INCOMPLETE;
	}
	unidle_req(req);

	tp->nonagle = 2;

	add_req_to_workqueue(req);
	return;

redirect:
	TDprintk("req %p will be redirected!\n", req);
	req_err(req);

redirect_error:
	unidle_req(req);

	if (len < 0)
		req->parsed_len = 0;
	else
		req->parsed_len = len;

	INC_STAT(parse_static_redirect);
	if (req->headers)
		kfree(req->headers);
	req->headers = NULL;
	if (req->error)
		zap_request(req, cachemiss);
	return;

incomplete:
	if (req->error)
		goto redirect_error;
	if (tp->urg_data && !(tp->urg_data & TCP_URG_READ))
		goto restart;

	add_tux_atom(req, parse_request);
	INC_STAT(parse_static_incomplete);
	tux_push_req(req);
}

int process_requests (threadinfo_t *ti, tux_req_t **user_req)
{
	struct list_head *head, *curr;
	int count = 0;
	tux_req_t *req;

	*user_req = NULL;

restart_loop:
	spin_lock_irq(&ti->work_lock);
	head = &ti->work_pending;
	curr = head->next;

	if (curr != head) {
		int i;

		req = list_entry(curr, tux_req_t, work);
		Dprintk("PROCESS req %p <%p>.\n",
			req, __builtin_return_address(0));
		for (i = 0; i < req->atom_idx; i++)
			Dprintk("... atom %d: %p\n", i, req->atoms[i]);

		if (req->ti != ti)
			TUX_BUG();
		if (req->magic != TUX_MAGIC)
			TUX_BUG();

		if (list_empty(&req->work))
			TUX_BUG();
		list_del(curr);
		DEBUG_DEL_LIST(&req->work);
		spin_unlock_irq(&ti->work_lock);

		if (!req->atom_idx) {
			if (req->usermode) {
				*user_req = req;
				return count;
			}
			/*
			 * idx == 0 requests are flushed automatically.
			 */
			flush_request(req, 0);
		} else
			tux_schedule_atom(req, 0);
		count++;
		goto restart_loop;
	}
	spin_unlock_irq(&ti->work_lock);

	return count;
}

int tux_flush_workqueue (threadinfo_t *ti)
{
	struct list_head *head, *curr, *next;
	tux_req_t *req;
	int count = 0;

restart:
	spin_lock_irq(&ti->work_lock);
	head = &ti->work_pending;
	curr = head->next;

	if (curr != head) {
		req = list_entry(curr, tux_req_t, work);
		next = curr->next;
		clear_bit(0, &req->idle_input);
		clear_bit(0, &req->wait_output_space);
		if (list_empty(&req->work))
			TUX_BUG();
		list_del(curr);
		DEBUG_DEL_LIST(curr);
		DEC_STAT(nr_input_pending);
		spin_unlock_irq(&ti->work_lock);
#ifdef CONFIG_TUX_DEBUG
		req->bytes_expected = 0;
#endif
		if (req->in_file)
			req->in_file->f_pos = 0;
		req->atom_idx = 0;
		clear_keepalive(req);
		req->status = -1;
		if (req->usermode) {
			req->usermode = 0;
			req->private = 0;
		}
		flush_request(req, 0);
		count++;
		goto restart;
	}
	spin_unlock_irq(&ti->work_lock);

	return count;
}

int print_all_requests (threadinfo_t *ti)
{
	struct list_head *head, *curr;
	tux_req_t *req;
	int count = 0;

	spin_lock_irq(&ti->work_lock);
	head = &ti->all_requests;
	curr = head->next;

	while (curr != head) {
		req = list_entry(curr, tux_req_t, all);
		curr = curr->next;
		print_req(req);
		count++;
	}
	spin_unlock_irq(&ti->work_lock);

	return count;
}

