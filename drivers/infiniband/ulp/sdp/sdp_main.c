/*
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if defined(__ia64__)
/* csum_partial_copy_from_user is not exported on ia64.
   We don't really need it for SDP - skb_copy_to_page happens to call it
   but for SDP HW checksum is always set, so ... */

#include <linux/errno.h>
#include <asm/checksum.h>

static inline
unsigned int csum_partial_copy_from_user_new (const char *src, char *dst,
						 int len, unsigned int sum,
						 int *errp)
{
	*errp = -EINVAL;
	return 0;
}

#define csum_partial_copy_from_user csum_partial_copy_from_user_new
#endif

#include <linux/tcp.h>
#include <asm/ioctls.h>
#include <linux/workqueue.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <linux/proc_fs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
/* TODO: remove when sdp_socket.h becomes part of include/linux/socket.h */
#include "sdp_socket.h"
#include "sdp.h"
#include <linux/delay.h>

MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("InfiniBand SDP module");
MODULE_LICENSE("Dual BSD/GPL");

#ifdef CONFIG_INFINIBAND_SDP_DEBUG
int sdp_debug_level;

module_param_named(debug_level, sdp_debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Enable debug tracing if > 0.");
#endif
#ifdef CONFIG_INFINIBAND_SDP_DEBUG
int sdp_data_debug_level;

module_param_named(data_debug_level, sdp_data_debug_level, int, 0644);
MODULE_PARM_DESC(data_debug_level, "Enable data path debug tracing if > 0.");
#endif

static int send_poll_hit;

module_param_named(send_poll_hit, send_poll_hit, int, 0644);
MODULE_PARM_DESC(send_poll_hit, "How many times send poll helped.");

static int send_poll_miss;

module_param_named(send_poll_miss, send_poll_miss, int, 0644);
MODULE_PARM_DESC(send_poll_miss, "How many times send poll missed.");

static int recv_poll_hit;

module_param_named(recv_poll_hit, recv_poll_hit, int, 0644);
MODULE_PARM_DESC(recv_poll_hit, "How many times recv poll helped.");

static int recv_poll_miss;

module_param_named(recv_poll_miss, recv_poll_miss, int, 0644);
MODULE_PARM_DESC(recv_poll_miss, "How many times recv poll missed.");

static int send_poll = 100;

module_param_named(send_poll, send_poll, int, 0644);
MODULE_PARM_DESC(send_poll, "How many times to poll send.");

static int recv_poll = 1000;

module_param_named(recv_poll, recv_poll, int, 0644);
MODULE_PARM_DESC(recv_poll, "How many times to poll recv.");

static int send_poll_thresh = 8192;

module_param_named(send_poll_thresh, send_poll_thresh, int, 0644);
MODULE_PARM_DESC(send_poll_thresh, "Send message size thresh hold over which to start polling.");

struct workqueue_struct *sdp_workqueue;

static struct list_head sock_list;
static spinlock_t sock_list_lock;

DEFINE_RWLOCK(device_removal_lock);

inline void sdp_add_sock(struct sdp_sock *ssk)
{
	spin_lock_irq(&sock_list_lock);
	list_add_tail(&ssk->sock_list, &sock_list);
	spin_unlock_irq(&sock_list_lock);
}

inline void sdp_remove_sock(struct sdp_sock *ssk)
{
	spin_lock_irq(&sock_list_lock);
	BUG_ON(list_empty(&sock_list));
	list_del_init(&(ssk->sock_list));
	spin_unlock_irq(&sock_list_lock);
}

static int sdp_get_port(struct sock *sk, unsigned short snum)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sockaddr_in *src_addr;
	int rc;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(snum),
		.sin_addr.s_addr = inet_sk(sk)->rcv_saddr,
	};

	sdp_dbg(sk, "%s: %u.%u.%u.%u:%hu\n", __func__,
		NIPQUAD(addr.sin_addr.s_addr), ntohs(addr.sin_port));

	if (!ssk->id)
		ssk->id = rdma_create_id(sdp_cma_handler, sk, RDMA_PS_SDP);

	if (!ssk->id)
	       return -ENOMEM;

	/* IP core seems to bind many times to the same address */
	/* TODO: I don't really understand why. Find out. */
	if (!memcmp(&addr, &ssk->id->route.addr.src_addr, sizeof addr))
		return 0;

	rc = rdma_bind_addr(ssk->id, (struct sockaddr *)&addr);
	if (rc) {
		rdma_destroy_id(ssk->id);
		ssk->id = NULL;
		return rc;
	}

	src_addr = (struct sockaddr_in *)&(ssk->id->route.addr.src_addr);
	inet_sk(sk)->num = ntohs(src_addr->sin_port);
	return 0;
}

static void sdp_destroy_qp(struct sdp_sock *ssk)
{
	struct ib_pd *pd = NULL;
	struct ib_cq *cq = NULL;

	if (ssk->qp) {
		pd = ssk->qp->pd;
		cq = ssk->cq;
		ssk->cq = NULL;
		ib_destroy_qp(ssk->qp);

		while (ssk->rx_head != ssk->rx_tail) {
			struct sk_buff *skb;
			skb = sdp_recv_completion(ssk, ssk->rx_tail);
			if (!skb)
				break;
			atomic_sub(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);
			__kfree_skb(skb);
		}
		while (ssk->tx_head != ssk->tx_tail) {
			struct sk_buff *skb;
			skb = sdp_send_completion(ssk, ssk->tx_tail);
			if (!skb)
				break;
			__kfree_skb(skb);
		}
	}

	if (cq)
		ib_destroy_cq(cq);

	if (ssk->mr)
		ib_dereg_mr(ssk->mr);

	if (pd)
		ib_dealloc_pd(pd);

	if (ssk->recv_frags)
		sdp_remove_large_sock();

	kfree(ssk->rx_ring);
	kfree(ssk->tx_ring);
}

void sdp_reset_sk(struct sock *sk, int rc)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	read_lock(&device_removal_lock);

	if (ssk->cq)
		sdp_poll_cq(ssk, ssk->cq);

	if (!(sk->sk_shutdown & RCV_SHUTDOWN) || !sk_stream_memory_free(sk))
		sdp_set_error(sk, rc);

	sdp_destroy_qp(ssk);

	memset((void *)&ssk->id, 0, sizeof(*ssk) - offsetof(typeof(*ssk), id));

	if (ssk->time_wait) {
		sdp_dbg(sk, "%s: destroy in time wait state\n", __func__);
		sdp_time_wait_destroy_sk(ssk);
	}

	sk->sk_state_change(sk);

	read_unlock(&device_removal_lock);
}

/* Like tcp_reset */
/* When we get a reset (completion with error) we do this. */
void sdp_reset(struct sock *sk)
{
	int err;

	if (sk->sk_state != TCP_ESTABLISHED)
		return;

	/* We want the right error as BSD sees it (and indeed as we do). */

	/* On fin we currently only set RCV_SHUTDOWN, so .. */
	err = (sk->sk_shutdown & RCV_SHUTDOWN) ? EPIPE : ECONNRESET;

	sdp_set_error(sk, -err);
	wake_up(&sdp_sk(sk)->wq);
	sk->sk_state_change(sk);
}

/* TODO: linger? */
static void sdp_close_sk(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct rdma_cm_id *id = NULL;
	sdp_dbg(sk, "%s\n", __func__);

	lock_sock(sk);

	sk->sk_send_head = NULL;
	skb_queue_purge(&sk->sk_write_queue);
        /*
         * If sendmsg cached page exists, toss it.
         */
        if (sk->sk_sndmsg_page) {
                __free_page(sk->sk_sndmsg_page);
                sk->sk_sndmsg_page = NULL;
        }

	id = ssk->id;
	if (ssk->id) {
		id->qp = NULL;
		ssk->id = NULL;
		release_sock(sk);
		rdma_destroy_id(id);
		lock_sock(sk);
	}

	skb_queue_purge(&sk->sk_receive_queue);

	sdp_destroy_qp(ssk);

	sdp_dbg(sk, "%s done; releasing sock\n", __func__);
	release_sock(sk);

	flush_scheduled_work();
}

static void sdp_destruct(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sdp_sock *s, *t;

	sdp_dbg(sk, "%s\n", __func__);

	sdp_remove_sock(ssk);
	
	sdp_close_sk(sk);

	if (ssk->parent)
		goto done;

	list_for_each_entry_safe(s, t, &ssk->backlog_queue, backlog_queue) {
		sk_common_release(&s->isk.sk);
	}
	list_for_each_entry_safe(s, t, &ssk->accept_queue, accept_queue) {
		sk_common_release(&s->isk.sk);
	}

done:
	sdp_dbg(sk, "%s done\n", __func__);
}

static void sdp_send_active_reset(struct sock *sk, gfp_t priority)
{
	sk->sk_prot->disconnect(sk, 0);
}

/*
 *	State processing on a close.
 *	TCP_ESTABLISHED -> TCP_FIN_WAIT1 -> TCP_FIN_WAIT2 -> TCP_CLOSE
 */

static int sdp_close_state(struct sock *sk)
{
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		return 0;

	if (sk->sk_state == TCP_ESTABLISHED)
		sk->sk_state = TCP_FIN_WAIT1;
	else if (sk->sk_state == TCP_CLOSE_WAIT)
		sk->sk_state = TCP_LAST_ACK;
	else
		return 0;
	return 1;
}

/* Like tcp_close */
static void sdp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;

	lock_sock(sk);

	sdp_dbg(sk, "%s\n", __func__);

	sk->sk_shutdown = SHUTDOWN_MASK;
	if (sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_SYN_SENT) {
		sdp_set_state(sk, TCP_CLOSE);

		/* Special case: stop listening.
		   This is done by sdp_destruct. */
		goto adjudge_to_death;
	}

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		data_was_unread = 1;
		__kfree_skb(skb);
	}

	sk_stream_mem_reclaim(sk);

	/* As outlined in draft-ietf-tcpimpl-prob-03.txt, section
	 * 3.10, we send a RST here because data was lost.  To
	 * witness the awful effects of the old behavior of always
	 * doing a FIN, run an older 2.1.x kernel or 2.0.x, start
	 * a bulk GET in an FTP client, suspend the process, wait
	 * for the client to advertise a zero window, then kill -9
	 * the FTP client, wheee...  Note: timeout is always zero
	 * in such a case.
	 */
	if (data_was_unread) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONCLOSE);
		sdp_set_state(sk, TCP_CLOSE);
		sdp_send_active_reset(sk, GFP_KERNEL);
	} else if (sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime) {
		/* Check zero linger _after_ checking for unread data. */
		sk->sk_prot->disconnect(sk, 0);
		NET_INC_STATS_USER(LINUX_MIB_TCPABORTONDATA);
	} else if (sdp_close_state(sk)) {
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		sdp_post_sends(sdp_sk(sk), 0);
	}

	/* TODO: state should move to CLOSE or CLOSE_WAIT etc on disconnect.
	   Since it currently doesn't, do it here to avoid blocking below. */
	if (!sdp_sk(sk)->id)
		sdp_set_state(sk, TCP_CLOSE);

	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);
	/* Now socket is owned by kernel and we acquire lock
	   to finish close. No need to check for user refs.
	 */
	lock_sock(sk);

	sock_hold(sk);
	sock_orphan(sk);

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */

	if (sk->sk_state == TCP_FIN_WAIT2 &&
		!sk->sk_send_head &&
		sdp_sk(sk)->tx_head == sdp_sk(sk)->tx_tail) {
		sk->sk_state = TCP_CLOSE;
	}

	if ((1 << sk->sk_state) & (TCPF_FIN_WAIT1 | TCPF_FIN_WAIT2)) {
		sdp_sk(sk)->time_wait = 1;
		/* TODO: liger2 unimplemented.
		   We should wait 3.5 * rto. How do I know rto? */
		/* TODO: tcp_fin_time to get timeout */
		sdp_dbg(sk, "%s: entering time wait refcnt %d\n", __func__,
			atomic_read(&sk->sk_refcnt));
		atomic_inc(sk->sk_prot->orphan_count);
		queue_delayed_work(sdp_workqueue, &sdp_sk(sk)->time_wait_work,
				   TCP_FIN_TIMEOUT);
		goto out;
	}

	/* TODO: limit number of orphaned sockets.
	   TCP has sysctl_tcp_mem and sysctl_tcp_max_orphans */
	sock_put(sk);

	/* Otherwise, socket is reprieved until protocol close. */
out:
	sdp_dbg(sk, "%s: last socket put %d\n", __func__,
		atomic_read(&sk->sk_refcnt));
	release_sock(sk);
	sk_common_release(sk);
}

static int sdp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sockaddr_in src_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(inet_sk(sk)->sport),
		.sin_addr.s_addr = inet_sk(sk)->saddr,
	};
	int rc;

        if (addr_len < sizeof(struct sockaddr_in))
                return -EINVAL;

        if (uaddr->sa_family != AF_INET)
                return -EAFNOSUPPORT;

	if (!ssk->id) {
		rc = sdp_get_port(sk, 0);
		if (rc)
			return rc;
		inet_sk(sk)->sport = htons(inet_sk(sk)->num);
	}

	sdp_dbg(sk, "%s %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n", __func__,
		NIPQUAD(src_addr.sin_addr.s_addr),
		ntohs(src_addr.sin_port),
		NIPQUAD(((struct sockaddr_in *)uaddr)->sin_addr.s_addr),
		ntohs(((struct sockaddr_in *)uaddr)->sin_port));

	if (!ssk->id) {
		printk("??? ssk->id == NULL. Ohh\n");
		return -EINVAL;
	}

	rc = rdma_resolve_addr(ssk->id, (struct sockaddr *)&src_addr,
			       uaddr, SDP_RESOLVE_TIMEOUT);
	if (rc) {
		sdp_warn(sk, "rdma_resolve_addr failed: %d\n", rc);
		return rc;
	}

	sk->sk_state = TCP_SYN_SENT;
	return 0;
}

static int sdp_disconnect(struct sock *sk, int flags)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int rc = 0;
	int old_state = sk->sk_state;
	struct sdp_sock *s, *t;
	struct rdma_cm_id *id;

	sdp_dbg(sk, "%s\n", __func__);
	if (ssk->id)
		rc = rdma_disconnect(ssk->id);

	if (old_state != TCP_LISTEN)
		return rc;

	sdp_set_state(sk, TCP_CLOSE);
	id = ssk->id;
	ssk->id = NULL;
	release_sock(sk); /* release socket since locking semantics is parent
			     inside child */
	rdma_destroy_id(id);

	list_for_each_entry_safe(s, t, &ssk->backlog_queue, backlog_queue) {
		sk_common_release(&s->isk.sk);
	}
	list_for_each_entry_safe(s, t, &ssk->accept_queue, accept_queue) {
		sk_common_release(&s->isk.sk);
	}

	lock_sock(sk);

	return 0;
}

/* Like inet_csk_wait_for_connect */
static int sdp_wait_for_connect(struct sock *sk, long timeo)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	DEFINE_WAIT(wait);
	int err;

	sdp_dbg(sk, "%s\n", __func__);
	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk->sk_sleep, &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (list_empty(&ssk->accept_queue)) {
			sdp_dbg(sk, "%s schedule_timeout\n", __func__);
			timeo = schedule_timeout(timeo);
			sdp_dbg(sk, "%s schedule_timeout done\n", __func__);
		}
		sdp_dbg(sk, "%s lock_sock\n", __func__);
		lock_sock(sk);
		sdp_dbg(sk, "%s lock_sock done\n", __func__);
		err = 0;
		if (!list_empty(&ssk->accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk->sk_sleep, &wait);
	sdp_dbg(sk, "%s returns %d\n", __func__, err);
	return err;
}

/* Consider using request_sock_queue instead of duplicating all this */
/* Like inet_csk_accept */
static struct sock *sdp_accept(struct sock *sk, int flags, int *err)
{
	struct sdp_sock *newssk, *ssk;
	struct sock *newsk;
	int error;

	sdp_dbg(sk, "%s state %d expected %d *err %d\n", __func__,
		sk->sk_state, TCP_LISTEN, *err);

	ssk = sdp_sk(sk);
	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	if (list_empty(&ssk->accept_queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = sdp_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}

	newssk = list_entry(ssk->accept_queue.next, struct sdp_sock, accept_queue);
	list_del_init(&newssk->accept_queue);
	newssk->parent = NULL;
	sk_acceptq_removed(sk);
	newsk = &newssk->isk.sk;
out:
	release_sock(sk);
	if (newsk) {
		lock_sock(newsk);
		if (newssk->cq) {
			sdp_dbg(newsk, "%s: ib_req_notify_cq\n", __func__);
			newssk->poll_cq = 1;
			ib_req_notify_cq(newssk->cq, IB_CQ_NEXT_COMP);
			sdp_poll_cq(newssk, newssk->cq);
		}
		release_sock(newsk);
	}
	sdp_dbg(sk, "%s: status %d sk %p newsk %p\n", __func__,
		*err, sk, newsk);
	return newsk;
out_err:
	sdp_dbg(sk, "%s: error %d\n", __func__, error);
	newsk = NULL;
	*err = error;
	goto out;
}

/* Like tcp_ioctl */
static int sdp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int answ;

	sdp_dbg(sk, "%s\n", __func__);

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !ssk->urg_data ||
			 before(ssk->urg_seq, ssk->copied_seq) ||
			 !before(ssk->urg_seq, ssk->rcv_nxt)) {
			answ = ssk->rcv_nxt - ssk->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			if (answ && !skb_queue_empty(&sk->sk_receive_queue))
				answ -=
		        ((struct sk_buff *)sk->sk_receive_queue.prev)->h.raw[0]
		        == SDP_MID_DISCONN ? 1 : 0;
		} else
			answ = ssk->urg_seq - ssk->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:
		answ = ssk->urg_data && ssk->urg_seq == ssk->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = ssk->write_seq - ssk->snd_una;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	/* TODO: Need to handle:
	   case SIOCOUTQ:
	 */
	return put_user(answ, (int __user *)arg); 
}

void sdp_destroy_work(void *_work)
{
	struct sdp_sock *ssk = container_of(_work, struct sdp_sock, destroy_work);
	struct sock *sk = &ssk->isk.sk;
	sdp_dbg(sk, "%s: refcnt %d\n", __func__, atomic_read(&sk->sk_refcnt));

	cancel_delayed_work(&sdp_sk(sk)->time_wait_work);
	atomic_dec(sk->sk_prot->orphan_count);

	sock_put(sk);
}

void sdp_time_wait_work(void *_work)
{
	struct sdp_sock *ssk = container_of(_work, struct sdp_sock, time_wait_work);
	struct sock *sk = &ssk->isk.sk;
	lock_sock(sk);
	sdp_dbg(sk, "%s\n", __func__);

	if (!sdp_sk(sk)->time_wait) {
		release_sock(sk);
		return;
	}

	sdp_dbg(sk, "%s: refcnt %d\n", __func__, atomic_read(&sk->sk_refcnt));

	sk->sk_state = TCP_CLOSE;
	sdp_sk(sk)->time_wait = 0;
	release_sock(sk);

	atomic_dec(sk->sk_prot->orphan_count);
	sock_put(sk);
}

void sdp_time_wait_destroy_sk(struct sdp_sock *ssk)
{
	ssk->time_wait = 0;
	ssk->isk.sk.sk_state = TCP_CLOSE;
	queue_work(sdp_workqueue, &ssk->destroy_work);
}

static int sdp_init_sock(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	INIT_LIST_HEAD(&ssk->accept_queue);
	INIT_LIST_HEAD(&ssk->backlog_queue);
	INIT_WORK(&ssk->time_wait_work, sdp_time_wait_work, &ssk->time_wait_work);
	INIT_WORK(&ssk->destroy_work, sdp_destroy_work, &ssk->destroy_work);

	sk->sk_route_caps |= NETIF_F_SG | NETIF_F_NO_CSUM;
	return 0;
}

static void sdp_shutdown(struct sock *sk, int how)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);
	if (!(how & SEND_SHUTDOWN))
		return;

	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		return;

	if (sk->sk_state == TCP_ESTABLISHED)
		sk->sk_state = TCP_FIN_WAIT1;
	else if (sk->sk_state == TCP_CLOSE_WAIT)
		sk->sk_state = TCP_LAST_ACK;
	else
		return;

	sdp_post_sends(ssk, 0);
}

static void sdp_mark_push(struct sdp_sock *ssk, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
	ssk->pushed_seq = ssk->write_seq;
	sdp_post_sends(ssk, 0);
}

static inline void sdp_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb = sk->sk_send_head;
	if (skb) {
		sdp_mark_push(sdp_sk(sk), skb);
		sdp_post_sends(sdp_sk(sk), 0);
	}
}

/* SOL_SOCKET level options are handled by sock_setsockopt */
static int sdp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int val;
	int err = 0;

	sdp_dbg(sk, "%s\n", __func__);
	if (level != SOL_TCP)
		return -ENOPROTOOPT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TCP_NODELAY:
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			ssk->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			sdp_push_pending_frames(sk);
		} else {
			ssk->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;
	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			ssk->nonagle |= TCP_NAGLE_CORK;
		} else {
			ssk->nonagle &= ~TCP_NAGLE_CORK;
			if (ssk->nonagle&TCP_NAGLE_OFF)
				ssk->nonagle |= TCP_NAGLE_PUSH;
			sdp_push_pending_frames(sk);
		}
		break;
	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

/* SOL_SOCKET level options are handled by sock_getsockopt */
static int sdp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *option)
{
	/* TODO */
	struct sdp_sock *ssk = sdp_sk(sk);
	int val, len;

	sdp_dbg(sk, "%s\n", __func__);

	if (level != SOL_TCP)
		return -EOPNOTSUPP;

	if (get_user(len, option))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_NODELAY:
		val = !!(ssk->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(ssk->nonagle&TCP_NAGLE_CORK);
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, option))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

static inline int poll_recv_cq(struct sock *sk)
{
	int i;
	if (sdp_sk(sk)->cq) {
		for (i = 0; i < recv_poll; ++i)
			if (!sdp_poll_cq(sdp_sk(sk), sdp_sk(sk)->cq)) {
				++recv_poll_hit;
				return 0;
			}
		++recv_poll_miss;
	}
	return 1;
}

static inline void poll_send_cq(struct sock *sk)
{
	int i;
	if (sdp_sk(sk)->cq) {
		for (i = 0; i < send_poll; ++i)
			if (!sdp_poll_cq(sdp_sk(sk), sdp_sk(sk)->cq)) {
				++send_poll_hit;
				return;
			}
		++send_poll_miss;
	}
}

/* Like tcp_recv_urg */
/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int sdp_recv_urg(struct sock *sk, long timeo,
			struct msghdr *msg, int len, int flags,
			int *addr_len)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	poll_recv_cq(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !ssk->urg_data ||
	    ssk->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (ssk->urg_data & TCP_URG_VALID) {
		int err = 0;
		char c = ssk->urg_data;

		if (!(flags & MSG_PEEK))
			ssk->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

static void sdp_rcv_space_adjust(struct sock *sk)
{
	sdp_post_recvs(sdp_sk(sk));
	sdp_post_sends(sdp_sk(sk), 0);
}

static unsigned int sdp_current_mss(struct sock *sk, int large_allowed)
{
	/* TODO */
	return PAGE_SIZE;
}

static int forced_push(struct sdp_sock *sk)
{
	/* TODO */
	return 0;
}

static inline int select_size(struct sock *sk, struct sdp_sock *ssk)
{
	return 0;
}

static inline void sdp_mark_urg(struct sock *sk, struct sdp_sock *ssk, int flags)
{
	if (unlikely(flags & MSG_OOB)) {
		struct sk_buff *skb = sk->sk_write_queue.prev;
		TCP_SKB_CB(skb)->flags |= TCPCB_URG;
	}
}

static inline void sdp_push(struct sock *sk, struct sdp_sock *ssk, int flags,
			    int mss_now, int nonagle)
{
	if (sk->sk_send_head)
		sdp_mark_urg(sk, ssk, flags);
	sdp_post_sends(ssk, nonagle);
}

static inline void skb_entail(struct sock *sk, struct sdp_sock *ssk,
                              struct sk_buff *skb)
{
        skb_header_release(skb);
        __skb_queue_tail(&sk->sk_write_queue, skb);
        sk_charge_skb(sk, skb);
        if (!sk->sk_send_head)
                sk->sk_send_head = skb;
        if (ssk->nonagle & TCP_NAGLE_PUSH)
                ssk->nonagle &= ~TCP_NAGLE_PUSH;
}

void sdp_push_one(struct sock *sk, unsigned int mss_now)
{
}

/* Like tcp_sendmsg */
/* TODO: check locking */
#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)
int sdp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t size)
{
	struct iovec *iov;
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now, size_goal;
	int err, copied;
	long timeo;

	lock_sock(sk);
	sdp_dbg_data(sk, "%s\n", __func__);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = sdp_current_mss(sk, !(flags&MSG_OOB));
	size_goal = ssk->xmit_size_goal;

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (--iovlen >= 0) {
		int seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;

		while (seglen > 0) {
			int copy;

			skb = sk->sk_write_queue.prev;

			if (!sk->sk_send_head ||
			    (copy = size_goal - skb->len) <= 0) {

new_segment:
				/* Allocate new segment. If the interface is SG,
				 * allocate skb fitting to single page.
				 */
				if (!sk_stream_memory_free(sk))
					goto wait_for_sndbuf;

				skb = sk_stream_alloc_pskb(sk, select_size(sk, ssk),
							   0, sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps &
				    (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM |
				     NETIF_F_HW_CSUM))
					skb->ip_summed = CHECKSUM_HW;

				skb_entail(sk, ssk, skb);
				copy = size_goal;
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* OOB data byte should be the last byte of
			   the data payload */
			if (unlikely(TCP_SKB_CB(skb)->flags & TCPCB_URG) &&
			    !(flags & MSG_OOB)) {
				sdp_mark_push(ssk, skb);
				goto new_segment;
			}
			/* Where to copy to? */
			if (skb_tailroom(skb) > 0) {
				/* We have some space in skb head. Superb! */
				if (copy > skb_tailroom(skb))
					copy = skb_tailroom(skb);
				if ((err = skb_add_data(skb, from, copy)) != 0)
					goto do_fault;
			} else {
				int merge = 0;
				int i = skb_shinfo(skb)->nr_frags;
				struct page *page = TCP_PAGE(sk);
				int off = TCP_OFF(sk);

				if (skb_can_coalesce(skb, i, page, off) &&
				    off != PAGE_SIZE) {
					/* We can extend the last page
					 * fragment. */
					merge = 1;
				} else if (i == ssk->send_frags ||
					   (!i &&
					   !(sk->sk_route_caps & NETIF_F_SG))) {
					/* Need to add new fragment and cannot
					 * do this because interface is non-SG,
					 * or because all the page slots are
					 * busy. */
					sdp_mark_push(ssk, skb);
					goto new_segment;
				} else if (page) {
					if (off == PAGE_SIZE) {
						put_page(page);
						TCP_PAGE(sk) = page = NULL;
						off = 0;
					}
				} else
					off = 0;

				if (copy > PAGE_SIZE - off)
					copy = PAGE_SIZE - off;

				if (!sk_stream_wmem_schedule(sk, copy))
					goto wait_for_memory;

				if (!page) {
					/* Allocate new cache page. */
					if (!(page = sk_stream_alloc_page(sk)))
						goto wait_for_memory;
				}

				/* Time to copy data. We are close to
				 * the end! */
				err = skb_copy_to_page(sk, from, skb, page,
						       off, copy);
				if (err) {
					/* If this page was new, give it to the
					 * socket so it does not get leaked.
					 */
					if (!TCP_PAGE(sk)) {
						TCP_PAGE(sk) = page;
						TCP_OFF(sk) = 0;
					}
					goto do_error;
				}

				/* Update the skb. */
				if (merge) {
					skb_shinfo(skb)->frags[i - 1].size +=
									copy;
				} else {
					skb_fill_page_desc(skb, i, page, off, copy);
					if (TCP_PAGE(sk)) {
						get_page(page);
					} else if (off + copy < PAGE_SIZE) {
						get_page(page);
						TCP_PAGE(sk) = page;
					}
				}

				TCP_OFF(sk) = off + copy;
			}

			if (!copied)
				TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

			ssk->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			/*unused: skb_shinfo(skb)->gso_segs = 0;*/

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < mss_now || (flags & MSG_OOB))
				continue;

			if (forced_push(ssk)) {
				sdp_mark_push(ssk, skb);
				/* TODO: and push pending frames mss_now */
				/* sdp_push_pending(sk, ssk, mss_now, TCP_NAGLE_PUSH); */
			} else if (skb == sk->sk_send_head)
				sdp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				sdp_push(sk, ssk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

			if ((err = sk_stream_wait_memory(sk, &timeo)) != 0)
				goto do_error;

			mss_now = sdp_current_mss(sk, !(flags&MSG_OOB));
			size_goal = ssk->xmit_size_goal;
		}
	}

out:
	if (copied)
		sdp_push(sk, ssk, flags, mss_now, ssk->nonagle);
	if (size > send_poll_thresh)
		poll_send_cq(sk);
	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		if (sk->sk_send_head == skb)
			sk->sk_send_head = NULL;
		__skb_unlink(skb, &sk->sk_write_queue);
		sk_stream_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}

/* Like tcp_recvmsg */
/* Maybe use skb_recv_datagram here? */
/* Note this does not seem to handle vectored messages. Relevant? */
static int sdp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len, int noblock, int flags, 
		       int *addr_len)
{
	struct sk_buff *skb = NULL;
	struct sdp_sock *ssk = sdp_sk(sk);
	long timeo;
	int target;
	unsigned long used;
	int err;
	u32 peek_seq;
	u32 *seq;
	int copied = 0;
	int rc;

	lock_sock(sk);
	sdp_dbg_data(sk, "%s\n", __func__);

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, noblock);
	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &ssk->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = ssk->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (ssk->urg_data && ssk->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		skb = skb_peek(&sk->sk_receive_queue);
		do {
			if (!skb)
				break;

			if (skb->h.raw[0] == SDP_MID_DISCONN)
				goto found_fin_ok;

			if (before(*seq, TCP_SKB_CB(skb)->seq)) {
				printk(KERN_INFO "recvmsg bug: copied %X "
				       "seq %X\n", *seq, TCP_SKB_CB(skb)->seq);
				break;
			}

			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (offset < skb->len)
				goto found_ok_skb;

			BUG_TRAP(flags & MSG_PEEK);
			skb = skb->next;
		} while (skb != (struct sk_buff *)&sk->sk_receive_queue);

		if (copied >= target)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current) ||
			    (flags & MSG_PEEK))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		rc = poll_recv_cq(sk);

		if (copied >= target && !recv_poll) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else if (rc) {
			sdp_dbg_data(sk, "%s: sk_wait_data %ld\n", __func__, timeo);
			sk_wait_data(sk, &timeo);
		}
		continue;

	found_ok_skb:
		sdp_dbg_data(sk, "%s: found_ok_skb len %d\n", __func__, skb->len);
		sdp_dbg_data(sk, "%s: len %Zd offset %d\n", __func__, len, offset);
		sdp_dbg_data(sk, "%s: copied %d target %d\n", __func__, copied, target);
		used = skb->len - offset;
		if (len < used)
			used = len;

		sdp_dbg_data(sk, "%s: used %ld\n", __func__, used);

		if (ssk->urg_data) {
			u32 urg_offset = ssk->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}
		if (!(flags & MSG_TRUNC)) {
			int err;
			err = skb_copy_datagram_iovec(skb, offset,
						      /* TODO: skip header? */
						      msg->msg_iov, used);
			if (err) {
				sdp_dbg(sk, "%s: skb_copy_datagram_iovec failed"
					"offset %d size %ld status %d\n",
					__func__, offset, used, err);
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		copied += used;
		len -= used;
		*seq += used;

		sdp_dbg_data(sk, "%s: done copied %d target %d\n", __func__, copied, target);

		sdp_rcv_space_adjust(sk);
skip_copy:
		if (ssk->urg_data && after(ssk->copied_seq, ssk->urg_seq))
			ssk->urg_data = 0;
		if (used + offset < skb->len)
			continue;
		offset = 0;

		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb, 0);

		continue;
found_fin_ok:
		++*seq;
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb, 0);

		break;
	} while (len > 0);

	release_sock(sk);
	return copied;

out:
	release_sock(sk);
	return err;

recv_urg:
	err = sdp_recv_urg(sk, timeo, msg, len, flags, addr_len);
	goto out;
}

static int sdp_listen(struct sock *sk, int backlog)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int rc;

	sdp_dbg(sk, "%s\n", __func__);

	if (!ssk->id) {
		rc = sdp_get_port(sk, 0);
		if (rc)
			return rc;
		inet_sk(sk)->sport = htons(inet_sk(sk)->num);
	}

	rc = rdma_listen(ssk->id, backlog);
	if (rc) {
		sdp_warn(sk, "rdma_listen failed: %d\n", rc);
		sdp_set_error(sk, rc);
	} else
		sk->sk_state = TCP_LISTEN;
	return rc;
}

/* We almost could use inet_listen, but that calls
   inet_csk_listen_start. Longer term we'll want to add
   a listen callback to struct proto, similiar to bind. */
int sdp_inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		err = sdp_listen(sk, backlog);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static void sdp_unhash(struct sock *sk)
{
        sdp_dbg(sk, "%s\n", __func__);
}

static inline unsigned int sdp_listen_poll(const struct sock *sk)
{
	        return !list_empty(&sdp_sk(sk)->accept_queue) ?
			(POLLIN | POLLRDNORM) : 0;
}

static unsigned int sdp_poll(struct file *file, struct socket *socket,
			     struct poll_table_struct *wait)
{
	int mask;
	sdp_dbg_data(socket->sk, "%s\n", __func__);

	mask = datagram_poll(file, socket, wait);
	/* TODO: Slightly ugly: it would be nicer if there was function
	 * like datagram_poll that didn't include poll_wait,
	 * then we could reverse the order. */
	if (socket->sk->sk_state == TCP_LISTEN)
		return sdp_listen_poll(socket->sk);

	if (sdp_sk(socket->sk)->urg_data & TCP_URG_VALID)
		mask |= POLLPRI;
	return mask;
}

static void sdp_enter_memory_pressure(void)
{
	sdp_dbg(NULL, "%s\n", __func__);
}

void sdp_urg(struct sdp_sock *ssk, struct sk_buff *skb)
{
	struct sock *sk = &ssk->isk.sk;
	u8 tmp;
	u32 ptr = skb->len - 1;

	ssk->urg_seq = TCP_SKB_CB(skb)->seq + ptr;

	if (skb_copy_bits(skb, ptr, &tmp, 1))
		BUG();
	ssk->urg_data = TCP_URG_VALID | tmp;
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);
}

static atomic_t sockets_allocated;
static atomic_t memory_allocated;
static atomic_t orphan_count;
static int memory_pressure;
struct proto sdp_proto = {
        .close       = sdp_close,
        .connect     = sdp_connect,
        .disconnect  = sdp_disconnect,
        .accept      = sdp_accept,
        .ioctl       = sdp_ioctl,
        .init        = sdp_init_sock,
        .shutdown    = sdp_shutdown,
        .setsockopt  = sdp_setsockopt,
        .getsockopt  = sdp_getsockopt,
        .sendmsg     = sdp_sendmsg,
        .recvmsg     = sdp_recvmsg,
	.unhash      = sdp_unhash,
        .get_port    = sdp_get_port,
	/* Wish we had this: .listen   = sdp_listen */
	.enter_memory_pressure = sdp_enter_memory_pressure,
	.sockets_allocated = &sockets_allocated,
	.memory_allocated = &memory_allocated,
	.memory_pressure = &memory_pressure,
	.orphan_count = &orphan_count,
        .sysctl_mem             = sysctl_tcp_mem,
        .sysctl_wmem            = sysctl_tcp_wmem,
        .sysctl_rmem            = sysctl_tcp_rmem,
	.max_header  = sizeof(struct sdp_bsdh),
        .obj_size    = sizeof(struct sdp_sock),
	.owner	     = THIS_MODULE,
	.name	     = "SDP",
};

static struct proto_ops sdp_proto_ops = {
	.family     = PF_INET,
	.owner      = THIS_MODULE,
	.release    = inet_release,
	.bind       = inet_bind,
	.connect    = inet_stream_connect, /* TODO: inet_datagram connect would
					      autobind, but need to fix get_port
					      with port 0 first. */
	.socketpair = sock_no_socketpair,
	.accept     = inet_accept,
	.getname    = inet_getname,
	.poll       = sdp_poll,
	.ioctl      = inet_ioctl,
	.listen     = sdp_inet_listen,
	.shutdown   = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg    = inet_sendmsg,
	.recvmsg    = sock_common_recvmsg,
	.mmap       = sock_no_mmap,
	.sendpage   = sock_no_sendpage,
};

static int sdp_create_socket(struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;

	sdp_dbg(NULL, "%s: type %d protocol %d\n", __func__, sock->type, protocol);

	if (sock->type != SOCK_STREAM) {
		sdp_warn(NULL, "SDP: unsupported type %d.\n", sock->type);
		return -ESOCKTNOSUPPORT;
	}

	/* IPPROTO_IP is a wildcard match */
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_IP) {
		sdp_warn(NULL, "SDP: unsupported protocol %d.\n", protocol);
		return -EPROTONOSUPPORT;
	}

	sk = sk_alloc(PF_INET_SDP, GFP_KERNEL, &sdp_proto, 1);
	if (!sk) {
		sdp_warn(NULL, "SDP: failed to allocate socket.\n");
		return -ENOMEM;
	}
	sock_init_data(sock, sk);
	sk->sk_protocol = 0x0 /* TODO: inherit tcp socket to use IPPROTO_TCP */;

	rc = sdp_init_sock(sk);
	if (rc) {
		sdp_warn(sk, "SDP: failed to init sock.\n");
		sk_common_release(sk);
		return -ENOMEM;
	}

	sk->sk_destruct = sdp_destruct;

	sock->ops = &sdp_proto_ops;
	sock->state = SS_UNCONNECTED;

	sdp_add_sock(sdp_sk(sk));

	return 0;
}

#ifdef CONFIG_PROC_FS

static void *sdp_get_idx(struct seq_file *seq, loff_t pos)
{
	int i = 0;
	struct sdp_sock *ssk;

	if (!list_empty(&sock_list))
		list_for_each_entry(ssk, &sock_list, sock_list) {
			if (i == pos)
				return ssk;
			i++;
		}

	return NULL;
}

static void *sdp_seq_start(struct seq_file *seq, loff_t *pos)
{
	void *start = NULL;
	struct sdp_iter_state* st = seq->private;

	st->num = 0;

	if (!*pos)
		return SEQ_START_TOKEN;

	spin_lock_irq(&sock_list_lock);
	start = sdp_get_idx(seq, *pos - 1);
	if (start)
		sock_hold((struct sock *)start);
	spin_unlock_irq(&sock_list_lock);

	return start;
}

static void *sdp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sdp_iter_state* st = seq->private;
	void *next = NULL;

	spin_lock_irq(&sock_list_lock);
	if (v == SEQ_START_TOKEN)
		next = sdp_get_idx(seq, 0);
	else
		next = sdp_get_idx(seq, *pos);
	if (next)
		sock_hold((struct sock *)next);
	spin_unlock_irq(&sock_list_lock);

	*pos += 1;
	st->num++;

	return next;
}

static void sdp_seq_stop(struct seq_file *seq, void *v)
{
}

#define TMPSZ 150

static int sdp_seq_show(struct seq_file *seq, void *v)
{
	struct sdp_iter_state* st;
	struct sock *sk = v;
	char tmpbuf[TMPSZ + 1];
	unsigned int dest;
	unsigned int src;
	int uid;
	unsigned long inode;
	__u16 destp;
	__u16 srcp;
	__u32 rx_queue, tx_queue;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
				"  sl  local_address rem_address        uid inode"
				"   rx_queue tx_queue");
		goto out;
	}

	st = seq->private;

	dest = inet_sk(sk)->daddr;
	src = inet_sk(sk)->rcv_saddr;
	destp = ntohs(inet_sk(sk)->dport);
	srcp = ntohs(inet_sk(sk)->sport);
	uid = sock_i_uid(sk);
	inode = sock_i_ino(sk);
	rx_queue = sdp_sk(sk)->rcv_nxt - sdp_sk(sk)->copied_seq;
	tx_queue = sdp_sk(sk)->write_seq - sdp_sk(sk)->snd_una;

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X %5d %lu	%08X:%08X",
		st->num, src, srcp, dest, destp, uid, inode,
		rx_queue, tx_queue);

	seq_printf(seq, "%-*s\n", TMPSZ - 1, tmpbuf);

	sock_put(sk);
out:
	return 0;
}

static int sdp_seq_open(struct inode *inode, struct file *file)
{
	struct sdp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	struct sdp_iter_state *s;
	int rc;

	if (unlikely(afinfo == NULL))
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->family               = afinfo->family;
	s->seq_ops.start        = sdp_seq_start;
	s->seq_ops.next         = sdp_seq_next;
	s->seq_ops.show         = afinfo->seq_show;
	s->seq_ops.stop         = sdp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;
	seq          = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}


static struct file_operations sdp_seq_fops;
static struct sdp_seq_afinfo sdp_seq_afinfo = {
	.owner          = THIS_MODULE,
	.name           = "sdp",
	.family         = AF_INET_SDP,
	.seq_show       = sdp_seq_show,
	.seq_fops       = &sdp_seq_fops,
};


static int __init sdp_proc_init(void)
{
	int rc = 0;
	struct proc_dir_entry *p;

	sdp_seq_afinfo.seq_fops->owner         = sdp_seq_afinfo.owner;
	sdp_seq_afinfo.seq_fops->open          = sdp_seq_open;
	sdp_seq_afinfo.seq_fops->read          = seq_read;
	sdp_seq_afinfo.seq_fops->llseek        = seq_lseek;
	sdp_seq_afinfo.seq_fops->release       = seq_release_private;

	p = proc_net_fops_create(sdp_seq_afinfo.name, S_IRUGO, sdp_seq_afinfo.seq_fops);
	if (p)
		p->data = &sdp_seq_afinfo;
	p = proc_net_fops_create(sdp_seq_afinfo.name, S_IRUGO, sdp_seq_afinfo.seq_fops);
	if (p)
		p->data = &sdp_seq_afinfo;
	else
		rc = -ENOMEM;

	return rc;
}

static void sdp_proc_unregister(void)
{
	proc_net_remove(sdp_seq_afinfo.name);
	memset(sdp_seq_afinfo.seq_fops, 0, sizeof(*sdp_seq_afinfo.seq_fops));
}

#else /* CONFIG_PROC_FS */

static int __init sdp_proc_init(void)
{
	return 0;
}

static void sdp_proc_unregister(void)
{

}
#endif /* CONFIG_PROC_FS */

static void sdp_add_device(struct ib_device *device)
{
}

static void sdp_remove_device(struct ib_device *device)
{
	write_lock(&device_removal_lock);
	write_unlock(&device_removal_lock);
}

static struct net_proto_family sdp_net_proto = {
	.family = AF_INET_SDP,
	.create = sdp_create_socket,
	.owner  = THIS_MODULE,
};

struct ib_client sdp_client = {
	.name   = "sdp",
	.add    = sdp_add_device,
	.remove = sdp_remove_device
};

static int __init sdp_init(void)
{
	int rc;

	INIT_LIST_HEAD(&sock_list);
	spin_lock_init(&sock_list_lock);
	spin_lock_init(&sdp_large_sockets_lock);

	sdp_workqueue = create_singlethread_workqueue("sdp");
	if (!sdp_workqueue) {
		return -ENOMEM;
	}

	rc = proto_register(&sdp_proto, 1);
	if (rc) {
		printk(KERN_WARNING "%s: proto_register failed: %d\n", __func__, rc);
		destroy_workqueue(sdp_workqueue);
		return rc;
	}

	rc = sock_register(&sdp_net_proto);
	if (rc) {
		printk(KERN_WARNING "%s: sock_register failed: %d\n", __func__, rc);
		proto_unregister(&sdp_proto);
		destroy_workqueue(sdp_workqueue);
		return rc;
	}

	sdp_proc_init();

	atomic_set(&sdp_current_mem_usage, 0);

	ib_register_client(&sdp_client);

	return 0;
}

static void __exit sdp_exit(void)
{
	sock_unregister(PF_INET_SDP);
	proto_unregister(&sdp_proto);

	if (atomic_read(&orphan_count))
		printk(KERN_WARNING "%s: orphan_count %d\n", __func__,
		       atomic_read(&orphan_count));
	destroy_workqueue(sdp_workqueue);
	flush_scheduled_work();

	BUG_ON(!list_empty(&sock_list));

	if (atomic_read(&sdp_current_mem_usage))
		printk(KERN_WARNING "%s: current mem usage %d\n", __func__,
		       atomic_read(&sdp_current_mem_usage));

	sdp_proc_unregister();

	ib_unregister_client(&sdp_client);
}

module_init(sdp_init);
module_exit(sdp_exit);
