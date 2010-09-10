/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * Cleaned up logger output for Alpha.
 * -- Phil Ezolt (Phillip.Ezolt@compaq.com) & Bill Carr (wcarr92@yahoo.com)
 *
 * logger.c: log requests finished by TUX.
 */

#define __KERNEL_SYSCALLS__
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

static DEFINE_SPINLOCK(log_lock);
static unsigned int log_head, log_tail;
static char * log_buffer = NULL;
static DECLARE_WAIT_QUEUE_HEAD(log_wait);
static DECLARE_WAIT_QUEUE_HEAD(log_full);
static int logger_pid = 0;

/*
 * High-speed TUX logging architecture:
 *
 * All fast threads share a common log-ringbuffer. (default size 1MB)
 * Log entries are binary and are padded to be cacheline aligned, this
 * ensures that there is no cache-pingpong between fast threads.
 *
 * The logger thread writes out pending log entries within 1 second
 * (buffer-cache writes data out within 5 seconds). The logger thread
 * gets activated once we have more than 25% of the log ringbuffer
 * filled - or the 1 second log timeout expires. Fast threads block
 * if if more than 95% of the ringbuffer is filled and unblock only
 * if used logbuffer space drops below 90%.
 *
 * This architecture guarantees that 1) logging is reliable (no
 * log entry is ever lost), 2) timely (touches disk within 6 seconds),
 * 3) in the log-contention case the saturation behavior is still
 * write-clustered, but 4) if the logger thread can keep up then
 * the coupling is completely asynchron and parallel.
 *
 * The binary log format gives us about 50% saved IO/memory bandwith
 * and 50% less on-disk used log space than the traditional W3C ASCII
 * format.
 *
 * (We might switch to raw IO though to write the logfile.)
 */

#define SOFT_LIMIT		(LOG_LEN*25/100)
#define HARD_LIMIT		(LOG_LEN*95/100)
#define HARD_RELAX_LIMIT	(LOG_LEN*90/100)

unsigned int tux_logentry_align_order = 5;

#if SMP_CACHE_BYTES == 8
# define TUX_LOGENTRY_ALIGN 3
#else
#if SMP_CACHE_BYTES == 16
# define TUX_LOGENTRY_ALIGN 4
#else
#if SMP_CACHE_BYTES == 32
# define TUX_LOGENTRY_ALIGN 5
#else
#if SMP_CACHE_BYTES == 64
# define TUX_LOGENTRY_ALIGN 6
#else
#if SMP_CACHE_BYTES == 128
# define TUX_LOGENTRY_ALIGN 7
#else
#if SMP_CACHE_BYTES == 256
# define TUX_LOGENTRY_ALIGN 8
#else
#error Add entry!
#endif
#endif
#endif
#endif
#endif
#endif

#define ROUND_UP(x) (((((x)-1) >> TUX_LOGENTRY_ALIGN) + 1) \
					<< TUX_LOGENTRY_ALIGN)

static void __throttle_logging (void)
{
	DECLARE_WAITQUEUE(wait, current);
	int pending;

	add_wait_queue(&log_full, &wait);
	for (;;) {
		static unsigned long last_warning = 0;

		if (jiffies - last_warning > 10*HZ) {
			last_warning = jiffies;
			printk(KERN_NOTICE "TUX: log buffer overflow, have to throttle TUX thread!\n");
		}

		current->state = TASK_INTERRUPTIBLE;

		spin_lock(&log_lock);
		pending = log_head-log_tail;
		spin_unlock(&log_lock);

		if ((pending % LOG_LEN) < HARD_LIMIT)
			break;

		schedule();
	}
	current->state = TASK_RUNNING;
	remove_wait_queue(&log_full, &wait);
}

#ifdef CONFIG_TUX_DEBUG
#define CHECK_LOGPTR(ptr) \
do { \
	if ((ptr < log_buffer) || (ptr > log_buffer + LOG_LEN)) { \
		printk(KERN_ERR "TUX: ouch: log ptr %p > %p + %ld!\n", \
			ptr, log_buffer, LOG_LEN); \
		TUX_BUG(); \
	} \
} while (0)
#else
#define CHECK_LOGPTR(ptr) do { } while (0)
#endif

void __log_request (tux_req_t *req)
{
	char *str, *next;
	const char *uri_str;
	unsigned int inc, len, uri_len, pending, next_head, def_vhost_len = 0;
	unsigned long flags;

	if (req->proto->pre_log)
		req->proto->pre_log(req);
	/*
	 * Log the reply status (success, or type of failure)
	 */
	if (!tux_log_incomplete && (!req->status || (req->bytes_sent == -1))) {

		Dprintk("not logging req %p: {%s} [%d/%d]\n", req, req->uri_str, req->status, req->bytes_sent);
		return;
	}
	Dprintk("uri: {%s} [%d]\n", req->uri_str, req->uri_len);

#define NO_URI "<none>"
	if (req->uri_len) {
		uri_len = req->uri_len;
		uri_str = req->uri_str;
	} else {
		uri_str = NO_URI;
		uri_len = sizeof(NO_URI)-1;
	}
	len = uri_len + 1;

	if (req->virtual) {
		if (req->host_len)
			len += req->host_len;
		else {
			def_vhost_len = strlen(tux_default_vhost);
			len += def_vhost_len;
		}
	}

	Dprintk("method_str: {%s} [%d]\n", req->method_str, req->method_len);
	len += req->method_len + 1;

	Dprintk("version_str: {%s} [%d]\n", req->version_str, req->version_len);
	len += req->version_len + 1;

#ifdef CONFIG_TUX_EXTENDED_LOG
	Dprintk("user_agent_str: {%s} [%d]\n", req->user_agent_str, req->user_agent_len);
	len += req->user_agent_len + 1;
#endif
	if (tux_referer_logging) {
		Dprintk("referer_str: {%s} [%d]\n", req->referer_str, req->referer_len);
		len += req->referer_len;
	}
	len++;

	inc = 5*sizeof(u32) + len;
#ifdef CONFIG_TUX_EXTENDED_LOG
	inc += 7*sizeof(u32);
#endif

	spin_lock_irqsave(&log_lock, flags);

	next_head = ROUND_UP(log_head + inc);

	if (next_head < LOG_LEN) {
		str = log_buffer + log_head;
		if (str > log_buffer + LOG_LEN)
			TUX_BUG();
		log_head = next_head;
	} else {
		if (log_head < LOG_LEN)
			memset(log_buffer+log_head, 0, LOG_LEN-log_head);
		str = log_buffer;
		log_head = ROUND_UP(inc);
	}

	if (str < log_buffer || str+inc >= log_buffer+LOG_LEN)
		TUX_BUG();

	/*
	 * Log record signature - this makes finding the next entry
	 * easier (since record length is variable), and makes the
	 * binary logfile more robust against potential data corruption
	 * and other damage. The signature also servers as a log format
	 * version identifier.
	 */
#ifdef CONFIG_TUX_EXTENDED_LOG
	*(u32 *)str = 0x2223beef;
#else
	*(u32 *)str = 0x1112beef;
#endif
	str += sizeof(u32);
	CHECK_LOGPTR(str);

	*(u32 *)str = 0;
	/*
	 * Log the client IP address:
	 */
	if (tux_ip_logging)
		*(u32 *)str = req->client_addr;
	str += sizeof(u32);
	CHECK_LOGPTR(str);

#ifdef CONFIG_TUX_EXTENDED_LOG
	/*
	 * Log the client port number:
	 */
	*(u32 *)str = 0;
	if (tux_ip_logging)
		*(u32 *)str = req->client_port;
	str += sizeof(u32);
	CHECK_LOGPTR(str);
#endif

	/*
	 * Log the request timestamp, in units of 'seconds since 1970'.
	 */
	*(u32 *)str = CURRENT_TIME.tv_sec;
	str += sizeof(u32);
	CHECK_LOGPTR(str);

#ifdef CONFIG_TUX_EXTENDED_LOG
	*(u32 *)str = req->accept_timestamp; str += sizeof(u32);
	*(u32 *)str = req->parse_timestamp; str += sizeof(u32);
	*(u32 *)str = req->output_timestamp; str += sizeof(u32);
	*(u32 *)str = req->flush_timestamp; str += sizeof(u32);
	*(u32 *)str = req->had_cachemiss; str += sizeof(u32);
	*(u32 *)str = req->keep_alive; str += sizeof(u32);
#endif
	/*
	 * Log the requested file size (in fact, log actual bytes sent.)
	 */
	*(u32 *)str = req->bytes_sent;
	str += sizeof(u32);
	CHECK_LOGPTR(str);

	*(u32 *)str = req->status;
	str += sizeof(u32);
	CHECK_LOGPTR(str);

	/*
	 * Zero-terminated method, (base) URI, query and version string.
	 */
	if (req->method_len) {
		memcpy(str, req->method_str, req->method_len);
		str += req->method_len;
		CHECK_LOGPTR(str);
	}
	*str++ = 0;

	if (req->virtual) {
		if (req->host_len) {
			memcpy(str, req->host, req->host_len);
			str += req->host_len;
		} else {
			memcpy(str, tux_default_vhost, def_vhost_len);
			str += def_vhost_len;
		}
		CHECK_LOGPTR(str);
	}

	memcpy(str, uri_str, uri_len);
	str += uri_len;
	*str++ = 0;

	CHECK_LOGPTR(str);

	if (req->version_len) {
		memcpy(str, req->version_str, req->version_len);
		str += req->version_len;
		CHECK_LOGPTR(str);
	}
	*str++ = 0;
#ifdef CONFIG_TUX_EXTENDED_LOG
	if (req->user_agent_len) {
		memcpy(str, req->user_agent_str, req->user_agent_len);
		str += req->user_agent_len;
		CHECK_LOGPTR(str);
	}
	*str++ = 0;
#endif
	CHECK_LOGPTR(str);

	if (tux_referer_logging && req->referer_len) {
		memcpy(str, req->referer_str, req->referer_len);
		str += req->referer_len;
		CHECK_LOGPTR(str);
	}
	*str++ = 0;
	CHECK_LOGPTR(str);
	/*
	 * pad with spaces to next cacheline, with an ending newline.
	 * (not needed for the user-space log utility, but results in
	 * a more readable binary log file, and reduces the amount
	 * of cache pingpong.)
	 */
	next = (char *)ROUND_UP((unsigned long)str);

	CHECK_LOGPTR(next);
	len = next-str;
	memset(str, ' ', len);

	pending = (log_head-log_tail) % LOG_LEN;
	spin_unlock_irqrestore(&log_lock, flags);

	if (pending >= SOFT_LIMIT)
		wake_up(&log_wait);

	if (pending >= HARD_LIMIT)
		__throttle_logging();
}

void tux_push_pending (struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	Dprintk("pushing pending frames on sock %p.\n", sk);
	lock_sock(sk);
	if ((sk->sk_state == TCP_ESTABLISHED) && !sk->sk_err) {
		icsk->icsk_ack.pingpong = tux_ack_pingpong;
		tp->nonagle = 1;
		__tcp_push_pending_frames(sk, tp, tcp_current_mss(sk, 0), TCP_NAGLE_OFF);
	}
	release_sock(sk);
}

inline void tux_push_req (tux_req_t *req)
{
	if (req->sock)
		tux_push_pending(req->sock->sk);
	if (req->data_sock)
		tux_push_pending(req->data_sock->sk);
}

void __put_data_sock (tux_req_t *req)
{
	unlink_tux_data_socket(req);
	if (req->data_sock->file)
		fput(req->data_sock->file);
	else
		sock_release(req->data_sock);
	req->data_sock = NULL;
}

void flush_request (tux_req_t *req, int cachemiss)
{
	struct socket *sock;
	struct sock *sk;
	int keep_alive;

	if (cachemiss)
		TUX_BUG();
	__set_task_state(current, TASK_RUNNING);

	if (req->magic != TUX_MAGIC)
		TUX_BUG();
	if (req->ti->thread != current)
		TUX_BUG();
#ifdef CONFIG_TUX_DEBUG
	if (req->bytes_expected && (req->bytes_sent != req->bytes_expected)) {
		printk("hm, bytes_expected: %d != bytes_sent: %d!\n",
			req->bytes_expected, req->bytes_sent);
		TUX_BUG();
	}
#endif
	SET_TIMESTAMP(req->flush_timestamp);

	log_request(req);
	sock = req->sock;
	sk = NULL;
	if (sock)
		sk = sock->sk;
	Dprintk("FLUSHING req %p <%p> (sock %p, sk %p) (keepalive: %d, status: %d)\n", req, __builtin_return_address(0), sock, sk, req->keep_alive, req->status);
	if (req->in_file->f_pos)
		/*TUX_BUG()*/;
	release_req_dentry(req);
	req->private = 0;

	if (req->docroot_dentry) {
		dput(req->docroot_dentry);
		req->docroot_dentry = NULL;
		if (!req->docroot_mnt)
			TUX_BUG();
	}
	if (req->docroot_mnt) {
		mntput(req->docroot_mnt);
		req->docroot_mnt = NULL;
	}

	req->offset_start = 0;
	req->offset_end = 0;
	req->output_len = 0;
	req->total_file_len = 0;
	req->lendigits = 0;
	req->mtime = 0;
	req->etaglen = 0;
	req->etag[0] = 0;
	req->ftp_command = 0;

	if (req->postponed)
		TUX_BUG();
	if (test_bit(0, &req->idle_input))
		TUX_BUG();
	if (test_bit(0, &req->wait_output_space))
		TUX_BUG();
	if (req->parsed_len)
		trunc_headers(req);
	if (req->parsed_len)
		TUX_BUG();
	req->attr = NULL;
	req->usermode = 0;
	req->usermodule_idx = 0;
	req->atom_idx = 0;
	if (req->module_dentry) {
		dput(req->module_dentry);
		req->module_dentry = NULL;
	}
	if (req->headers)
		kfree(req->headers);
	req->headers = NULL;
	req->headers_len = 0;

	req->method = METHOD_NONE;
	req->method_len = 0;
	req->method_str = NULL;
	req->version = 0;
	req->version_str = NULL;
	req->version_len = 0;

	req->uri_str = NULL;
	req->uri_len = 0;

	req->objectname[0] = 0;
	req->objectname_len = 0;

	req->query_str = NULL;
	req->query_len = 0;

	req->cookies_str = NULL;
	req->cookies_len = 0;
	req->parse_cookies = 0;

	req->contentlen_str = NULL;
	req->contentlen_len = 0;
	req->content_len = 0;

	req->user_agent_str = NULL;
	req->user_agent_len = 0;

	req->may_send_gzip = 0;
	req->content_gzipped = 0;

	req->content_type_str = NULL;
	req->content_type_len = 0;

	req->accept_str = NULL;
	req->accept_len = 0;

	req->accept_charset_str = NULL;
	req->accept_charset_len = 0;

	req->accept_encoding_str = NULL;
	req->accept_encoding_len = 0;

	req->accept_language_str = NULL;
	req->accept_language_len = 0;

	req->cache_control_str = NULL;
	req->cache_control_len = 0;

	req->if_modified_since_str = NULL;
	req->if_modified_since_len = 0;

	req->if_none_match_str = NULL;
	req->if_none_match_len = 0;

	req->if_range_str = NULL;
	req->if_range_len = 0;

	req->negotiate_str = NULL;
	req->negotiate_len = 0;

	req->pragma_str = NULL;
	req->pragma_len = 0;

	req->referer_str = NULL;
	req->referer_len = 0;

	req->post_data_str = NULL;
	req->post_data_len = 0;

	SET_TIMESTAMP(req->accept_timestamp);
#ifdef CONFIG_TUX_EXTENDED_LOG
	req->parse_timestamp = 0;
	req->output_timestamp = 0;
	req->flush_timestamp = 0;
#endif
	req->status = 0;

	req->total_bytes += req->bytes_sent;
	req->bytes_sent = 0;
#ifdef CONFIG_TUX_DEBUG
	req->bytes_expected = 0;
#endif
	req->body_len = 0;
	keep_alive = req->keep_alive;
	clear_keepalive(req);
	req->had_cachemiss = 0;
	// first_timestamp and total_bytes is kept!
	req->event = 0;
	req->lookup_dir = 0;
	req->lookup_404 = 0;

	req->error = 0;
	req->user_error = 0;

	if (req->abuf.page)
		__free_page(req->abuf.page);
	memset(&req->abuf, 0, sizeof(req->abuf));

	if (sk && keep_alive) {
		add_tux_atom(req, parse_request);
		if (skb_queue_empty(&sk->sk_receive_queue)) {
			spin_lock_irq(&req->ti->work_lock);
			add_keepalive_timer(req);
			if (test_and_set_bit(0, &req->idle_input))
				TUX_BUG();
			/*
			 * Avoid the race with the event callback:
			 */
			if (skb_queue_empty(&sk->sk_receive_queue) ||
				   !test_and_clear_bit(0, &req->idle_input)) {
				INC_STAT(nr_idle_input_pending);
				spin_unlock_irq(&req->ti->work_lock);
				tux_push_req(req);
				goto out;
			}
			del_keepalive_timer(req);
			spin_unlock_irq(&req->ti->work_lock);
		}
		Dprintk("KEEPALIVE PENDING req %p <%p> (sock %p, sk %p) (keepalive: %d, status: %d)\n", req, __builtin_return_address(0), req->sock, req->sock->sk, req->keep_alive, req->status);
		add_req_to_workqueue(req);
		INC_STAT(nr_keepalive_optimized);
		goto out;
	}

	del_timer_sync(&req->keepalive_timer);
	del_timer_sync(&req->output_timer);

	if (timer_pending(&req->keepalive_timer))
		TUX_BUG();
	if (timer_pending(&req->output_timer))
		TUX_BUG();
	if (!list_empty(&req->lru))
		TUX_BUG();
	req->nr_keepalives = 0;
	req->client_addr = 0;
	req->client_port = 0;
	req->virtual = 0;
	req->ftp_offset_start = 0;

	req->host[0] = 0;
	req->host_len = 0;

	if (req->cwd_dentry) {
		dput(req->cwd_dentry);
		req->cwd_dentry = NULL;
		if (!req->cwd_mnt)
			TUX_BUG();
	}
	if (req->cwd_mnt) {
		mntput(req->cwd_mnt);
		req->cwd_mnt = NULL;
	}
	put_data_sock(req);
	req->prev_pos = 0;
	req->curroff = 0;
	req->total = 0;
	if (req->dirp0) {
		kfree(req->dirp0);
		req->dirp0 = NULL;
	}

	if (sk)
		unlink_tux_socket(req);
	req->sock = NULL;
	/*
	 * Close potential user-space file descriptors.
	 */
	{
		int fd = req->fd, ret;

		if (fd != -1) {
			Dprintk("closing req->fd: %d\n", fd);
			req->fd = -1;
			ret = tux_close(fd);
			if (ret)
				TUX_BUG();
		} else
			if (sock)
				sock_release(sock);
	}
	kfree_req(req);
out:
	;
}

static int warn_once = 1;

static loff_t log_filp_last_index;

static unsigned int writeout_log (void)
{
	unsigned int len, pending, next_log_tail;
	mm_segment_t oldmm = get_fs();
	struct file *log_filp;
	char * str;
	unsigned int ret;
	struct inode *inode;
	struct address_space *mapping;

	if (tux_logging)
		Dprintk("TUX logger: opening log file {%s}.\n", tux_logfile);
	log_filp = tux_open_file(tux_logfile, O_CREAT|O_APPEND|O_WRONLY|O_LARGEFILE);
	if (!log_filp) {
		if (warn_once) {
			printk(KERN_ERR "TUX: could not open log file {%s}!\n",
				tux_logfile);
			warn_once = 0;
		}
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
		return 0;
	}
	spin_lock(&log_lock);
	str = log_buffer + log_tail;
	if (log_head < log_tail) {
		len = LOG_LEN-log_tail;
		next_log_tail = 0;
	} else {
		len = log_head-log_tail;
		next_log_tail = log_head;
	}
	if (!len)
		goto out;
	spin_unlock(&log_lock);

	set_fs(KERNEL_DS);
	ret = log_filp->f_op->write(log_filp, str, len, &log_filp->f_pos);
	set_fs(oldmm);

	if (len != ret) {
		if (ret == -ENOSPC) {
			printk(KERN_ERR "TUX: trying to write TUX logfile %s, but filesystem is full! Lost %d bytes of log data.\n", tux_logfile, len);
		} else {
			printk(KERN_ERR "TUX: log write %d != %d.\n", ret, len);
			printk(KERN_ERR "TUX: log_filp: %p, str: %p, len: %d str[len-1]: %d.\n", log_filp, str, len, str[len-1]);
		}
		goto out_lock;
	}

	/*
	 * Sync log data to disk:
	 */
	inode = log_filp->f_dentry->d_inode;
	mapping = inode->i_mapping;
	if (mapping->nrpages > 256) {   /* batch stuff up */
		mutex_lock(&inode->i_mutex);
		filemap_fdatawrite(inode->i_mapping);

		/*
		 * Now nuke old pagecache up to the place where we just
		 * started the I/O.   There's no point in trying to invalidate
		 * pages after that, because they're currently in-flight.
		 */
		invalidate_mapping_pages(mapping, 0, log_filp_last_index);
		log_filp_last_index = log_filp->f_pos >> PAGE_CACHE_SHIFT;
		mutex_unlock(&inode->i_mutex);
	}

out_lock:
	spin_lock(&log_lock);
out:
	log_tail = next_log_tail;
	pending = (log_head-log_tail) % LOG_LEN;
	spin_unlock(&log_lock);

	if (pending < HARD_LIMIT)
		wake_up(&log_full);

	fput(log_filp);
	return pending;
}

static DECLARE_WAIT_QUEUE_HEAD(stop_logger_wait);
static int stop_logger = 0;

static int logger_thread (void *data)
{
	DECLARE_WAITQUEUE(wait, current);
	mm_segment_t oldmm;

	daemonize("TUX logger");

	oldmm = get_fs();
	set_fs(KERNEL_DS);
	printk(KERN_NOTICE "TUX: logger thread started.\n");
#ifdef CONFIG_SMP
	{
		cpumask_t map;

		cpus_and(map, cpu_online_map, tux_log_cpu_mask);
		if (!(cpus_empty(map)))
			set_cpus_allowed(current, map);

	}
#endif


	spin_lock_irq(&current->sighand->siglock);
	siginitsetinv(&current->blocked, 0);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	if (log_buffer)
		TUX_BUG();
	log_buffer = vmalloc(LOG_LEN);
	if (!log_buffer) {
		TUX_BUG();
		goto out;
	}
	memset(log_buffer, 0, LOG_LEN);
	log_head = log_tail = 0;

	current->signal->rlim[RLIMIT_FSIZE].rlim_cur = RLIM_INFINITY;

	add_wait_queue(&log_wait, &wait);
	for (;;) {
		if (tux_logging)
			Dprintk("logger does writeout - stop:%d.\n", stop_logger);

		while (writeout_log() >= SOFT_LIMIT) {
			if (stop_logger)
				break;
		}
		if (stop_logger)
			break;
			/* nothing */;

		if (tux_logging)
			Dprintk("logger does sleep - stop:%d.\n", stop_logger);
		__set_current_state(TASK_INTERRUPTIBLE);
		if (log_head != log_tail) {
			__set_current_state(TASK_RUNNING);
			continue;
		}
		schedule_timeout(HZ);
		if (tux_logging)
			Dprintk("logger back from sleep - stop:%d.\n", stop_logger);
		if (signal_pending(current))
			flush_all_signals();
	}
	remove_wait_queue(&log_wait, &wait);

	vfree(log_buffer);
	log_buffer = NULL;
	stop_logger = 0;
	wake_up(&stop_logger_wait);
out:
	set_fs(oldmm);

	return 0;
}

void start_log_thread (void)
{
	warn_once = 1;

	logger_pid = kernel_thread(logger_thread, NULL, 0);
	if (logger_pid < 0)
		TUX_BUG();
}

void stop_log_thread (void)
{
	DECLARE_WAITQUEUE(wait, current);

	Dprintk("stopping logger thread %d ...\n", logger_pid);

	__set_current_state(TASK_UNINTERRUPTIBLE);
	add_wait_queue(&stop_logger_wait, &wait);
	stop_logger = 1;
	wake_up(&log_wait);
	schedule();
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&stop_logger_wait, &wait);

	Dprintk("logger thread stopped!\n");
}
