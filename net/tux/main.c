/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * main.c: main management and initialization routines
 */

#define __KERNEL_SYSCALLS__
#define __KERNEL_SYSCALLS_NO_ERRNO__

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

/*
 * Threads information.
 */
unsigned int nr_tux_threads;
static atomic_t nr_tux_threads_running = ATOMIC_INIT(0);
static int stop_threads = 0;

threadinfo_t threadinfo[CONFIG_TUX_NUMTHREADS];

static void flush_all_requests (threadinfo_t *ti);

void flush_all_signals (void)
{
	flush_signals(current);
	spin_lock_irq(&current->sighand->siglock);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);
}

int nr_requests_used (void)
{
	unsigned int i, nr = 0;

	for (i = 0; i < nr_tux_threads; i++) {
		threadinfo_t *ti = threadinfo + i;
		nr += ti->nr_requests - ti->nr_free_requests;
	}

	return nr;
}

static inline int accept_pending (threadinfo_t *ti)
{
	int j;

	for (j = 0; j < CONFIG_TUX_NUMSOCKETS; j++) {
		if (!ti->listen[j].proto)
			break;
		if (!ti->listen[j].sock)
			break;
		if (!reqsk_queue_empty(&inet_csk(ti->listen[j].sock->sk)->icsk_accept_queue))
			return 1;
	}
	return 0;
}

static inline int requests_pending (threadinfo_t *ti)
{
	if (!list_empty(&ti->work_pending))
		return 1;
	return 0;
}

static int event_loop (threadinfo_t *ti)
{
	tux_req_t *req;
	int work_done;

repeat_accept:
	if (ti->thread != current)
		TUX_BUG();

	/*
	 * Any (relevant) event on the socket will change this
	 * thread to TASK_RUNNING because we add it to both
	 * the main listening and the connection request socket
	 * waitqueues. Thus we can do 'lazy checking' of work
	 * to be done and schedule away only if the thread is
	 * still TASK_INTERRUPTIBLE. This makes TUX fully
	 * event driven.
	 */
	set_task_state(current, TASK_INTERRUPTIBLE);
	current->flags |= PF_MEMALLOC;
	work_done = 0;
	if (accept_pending(ti))
		work_done = accept_requests(ti);

	if (requests_pending(ti)) {
		work_done = process_requests(ti, &req);
		if (req)
			goto handle_userspace_req;
	}

	/*
	 * Be nice to other processes:
	 */
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) {
		__set_task_state(current, TASK_RUNNING);
		schedule();
		goto repeat_accept;
	}

	if (ti->userspace_req)
		TUX_BUG();
	if (unlikely(stop_threads))
		goto handle_stop;

	/* Any signals? */
	if (unlikely(signal_pending(current)))
		goto handle_signal;

	if (work_done)
		goto repeat_accept;
	/*
	 * Any socket event either on the listen socket
	 * or on the request sockets will wake us up:
	 */
	if ((current->state != TASK_RUNNING) &&
			!requests_pending(ti) && !accept_pending(ti)) {
		Dprintk("fast thread: no work to be done, sleeping.\n");
		schedule();
		Dprintk("fast thread: back from sleep!\n");
		goto repeat_accept;
	}
	goto repeat_accept;

handle_userspace_req:
	if (req->attr)
		TUX_BUG();
	switch_docroot(req);
	ti->userspace_req = req;
	__set_task_state(current, TASK_RUNNING);
	return TUX_RETURN_USERSPACE_REQUEST;

handle_signal:
	__set_task_state(current, TASK_RUNNING);
	return TUX_RETURN_SIGNAL;

handle_stop:
	__set_task_state(current, TASK_RUNNING);
	return TUX_RETURN_EXIT;
}

static int init_queues (int nr_tux_threads)
{
	int i;

	for (i = 0; i < nr_tux_threads; i++) {
		threadinfo_t *ti = threadinfo + i;

		INIT_LIST_HEAD(&ti->all_requests);

		spin_lock_init(&ti->free_requests_lock);
		INIT_LIST_HEAD(&ti->free_requests);

		spin_lock_init(&ti->work_lock);
		INIT_LIST_HEAD(&ti->work_pending);
		INIT_LIST_HEAD(&ti->lru);

	}
	return 0;
}

int tux_chroot (char *dir)
{
	kernel_cap_t saved_cap = current->cap_effective;
	mm_segment_t oldmm;
	int err;

	/* Allow chroot dir to be in kernel space. */
	oldmm = get_fs(); set_fs(KERNEL_DS);
	set_fs(KERNEL_DS);
	cap_raise (current->cap_effective, CAP_SYS_CHROOT);

	err = sys_chroot(dir);
	if (!err)
		sys_chdir("/");

	current->cap_effective = saved_cap;
	set_fs(oldmm);

	return err;
}

/*
 * Right now this is not fully SMP-safe against multiple TUX
 * managers. It's just a rudimentary protection against typical
 * mistakes.
 */
static int initialized = 0;

#define MAX_DOCROOTLEN 500

static int lookup_docroot(struct nameidata *docroot, const char *name)
{
	int err;

	docroot->mnt = mntget(current->fs->rootmnt);
	docroot->dentry = dget(current->fs->root);
	docroot->last.len = 0;
	docroot->flags = LOOKUP_FOLLOW;

	err = path_walk(name, docroot);
	if (err) {
		mntput(docroot->mnt);
		docroot->mnt = NULL;
		return err;
	}
	return 0;
}

static int user_req_startup (void)
{
	char name[MAX_DOCROOTLEN];
	struct nameidata *docroot;
	unsigned int i;
	int err;

	if (initialized)
		return -EINVAL;
	initialized = 1;

	/*
	 * Look up the HTTP and FTP document root.
	 * (typically they are shared, but can be
	 * different directories.)
	 */
	docroot = &tux_proto_http.main_docroot;
	if (docroot->mnt)
		TUX_BUG();
	strcpy(name, tux_common_docroot);
	strcat(name, tux_http_subdocroot);

	err = lookup_docroot(docroot, name);
	if (err) {
		initialized = 0;
		printk(KERN_ERR "TUX: could not look up HTTP documentroot: \"%s\"\n", name);
		return err;
	}

	docroot = &tux_proto_ftp.main_docroot;
	if (docroot->mnt)
		TUX_BUG();
	strcpy(name, tux_common_docroot);
	strcat(name, tux_ftp_subdocroot);

	err = lookup_docroot(docroot, name);
	if (err) {
abort:
		docroot = &tux_proto_http.main_docroot;
		path_release(docroot);
		memset(docroot, 0, sizeof(*docroot));
		initialized = 0;
		printk(KERN_ERR "TUX: could not look up FTP documentroot: \"%s\"\n", name);
		return err;
	}

	/*
	 * Start up the logger thread. (which opens the logfile)
	 */
	start_log_thread();

	nr_tux_threads = tux_threads;
	if (nr_tux_threads < 1)
		nr_tux_threads = 1;
	if (nr_tux_threads > CONFIG_TUX_NUMTHREADS)
		nr_tux_threads = CONFIG_TUX_NUMTHREADS;
	tux_threads = nr_tux_threads;

	/*
	 * Set up per-thread work-queues:
	 */
	memset(threadinfo, 0, CONFIG_TUX_NUMTHREADS*sizeof(threadinfo_t));
	init_queues(nr_tux_threads);

	/*
	 * Prepare the worker thread structures.
	 */
	for (i = 0; i < nr_tux_threads; i++) {
		threadinfo_t *ti = threadinfo + i;
		ti->cpu = i;
		ti->gzip_state.workspace =
			vmalloc(zlib_deflate_workspacesize());
		if (!ti->gzip_state.workspace ||
			    (zlib_deflateInit(&ti->gzip_state, 6) != Z_OK)) {
			stop_log_thread();
			goto abort;
		}
		init_MUTEX(&ti->gzip_sem);
	}

	__module_get(tux_module);

	return 0;
}

static DECLARE_WAIT_QUEUE_HEAD(wait_stop);
static DECLARE_WAIT_QUEUE_HEAD(thread_stopped);

static int user_req_shutdown (void)
{
	DECLARE_WAITQUEUE(wait, current);
	struct nameidata *docroot;
	int i, err = -EINVAL;

	lock_kernel();
	if (!initialized) {
		Dprintk("TUX is not up - cannot shut down.\n");
		goto err;
	}
	initialized = 0;
	stop_threads = 1;
	add_wait_queue(&thread_stopped, &wait);

wait_more:
	/*
	 * Wake up all the worker threads so they notice
	 * that we are being stopped.
	 */
	set_task_state(current, TASK_UNINTERRUPTIBLE);
	if (atomic_read(&nr_tux_threads_running)) {
		Dprintk("TUX: shutdown, %d threads still running.\n",
			atomic_read(&nr_tux_threads_running));
		wake_up(&wait_stop);
		schedule();
		goto wait_more;
	}
	set_task_state(current, TASK_RUNNING);
	stop_threads = 0;
	remove_wait_queue(&thread_stopped, &wait);

	if (nr_async_io_pending())
		TUX_BUG();

	stop_log_thread();

	docroot = &tux_proto_http.main_docroot;
	path_release(docroot);
	memset(docroot, 0, sizeof(*docroot));
	docroot = &tux_proto_ftp.main_docroot;
	path_release(docroot);
	memset(docroot, 0, sizeof(*docroot));
	err = 0;

	flush_dentry_attributes();
	free_mimetypes();
	unregister_all_tuxmodules();

	for (i = 0; i < nr_tux_threads; i++) {
		threadinfo_t *ti = threadinfo + i;
		vfree(ti->gzip_state.workspace);
	}

	module_put(tux_module);

err:
	unlock_kernel();
	return err;
}

void drop_permissions (void)
{
	/*
	 * Userspace drops privileges already, and group
	 * membership is important to keep.
	 */
	/* Give the new process no privileges.. */
	current->uid = current->euid =
		current->suid = current->fsuid = tux_cgi_uid;
	current->gid = current->egid =
		current->sgid = current->fsgid = tux_cgi_gid;
	cap_clear(current->cap_permitted);
	cap_clear(current->cap_inheritable);
	cap_clear(current->cap_effective);
}

static int wait_for_others (void)
{
	threadinfo_t *ti;
	unsigned int cpu;

repeat:
	if (signal_pending(current))
		return -1;
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(HZ/10);

	for (cpu = 0; cpu < nr_tux_threads; cpu++) {
		ti = threadinfo + cpu;
		if (ti->listen_error)
			return -1;
		if (!ti->started)
			goto repeat;
	}
	/* ok, all threads have started up. */
	return 0;
}

static void zap_listen_sockets (threadinfo_t *ti)
{
	struct socket *sock;
	int i;

	for (i = 0; i < CONFIG_TUX_NUMSOCKETS; i++) {
		if (!ti->listen[i].proto)
			break;
		sock = ti->listen[i].sock;
		if (!ti->listen[i].cloned && sock) {
			while (waitqueue_active(sock->sk->sk_sleep))
				yield();
			sock_release(sock);
		}
		ti->listen[i].sock = NULL;
		ti->listen[i].proto = NULL;
		ti->listen[i].cloned = 0;
	}
}

static DECLARE_MUTEX(serialize_startup);

static int user_req_start_thread (threadinfo_t *ti)
{
	unsigned int err, cpu, i, j, k;
	struct k_sigaction *ka;

	cpu = ti->cpu;
#ifdef CONFIG_SMP
	{
		unsigned int home_cpu;
		cpumask_t map;

		home_cpu = (cpu + tux_cpu_offset) % num_online_cpus();
		map = cpumask_of_cpu(home_cpu);

		cpus_and(map, map, cpu_online_map);
		if (!(cpus_empty(map)))
			set_cpus_allowed(current, map);
	}
#endif
	ti->thread = current;
	atomic_inc(&nr_tux_threads_running);

	err = start_cachemiss_threads(ti);
	if (err)
		goto out;

	init_waitqueue_entry(&ti->stop, current);
	for (j = 0; j < CONFIG_TUX_NUMSOCKETS; j++)
		init_waitqueue_entry(ti->wait_event + j, current);

	ka = current->sighand->action + SIGCHLD-1;
	ka->sa.sa_handler = SIG_IGN;

	/* Block all signals except SIGKILL, SIGSTOP, SIGHUP and SIGCHLD */
	spin_lock_irq(&current->sighand->siglock);
	siginitsetinv(&current->blocked, sigmask(SIGKILL) |
			sigmask(SIGSTOP)| sigmask(SIGHUP) | sigmask(SIGCHLD));
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	if (!tux_listen[cpu][0].proto) {
		printk(KERN_ERR "no listen socket specified for TUX thread %d, in /proc/net/tux/%d/listen/, aborting.\n", cpu, cpu);
		goto error;
	}

	/*
	 * Serialize startup so that listen sockets can be
	 * created race-free.
	 */
	down(&serialize_startup);

	Dprintk("thread %d initializing sockets.\n", cpu);

	for (k = 0; k < CONFIG_TUX_NUMSOCKETS; k++) {
		tux_socket_t *e1, *e2;

		e1 = tux_listen[cpu] + k;
		if (!e1->proto)
			break;
		for (i = 0; i < CONFIG_TUX_NUMTHREADS; i++) {
			if (i == cpu)
				continue;
			for (j = 0; j < CONFIG_TUX_NUMSOCKETS; j++) {
				e2 = tux_listen[i] + j;
				if (!e2->proto)
					continue;
				if ((e1->ip == e2->ip) && (e1->port == e2->port) && (e1->proto == e2->proto) && threadinfo[i].listen[j].proto) {
					ti->listen[k] = threadinfo[i].listen[j];
					ti->listen[k].cloned = 1;
					Dprintk("cloned socket %d from thread %d's socket %d.\n", k, i, j);
					goto next_socket;
				}
			}
		}

		ti->listen[k].sock = start_listening(tux_listen[cpu] + k, cpu);
		if (!ti->listen[k].sock)
			goto error_unlock;
		ti->listen[k].cloned = 0;
		ti->listen[k].proto = tux_listen[cpu][k].proto;
		Dprintk("thread %d got sock %p (%d), proto %s.\n", cpu, ti->listen[k].sock, k, ti->listen[k].proto->name);
next_socket:
		;
	}
	Dprintk("thread %d done initializing sockets.\n", cpu);
	up(&serialize_startup);

	if (wait_for_others())
		goto error_nomsg;

	if (!ti->listen[0].proto) {
		printk("hm, socket 0 has no protocol.\n");
		goto error;
	}

	add_wait_queue(&wait_stop, &ti->stop);
	for (j = 0; j < CONFIG_TUX_NUMSOCKETS; j++)
		if (ti->listen[j].proto)
			add_wait_queue_exclusive(ti->listen[j].sock->sk->sk_sleep,
				ti->wait_event + j);
	drop_permissions();

	__module_get(tux_module);
	return 0;

error_unlock:
	up(&serialize_startup);
error:
	printk(KERN_NOTICE "TUX: could not start worker thread %d.\n", ti->cpu);

error_nomsg:
	ti->listen_error = 1;
	ti->started = 0;

	zap_listen_sockets(ti);
	flush_all_requests(ti);
	stop_cachemiss_threads(ti);

	err = -EINVAL;

out:
	/*
	 * Last thread close the door:
	 */
	if (atomic_dec_and_test(&nr_tux_threads_running))
		user_req_shutdown();

	return -err;
}

static int flush_idleinput (threadinfo_t * ti)
{
	struct list_head *head, *tmp;
	tux_req_t *req;
	int count = 0;

	head = &ti->all_requests;
	tmp = head->next;

	while (tmp != head) {
		req = list_entry(tmp, tux_req_t, all);
		tmp = tmp->next;
		if (test_bit(0, &req->idle_input)) {
			idle_event(req);
			count++;
		}
	}
	return count;
}

static int flush_waitoutput (threadinfo_t * ti)
{
	struct list_head *head, *tmp;
	tux_req_t *req;
	int count = 0;

	head = &ti->all_requests;
	tmp = head->next;

	while (tmp != head) {
		req = list_entry(tmp, tux_req_t, all);
		tmp = tmp->next;
		if (test_bit(0, &req->wait_output_space)) {
			output_space_event(req);
			count++;
		}
	}
	return count;
}

static void flush_all_requests (threadinfo_t *ti)
{
	for (;;) {
		int count;

		count = flush_idleinput(ti);
		count += flush_waitoutput(ti);
		count += tux_flush_workqueue(ti);
		count += flush_freequeue(ti);
		if (!ti->nr_requests)
			break;
		/*
		 * Go through again if we advanced:
		 */
		if (count)
			continue;
		Dprintk("flush_all_requests: %d requests still waiting.\n", ti->nr_requests);
#ifdef CONFIG_TUX_DEBUG
		count = print_all_requests(ti);
		Dprintk("flush_all_requests: printed %d requests.\n", count);
#endif
		current->state = TASK_UNINTERRUPTIBLE;
		schedule_timeout(HZ/10);
	}
}

int nr_async_io_pending (void)
{
	unsigned int i, sum = 0;

	for (i = 0; i < nr_tux_threads; i++) {
		threadinfo_t *ti = threadinfo + i;
		if (ti->iot)
			sum += ti->iot->nr_async_pending;
	}
	return sum;
}

static int user_req_stop_thread (threadinfo_t *ti)
{
	int j;

	printk(KERN_NOTICE "TUX: thread %d stopping ...\n",
		(int)(ti-threadinfo));

	if (!ti->started)
		TUX_BUG();
	for (j = 0; j < CONFIG_TUX_NUMSOCKETS; j++)
		if (ti->listen[j].proto)
			remove_wait_queue(ti->listen[j].sock->sk->sk_sleep,
				ti->wait_event + j);
	remove_wait_queue(&wait_stop, &ti->stop);

	Dprintk(KERN_NOTICE "TUX: thread %d waiting for sockets to go inactive ...\n", (int)(ti-threadinfo));
	zap_listen_sockets(ti);

	Dprintk(KERN_NOTICE "TUX: thread %d has all sockets inactive.\n", (int)(ti-threadinfo));

	flush_all_requests(ti);
	stop_cachemiss_threads(ti);

	if (ti->nr_requests)
		TUX_BUG();
	ti->started = 0;

	printk(KERN_INFO "TUX: thread %d stopped.\n", ti->cpu);

	ti->thread = NULL;
	current->tux_info = NULL;
	current->tux_exit = NULL;
	atomic_dec(&nr_tux_threads_running);
	wake_up(&thread_stopped);

	module_put(tux_module);

	return 0;
}

#define COPY_INT(u_field, k_field)					\
do {									\
	if (__copy_to_user(&u_info->u_field, &req->k_field,		\
					sizeof(req->k_field)))		\
		return_EFAULT;						\
} while (0)

#define GETLEN(k_field, maxlen)						\
		((req->k_field##_len < maxlen) ?			\
		req->k_field##_len : maxlen-1)

#define COPY_STR(u_field, k_field, maxlen)				\
do {									\
	if (__copy_to_user(u_info->u_field, req->k_field##_str,		\
		GETLEN(k_field, maxlen)))				\
			return_EFAULT;					\
} while (0)

#define COPY_COND_STR(u_field,k_field,maxlen)				\
do {									\
	if (req->k_field##_len)						\
		COPY_STR(u_field, k_field, maxlen);			\
	if (__put_user((char)0, u_info->u_field +			\
			GETLEN(k_field, maxlen)))			\
		return_EFAULT;						\
} while (0)

static void finish_userspace_req (tux_req_t *req)
{
	threadinfo_t *ti = req->ti;

	ti->userspace_req = NULL;
	req->usermode = 0;
	req->private = 0;
	req->error = 0;
	DEC_STAT(nr_userspace_pending);
	flush_request(req, 0);
}

static void zap_userspace_req (tux_req_t *req)
{
	clear_keepalive(req);
	finish_userspace_req(req);
}

/*
 * Fills in the user-space request structure:
 */
static int prepare_userspace_req (threadinfo_t *ti, user_req_t *u_info)
{
	u64 u_req;
	tux_req_t *req = ti->userspace_req;
	unsigned int tmp;
	int filelen;
	int fd;

	Dprintk("prepare_userspace_req(%p).\n", req);
	if (!req)
		TUX_BUG();
	if (req->error) {
		TDprintk("userspace request has error %d.\n", req->error);
		return -1;
	}
	fd = req->fd;
	if (fd == -1) {
		fd = sock_map_fd(req->sock);
		Dprintk("sock_map_fd(%p) :%d.\n", req, fd);
		if (fd < 0) {
			Dprintk("sock_map_fd() returned %d.\n", fd);
			return -EMFILE;
		}
		req->fd = fd;
	}

#define return_EFAULT do { Dprintk("-EFAULT at %d:%s.\n", __LINE__, __FILE__); return -EFAULT; } while (0)

	if (!access_ok(VERIFY_WRITE, u_info, sizeof(*u_info)))
		return_EFAULT;
	if (__copy_to_user(&u_info->sock, &fd, sizeof(fd)))
		return_EFAULT;
	if (req->attr)
		TUX_BUG();

	COPY_INT(module_index, usermodule_idx);

	COPY_COND_STR(query, query, MAX_URI_LEN);

	COPY_INT(event, event);
	Dprintk("prepare userspace, user error: %d, event %d.\n", req->user_error, req->event);
	COPY_INT(error, user_error);
	req->user_error = 0;

	filelen = req->total_file_len;
	if (filelen < 0)
		filelen = 0;
	if (__copy_to_user(&u_info->objectlen, &filelen, sizeof(filelen)))
		return_EFAULT;
	if ((req->method == METHOD_POST) && !filelen)
		if (__copy_to_user(&u_info->objectlen,
			&req->content_len, sizeof(filelen)))
		return_EFAULT;
	if (req->objectname_len) {
		if (req->objectname[req->objectname_len])
			TUX_BUG();
		if (__copy_to_user(u_info->objectname, req->objectname,
				req->objectname_len + 1))
			return_EFAULT;
	} else
		if (__put_user((char)0, u_info->objectname))
			return_EFAULT;

	COPY_INT(http_version, version);
	COPY_INT(http_method, method);
	COPY_INT(keep_alive, keep_alive);

	COPY_INT(cookies_len, cookies_len);
	if (req->cookies_len)
		COPY_STR(cookies, cookies, MAX_COOKIE_LEN);
	if (__put_user((char)0, u_info->cookies + req->cookies_len))
		return_EFAULT;

	u_req = (u64)(unsigned long)req;
	if (__copy_to_user(&u_info->id, &u_req, sizeof(u_req)))
		return_EFAULT;
	COPY_INT(priv, private);
	COPY_INT(bytes_sent, bytes_sent);

	tmp = inet_sk(req->sock->sk)->daddr;
	if (__copy_to_user(&u_info->client_host, &tmp, sizeof(tmp)))
		return_EFAULT;

	COPY_COND_STR(content_type, content_type, MAX_FIELD_LEN);
	COPY_COND_STR(user_agent, user_agent, MAX_FIELD_LEN);
	COPY_COND_STR(accept, accept, MAX_FIELD_LEN);
	COPY_COND_STR(accept_charset, accept_charset, MAX_FIELD_LEN);
	COPY_COND_STR(accept_encoding, accept_encoding, MAX_FIELD_LEN);
	COPY_COND_STR(accept_language, accept_language, MAX_FIELD_LEN);
	COPY_COND_STR(cache_control, cache_control, MAX_FIELD_LEN);
	COPY_COND_STR(if_modified_since, if_modified_since, MAX_FIELD_LEN);
	COPY_COND_STR(negotiate, negotiate, MAX_FIELD_LEN);
	COPY_COND_STR(pragma, pragma, MAX_FIELD_LEN);
	COPY_COND_STR(referer, referer, MAX_FIELD_LEN);

	return TUX_RETURN_USERSPACE_REQUEST;
}

#define GOTO_ERR_no_unlock do { Dprintk("sys_tux() ERR at %s:%d.\n", __FILE__, __LINE__); goto err_no_unlock; } while (0)
#define GOTO_ERR_unlock do { Dprintk("sys_tux() ERR at %s:%d.\n", __FILE__, __LINE__); goto err_unlock; } while (0)

static int register_mimetype(user_req_t *u_info)
{
	char extension[MAX_URI_LEN], mimetype[MAX_URI_LEN], expires[MAX_URI_LEN];
	u64 u_addr;
	char *addr;
	int ret;

	ret = strncpy_from_user(extension, u_info->objectname, MAX_URI_LEN);
	if (ret <= 0)
		GOTO_ERR_no_unlock;
	extension[ret] = 0;
	Dprintk("got MIME extension: %s.\n", extension);
	ret = copy_from_user(&u_addr, &u_info->object_addr, sizeof(u_addr));
	if (ret)
		GOTO_ERR_no_unlock;
	addr = (char *)(unsigned long)u_addr;
	ret = strncpy_from_user(mimetype, addr, MAX_URI_LEN);
	if (ret <= 0)
		GOTO_ERR_no_unlock;
	mimetype[ret] = 0;
	Dprintk("got MIME type: %s.\n", mimetype);
       ret = strncpy_from_user(expires, u_info->cache_control, MAX_URI_LEN);
       if (ret >= 0)
		expires[ret] = 0;
	else
		expires[0] = 0;
       Dprintk("got expires header: %s.\n", expires);

	add_mimetype(extension, mimetype, expires);
	ret = 0;
err_no_unlock:
	return ret;
}

void user_send_buffer (tux_req_t *req, int cachemiss)
{
	int ret;


	SET_TIMESTAMP(req->output_timestamp);

repeat:
	ret = send_sync_buf(req, req->sock, req->userbuf, req->userlen, MSG_DONTWAIT | MSG_MORE);
	switch (ret) {
		case -EAGAIN:
			add_tux_atom(req, user_send_buffer);
			if (add_output_space_event(req, req->sock)) {
				del_tux_atom(req);
				goto repeat;
			}
			INC_STAT(user_sendbuf_write_misses);
			break;
		default:
			if (ret <= 0) {
				req_err(req);
				req->usermode = 0;
				req->private = 0;
				add_req_to_workqueue(req);
				break;
			}
			req->userbuf += ret;
			req->userlen -= ret;
			if ((int)req->userlen < 0)
				TUX_BUG();
			if (req->userlen)
				goto repeat;
			add_req_to_workqueue(req);
			break;
	}
}

void user_send_object (tux_req_t *req, int cachemiss)
{
	int ret;


	SET_TIMESTAMP(req->output_timestamp);

repeat:
	ret = generic_send_file(req, req->sock, cachemiss);
	switch (ret) {
		case -5:
			add_tux_atom(req, user_send_object);
			output_timeout(req);
			break;
		case -4:
			add_tux_atom(req, user_send_object);
			if (add_output_space_event(req, req->sock)) {
				del_tux_atom(req);
				goto repeat;
			}
			INC_STAT(user_sendobject_write_misses);
			break;
		case -3:
			INC_STAT(user_sendobject_cachemisses);
			add_tux_atom(req, user_send_object);
			queue_cachemiss(req);
			break;
		case -1:
			break;
		default:
			req->in_file->f_pos = 0;
			add_req_to_workqueue(req);
			break;
	}
}

void user_get_object (tux_req_t *req, int cachemiss)
{
	int missed;

	if (!req->dentry) {
		req->usermode = 0;
		missed = lookup_object(req, cachemiss ? 0 : LOOKUP_ATOMIC);
		if (req->usermode)
			TUX_BUG();
		req->usermode = 1;
		if (!missed && !req->dentry) {
			req->error = 0;
			req->user_error = -ENOENT;
			add_req_to_workqueue(req);
			return;
		}
		if (missed) {
			if (cachemiss)
				TUX_BUG();
			INC_STAT(user_lookup_cachemisses);
fetch_missed:
			req->ti->userspace_req = NULL;
			DEC_STAT(nr_userspace_pending);
			add_tux_atom(req, user_get_object);
			queue_cachemiss(req);
			return;
		}
	}
	req->total_file_len = req->dentry->d_inode->i_size;
	if (!req->output_len)
		req->output_len = req->total_file_len;
	if (tux_fetch_file(req, !cachemiss)) {
		INC_STAT(user_fetch_cachemisses);
		goto fetch_missed;
	}
	req->in_file->f_pos = 0;
	add_req_to_workqueue(req);
}

asmlinkage long __sys_tux (unsigned int action, user_req_t *u_info)
{
	int ret = -1;
	threadinfo_t *ti;
	tux_req_t *req;

	if (action != TUX_ACTION_CURRENT_DATE)
		Dprintk("got sys_tux(%d, %p).\n", action, u_info);

	if (action >= MAX_TUX_ACTION)
		GOTO_ERR_no_unlock;

	ti = (threadinfo_t *) current->tux_info;
	if (ti)
		if (ti->thread != current)
			TUX_BUG();

	if (!capable(CAP_SYS_ADMIN)
			&& (action != TUX_ACTION_CONTINUE_REQ) &&
				(action != TUX_ACTION_STOPTHREAD))
		goto userspace_actions;

	switch (action) {
		case TUX_ACTION_CONTINUE_REQ:
			ret = continue_request((int)(long)u_info);
			goto out;

		case TUX_ACTION_STARTUP:
			lock_kernel();
			ret = user_req_startup();
			unlock_kernel();
			goto out;

		case TUX_ACTION_SHUTDOWN:
			lock_kernel();
			ret = user_req_shutdown();
			unlock_kernel();
			goto out;

		case TUX_ACTION_REGISTER_MODULE:
			ret = user_register_module(u_info);
			goto out;

		case TUX_ACTION_UNREGISTER_MODULE:
			ret = user_unregister_module(u_info);
			goto out;

		case TUX_ACTION_STARTTHREAD:
		{
			unsigned int nr;

			ret = copy_from_user(&nr, &u_info->thread_nr,
						sizeof(int));
			if (ret)
				GOTO_ERR_no_unlock;
			if (nr >= nr_tux_threads)
				GOTO_ERR_no_unlock;
			ti = threadinfo + nr;
			if (ti->started)
				GOTO_ERR_unlock;
			ti->started = 1;
			current->tux_info = ti;
			current->tux_exit = tux_exit;
			if (ti->thread)
				TUX_BUG();
			Dprintk("TUX: current open files limit for TUX%d: %ld.\n", nr, current->signal->rlim[RLIMIT_NOFILE].rlim_cur);
			lock_kernel();
			ret = user_req_start_thread(ti);
			unlock_kernel();
			if (ret) {
				current->tux_info = NULL;
				current->tux_exit = NULL;
			} else {
				if (ti->thread != current)
					TUX_BUG();
			}
			goto out_userreq;
		}

		case TUX_ACTION_STOPTHREAD:
			if (!ti)
				GOTO_ERR_no_unlock;
			if (!ti->started)
				GOTO_ERR_unlock;
			req = ti->userspace_req;
			if (req)
				zap_userspace_req(req);

			lock_kernel();
			ret = user_req_stop_thread(ti);
			unlock_kernel();
			goto out_userreq;

		case TUX_ACTION_CURRENT_DATE:
			ret = strncpy_from_user(tux_date, u_info->new_date,
				DATE_LEN);
			if (ret <= 0)
				GOTO_ERR_no_unlock;
			goto out;

		case TUX_ACTION_REGISTER_MIMETYPE:
			ret = register_mimetype(u_info);
			if (ret)
				GOTO_ERR_no_unlock;
			goto out;

		case TUX_ACTION_QUERY_VERSION:
			ret = (TUX_MAJOR_VERSION << 24) | (TUX_MINOR_VERSION << 16) | TUX_PATCHLEVEL_VERSION;
			goto out;
		default:
			;
	}

userspace_actions:

	if (!ti)
		GOTO_ERR_no_unlock;

	if (!ti->started)
		GOTO_ERR_unlock;

	req = ti->userspace_req;
	if (!req) {
		if (action == TUX_ACTION_EVENTLOOP)
			goto eventloop;
		GOTO_ERR_unlock;
	}
	if (!req->usermode)
		TUX_BUG();

	ret = copy_from_user(&req->event, &u_info->event, sizeof(int));
	if (ret)
		GOTO_ERR_unlock;
	ret = copy_from_user(&req->status, &u_info->http_status, sizeof(int));
	if (ret)
		GOTO_ERR_unlock;
	ret = copy_from_user(&req->bytes_sent, &u_info->bytes_sent, sizeof(int));
	if (ret)
		GOTO_ERR_unlock;
	ret = copy_from_user(&req->private, &u_info->priv, sizeof(req->private));
	if (ret)
		GOTO_ERR_unlock;

	switch (action) {

		case TUX_ACTION_EVENTLOOP:
eventloop:
			req = ti->userspace_req;
			if (req)
				zap_userspace_req(req);
			ret = event_loop(ti);
			goto out_userreq;

		/*
		 * Module forces keepalive off, server will close
		 * the connection.
		 */
		case TUX_ACTION_FINISH_CLOSE_REQ:
			clear_keepalive(req);

		case TUX_ACTION_FINISH_REQ:
			finish_userspace_req(req);
			goto eventloop;

		case TUX_ACTION_REDIRECT_REQ:

			ti->userspace_req = NULL;
			req->usermode = 0;
			req->private = 0;
			req->error = TUX_ERROR_REDIRECT;
			DEC_STAT(nr_userspace_pending);
			add_tux_atom(req, redirect_request);
			add_req_to_workqueue(req);

			goto eventloop;

		case TUX_ACTION_POSTPONE_REQ:

			postpone_request(req);
			ti->userspace_req = NULL;
			ret = TUX_RETURN_USERSPACE_REQUEST;
			break;

		case TUX_ACTION_GET_OBJECT:
			release_req_dentry(req);
			ret = strncpy_from_user(req->objectname,
				u_info->objectname, MAX_URI_LEN-1);
			if (ret <= 0) {
				req->objectname[0] = 0;
				req->objectname_len = 0;
				GOTO_ERR_unlock;
			}
			req->objectname[ret] = 0; // string delimit
			req->objectname_len = ret;

			Dprintk("got objectname {%s} (%d) from user-space req %p (req: %p).\n", req->objectname, req->objectname_len, u_info, req);
			req->ti->userspace_req = NULL;
			DEC_STAT(nr_userspace_pending);
			user_get_object(req, 0);
			goto eventloop;

		case TUX_ACTION_READ_OBJECT:
		{
			u64 u_addr;
			char *addr;
			loff_t ppos = 0;
			struct file *filp;

			if (!req->dentry)
				GOTO_ERR_unlock;

			ret = copy_from_user(&u_addr, &u_info->object_addr,
					sizeof(u_addr));
			if (ret)
				GOTO_ERR_unlock;
			addr = (char *)(unsigned long)u_addr;
			filp = dentry_open(req->dentry, NULL, O_RDONLY);
			dget(req->dentry);
			generic_file_read(filp, addr, req->total_file_len, &ppos);
			fput(filp);
			ret = TUX_RETURN_USERSPACE_REQUEST;
			break;
		}

		case TUX_ACTION_SEND_OBJECT:
			if (!req->dentry)
				GOTO_ERR_unlock;
			req->ti->userspace_req = NULL;
			DEC_STAT(nr_userspace_pending);
			user_send_object(req, 0);
			goto eventloop;

		case TUX_ACTION_SEND_BUFFER:
		{
			u64 u_addr;
			char *addr;
			unsigned int len;

			ret = copy_from_user(&u_addr,
					&u_info->object_addr, sizeof(u_addr));
			if (ret)
				GOTO_ERR_unlock;
			addr = (char *)(unsigned long)u_addr;
			ret = copy_from_user(&len,
					&u_info->objectlen, sizeof(addr));
			if (ret)
				GOTO_ERR_unlock;
			if ((int)len <= 0)
				GOTO_ERR_unlock;

			ret = -EFAULT;
			if (!access_ok(VERIFY_READ, addr, len))
				GOTO_ERR_unlock;
			req->userbuf = addr;
			req->userlen = len;

			req->ti->userspace_req = NULL;
			DEC_STAT(nr_userspace_pending);
			user_send_buffer(req, 0);
			ret = 0;
			goto eventloop;
		}

		case TUX_ACTION_READ_HEADERS:
		{
			char *addr;
			u64 u_addr;

			ret = copy_from_user(&u_addr, &u_info->object_addr,
					sizeof(u_addr));
			if (ret)
				GOTO_ERR_unlock;
			addr = (char *)(unsigned long)u_addr;
			ret = copy_to_user(&u_info->objectlen,
				 &req->headers_len, sizeof(req->headers_len));
			if (ret)
				GOTO_ERR_unlock;
			ret = copy_to_user(addr,req->headers, req->headers_len);
			if (ret)
				GOTO_ERR_unlock;
			break;
		}

		case TUX_ACTION_READ_POST_DATA:
		{
			char *addr;
			unsigned int size;
			u64 u_addr;

			ret = copy_from_user(&u_addr, &u_info->object_addr,
					sizeof(u_addr));
			if (ret)
				GOTO_ERR_unlock;
			addr = (char *)(unsigned long)u_addr;

			ret = copy_from_user(&size, &u_info->objectlen,
					sizeof(size));
			if (ret)
				GOTO_ERR_unlock;
			Dprintk("READ_POST_DATA: got %p(%d).\n", addr, size);
			if (req->post_data_len < size)
				size = req->post_data_len;
			Dprintk("READ_POST_DATA: writing %d.\n", size);
			ret = copy_to_user(&u_info->objectlen,
						&size, sizeof(size));
			if (ret)
				GOTO_ERR_unlock;
			ret = copy_to_user(addr, req->post_data_str, size);
			if (ret)
				GOTO_ERR_unlock;
			goto out;
		}

		case TUX_ACTION_WATCH_PROXY_SOCKET:
		{
			struct socket *sock;
			int err;
			long fd;
			u64 u_addr;

			ret = copy_from_user(&u_addr, &u_info->object_addr,
					sizeof(u_addr));
			if (ret)
				GOTO_ERR_unlock;
			fd = (int)(unsigned long)u_addr;

			sock = sockfd_lookup(fd, &err);
			if (!sock)
				GOTO_ERR_unlock;
			put_data_sock(req);
			link_tux_data_socket(req, sock);

			ret = 0;
			goto out;
		}

		case TUX_ACTION_WAIT_PROXY_SOCKET:
		{
			if (!req->data_sock)
				GOTO_ERR_unlock;
			if (socket_input(req->data_sock)) {
				ret = TUX_RETURN_USERSPACE_REQUEST;
				goto out_userreq;
			}
			spin_lock_irq(&req->ti->work_lock);
			add_keepalive_timer(req);
			if (test_and_set_bit(0, &req->idle_input))
				TUX_BUG();
			spin_unlock_irq(&req->ti->work_lock);
			if (socket_input(req->data_sock)) {
				unidle_req(req);
				ret = TUX_RETURN_USERSPACE_REQUEST;
				goto out_userreq;
			}
			req->ti->userspace_req = NULL;
			goto eventloop;
		}

		default:
			GOTO_ERR_unlock;
	}

out_userreq:
	req = ti->userspace_req;
	if (req) {
		ret = prepare_userspace_req(ti, u_info);
		if (ret < 0) {
			TDprintk("hm, user req %p returned %d, zapping.\n",
				req, ret);
			zap_userspace_req(req);
			goto eventloop;
		}
	}
out:
	if (action != TUX_ACTION_CURRENT_DATE)
		Dprintk("sys_tux(%d, %p) returning %d.\n", action, u_info, ret);
	while (unlikely(test_thread_flag(TIF_NEED_RESCHED))) {
		__set_task_state(current, TASK_RUNNING);
		schedule();
	}
	return ret;
err_unlock:
err_no_unlock:
	Dprintk("sys_tux(%d, %p) returning -EINVAL (ret:%d)!\n", action, u_info, ret);
	while (unlikely(test_thread_flag(TIF_NEED_RESCHED))) {
		__set_task_state(current, TASK_RUNNING);
		schedule();
	}
	return -EINVAL;
}

/*
 * This gets called if a TUX thread does an exit().
 */
void tux_exit (void)
{
	__sys_tux(TUX_ACTION_STOPTHREAD, NULL);
}

int tux_init(void)
{
	if (init_tux_request_slabs())
		return -ENOMEM;

	start_sysctl();

#ifdef CONFIG_TUX_MODULE
	spin_lock(&tux_module_lock);
	sys_tux_ptr = __sys_tux;
	tux_module = THIS_MODULE;
	spin_unlock(&tux_module_lock);
#endif

	return 0;
}

void tux_cleanup (void)
{
#ifdef CONFIG_TUX_MODULE
	spin_lock(&tux_module_lock);
	tux_module = NULL;
	sys_tux_ptr = NULL;
	spin_unlock(&tux_module_lock);
#endif
	end_sysctl();

	free_tux_request_slabs();
}

module_init(tux_init)
module_exit(tux_cleanup)

MODULE_LICENSE("GPL");

