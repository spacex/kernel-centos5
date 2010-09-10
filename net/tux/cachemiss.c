/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * cachemiss.c: handle the 'slow IO path' by queueing not-yet-cached
 * requests to the IO-thread pool. Dynamic load balancing is done
 * between IO threads, based on the number of requests they have pending.
 */

#include <net/tux.h>
#include <linux/delay.h>

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

void queue_cachemiss (tux_req_t *req)
{
	iothread_t *iot = req->ti->iot;

	Dprintk("queueing_cachemiss(req:%p) (req->cwd_dentry: %p) at %p:%p.\n",
		req, req->cwd_dentry, __builtin_return_address(0), __builtin_return_address(1));
	if (req->idle_input || req->wait_output_space)
		TUX_BUG();
	req->had_cachemiss = 1;
	if (!list_empty(&req->work))
		TUX_BUG();
	spin_lock(&iot->async_lock);
	if (connection_too_fast(req))
		list_add_tail(&req->work, &iot->async_queue);
	else
		list_add(&req->work, &iot->async_queue);
	iot->nr_async_pending++;
	INC_STAT(nr_cachemiss_pending);
	spin_unlock(&iot->async_lock);

	wake_up(&iot->async_sleep);
}

static tux_req_t * get_cachemiss (iothread_t *iot)
{
	struct list_head *tmp;
	tux_req_t *req = NULL;

	spin_lock(&iot->async_lock);
	if (!list_empty(&iot->async_queue)) {

		tmp = iot->async_queue.next;
		req = list_entry(tmp, tux_req_t, work);

		Dprintk("get_cachemiss(%p): got req %p.\n", iot, req);
		list_del(tmp);
		DEBUG_DEL_LIST(tmp);
		iot->nr_async_pending--;
		DEC_STAT(nr_cachemiss_pending);

		if (req->ti->iot != iot)
			TUX_BUG();
	}
	spin_unlock(&iot->async_lock);
	return req;
}

struct file * tux_open_file (char *filename, int mode)
{
	struct file *filp;

	if (!filename)
		TUX_BUG();

	/* Rule no. 3 -- Does the file exist ? */

	filp = filp_open(filename, mode, 0600);

	if (IS_ERR(filp) || !filp || !filp->f_dentry)
		goto err;

out:
	return filp;
err:
	Dprintk("filp_open() error: %d.\n", (int)filp);
	filp = NULL;
	goto out;
}

static int cachemiss_thread (void *data)
{
	tux_req_t *req;
	struct k_sigaction *ka;
	DECLARE_WAITQUEUE(wait, current);
	iothread_t *iot = data;
	int nr = iot->ti->cpu, wake_up;

	Dprintk("iot %p/%p got started.\n", iot, current);
	drop_permissions();

	spin_lock(&iot->async_lock);
	iot->threads++;
	sprintf(current->comm, "async IO %d/%d", nr, iot->threads);


	spin_lock_irq(&current->sighand->siglock);
	ka = current->sighand->action + SIGCHLD-1;
	ka->sa.sa_handler = SIG_IGN;
	siginitsetinv(&current->blocked, sigmask(SIGCHLD));
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	spin_unlock(&iot->async_lock);
#ifdef CONFIG_SMP
	{
		cpumask_t mask;

		if (cpu_isset(nr, cpu_online_map)) {
			cpus_clear(mask);
			cpu_set(nr, mask);
			set_cpus_allowed(current, mask);
		}

	}
#endif

	add_wait_queue_exclusive(&iot->async_sleep, &wait);

	for (;;) {
		while (!list_empty(&iot->async_queue) &&
				(req = get_cachemiss(iot))) {

			if (!req->atom_idx) {
				add_tux_atom(req, flush_request);
				add_req_to_workqueue(req);
				continue;
			}
			tux_schedule_atom(req, 1);
			if (signal_pending(current))
				flush_all_signals();
		}
		if (signal_pending(current))
			flush_all_signals();
		if (!list_empty(&iot->async_queue))
			continue;
		if (iot->shutdown) {
			Dprintk("iot %p/%p got shutdown!\n", iot, current);
			break;
		}
		__set_current_state(TASK_INTERRUPTIBLE);
		if (list_empty(&iot->async_queue)) {
			Dprintk("iot %p/%p going to sleep.\n", iot, current);
			schedule();
			Dprintk("iot %p/%p got woken up.\n", iot, current);
		}
		__set_current_state(TASK_RUNNING);
	}

	remove_wait_queue(&iot->async_sleep, &wait);

	wake_up = 0;
	spin_lock(&iot->async_lock);
	if (!--iot->threads)
		wake_up = 1;
	spin_unlock(&iot->async_lock);
	Dprintk("iot %p/%p has finished shutdown!\n", iot, current);
	if (wake_up) {
		Dprintk("iot %p/%p waking up master.\n", iot, current);
		wake_up(&iot->wait_shutdown);
	}

	return 0;
}

static void __stop_cachemiss_threads (iothread_t *iot)
{
	DECLARE_WAITQUEUE(wait, current);

	__set_current_state(TASK_UNINTERRUPTIBLE);

	Dprintk("stopping async IO threads %p.\n", iot);
	add_wait_queue(&iot->wait_shutdown, &wait);

	spin_lock(&iot->async_lock);
	if (iot->shutdown)
		TUX_BUG();
	if (!iot->threads)
		TUX_BUG();
	iot->shutdown = 1;
	wake_up_all(&iot->async_sleep);
	spin_unlock(&iot->async_lock);

	Dprintk("waiting for async IO threads %p to exit.\n", iot);
	schedule();
	remove_wait_queue(&iot->wait_shutdown, &wait);

	if (iot->threads)
		TUX_BUG();
	if (iot->nr_async_pending)
		TUX_BUG();
	Dprintk("stopped async IO threads %p.\n", iot);
}

void stop_cachemiss_threads (threadinfo_t *ti)
{
	iothread_t *iot = ti->iot;

	if (!iot)
		TUX_BUG();
	if (iot->nr_async_pending)
		TUX_BUG();
	__stop_cachemiss_threads(iot);
	ti->iot = NULL;
	kfree(iot);
}

int start_cachemiss_threads (threadinfo_t *ti)
{
	int i, pid;

	iothread_t *iot;

	iot = kmalloc(sizeof(*iot), GFP_KERNEL);
	if (!iot)
		return -ENOMEM;
	memset(iot, 0, sizeof(*iot));

	iot->ti = ti;
	spin_lock_init(&iot->async_lock);
	iot->nr_async_pending = 0;
	INIT_LIST_HEAD(&iot->async_queue);
	init_waitqueue_head(&iot->async_sleep);
	init_waitqueue_head(&iot->wait_shutdown);

	for (i = 0; i < NR_IO_THREADS; i++) {
		pid = kernel_thread(cachemiss_thread, (void *)iot, 0);
		if (pid < 0) {
			printk(KERN_ERR "TUX: error %d creating IO thread!\n",
					pid);
			__stop_cachemiss_threads(iot);
			kfree(iot);
			return pid;
		}
	}
	ti->iot = iot;
	/*
	 * Wait for all cachemiss threads to start up:
	 */
	while (iot->threads != NR_IO_THREADS) {
		__set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ/10);
	}
	return 0;
}

