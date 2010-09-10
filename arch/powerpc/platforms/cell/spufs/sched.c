/* sched.c - SPU scheduler.
 *
 * Copyright (C) IBM 2005
 * Author: Mark Nutter <mnutter@us.ibm.com>
 *
 * 2006-03-31	NUMA domains added.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#undef DEBUG

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/completion.h>
#include <linux/vmalloc.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/numa.h>
#include <linux/mutex.h>
#include <linux/notifier.h>

#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/spu.h>
#include <asm/spu_csa.h>
#include <asm/spu_priv1.h>
#include "spufs.h"

#define SPU_TIMESLICE	(HZ)

struct spu_prio_array {
	DECLARE_BITMAP(bitmap, MAX_PRIO);
	struct list_head runq[MAX_PRIO];
	spinlock_t runq_lock;
	struct list_head active_list[MAX_NUMNODES];
	struct mutex active_mutex[MAX_NUMNODES];
};

static struct spu_prio_array *spu_prio;
static struct workqueue_struct *spu_sched_wq;

static struct spu_context *grab_runnable_context(int prio);
static void spu_unbind_context(struct spu *spu, struct spu_context *ctx);


static inline int node_allowed(int node)
{
	cpumask_t mask;

	if (!nr_cpus_node(node))
		return 0;
	mask = node_to_cpumask(node);
	if (!cpus_intersects(mask, current->cpus_allowed))
		return 0;
	return 1;
}

void spu_start_tick(struct spu_context *ctx)
{
	if (ctx->policy == SCHED_RR) {
		/*
		 * Make sure the exiting bit is cleared.
		 */
		clear_bit(SPU_SCHED_EXITING, &ctx->sched_flags);
		mb();
		queue_delayed_work(spu_sched_wq, &ctx->sched_work, SPU_TIMESLICE);
	}
}

void spu_stop_tick(struct spu_context *ctx)
{
	if (ctx->policy == SCHED_RR) {
		/*
		 * While the work can be rearming normally setting this flag
		 * makes sure it does not rearm itself anymore.
		 */
		set_bit(SPU_SCHED_EXITING, &ctx->sched_flags);
		mb();
		cancel_delayed_work(&ctx->sched_work);
	}
}

void spu_sched_tick(void *data)
{
	struct spu_context *ctx = data;
	struct spu *spu;
	int preempted = 0;

	/*
	 * If this context is beeing stopped avoid rescheduling from the
	 * scheduler tick because we would deadlock on the state_mutex.
	 * The caller will yield the spu later on anyway.
	 */
	if (test_bit(SPU_SCHED_EXITING, &ctx->sched_flags))
		return;

	mutex_lock(&ctx->state_mutex);
	spu = ctx->spu;
	if (spu) {
		struct spu_context *new;

		new = grab_runnable_context(ctx->prio + 1);
		if (new) {
			spu_unbind_context(spu, ctx);
			spu_free(spu);
			if (new)
				wake_up(&new->stop_wq);
			preempted = 1;
		}
	}
	mutex_unlock(&ctx->state_mutex);

	if (preempted) {
		/*
		 * We need to break out of the wait loop in spu_run manually
		 * to ensure this context gets put on the runqueue again
		 * ASAP.
		 */
		wake_up(&ctx->stop_wq);
	} else
		spu_start_tick(ctx);
}

/**
 * spu_add_to_active_list - add spu to active list
 * @spu:	spu to add to the active list
 */
static void spu_add_to_active_list(struct spu *spu)
{
	mutex_lock(&spu_prio->active_mutex[spu->node]);
	list_add_tail(&spu->list, &spu_prio->active_list[spu->node]);
	mutex_unlock(&spu_prio->active_mutex[spu->node]);
}

/**
 * spu_remove_from_active_list - remove spu from active list
 * @spu:       spu to remove from the active list
 */
static void spu_remove_from_active_list(struct spu *spu)
{
	int node = spu->node;

	mutex_lock(&spu_prio->active_mutex[node]);
	list_del_init(&spu->list);
	mutex_unlock(&spu_prio->active_mutex[node]);
}

static BLOCKING_NOTIFIER_HEAD(spu_switch_notifier);

void spu_switch_notify(struct spu *spu, struct spu_context *ctx)
{
	blocking_notifier_call_chain(&spu_switch_notifier,
			    ctx ? ctx->object_id : 0, spu);
}

static void notify_spus_active(void)
{
	int node;
	/* Wake up the active spu_contexts. When the awakened processes
	 * see their "notify_active" flag is set, they will call
	 * spu_switch_notify();
	 */
	for (node = 0; node < MAX_NUMNODES; node++) {
		struct spu *spu;
		mutex_lock(&spu_prio->active_mutex[node]);
		list_for_each_entry(spu, &spu_prio->active_list[node], list) {
			struct spu_context *ctx = spu->ctx;
			set_bit(SPU_SCHED_NOTIFY_ACTIVE, &ctx->sched_flags);
			mb();
			wake_up_all(&ctx->stop_wq);
		}
		mutex_unlock(&spu_prio->active_mutex[node]);
	}
}

int spu_switch_event_register(struct notifier_block * n)
{
	int ret;
	ret = blocking_notifier_chain_register(&spu_switch_notifier, n);
	if (!ret)
		notify_spus_active();
	return ret;
}
EXPORT_SYMBOL_GPL(spu_switch_event_register);

int spu_switch_event_unregister(struct notifier_block * n)
{
	return blocking_notifier_chain_unregister(&spu_switch_notifier, n);
}
EXPORT_SYMBOL_GPL(spu_switch_event_unregister);

/**
 * spu_bind_context - bind spu context to physical spu
 * @spu:	physical spu to bind to
 * @ctx:	context to bind
 */
static void spu_bind_context(struct spu *spu, struct spu_context *ctx)
{
	pr_debug("%s: pid=%d SPU=%d NODE=%d\n", __FUNCTION__, current->pid,
		 spu->number, spu->node);
	if (ctx->flags & SPU_CREATE_NOSCHED)
		atomic_inc(&be_spu_info[spu->node].reserved_spus);
	if (!list_empty(&ctx->aff_list))
		atomic_inc(&ctx->gang->aff_sched_count);
	spu->ctx = ctx;
	spu->flags = 0;
	ctx->spu = spu;
	ctx->ops = &spu_hw_ops;
	spu->pid = current->pid;
	spu->tgid = current->tgid;
	spu_associate_mm(spu, ctx->owner);
	spu->ibox_callback = spufs_ibox_callback;
	spu->wbox_callback = spufs_wbox_callback;
	spu->stop_callback = spufs_stop_callback;
	spu->mfc_callback = spufs_mfc_callback;
	spu->dma_callback = spufs_dma_callback;
	mb();
	spu_unmap_mappings(ctx);
	spu_restore(&ctx->csa, spu);
	spu->timestamp = jiffies;
	spu_cpu_affinity_set(spu, raw_smp_processor_id());
	spu_switch_notify(spu, ctx);
	spu_add_to_active_list(spu);
	ctx->state = SPU_STATE_RUNNABLE;
}

/**
 * spu_unbind_context - unbind spu context from physical spu
 * @spu:	physical spu to unbind from
 * @ctx:	context to unbind
 */
static void spu_unbind_context(struct spu *spu, struct spu_context *ctx)
{
	pr_debug("%s: unbind pid=%d SPU=%d NODE=%d\n", __FUNCTION__,
		 spu->pid, spu->number, spu->node);

	if (spu->ctx->flags & SPU_CREATE_NOSCHED)
		atomic_dec(&be_spu_info[spu->node].reserved_spus);
	if (!list_empty(&ctx->aff_list))
		if (atomic_dec_and_test(&ctx->gang->aff_sched_count))
			ctx->gang->aff_ref_spu = NULL;
	spu_remove_from_active_list(spu);
	spu_switch_notify(spu, NULL);
	spu_unmap_mappings(ctx);
	spu_save(&ctx->csa, spu);
	spu->timestamp = jiffies;
	ctx->state = SPU_STATE_SAVED;
	spu->ibox_callback = NULL;
	spu->wbox_callback = NULL;
	spu->stop_callback = NULL;
	spu->mfc_callback = NULL;
	spu->dma_callback = NULL;
	spu_associate_mm(spu, NULL);
	spu->pid = 0;
	spu->tgid = 0;
	ctx->ops = &spu_backing_ops;
	ctx->spu = NULL;
	spu->flags = 0;
	spu->ctx = NULL;
}

/**
 * spu_add_to_rq - add a context to the runqueue
 * @ctx:       context to add
 */
static void __spu_add_to_rq(struct spu_context *ctx)
{
	int prio = ctx->prio;

	list_add_tail(&ctx->rq, &spu_prio->runq[prio]);
	set_bit(prio, spu_prio->bitmap);
}

static void __spu_del_from_rq(struct spu_context *ctx)
{
	int prio = ctx->prio;

	if (!list_empty(&ctx->rq))
		list_del_init(&ctx->rq);
	if (list_empty(&spu_prio->runq[prio]))
		clear_bit(prio, spu_prio->bitmap);
}

static void spu_prio_wait(struct spu_context *ctx)
{
	DEFINE_WAIT(wait);

	spin_lock(&spu_prio->runq_lock);
	prepare_to_wait_exclusive(&ctx->stop_wq, &wait, TASK_INTERRUPTIBLE);
	if (!signal_pending(current)) {
		__spu_add_to_rq(ctx);
		spin_unlock(&spu_prio->runq_lock);
		mutex_unlock(&ctx->state_mutex);
		schedule();
		mutex_lock(&ctx->state_mutex);
		spin_lock(&spu_prio->runq_lock);
		__spu_del_from_rq(ctx);
	}
	spin_unlock(&spu_prio->runq_lock);
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(&ctx->stop_wq, &wait);
}

/**
 * grab_runnable_context - try to find a runnable context
 *
 * Remove the highest priority context on the runqueue and return it
 * to the caller.  Returns %NULL if no runnable context was found.
 */
static struct spu_context *grab_runnable_context(int prio)
{
	struct spu_context *ctx = NULL;
	int best;

	spin_lock(&spu_prio->runq_lock);
	best = sched_find_first_bit(spu_prio->bitmap);
	if (best < prio) {
		struct list_head *rq = &spu_prio->runq[best];

		BUG_ON(list_empty(rq));

		ctx = list_entry(rq->next, struct spu_context, rq);
		__spu_del_from_rq(ctx);
	}
	spin_unlock(&spu_prio->runq_lock);

	return ctx;
}

/**
 * spu_reschedule - try to find a runnable context for a spu
 * @spu:       spu available
 *
 * This function is called whenever a spu becomes idle.	 It looks for the
 * most suitable runnable spu context and schedules it for execution.
 */
static void spu_reschedule(struct spu *spu)
{
	struct spu_context *ctx;

	spu_free(spu);

	ctx = grab_runnable_context(MAX_PRIO);
	if (ctx)
		wake_up(&ctx->stop_wq);
}

static struct spu *spu_get_idle(struct spu_context *ctx)
{
	struct spu *spu = NULL;
	int node = cpu_to_node(raw_smp_processor_id());
	int n;

	spu = affinity_check(ctx);
	if (spu)
		return spu_alloc_spu(spu);

	for (n = 0; n < MAX_NUMNODES; n++, node++) {
		node = (node < MAX_NUMNODES) ? node : 0;
		if (!node_allowed(node))
			continue;
		spu = spu_alloc_node(node);
		if (spu)
			break;
	}
	return spu;
}

/**
 * find_victim - find a lower priority context to preempt
 * @ctx:	canidate context for running
 *
 * Returns the freed physical spu to run the new context on.
 */
static struct spu *find_victim(struct spu_context *ctx)
{
	struct spu_context *victim = NULL;
	struct spu *spu;
	int node, n;

	/*
	 * Look for a possible preemption candidate on the local node first.
	 * If there is no candidate look at the other nodes.  This isn't
	 * exactly fair, but so far the whole spu schedule tries to keep
	 * a strong node affinity.  We might want to fine-tune this in
	 * the future.
	 */
 restart:
	node = cpu_to_node(raw_smp_processor_id());
	for (n = 0; n < MAX_NUMNODES; n++, node++) {
		node = (node < MAX_NUMNODES) ? node : 0;
		if (!node_allowed(node))
			continue;

		mutex_lock(&spu_prio->active_mutex[node]);
		list_for_each_entry(spu, &spu_prio->active_list[node], list) {
			struct spu_context *tmp = spu->ctx;

			if (tmp->rt_priority < ctx->rt_priority &&
			    (!victim || tmp->rt_priority < victim->rt_priority))
				victim = spu->ctx;
		}
		mutex_unlock(&spu_prio->active_mutex[node]);

		if (victim) {
			/*
			 * This nests ctx->state_mutex, but we always lock
			 * higher priority contexts before lower priority
			 * ones, so this is safe until we introduce
			 * priority inheritance schemes.
			 */
			if (!mutex_trylock(&victim->state_mutex)) {
				victim = NULL;
				goto restart;
			}

			spu = victim->spu;
			if (!spu) {
				/*
				 * This race can happen because we've dropped
				 * the active list mutex.  No a problem, just
				 * restart the search.
				 */
				mutex_unlock(&victim->state_mutex);
				victim = NULL;
				goto restart;
			}
			spu_unbind_context(spu, victim);
			mutex_unlock(&victim->state_mutex);
			/*
			 * We need to break out of the wait loop in spu_run
			 * manually to ensure this context gets put on the
			 * runqueue again ASAP.
			 */
			wake_up(&victim->stop_wq);
			return spu;
		}
	}

	return NULL;
}

/**
 * spu_activate - find a free spu for a context and execute it
 * @ctx:	spu context to schedule
 * @flags:	flags (currently ignored)
 *
 * Tries to find a free spu to run @ctx.  If no free spu is availble
 * add the context to the runqueue so it gets woken up once an spu
 * is available.
 */
int spu_activate(struct spu_context *ctx, unsigned long flags)
{

	if (ctx->spu)
		return 0;

	do {
		struct spu *spu;

		spu = spu_get_idle(ctx);
		/*
		 * If this is a realtime thread we try to get it running by
		 * preempting a lower priority thread.
		 */
		if (!spu && ctx->rt_priority)
			spu = find_victim(ctx);
		if (spu) {
			spu_bind_context(spu, ctx);
			return 0;
		}

		spu_prio_wait(ctx);
	} while (!signal_pending(current));

	return -ERESTARTSYS;
}

/**
 * spu_deactivate - unbind a context from it's physical spu
 * @ctx:	spu context to unbind
 *
 * Unbind @ctx from the physical spu it is running on and schedule
 * the highest priority context to run on the freed physical spu.
 */
void spu_deactivate(struct spu_context *ctx)
{
	struct spu *spu = ctx->spu;

	if (spu) {
		spu_unbind_context(spu, ctx);
		spu_reschedule(spu);
	}
}

/**
 * spu_yield -	yield a physical spu if others are waiting
 * @ctx:	spu context to yield
 *
 * Check if there is a higher priority context waiting and if yes
 * unbind @ctx from the physical spu and schedule the highest
 * priority context to run on the freed physical spu instead.
 */
void spu_yield(struct spu_context *ctx)
{
	struct spu *spu;
	int need_yield = 0;

	if (mutex_trylock(&ctx->state_mutex)) {
		if ((spu = ctx->spu) != NULL) {
			int best = sched_find_first_bit(spu_prio->bitmap);
			if (best < MAX_PRIO) {
				pr_debug("%s: yielding SPU %d NODE %d\n",
					 __FUNCTION__, spu->number, spu->node);
				spu_deactivate(ctx);
				need_yield = 1;
			}
		}
		mutex_unlock(&ctx->state_mutex);
	}
	if (unlikely(need_yield))
		yield();
}

int __init spu_sched_init(void)
{
	int i;

	spu_sched_wq = create_singlethread_workqueue("spusched");
	if (!spu_sched_wq)
		return 1;

	spu_prio = kzalloc(sizeof(struct spu_prio_array), GFP_KERNEL);
	if (!spu_prio) {
		printk(KERN_WARNING "%s: Unable to allocate priority queue.\n",
		       __FUNCTION__);
		       destroy_workqueue(spu_sched_wq);
		return 1;
	}
	for (i = 0; i < MAX_PRIO; i++) {
		INIT_LIST_HEAD(&spu_prio->runq[i]);
		__clear_bit(i, spu_prio->bitmap);
	}
	__set_bit(MAX_PRIO, spu_prio->bitmap);
	for (i = 0; i < MAX_NUMNODES; i++) {
		mutex_init(&spu_prio->active_mutex[i]);
		INIT_LIST_HEAD(&spu_prio->active_list[i]);
	}
	spin_lock_init(&spu_prio->runq_lock);
	return 0;
}

void __exit spu_sched_exit(void)
{
	struct spu *spu, *tmp;
	int node;

	for (node = 0; node < MAX_NUMNODES; node++) {
		mutex_lock(&spu_prio->active_mutex[node]);
		list_for_each_entry_safe(spu, tmp, &spu_prio->active_list[node],
					 list) {
			list_del_init(&spu->list);
			spu_free(spu);
		}
		mutex_unlock(&spu_prio->active_mutex[node]);
	}
	kfree(spu_prio);
	destroy_workqueue(spu_sched_wq);
}

static void aff_merge_remaining_ctxs(struct spu_gang *gang)
{
	struct spu_context *ctx;

	list_for_each_entry(ctx, &gang->aff_list_head, aff_list) {
		if (list_empty(&ctx->aff_list))
			list_add(&ctx->aff_list, &gang->aff_list_head);
	}
	gang->aff_flags |= AFF_MERGED;
}

static void aff_set_offsets(struct spu_gang *gang)
{
	struct spu_context *ctx;
	int offset;

	offset = -1;
	list_for_each_entry_reverse(ctx, &gang->aff_ref_ctx->aff_list,
								aff_list) {
		if (&ctx->aff_list == &gang->aff_list_head)
			break;
		ctx->aff_offset = offset--;
	}

	offset = 0;
	list_for_each_entry(ctx, gang->aff_ref_ctx->aff_list.prev, aff_list) {
		if (&ctx->aff_list == &gang->aff_list_head)
			break;
		ctx->aff_offset = offset++;
	}

	gang->aff_flags |= AFF_OFFSETS_SET;
}

static inline int sched_spu(struct spu *spu)
{
	return (!spu->ctx || !(spu->ctx->flags & SPU_CREATE_NOSCHED));
}

static struct spu *
aff_ref_location(int mem_aff, int group_size, int prio, int lowest_offset)
{
	struct spu *spu;
	int node, n;

	/* TODO: A better algorithm could be used to find a good spu to be
	 *	 used as reference location for the ctxs chain.
	 */
	node = cpu_to_node(raw_smp_processor_id());
	for (n = 0; n < MAX_NUMNODES; n++, node++) {
		node = (node < MAX_NUMNODES) ? node : 0;
		if (!node_allowed(node))
			continue;
		list_for_each_entry(spu, &be_spu_info[node].spus, be_list) {
			if ((!mem_aff || spu->has_mem_affinity) &&
							sched_spu(spu))
				return spu;
		}
	}
	return NULL;
}

static void aff_set_ref_point_location(struct spu_gang *gang)
{
	int mem_aff, gs, lowest_offset;
	struct spu_context *ctx;
	struct spu *tmp;

	mem_aff = gang->aff_ref_ctx->flags & SPU_CREATE_AFFINITY_MEM;
	lowest_offset = 0;
	gs = 0;
	list_for_each_entry(tmp, &gang->aff_list_head, aff_list)
		gs++;

	list_for_each_entry_reverse(ctx, &gang->aff_ref_ctx->aff_list,
								aff_list) {
		if (&ctx->aff_list == &gang->aff_list_head)
			break;
		lowest_offset = ctx->aff_offset;
	}

	gang->aff_ref_spu = aff_ref_location(mem_aff, gs, ctx->prio,
							lowest_offset);
}

static struct spu* ctx_location(struct spu *ref, int offset)
{
	struct spu *spu;

	spu = NULL;
	if (offset >= 0) {
		list_for_each_entry(spu, ref->aff_list.prev, aff_list) {
			if (offset == 0)
				break;
			if (sched_spu(spu))
				offset--;
		}
	} else {
		list_for_each_entry_reverse(spu, ref->aff_list.next, aff_list) {
			if (offset == 0)
				break;
			if (sched_spu(spu))
				offset++;
		}
	}
	return spu;
}

/**
 * affinity_check is called each time a context is going to be scheduled.
 * It returns the spu ptr on which the context must run.
 */
struct spu* affinity_check(struct spu_context *ctx)
{
	struct spu_gang *gang;

	if (list_empty(&ctx->aff_list))
		return NULL;
	gang = ctx->gang;
	mutex_lock(&gang->aff_mutex);
	if (!gang->aff_ref_spu) {
		if (!(gang->aff_flags & AFF_MERGED))
			aff_merge_remaining_ctxs(gang);
		if (!(gang->aff_flags & AFF_OFFSETS_SET))
			aff_set_offsets(gang);
		aff_set_ref_point_location(gang);
	}
	mutex_unlock(&gang->aff_mutex);
	if (!gang->aff_ref_spu)
		return NULL;
	return ctx_location(gang->aff_ref_spu, ctx->aff_offset);
}
