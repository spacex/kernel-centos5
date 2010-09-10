#include <linux/utrace.h>
#include <linux/tracehook.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <asm/tracehook.h>


static struct kmem_cache *utrace_cachep;
static struct kmem_cache *utrace_engine_cachep;

static int __init
utrace_init(void)
{
	utrace_cachep =
		kmem_cache_create("utrace_cache",
				  sizeof(struct utrace), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	utrace_engine_cachep =
		kmem_cache_create("utrace_engine_cache",
				  sizeof(struct utrace_attached_engine), 0,
				  SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL, NULL);
	return 0;
}
subsys_initcall(utrace_init);


/*
 * Make sure target->utrace is allocated, and return with it locked on
 * success.  This function mediates startup races.  The creating parent
 * task has priority, and other callers will delay here to let its call
 * succeed and take the new utrace lock first.
 */
static struct utrace *
utrace_first_engine(struct task_struct *target,
		    struct utrace_attached_engine *engine)
{
	struct utrace *utrace, *ret;

	/*
	 * If this is a newborn thread and we are not the creator,
	 * we have to wait for it.  The creator gets the first chance
	 * to attach.  The PF_STARTING flag is cleared after its
	 * report_clone hook has had a chance to run.
	 */
	if ((target->flags & PF_STARTING)
	    && (current->utrace == NULL
		|| current->utrace->u.live.cloning != target)) {
		yield();
		return (signal_pending(current)
			? ERR_PTR(-ERESTARTNOINTR) : NULL);
	}

	utrace = kmem_cache_alloc(utrace_cachep, GFP_KERNEL);
	if (unlikely(utrace == NULL))
		return ERR_PTR(-ENOMEM);

	utrace->u.live.cloning = NULL;
	utrace->u.live.signal = NULL;
	INIT_LIST_HEAD(&utrace->engines);
	list_add(&engine->entry, &utrace->engines);
	spin_lock_init(&utrace->lock);

	ret = utrace;
	utrace_lock(utrace);
	task_lock(target);
	if (likely(target->utrace == NULL)) {
		rcu_assign_pointer(target->utrace, utrace);
		/*
		 * The task_lock protects us against another thread doing
		 * the same thing.  We might still be racing against
		 * tracehook_release_task.  It's called with ->exit_state
		 * set to EXIT_DEAD and then checks ->utrace with an
		 * smp_mb() in between.  If EXIT_DEAD is set, then
		 * release_task might have checked ->utrace already and saw
		 * it NULL; we can't attach.  If we see EXIT_DEAD not yet
		 * set after our barrier, then we know release_task will
		 * see our target->utrace pointer.
		 */
		smp_mb();
		if (target->exit_state == EXIT_DEAD) {
			/*
			 * The target has already been through release_task.
			 */
			target->utrace = NULL;
			goto cannot_attach;
		}
		task_unlock(target);
	}
	else {
		/*
		 * Another engine attached first, so there is a struct already.
		 * A null return says to restart looking for the existing one.
		 */
	cannot_attach:
		ret = NULL;
		task_unlock(target);
		utrace_unlock(utrace);
		kmem_cache_free(utrace_cachep, utrace);
	}

	return ret;
}

static void
utrace_free(struct rcu_head *rhead)
{
	struct utrace *utrace = container_of(rhead, struct utrace, u.dead);
	kmem_cache_free(utrace_cachep, utrace);
}

/*
 * Called with utrace locked.  Clean it up and free it via RCU.
 */
static void
rcu_utrace_free(struct utrace *utrace)
{
	utrace_unlock(utrace);
	INIT_RCU_HEAD(&utrace->u.dead);
	call_rcu(&utrace->u.dead, utrace_free);
}

static void
utrace_engine_free(struct rcu_head *rhead)
{
	struct utrace_attached_engine *engine =
		container_of(rhead, struct utrace_attached_engine, rhead);
	kmem_cache_free(utrace_engine_cachep, engine);
}

/*
 * Remove the utrace pointer from the task, unless there is a pending
 * forced signal (or it's quiescent in utrace_get_signal).
 */
static inline void
utrace_clear_tsk(struct task_struct *tsk, struct utrace *utrace)
{
	if (utrace->u.live.signal == NULL) {
		task_lock(tsk);
		if (likely(tsk->utrace != NULL)) {
			rcu_assign_pointer(tsk->utrace, NULL);
			tsk->utrace_flags &= UTRACE_ACTION_NOREAP;
		}
		task_unlock(tsk);
	}
}

/*
 * Called with utrace locked and the target quiescent (maybe current).
 * If this was the last engine and there is no parting forced signal
 * pending, utrace is left locked and not freed, but is removed from the task.
 */
static void
remove_engine(struct utrace_attached_engine *engine,
	      struct task_struct *tsk, struct utrace *utrace)
{
	list_del_rcu(&engine->entry);
	if (list_empty(&utrace->engines))
		utrace_clear_tsk(tsk, utrace);
	call_rcu(&engine->rhead, utrace_engine_free);
}


/*
 * Called with utrace locked, after remove_engine may have run.
 * Passed the flags from all remaining engines, i.e. zero if none
 * left.  Install the flags in tsk->utrace_flags and return with
 * utrace unlocked.  If no engines are left and there is no parting
 * forced signal pending, utrace is freed.
 */
static void
check_dead_utrace(struct task_struct *tsk, struct utrace *utrace,
		  unsigned long flags)
{
	long exit_state = 0;

	if (!tsk->exit_state && utrace->u.live.signal != NULL)
		/*
		 * There is a pending forced signal.  It may have been
		 * left by an engine now detached.  The empty utrace
		 * remains attached until it can be processed.
		 */
		flags |= UTRACE_ACTION_QUIESCE;

	/*
	 * If tracing was preventing a SIGCHLD or self-reaping
	 * and is no longer, we'll do that report or reaping now.
	 */
	if (((tsk->utrace_flags &~ flags) & UTRACE_ACTION_NOREAP)
	    && tsk->exit_state) {
		BUG_ON(tsk->exit_state != EXIT_ZOMBIE);
		/*
		 * While holding the utrace lock, mark that it's been done.
		 * For self-reaping, we need to change tsk->exit_state
		 * before clearing tsk->utrace_flags, so that the real
		 * parent can't see it in EXIT_ZOMBIE momentarily and reap it.
		 */
		if (tsk->exit_signal == -1) {
			exit_state = xchg(&tsk->exit_state, EXIT_DEAD);
			BUG_ON(exit_state != EXIT_ZOMBIE);
			exit_state = EXIT_DEAD;

			/*
			 * Now that we've changed its state to DEAD,
			 * it's safe to install the new tsk->utrace_flags
			 * value without the UTRACE_ACTION_NOREAP bit set.
			 */
		}
		else if (thread_group_empty(tsk)) {
			/*
			 * We need to prevent the real parent from reaping
			 * until after we've called do_notify_parent, below.
			 * It can get into wait_task_zombie any time after
			 * the UTRACE_ACTION_NOREAP bit is cleared.  It's
			 * safe for that to do everything it does until its
			 * release_task call starts tearing things down.
			 * Holding tasklist_lock for reading prevents
			 * release_task from proceeding until we've done
			 * everything we need to do.
			 */
			exit_state = EXIT_ZOMBIE;
			read_lock(&tasklist_lock);
		}
	}

	tsk->utrace_flags = flags;
	if (flags)
		utrace_unlock(utrace);
	else {
		rcu_utrace_free(utrace);
		utrace = NULL;
	}

	/*
	 * Now we're finished updating the utrace state.
	 * Do a pending self-reaping or parent notification.
	 */
	if (exit_state == EXIT_DEAD)
		/*
		 * Note this can wind up in utrace_reap and do more callbacks.
		 * Our callers must be in places where that is OK.
		 */
		release_task(tsk);
	else if (exit_state == EXIT_ZOMBIE) {
		do_notify_parent(tsk, tsk->exit_signal);
		read_unlock(&tasklist_lock); /* See comment above.  */
	}
}



/*
 * Get the target thread to quiesce.  Return nonzero if it's already quiescent.
 * Return zero if it will report a QUIESCE event soon.
 * If interrupt is nonzero, wake it like a signal would so it quiesces ASAP.
 * If interrupt is zero, just make sure it quiesces before going to user mode.
 */
static int
quiesce(struct task_struct *target, int interrupt)
{
	int quiescent;

	target->utrace_flags |= UTRACE_ACTION_QUIESCE;
	read_barrier_depends();

	quiescent = (target->exit_state
		     || target->state & (TASK_TRACED | TASK_STOPPED));

	if (!quiescent) {
		spin_lock_irq(&target->sighand->siglock);
		quiescent = (unlikely(target->exit_state)
			     || unlikely(target->state
					 & (TASK_TRACED | TASK_STOPPED)));
		if (!quiescent) {
			if (interrupt)
				signal_wake_up(target, 0);
			else {
				set_tsk_thread_flag(target, TIF_SIGPENDING);
				kick_process(target);
			}
		}
		spin_unlock_irq(&target->sighand->siglock);
	}

	return quiescent;
}


static struct utrace_attached_engine *
matching_engine(struct utrace *utrace, int flags,
		const struct utrace_engine_ops *ops, unsigned long data)
{
	struct utrace_attached_engine *engine;
	list_for_each_entry_rcu(engine, &utrace->engines, entry) {
		if ((flags & UTRACE_ATTACH_MATCH_OPS)
		    && engine->ops != ops)
			continue;
		if ((flags & UTRACE_ATTACH_MATCH_DATA)
		    && engine->data != data)
			continue;
		return engine;
	}
	return ERR_PTR(-ENOENT);
}

/*
  option to stop it?
  option to match existing on ops, ops+data, return it; nocreate:lookup only
 */
struct utrace_attached_engine *
utrace_attach(struct task_struct *target, int flags,
	     const struct utrace_engine_ops *ops, unsigned long data)
{
	struct utrace *utrace;
	struct utrace_attached_engine *engine;

restart:
	rcu_read_lock();
	utrace = rcu_dereference(target->utrace);
	smp_rmb();
	if (utrace == NULL) {
		rcu_read_unlock();

		if (!(flags & UTRACE_ATTACH_CREATE)) {
			return ERR_PTR(-ENOENT);
		}

		engine = kmem_cache_alloc(utrace_engine_cachep, GFP_KERNEL);
		if (unlikely(engine == NULL))
			return ERR_PTR(-ENOMEM);
		engine->flags = 0;

	first:
		utrace = utrace_first_engine(target, engine);
		if (IS_ERR(utrace)) {
			kmem_cache_free(utrace_engine_cachep, engine);
			return ERR_PTR(PTR_ERR(utrace));
		}
		if (unlikely(utrace == NULL)) /* Race condition.  */
			goto restart;
	}
	else if (unlikely(target->exit_state == EXIT_DEAD)) {
		/*
		 * The target has already been reaped.
		 */
		rcu_read_unlock();
		return ERR_PTR(-ESRCH);
	}
	else {
		if (!(flags & UTRACE_ATTACH_CREATE)) {
			engine = matching_engine(utrace, flags, ops, data);
			rcu_read_unlock();
			return engine;
		}
		rcu_read_unlock();

		engine = kmem_cache_alloc(utrace_engine_cachep, GFP_KERNEL);
		if (unlikely(engine == NULL))
			return ERR_PTR(-ENOMEM);
		engine->flags = 0;

		rcu_read_lock();
		utrace = rcu_dereference(target->utrace);
		if (unlikely(utrace == NULL)) { /* Race with detach.  */
			rcu_read_unlock();
			goto first;
		}
		utrace_lock(utrace);

		if (flags & UTRACE_ATTACH_EXCLUSIVE) {
			struct utrace_attached_engine *old;
			old = matching_engine(utrace, flags, ops, data);
			if (!IS_ERR(old)) {
				utrace_unlock(utrace);
				rcu_read_unlock();
				kmem_cache_free(utrace_engine_cachep, engine);
				return ERR_PTR(-EEXIST);
			}
		}

		if (unlikely(rcu_dereference(target->utrace) != utrace)) {
			/*
			 * We lost a race with other CPUs doing a sequence
			 * of detach and attach before we got in.
			 */
			utrace_unlock(utrace);
			rcu_read_unlock();
			kmem_cache_free(utrace_engine_cachep, engine);
			goto restart;
		}
		rcu_read_unlock();

		list_add_tail_rcu(&engine->entry, &utrace->engines);
	}

	engine->ops = ops;
	engine->data = data;

	utrace_unlock(utrace);

	return engine;
}
EXPORT_SYMBOL_GPL(utrace_attach);

/*
 * When an engine is detached, the target thread may still see it and make
 * callbacks until it quiesces.  We reset its event flags to just QUIESCE
 * and install a special ops vector whose callback is dead_engine_delete.
 * When the target thread quiesces, it can safely free the engine itself.
 */
static u32
dead_engine_delete(struct utrace_attached_engine *engine,
		   struct task_struct *tsk)
{
	return UTRACE_ACTION_DETACH;
}

static const struct utrace_engine_ops dead_engine_ops =
{
	.report_quiesce = &dead_engine_delete
};


/*
 * Called with utrace locked.  Recompute the union of engines' flags.
 */
static inline unsigned long
rescan_flags(struct utrace *utrace)
{
	struct utrace_attached_engine *engine;
	unsigned long flags = 0;
	list_for_each_entry(engine, &utrace->engines, entry)
		flags |= engine->flags | UTRACE_EVENT(REAP);
	return flags;
}

/*
 * Only these flags matter any more for a dead task (exit_state set).
 * We use this mask on flags installed in ->utrace_flags after
 * exit_notify (and possibly utrace_report_death) has run.
 * This ensures that utrace_release_task knows positively that
 * utrace_report_death will not run later.
 */
#define DEAD_FLAGS_MASK	(UTRACE_EVENT(REAP) | UTRACE_ACTION_NOREAP)

/*
 * We may have been the one keeping the target thread quiescent.
 * Check if it should wake up now.
 * Called with utrace locked, and unlocks it on return.
 * If we were keeping it stopped, resume it.
 * If we were keeping its zombie from reporting/self-reap, do it now.
 */
static void
wake_quiescent(unsigned long old_flags,
	       struct utrace *utrace, struct task_struct *target)
{
	unsigned long flags;

	/*
	 * Update the set of events of interest from the union
	 * of the interests of the remaining tracing engines.
	 */
	flags = rescan_flags(utrace);
	if (target->exit_state) {
		BUG_ON(utrace->u.exit.report_death);
		flags &= DEAD_FLAGS_MASK;
	}
	check_dead_utrace(target, utrace, flags);

	if (target->exit_state || (flags & UTRACE_ACTION_QUIESCE))
		return;

	read_lock(&tasklist_lock);
	if (!unlikely(target->exit_state)) {
		/*
		 * The target is not dead and should not be in tracing stop
		 * any more.  Wake it unless it's in job control stop.
		 */
		spin_lock_irq(&target->sighand->siglock);
		if (target->signal->flags & SIGNAL_STOP_STOPPED) {
			int stop_count = target->signal->group_stop_count;
			target->state = TASK_STOPPED;
			spin_unlock_irq(&target->sighand->siglock);

			/*
			 * If tracing was preventing a CLD_STOPPED report
			 * and is no longer, do that report right now.
			 */
			if (stop_count == 0
			    && ((old_flags &~ flags) & UTRACE_ACTION_NOREAP))
				do_notify_parent_cldstop(target, CLD_STOPPED);
		}
		else {
			/*
			 * Wake the task up.
			 */
			recalc_sigpending_tsk(target);
			wake_up_state(target, TASK_STOPPED | TASK_TRACED);
			spin_unlock_irq(&target->sighand->siglock);
		}
	}
	read_unlock(&tasklist_lock);
}

/*
 * The engine is supposed to be attached.  The caller really needs
 * rcu_read_lock if it wants to look at the engine struct
 * (e.g. engine->data), to be sure it hasn't been freed by utrace_reap
 * asynchronously--unless he has synchronized with his report_reap
 * callback, which would have happened before then.  A simultaneous
 * utrace_detach call or UTRACE_ACTION_DETACH return from a callback can
 * also free the engine if rcu_read_lock is not held, but that is in the
 * tracing engine's power to avoid.
 *
 * Get the utrace lock for the target task.
 * Returns the struct if locked, or ERR_PTR(-errno).
 *
 * This has to be robust against races with:
 *	utrace_detach calls
 *	UTRACE_ACTION_DETACH after reports
 *	utrace_report_death
 *	utrace_release_task
 */
static struct utrace *
get_utrace_lock_attached(struct task_struct *target,
			 struct utrace_attached_engine *engine)
{
	struct utrace *utrace;

	rcu_read_lock();
	utrace = rcu_dereference(target->utrace);
	smp_rmb();
	if (unlikely(target->exit_state == EXIT_DEAD)) {
		/*
		 * Called after utrace_release_task might have started.
		 * A call to this engine's report_reap callback might
		 * already be in progress or engine might even have been
		 * freed already.
		 */
		utrace = ERR_PTR(-ESRCH);
	}
	else {
		utrace_lock(utrace);
		if (unlikely(rcu_dereference(target->utrace) != utrace)
		    || unlikely(rcu_dereference(engine->ops)
				== &dead_engine_ops)) {
			/*
			 * By the time we got the utrace lock,
			 * it had been reaped or detached already.
			 */
			utrace_unlock(utrace);
			utrace = ERR_PTR(-ESRCH);
		}
	}
	rcu_read_unlock();

	return utrace;
}

int
utrace_detach(struct task_struct *target,
	      struct utrace_attached_engine *engine)
{
	struct utrace *utrace;
	unsigned long flags;

	utrace = get_utrace_lock_attached(target, engine);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

	if (target->exit_state
	    && unlikely(utrace->u.exit.reap || utrace->u.exit.report_death)) {
		/*
		 * We have already started the death report, or
		 * even entered release_task.  We can't prevent
		 * the report_death and report_reap callbacks,
		 * so tell the caller they will happen.
		 */
		int ret = utrace->u.exit.reap ? -ESRCH : -EALREADY;
		utrace_unlock(utrace);
		return ret;
	}

	flags = engine->flags;
	engine->flags = UTRACE_EVENT(QUIESCE) | UTRACE_ACTION_QUIESCE;
	rcu_assign_pointer(engine->ops, &dead_engine_ops);

	if (quiesce(target, 1)) {
		remove_engine(engine, target, utrace);
		wake_quiescent(flags, utrace, target);
	}
	else
		utrace_unlock(utrace);


	return 0;
}
EXPORT_SYMBOL_GPL(utrace_detach);


/*
 * Called with utrace->lock held.
 * Notify and clean up all engines, then free utrace.
 */
static void
utrace_reap(struct task_struct *target, struct utrace *utrace)
{
	struct utrace_attached_engine *engine, *next;
	const struct utrace_engine_ops *ops;

restart:
	list_for_each_entry_safe(engine, next, &utrace->engines, entry) {
		list_del_rcu(&engine->entry);

		/*
		 * Now nothing else refers to this engine.
		 */
		if (engine->flags & UTRACE_EVENT(REAP)) {
			ops = rcu_dereference(engine->ops);
			if (ops != &dead_engine_ops) {
				utrace_unlock(utrace);
				(*ops->report_reap)(engine, target);
				call_rcu(&engine->rhead, utrace_engine_free);
				utrace_lock(utrace);
				goto restart;
			}
		}
		call_rcu(&engine->rhead, utrace_engine_free);
	}

	rcu_utrace_free(utrace);
}

/*
 * Called by release_task.  After this, target->utrace must be cleared.
 */
void
utrace_release_task(struct task_struct *target)
{
	struct utrace *utrace;

	task_lock(target);
	utrace = target->utrace;
	rcu_assign_pointer(target->utrace, NULL);
	task_unlock(target);

	if (unlikely(utrace == NULL))
		return;

	utrace_lock(utrace);
	utrace->u.exit.reap = 1;

	if (target->utrace_flags & (UTRACE_EVENT(DEATH)
				    | UTRACE_EVENT(QUIESCE)))
		/*
		 * The target will do some final callbacks but hasn't
		 * finished them yet.  We know because it clears these
		 * event bits after it's done.  Instead of cleaning up here
		 * and requiring utrace_report_death to cope with it, we
		 * delay the REAP report and the teardown until after the
		 * target finishes its death reports.
		 */
		utrace_unlock(utrace);
	else
		utrace_reap(target, utrace); /* Unlocks and frees.  */
}


int
utrace_set_flags(struct task_struct *target,
		 struct utrace_attached_engine *engine,
		 unsigned long flags)
{
	struct utrace *utrace;
	int report;
	unsigned long old_flags, old_utrace_flags;
	int ret = -EALREADY;

#ifdef ARCH_HAS_SINGLE_STEP
	if (! ARCH_HAS_SINGLE_STEP)
#endif
		WARN_ON(flags & UTRACE_ACTION_SINGLESTEP);
#ifdef ARCH_HAS_BLOCK_STEP
	if (! ARCH_HAS_BLOCK_STEP)
#endif
		WARN_ON(flags & UTRACE_ACTION_BLOCKSTEP);

	utrace = get_utrace_lock_attached(target, engine);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

restart:			/* See below. */

	old_utrace_flags = target->utrace_flags;
	old_flags = engine->flags;

	if (target->exit_state
	    && (((flags &~ old_flags) & (UTRACE_ACTION_QUIESCE
					 | UTRACE_ACTION_NOREAP
					 | UTRACE_EVENT(DEATH)
					 | UTRACE_EVENT(QUIESCE)))
		|| (utrace->u.exit.report_death
		    && ((old_flags &~ flags) & (UTRACE_EVENT(DEATH) |
						UTRACE_EVENT(QUIESCE))))
		|| (utrace->u.exit.reap
		    && ((old_flags &~ flags) & UTRACE_EVENT(REAP))))) {
		utrace_unlock(utrace);
		return ret;
	}

	/*
	 * When setting these flags, it's essential that we really
	 * synchronize with exit_notify.  They cannot be set after
	 * exit_notify takes the tasklist_lock.  By holding the read
	 * lock here while setting the flags, we ensure that the calls
	 * to tracehook_notify_death and tracehook_report_death will
	 * see the new flags.  This ensures that utrace_release_task
	 * knows positively that utrace_report_death will be called or
	 * that it won't.
	 */
	if ((flags &~ old_utrace_flags) & (UTRACE_ACTION_NOREAP
					   | UTRACE_EVENT(DEATH)
					   | UTRACE_EVENT(QUIESCE))) {
		read_lock(&tasklist_lock);
		if (unlikely(target->exit_state)) {
			read_unlock(&tasklist_lock);
			utrace_unlock(utrace);
			return ret;
		}
		target->utrace_flags |= flags;
		read_unlock(&tasklist_lock);
	}

	engine->flags = flags;
	target->utrace_flags |= flags;
	ret = 0;

	report = 0;
	if ((old_flags ^ flags) & UTRACE_ACTION_QUIESCE) {
		if (flags & UTRACE_ACTION_QUIESCE) {
			report = (quiesce(target, 1)
				  && (flags & UTRACE_EVENT(QUIESCE)));
			utrace_unlock(utrace);
		}
		else
			wake_quiescent(old_flags, utrace, target);
	}
	else if (((old_flags &~ flags) & UTRACE_ACTION_NOREAP)
		 && target->exit_state)
			wake_quiescent(old_flags, utrace, target);
	else {
		/*
		 * If we're asking for single-stepping or syscall tracing,
		 * we need to pass through utrace_quiescent before resuming
		 * in user mode to get those effects, even if the target is
		 * not going to be quiescent right now.
		 */
		if (!(target->utrace_flags & UTRACE_ACTION_QUIESCE)
		    && !target->exit_state
		    && ((flags &~ old_utrace_flags)
			& (UTRACE_ACTION_SINGLESTEP | UTRACE_ACTION_BLOCKSTEP
			   | UTRACE_EVENT_SYSCALL)))
			quiesce(target, 0);
		utrace_unlock(utrace);
	}

	if (report) {	/* Already quiescent, won't report itself.  */
		u32 action = (*engine->ops->report_quiesce)(engine, target);
		if (action & UTRACE_ACTION_DETACH)
			utrace_detach(target, engine);
		else if (action & UTRACE_ACTION_NEWSTATE) {
			/*
			 * The callback has us changing the flags yet
			 * again.  Since we released the lock, they
			 * could have changed asynchronously just now.
			 * We must refetch the current flags to change
			 * the UTRACE_ACTION_STATE_MASK bits.  If the
			 * target thread started dying, then there is
			 * nothing we can do--but that failure is due
			 * to the report_quiesce callback after the
			 * original utrace_set_flags has already
			 * succeeded, so we don't want to return
			 * failure here (hence leave ret = 0).
			 */
			utrace = get_utrace_lock_attached(target, engine);
			if (!unlikely(IS_ERR(utrace))) {
				flags = action & UTRACE_ACTION_STATE_MASK;
				flags |= (engine->flags
					  &~ UTRACE_ACTION_STATE_MASK);
				goto restart;
			}
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_set_flags);

/*
 * While running an engine callback, no locks are held.
 * If a callback updates its engine's action state, then
 * we need to take the utrace lock to install the flags update.
 */
static inline u32
update_action(struct task_struct *tsk, struct utrace *utrace,
	      struct utrace_attached_engine *engine,
	      u32 ret)
{
	if (ret & UTRACE_ACTION_DETACH)
		rcu_assign_pointer(engine->ops, &dead_engine_ops);
	else if ((ret & UTRACE_ACTION_NEWSTATE)
		 && ((ret ^ engine->flags) & UTRACE_ACTION_STATE_MASK)) {
#ifdef ARCH_HAS_SINGLE_STEP
		if (! ARCH_HAS_SINGLE_STEP)
#endif
			WARN_ON(ret & UTRACE_ACTION_SINGLESTEP);
#ifdef ARCH_HAS_BLOCK_STEP
		if (! ARCH_HAS_BLOCK_STEP)
#endif
			WARN_ON(ret & UTRACE_ACTION_BLOCKSTEP);
		utrace_lock(utrace);
		/*
		 * If we're changing something other than just QUIESCE,
		 * make sure we pass through utrace_quiescent before
		 * resuming even if we aren't going to stay quiescent.
		 * That's where we get the correct union of all engines'
		 * flags after they've finished changing, and apply changes.
		 */
		if (((ret ^ engine->flags) & (UTRACE_ACTION_STATE_MASK
					      & ~UTRACE_ACTION_QUIESCE)))
			tsk->utrace_flags |= UTRACE_ACTION_QUIESCE;
		engine->flags &= ~UTRACE_ACTION_STATE_MASK;
		engine->flags |= ret & UTRACE_ACTION_STATE_MASK;
		tsk->utrace_flags |= engine->flags;
		utrace_unlock(utrace);
	}
	else
		ret |= engine->flags & UTRACE_ACTION_STATE_MASK;
	return ret;
}

#define REPORT(callback, ...) do { \
	u32 ret = (*rcu_dereference(engine->ops)->callback) \
		(engine, tsk, ##__VA_ARGS__); \
	action = update_action(tsk, utrace, engine, ret); \
	} while (0)


/*
 * Called with utrace->lock held, returns with it released.
 */
static u32
remove_detached(struct task_struct *tsk, struct utrace *utrace,
		u32 action, unsigned long mask)
{
	struct utrace_attached_engine *engine, *next;
	unsigned long flags = 0;

	list_for_each_entry_safe(engine, next, &utrace->engines, entry) {
		if (engine->ops == &dead_engine_ops)
			remove_engine(engine, tsk, utrace);
		else
			flags |= engine->flags | UTRACE_EVENT(REAP);
	}
	check_dead_utrace(tsk, utrace, flags & mask);

	flags &= UTRACE_ACTION_STATE_MASK;
	return flags | (action & UTRACE_ACTION_OP_MASK);
}

/*
 * Called after an event report loop.  Remove any engines marked for detach.
 */
static inline u32
check_detach(struct task_struct *tsk, u32 action)
{
	if (action & UTRACE_ACTION_DETACH) {
		/*
		 * This must be current to be sure it's not possibly
		 * getting into utrace_report_death.
		 */
		BUG_ON(tsk != current);
		utrace_lock(tsk->utrace);
		action = remove_detached(tsk, tsk->utrace, action, ~0UL);
	}
	return action;
}

static inline int
check_quiescent(struct task_struct *tsk, u32 action)
{
	if (action & UTRACE_ACTION_STATE_MASK)
		return utrace_quiescent(tsk, NULL);
	return 0;
}

/*
 * Called iff UTRACE_EVENT(CLONE) flag is set.
 * This notification call blocks the wake_up_new_task call on the child.
 * So we must not quiesce here.  tracehook_report_clone_complete will do
 * a quiescence check momentarily.
 */
void
utrace_report_clone(unsigned long clone_flags, struct task_struct *child)
{
	struct task_struct *tsk = current;
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	unsigned long action;

	utrace->u.live.cloning = child;

	/* XXX must change for sharing */
	action = UTRACE_ACTION_RESUME;
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(CLONE))
			REPORT(report_clone, clone_flags, child);
		if (action & UTRACE_ACTION_HIDE)
			break;
	}

	utrace->u.live.cloning = NULL;

	check_detach(tsk, action);
}

static unsigned long
report_quiescent(struct task_struct *tsk, struct utrace *utrace, u32 action)
{
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;

	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(QUIESCE))
			REPORT(report_quiesce);
		action |= engine->flags & UTRACE_ACTION_STATE_MASK;
	}

	return check_detach(tsk, action);
}

/*
 * Called iff UTRACE_EVENT(JCTL) flag is set.
 */
int
utrace_report_jctl(int what)
{
	struct task_struct *tsk = current;
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	unsigned long action;

	/* XXX must change for sharing */
	action = UTRACE_ACTION_RESUME;
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(JCTL))
			REPORT(report_jctl, what);
		if (action & UTRACE_ACTION_HIDE)
			break;
	}

	/*
	 * We are becoming quiescent, so report it now.
	 * We don't block in utrace_quiescent because we are stopping anyway.
	 * We know that upon resuming we'll go through tracehook_induce_signal,
	 * which will keep us quiescent or set us up to resume with tracing.
	 */
	action = report_quiescent(tsk, utrace, action);

	if (what == CLD_STOPPED && tsk->state != TASK_STOPPED) {
		/*
		 * The event report hooks could have blocked, though
		 * it should have been briefly.  Make sure we're in
		 * TASK_STOPPED state again to block properly, unless
		 * we've just come back out of job control stop.
		 */
		spin_lock_irq(&tsk->sighand->siglock);
		if (tsk->signal->flags & SIGNAL_STOP_STOPPED)
			set_current_state(TASK_STOPPED);
		spin_unlock_irq(&tsk->sighand->siglock);
	}

	return action & UTRACE_JCTL_NOSIGCHLD;
}


/*
 * Return nonzero if there is a SIGKILL that should be waking us up.
 * Called with the siglock held.
 */
static inline int
sigkill_pending(struct task_struct *tsk)
{
	return ((sigismember(&tsk->pending.signal, SIGKILL)
		 || sigismember(&tsk->signal->shared_pending.signal, SIGKILL))
		&& !unlikely(sigismember(&tsk->blocked, SIGKILL)));
}

/*
 * Called if UTRACE_EVENT(QUIESCE) or UTRACE_ACTION_QUIESCE flag is set.
 * Also called after other event reports.
 * It is a good time to block.
 * Returns nonzero if we woke up prematurely due to SIGKILL.
 *
 * The signal pointer is nonzero when called from utrace_get_signal,
 * where a pending forced signal can be processed right away.  Otherwise,
 * we keep UTRACE_ACTION_QUIESCE set after resuming so that utrace_get_signal
 * will be entered before user mode.
 */
int
utrace_quiescent(struct task_struct *tsk, struct utrace_signal *signal)
{
	struct utrace *utrace = tsk->utrace;
	unsigned long action;

restart:
	/* XXX must change for sharing */

	action = report_quiescent(tsk, utrace, UTRACE_ACTION_RESUME);

	/*
	 * If some engines want us quiescent, we block here.
	 */
	if (action & UTRACE_ACTION_QUIESCE) {
		int killed;

		if (signal != NULL) {
			BUG_ON(utrace->u.live.signal != NULL);
			utrace->u.live.signal = signal;
		}

		spin_lock_irq(&tsk->sighand->siglock);
		/*
		 * If wake_quiescent is trying to wake us up now, it will
		 * have cleared the QUIESCE flag before trying to take the
		 * siglock.  Now we have the siglock, so either it has
		 * already cleared the flag, or it will wake us up after we
		 * release the siglock it's waiting for.
		 * Never stop when there is a SIGKILL bringing us down.
		 */
		killed = sigkill_pending(tsk);
		if (!killed && (tsk->utrace_flags & UTRACE_ACTION_QUIESCE)) {
			set_current_state(TASK_TRACED);
			/*
			 * If there is a group stop in progress,
			 * we must participate in the bookkeeping.
			 */
			if (tsk->signal->group_stop_count > 0)
				--tsk->signal->group_stop_count;
			spin_unlock_irq(&tsk->sighand->siglock);
			schedule();
		}
		else
			spin_unlock_irq(&tsk->sighand->siglock);

		if (signal != NULL) {
			/*
			 * We know the struct stays in place when its
			 * u.live.signal is set, see check_dead_utrace.
			 * This makes it safe to clear its pointer here.
			 */
			BUG_ON(tsk->utrace != utrace);
			BUG_ON(utrace->u.live.signal != signal);
			utrace->u.live.signal = NULL;
		}

		if (killed)	/* Game over, man!  */
			return 1;

		/*
		 * We've woken up.  One engine could be waking us up while
		 * another has asked us to quiesce.  So check afresh.  We
		 * could have been detached while quiescent.  Now we are no
		 * longer quiescent, so don't need to do any RCU locking.
		 * But we do need to check our utrace pointer anew.
		 */
		utrace = tsk->utrace;
		if (tsk->utrace_flags
		    & (UTRACE_EVENT(QUIESCE) | UTRACE_ACTION_STATE_MASK))
			goto restart;
	}
	else if (tsk->utrace_flags & UTRACE_ACTION_QUIESCE) {
		/*
		 * Our flags are out of date.
		 * Update the set of events of interest from the union
		 * of the interests of the remaining tracing engines.
		 * This may notice that there are no engines left
		 * and clean up the struct utrace.  It's left in place
		 * and the QUIESCE flag set as long as utrace_get_signal
		 * still needs to process a pending forced signal.
		 */
		unsigned long flags;
		utrace = rcu_dereference(tsk->utrace);
		utrace_lock(utrace);
		flags = rescan_flags(utrace);
		if (flags == 0)
			utrace_clear_tsk(tsk, utrace);
		check_dead_utrace(tsk, utrace, flags);
	}

	/*
	 * We're resuming.  Update the machine layer tracing state and then go.
	 */
#ifdef ARCH_HAS_SINGLE_STEP
	if (action & UTRACE_ACTION_SINGLESTEP)
		tracehook_enable_single_step(tsk);
	else
		tracehook_disable_single_step(tsk);
#endif
#ifdef ARCH_HAS_BLOCK_STEP
	if ((action & (UTRACE_ACTION_BLOCKSTEP|UTRACE_ACTION_SINGLESTEP))
	    == UTRACE_ACTION_BLOCKSTEP)
		tracehook_enable_block_step(tsk);
	else
		tracehook_disable_block_step(tsk);
#endif
	if (tsk->utrace_flags & UTRACE_EVENT_SYSCALL)
		tracehook_enable_syscall_trace(tsk);
	else
		tracehook_disable_syscall_trace(tsk);

	return 0;
}


/*
 * Called iff UTRACE_EVENT(EXIT) flag is set.
 */
void
utrace_report_exit(long *exit_code)
{
	struct task_struct *tsk = current;
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	unsigned long action;
	long orig_code = *exit_code;

	/* XXX must change for sharing */
	action = UTRACE_ACTION_RESUME;
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(EXIT))
			REPORT(report_exit, orig_code, exit_code);
	}
	action = check_detach(tsk, action);
	check_quiescent(tsk, action);
}

/*
 * Called iff UTRACE_EVENT(DEATH) or UTRACE_ACTION_QUIESCE flag is set.
 *
 * It is always possible that we are racing with utrace_release_task here,
 * if UTRACE_ACTION_NOREAP is not set, or in the case of non-leader exec
 * where the old leader will get released regardless of NOREAP.  For this
 * reason, utrace_release_task checks for the event bits that get us here,
 * and delays its cleanup for us to do.
 */
void
utrace_report_death(struct task_struct *tsk, struct utrace *utrace)
{
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	u32 action;

	BUG_ON(!tsk->exit_state);

	/*
	 * We are presently considered "quiescent"--which is accurate
	 * inasmuch as we won't run any more user instructions ever again.
	 * But for utrace_detach and utrace_set_flags to be robust, they
	 * must be sure whether or not we will run any more callbacks.  If
	 * a call comes in before we do, taking the lock here synchronizes
	 * us so we don't run any callbacks just disabled.  Calls that come
	 * in while we're running the callbacks will see the report_death
	 * flag and know that we are not yet fully quiescent for purposes
	 * of detach bookkeeping.
	 */
	utrace_lock(utrace);
	BUG_ON(utrace->u.exit.report_death);
	utrace->u.exit.report_death = 1;
	utrace_unlock(utrace);

	/* XXX must change for sharing */
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(DEATH))
			REPORT(report_death);
		if (engine->flags & UTRACE_EVENT(QUIESCE))
			REPORT(report_quiesce);
	}

	/*
	 * Unconditionally lock and recompute the flags.
	 * This may notice that there are no engines left and
	 * free the utrace struct.
	 */
	utrace_lock(utrace);

	/*
	 * After we unlock (possibly inside utrace_reap for callbacks) with
	 * this flag clear, competing utrace_detach/utrace_set_flags calls
	 * know that we've finished our callbacks and any detach bookkeeping.
	 */
	utrace->u.exit.report_death = 0;

	if (utrace->u.exit.reap)
		/*
		 * utrace_release_task was already called in parallel.
		 * We must complete its work now.
		 */
		utrace_reap(tsk, utrace);
	else
		/*
		 * Clear out any detached engines and in the process
		 * recompute the flags.  Mask off event bits we can't
		 * see any more.  This tells utrace_release_task we
		 * have already finished, if it comes along later.
		 * Note this all happens on the already-locked utrace,
		 * which might already be removed from the task.
		 */
		remove_detached(tsk, utrace, 0, DEAD_FLAGS_MASK);
}

/*
 * Called iff UTRACE_EVENT(VFORK_DONE) flag is set.
 */
void
utrace_report_vfork_done(pid_t child_pid)
{
	struct task_struct *tsk = current;
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	unsigned long action;

	/* XXX must change for sharing */
	action = UTRACE_ACTION_RESUME;
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(VFORK_DONE))
			REPORT(report_vfork_done, child_pid);
		if (action & UTRACE_ACTION_HIDE)
			break;
	}
	action = check_detach(tsk, action);
	check_quiescent(tsk, action);
}

/*
 * Called iff UTRACE_EVENT(EXEC) flag is set.
 */
void
utrace_report_exec(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	unsigned long action;

	/* XXX must change for sharing */
	action = UTRACE_ACTION_RESUME;
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & UTRACE_EVENT(EXEC))
			REPORT(report_exec, bprm, regs);
		if (action & UTRACE_ACTION_HIDE)
			break;
	}
	action = check_detach(tsk, action);
	check_quiescent(tsk, action);
}

/*
 * Called iff UTRACE_EVENT(SYSCALL_{ENTRY,EXIT}) flag is set.
 */
void
utrace_report_syscall(struct pt_regs *regs, int is_exit)
{
	struct task_struct *tsk = current;
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	unsigned long action, ev;

/*
  XXX pass syscall # to engine hook directly, let it return inhibit-action
  to reset to -1
	long syscall = tracehook_syscall_number(regs, is_exit);
*/

	ev = is_exit ? UTRACE_EVENT(SYSCALL_EXIT) : UTRACE_EVENT(SYSCALL_ENTRY);

	/* XXX must change for sharing */
	action = UTRACE_ACTION_RESUME;
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if (engine->flags & ev) {
			if (is_exit)
				REPORT(report_syscall_exit, regs);
			else
				REPORT(report_syscall_entry, regs);
		}
		if (action & UTRACE_ACTION_HIDE)
			break;
	}
	action = check_detach(tsk, action);
	if (unlikely(check_quiescent(tsk, action)) && !is_exit)
		/*
		 * We are continuing despite QUIESCE because of a SIGKILL.
		 * Don't let the system call actually proceed.
		 */
		tracehook_abort_syscall(regs);
}


/*
 * This is pointed to by the utrace struct, but it's really a private
 * structure between utrace_get_signal and utrace_inject_signal.
 */
struct utrace_signal
{
	siginfo_t *const info;
	struct k_sigaction *return_ka;
	int signr;
};


// XXX copied from signal.c
#ifdef SIGEMT
#define M_SIGEMT	M(SIGEMT)
#else
#define M_SIGEMT	0
#endif

#if SIGRTMIN > BITS_PER_LONG
#define M(sig) (1ULL << ((sig)-1))
#else
#define M(sig) (1UL << ((sig)-1))
#endif
#define T(sig, mask) (M(sig) & (mask))

#define SIG_KERNEL_ONLY_MASK (\
	M(SIGKILL)   |  M(SIGSTOP)                                   )

#define SIG_KERNEL_STOP_MASK (\
	M(SIGSTOP)   |  M(SIGTSTP)   |  M(SIGTTIN)   |  M(SIGTTOU)   )

#define SIG_KERNEL_COREDUMP_MASK (\
        M(SIGQUIT)   |  M(SIGILL)    |  M(SIGTRAP)   |  M(SIGABRT)   | \
        M(SIGFPE)    |  M(SIGSEGV)   |  M(SIGBUS)    |  M(SIGSYS)    | \
        M(SIGXCPU)   |  M(SIGXFSZ)   |  M_SIGEMT                     )

#define SIG_KERNEL_IGNORE_MASK (\
        M(SIGCONT)   |  M(SIGCHLD)   |  M(SIGWINCH)  |  M(SIGURG)    )

#define sig_kernel_only(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_ONLY_MASK))
#define sig_kernel_coredump(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_COREDUMP_MASK))
#define sig_kernel_ignore(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_IGNORE_MASK))
#define sig_kernel_stop(sig) \
		(((sig) < SIGRTMIN)  && T(sig, SIG_KERNEL_STOP_MASK))


/*
 * Call each interested tracing engine's report_signal callback.
 */
static u32
report_signal(struct task_struct *tsk, struct pt_regs *regs,
	      struct utrace *utrace, u32 action,
	      unsigned long flags1, unsigned long flags2, siginfo_t *info,
	      const struct k_sigaction *ka, struct k_sigaction *return_ka)
{
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;

	/* XXX must change for sharing */
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		if ((engine->flags & flags1) && (engine->flags & flags2)) {
			u32 disp = action & UTRACE_ACTION_OP_MASK;
			action &= ~UTRACE_ACTION_OP_MASK;
			REPORT(report_signal, regs, disp, info, ka, return_ka);
			if ((action & UTRACE_ACTION_OP_MASK) == 0)
				action |= disp;
			if (action & UTRACE_ACTION_HIDE)
				break;
		}
	}

	return action;
}

void
utrace_signal_handler_singlestep(struct task_struct *tsk, struct pt_regs *regs)
{
	u32 action;
	action = report_signal(tsk, regs, tsk->utrace, UTRACE_SIGNAL_HANDLER,
			       UTRACE_EVENT_SIGNAL_ALL,
			       UTRACE_ACTION_SINGLESTEP|UTRACE_ACTION_BLOCKSTEP,
			       NULL, NULL, NULL);
	action = check_detach(tsk, action);
	check_quiescent(tsk, action);
}


/*
 * This is the hook from the signals code, called with the siglock held.
 * Here is the ideal place to quiesce.  We also dequeue and intercept signals.
 */
int
utrace_get_signal(struct task_struct *tsk, struct pt_regs *regs,
		  siginfo_t *info, struct k_sigaction *return_ka)
{
	struct utrace *utrace = tsk->utrace;
	struct utrace_signal signal = { info, return_ka, 0 };
	struct k_sigaction *ka;
	unsigned long action, event;

	/*
	 * If a signal was injected previously, it could not use our
	 * stack space directly.  It had to allocate a data structure,
	 * which we can now copy out of and free.
	 *
	 * We don't have to lock access to u.live.signal because it's only
	 * touched by utrace_inject_signal when we're quiescent.
	 */
	if (utrace->u.live.signal != NULL) {
		signal.signr = utrace->u.live.signal->signr;
		copy_siginfo(info, utrace->u.live.signal->info);
		if (utrace->u.live.signal->return_ka)
			*return_ka = *utrace->u.live.signal->return_ka;
		else
			signal.return_ka = NULL;
		kfree(utrace->u.live.signal);
		utrace->u.live.signal = NULL;
	}

	/*
	 * If we should quiesce, now is the time.
	 * First stash a pointer to the state on our stack,
	 * so that utrace_inject_signal can tell us what to do.
	 */
	if (tsk->utrace_flags & UTRACE_ACTION_QUIESCE) {
		int killed = sigkill_pending(tsk);
		if (!killed) {
			spin_unlock_irq(&tsk->sighand->siglock);

			killed = utrace_quiescent(tsk, &signal);

			/*
			 * Noone wants us quiescent any more, we can take
			 * signals.  Unless we have a forced signal to take,
			 * back out to the signal code to resynchronize after
			 * releasing the siglock.
			 */
			if (signal.signr == 0 && !killed)
				/*
				 * This return value says to reacquire the
				 * siglock and check again.  This will check
				 * for a pending group stop and process it
				 * before coming back here.
				 */
				return -1;

			spin_lock_irq(&tsk->sighand->siglock);
		}
		if (killed) {
			/*
			 * The only reason we woke up now was because of a
			 * SIGKILL.  Don't do normal dequeuing in case it
			 * might get a signal other than SIGKILL.  That would
			 * perturb the death state so it might differ from
			 * what the debugger would have allowed to happen.
			 * Instead, pluck out just the SIGKILL to be sure
			 * we'll die immediately with nothing else different
			 * from the quiescent state the debugger wanted us in.
			 */
			sigset_t sigkill_only;
			sigfillset(&sigkill_only);
			sigdelset(&sigkill_only, SIGKILL);
			killed = dequeue_signal(tsk, &sigkill_only, info);
			BUG_ON(killed != SIGKILL);
			*return_ka = tsk->sighand->action[killed - 1];
			return killed;
		}
	}

	/*
	 * If a signal was injected, everything is in place now.  Go do it.
	 */
	if (signal.signr != 0) {
		if (signal.return_ka == NULL) {
			ka = &tsk->sighand->action[signal.signr - 1];
			if (ka->sa.sa_flags & SA_ONESHOT)
				ka->sa.sa_handler = SIG_DFL;
			*return_ka = *ka;
		}
		else
			BUG_ON(signal.return_ka != return_ka);
		return signal.signr;
	}

	/*
	 * If noone is interested in intercepting signals, let the caller
	 * just dequeue them normally.
	 */
	if ((tsk->utrace_flags & UTRACE_EVENT_SIGNAL_ALL) == 0)
		return 0;

	/*
	 * Steal the next signal so we can let tracing engines examine it.
	 * From the signal number and sigaction, determine what normal
	 * delivery would do.  If no engine perturbs it, we'll do that
	 * by returning the signal number after setting *return_ka.
	 */
	signal.signr = dequeue_signal(tsk, &tsk->blocked, info);
	if (signal.signr == 0)
		return 0;

	BUG_ON(signal.signr != info->si_signo);

	ka = &tsk->sighand->action[signal.signr - 1];
	*return_ka = *ka;

	/*
	 * We are never allowed to interfere with SIGKILL,
	 * just punt after filling in *return_ka for our caller.
	 */
	if (signal.signr == SIGKILL)
		return signal.signr;

	if (ka->sa.sa_handler == SIG_IGN) {
		event = UTRACE_EVENT(SIGNAL_IGN);
		action = UTRACE_SIGNAL_IGN;
	}
	else if (ka->sa.sa_handler != SIG_DFL) {
		event = UTRACE_EVENT(SIGNAL);
		action = UTRACE_ACTION_RESUME;
	}
	else if (sig_kernel_coredump(signal.signr)) {
		event = UTRACE_EVENT(SIGNAL_CORE);
		action = UTRACE_SIGNAL_CORE;
	}
	else if (sig_kernel_ignore(signal.signr)) {
		event = UTRACE_EVENT(SIGNAL_IGN);
		action = UTRACE_SIGNAL_IGN;
	}
	else if (sig_kernel_stop(signal.signr)) {
		event = UTRACE_EVENT(SIGNAL_STOP);
		action = (signal.signr == SIGSTOP
			  ? UTRACE_SIGNAL_STOP : UTRACE_SIGNAL_TSTP);
	}
	else {
		event = UTRACE_EVENT(SIGNAL_TERM);
		action = UTRACE_SIGNAL_TERM;
	}

	if (tsk->utrace_flags & event) {
		/*
		 * We have some interested engines, so tell them about the
		 * signal and let them change its disposition.
		 */

		spin_unlock_irq(&tsk->sighand->siglock);

		action = report_signal(tsk, regs, utrace, action, event, event,
				       info, ka, return_ka);
		action &= UTRACE_ACTION_OP_MASK;

		if (action & UTRACE_SIGNAL_HOLD) {
			struct sigqueue *q = sigqueue_alloc();
			if (likely(q != NULL)) {
				q->flags = 0;
				copy_siginfo(&q->info, info);
			}
			action &= ~UTRACE_SIGNAL_HOLD;
			spin_lock_irq(&tsk->sighand->siglock);
			sigaddset(&tsk->pending.signal, info->si_signo);
			if (likely(q != NULL))
				list_add(&q->list, &tsk->pending.list);
		}
		else
			spin_lock_irq(&tsk->sighand->siglock);

		recalc_sigpending_tsk(tsk);
	}

	/*
	 * We express the chosen action to the signals code in terms
	 * of a representative signal whose default action does it.
	 */
	switch (action) {
	case UTRACE_SIGNAL_IGN:
		/*
		 * We've eaten the signal.  That's all we do.
		 * Tell the caller to restart.
		 */
		spin_unlock_irq(&tsk->sighand->siglock);
		return -1;

	case UTRACE_ACTION_RESUME:
	case UTRACE_SIGNAL_DELIVER:
		/*
		 * The handler will run.  We do the SA_ONESHOT work here
		 * since the normal path will only touch *return_ka now.
		 */
		if (return_ka->sa.sa_flags & SA_ONESHOT)
			ka->sa.sa_handler = SIG_DFL;
		break;

	case UTRACE_SIGNAL_TSTP:
		signal.signr = SIGTSTP;
		tsk->signal->flags |= SIGNAL_STOP_DEQUEUED;
		return_ka->sa.sa_handler = SIG_DFL;
		break;

	case UTRACE_SIGNAL_STOP:
		signal.signr = SIGSTOP;
		tsk->signal->flags |= SIGNAL_STOP_DEQUEUED;
		return_ka->sa.sa_handler = SIG_DFL;
		break;

	case UTRACE_SIGNAL_TERM:
		signal.signr = SIGTERM;
		return_ka->sa.sa_handler = SIG_DFL;
		break;

	case UTRACE_SIGNAL_CORE:
		signal.signr = SIGQUIT;
		return_ka->sa.sa_handler = SIG_DFL;
		break;

	default:
		BUG();
	}

	return signal.signr;
}


/*
 * Cause a specified signal delivery in the target thread,
 * which must be quiescent.  The action has UTRACE_SIGNAL_* bits
 * as returned from a report_signal callback.  If ka is non-null,
 * it gives the sigaction to follow for UTRACE_SIGNAL_DELIVER;
 * otherwise, the installed sigaction at the time of delivery is used.
 */
int
utrace_inject_signal(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     u32 action, siginfo_t *info,
		     const struct k_sigaction *ka)
{
	struct utrace *utrace;
	struct utrace_signal *signal;
	int ret;

	if (info->si_signo == 0 || !valid_signal(info->si_signo))
		return -EINVAL;

	utrace = get_utrace_lock_attached(target, engine);
	if (unlikely(IS_ERR(utrace)))
		return PTR_ERR(utrace);

	ret = 0;
	signal = utrace->u.live.signal;
	if (unlikely(target->exit_state))
		ret = -ESRCH;
	else if (signal == NULL) {
		ret = -ENOSYS;	/* XXX */
	}
	else if (signal->signr != 0)
		ret = -EAGAIN;
	else {
		if (info != signal->info)
			copy_siginfo(signal->info, info);

		switch (action) {
		default:
			ret = -EINVAL;
			break;

		case UTRACE_SIGNAL_IGN:
			break;

		case UTRACE_ACTION_RESUME:
		case UTRACE_SIGNAL_DELIVER:
			/*
			 * The handler will run.  We do the SA_ONESHOT work
			 * here since the normal path will not touch the
			 * real sigaction when using an injected signal.
			 */
			if (ka == NULL)
				signal->return_ka = NULL;
			else if (ka != signal->return_ka)
				*signal->return_ka = *ka;
			if (ka && ka->sa.sa_flags & SA_ONESHOT) {
				struct k_sigaction *a;
				a = &target->sighand->action[info->si_signo-1];
				spin_lock_irq(&target->sighand->siglock);
				a->sa.sa_handler = SIG_DFL;
				spin_unlock_irq(&target->sighand->siglock);
			}
			signal->signr = info->si_signo;
			break;

		case UTRACE_SIGNAL_TSTP:
			signal->signr = SIGTSTP;
			spin_lock_irq(&target->sighand->siglock);
			target->signal->flags |= SIGNAL_STOP_DEQUEUED;
			spin_unlock_irq(&target->sighand->siglock);
			signal->return_ka->sa.sa_handler = SIG_DFL;
			break;

		case UTRACE_SIGNAL_STOP:
			signal->signr = SIGSTOP;
			spin_lock_irq(&target->sighand->siglock);
			target->signal->flags |= SIGNAL_STOP_DEQUEUED;
			spin_unlock_irq(&target->sighand->siglock);
			signal->return_ka->sa.sa_handler = SIG_DFL;
			break;

		case UTRACE_SIGNAL_TERM:
			signal->signr = SIGTERM;
			signal->return_ka->sa.sa_handler = SIG_DFL;
			break;

		case UTRACE_SIGNAL_CORE:
			signal->signr = SIGQUIT;
			signal->return_ka->sa.sa_handler = SIG_DFL;
			break;
		}
	}

	utrace_unlock(utrace);

	return ret;
}
EXPORT_SYMBOL_GPL(utrace_inject_signal);


const struct utrace_regset *
utrace_regset(struct task_struct *target,
	      struct utrace_attached_engine *engine,
	      const struct utrace_regset_view *view, int which)
{
	if (unlikely((unsigned) which >= view->n))
		return NULL;

	if (target != current)
		wait_task_inactive(target);

	return &view->regsets[which];
}
EXPORT_SYMBOL_GPL(utrace_regset);


/*
 * Return the task_struct for the task using ptrace on this one, or NULL.
 * Must be called with rcu_read_lock held to keep the returned struct alive.
 *
 * At exec time, this may be called with task_lock(p) still held from when
 * tracehook_unsafe_exec was just called.  In that case it must give
 * results consistent with those unsafe_exec results, i.e. non-NULL if
 * any LSM_UNSAFE_PTRACE_* bits were set.
 *
 * The value is also used to display after "TracerPid:" in /proc/PID/status,
 * where it is called with only rcu_read_lock held.
 */
struct task_struct *
utrace_tracer_task(struct task_struct *target)
{
	struct utrace *utrace;
	struct task_struct *tracer = NULL;

	utrace = rcu_dereference(target->utrace);
	if (utrace != NULL) {
		struct list_head *pos, *next;
		struct utrace_attached_engine *engine;
		const struct utrace_engine_ops *ops;
		list_for_each_safe_rcu(pos, next, &utrace->engines) {
			engine = list_entry(pos, struct utrace_attached_engine,
					    entry);
			ops = rcu_dereference(engine->ops);
			if (ops->tracer_task) {
				tracer = (*ops->tracer_task)(engine, target);
				if (tracer != NULL)
					break;
			}
		}
	}

	return tracer;
}

int
utrace_allow_access_process_vm(struct task_struct *target)
{
	struct utrace *utrace;
	int ret = 0;

	rcu_read_lock();
	utrace = rcu_dereference(target->utrace);
	if (utrace != NULL) {
		struct list_head *pos, *next;
		struct utrace_attached_engine *engine;
		const struct utrace_engine_ops *ops;
		list_for_each_safe_rcu(pos, next, &utrace->engines) {
			engine = list_entry(pos, struct utrace_attached_engine,
					    entry);
			ops = rcu_dereference(engine->ops);
			if (ops->allow_access_process_vm) {
				ret = (*ops->allow_access_process_vm)(engine,
								      target,
								      current);
				if (ret)
					break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

/*
 * Called on the current task to return LSM_UNSAFE_* bits implied by tracing.
 * Called with task_lock held.
 */
int
utrace_unsafe_exec(struct task_struct *tsk)
{
	struct utrace *utrace = tsk->utrace;
	struct list_head *pos, *next;
	struct utrace_attached_engine *engine;
	const struct utrace_engine_ops *ops;
	int unsafe = 0;

	/* XXX must change for sharing */
	list_for_each_safe_rcu(pos, next, &utrace->engines) {
		engine = list_entry(pos, struct utrace_attached_engine, entry);
		ops = rcu_dereference(engine->ops);
		if (ops->unsafe_exec)
			unsafe |= (*ops->unsafe_exec)(engine, tsk);
	}

	return unsafe;
}
