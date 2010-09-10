/*
 * linux/kernel/ptrace.c
 *
 * (C) Copyright 1999 Linus Torvalds
 *
 * Common interfaces for "ptrace()" which we do not want
 * to continually duplicate across every architecture.
 */

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/syscalls.h>
#include <linux/utrace.h>
#include <linux/tracehook.h>
#include <linux/audit.h>

#include <asm/tracehook.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>


/*
 * Access another process' address space.
 * Source/target buffer must be kernel space, 
 * Do not walk the page table directly, use get_user_pages
 */

int access_process_vm(struct task_struct *tsk, unsigned long addr, void *buf, int len, int write)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct page *page;
	void *old_buf = buf;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was sucessfully transfered */
	while (len) {
		int bytes, ret, offset;
		void *maddr;

		ret = get_user_pages(tsk, mm, addr, 1,
				write, 1, &page, &vma);
		if (ret <= 0)
			break;

		bytes = len;
		offset = addr & (PAGE_SIZE-1);
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

		maddr = kmap(page);
		if (write) {
			copy_to_user_page(vma, page, addr,
					  maddr + offset, buf, bytes);
			set_page_dirty_lock(page);
		} else {
			copy_from_user_page(vma, page, addr,
					    buf, maddr + offset, bytes);
		}
		kunmap(page);
		page_cache_release(page);
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);
	mmput(mm);
	
	return buf - old_buf;
}
EXPORT_SYMBOL_GPL(access_process_vm);


#ifdef CONFIG_DEBUG_PREEMPT
#define NO_LOCKS	WARN_ON(preempt_count() != 0)
#define START_CHECK	do { int _dbg_preempt = preempt_count()
#define	END_CHECK	BUG_ON(preempt_count() != _dbg_preempt); } while (0)
#else
#define NO_LOCKS	do { } while (0)
#define START_CHECK	do { } while (0)
#define	END_CHECK	do { } while (0)
#endif

#define PTRACE_DEBUG 1
#ifdef PTRACE_DEBUG
#define CHECK_INIT(p)	atomic_set(&(p)->check_dead, 1)
#define CHECK_DEAD(p)	BUG_ON(!atomic_dec_and_test(&(p)->check_dead))
#else
#define CHECK_INIT(p)	do { } while (0)
#define CHECK_DEAD(p)	do { } while (0)
#endif

struct ptrace_state
{
	struct rcu_head rcu;
	atomic_t refcnt;
#ifdef PTRACE_DEBUG
	atomic_t check_dead;
#endif

	/*
	 * These elements are always available, even when the struct is
	 * awaiting destruction at the next RCU callback point.
	 */
	struct utrace_attached_engine *engine;
	struct task_struct *task; /* Target task.  */
	struct task_struct *parent; /* Whom we report to.  */
	struct list_head entry;	/* Entry on parent->ptracees list.  */

	u8 options;		/* PTRACE_SETOPTIONS bits.  */
	unsigned int syscall:1;	/* Reporting for syscall.  */
#ifdef PTRACE_SYSEMU
	unsigned int sysemu:1;	/* PTRACE_SYSEMU in progress. */
#endif
	unsigned int have_eventmsg:1; /* u.eventmsg valid. */
	unsigned int cap_sys_ptrace:1; /* Tracer capable.  */

	union
	{
		unsigned long eventmsg;
		siginfo_t *siginfo;
	} u;
};

static const struct utrace_engine_ops ptrace_utrace_ops; /* Initialized below. */

/*
 * We use this bit in task_struct.exit_code of a ptrace'd task to indicate
 * a ptrace stop.  It must not overlap with any bits used in real exit_code's.
 * Those are (PTRACE_EVENT_* << 8) | 0xff.
 */
#define PTRACE_TRAPPED_MASK	0x10000


static void
ptrace_state_unlink(struct ptrace_state *state)
{
	task_lock(state->parent);
	list_del_rcu(&state->entry);
	task_unlock(state->parent);
}

static struct ptrace_state *
ptrace_setup(struct task_struct *target, struct utrace_attached_engine *engine,
	     struct task_struct *parent, u8 options, int cap_sys_ptrace)
{
	struct ptrace_state *state;

	NO_LOCKS;

	state = kzalloc(sizeof *state, GFP_USER);
	if (unlikely(state == NULL))
		return ERR_PTR(-ENOMEM);

	INIT_RCU_HEAD(&state->rcu);
	atomic_set(&state->refcnt, 1);
	CHECK_INIT(state);
	state->task = target;
	state->engine = engine;
	state->options = options;
	state->cap_sys_ptrace = cap_sys_ptrace;

	rcu_read_lock();

	/*
	 * In ptrace_traceme, it's only safe to use this inside rcu_read_lock.
	 */
	if (parent == NULL)
		parent = current->parent;

	state->parent = parent;

	task_lock(parent);
	if (unlikely(parent->flags & PF_EXITING)) {
		task_unlock(parent);
		kfree(state);
		state = ERR_PTR(-EALREADY);
	}
	else {
		list_add_rcu(&state->entry, &state->parent->ptracees);
		task_unlock(state->parent);
	}

	rcu_read_unlock();

	NO_LOCKS;

	return state;
}

static void __ptrace_state_free(struct ptrace_state *state)
{
	if (atomic_dec_and_test(&state->refcnt))
		kfree(state);
}

static void
ptrace_state_free(struct rcu_head *rhead)
{
	struct ptrace_state *state = container_of(rhead,
						  struct ptrace_state, rcu);
	__ptrace_state_free(state);
}

static void
ptrace_done(struct ptrace_state *state)
{
	CHECK_DEAD(state);
	BUG_ON(state->rcu.func);
	BUG_ON(state->rcu.next);
	/*
	 * We clear @task here, while we are sure that the task_struct is
	 * still live, because our caller has to permit its release.
	 * By RCU rules, this means that inside rcu_read_lock(),
	 * rcu_dereference(state->task) will always produce either
	 * a pointer that is being kept alive by RCU, or NULL.
	 */
	rcu_assign_pointer(state->task, NULL);
	call_rcu(&state->rcu, ptrace_state_free);
}

/*
 * Update the tracing engine state to match the new ptrace state.
 */
static int __must_check
ptrace_update(struct task_struct *target, struct ptrace_state *state,
	      unsigned long flags, int from_stopped)
{
	int ret;

	START_CHECK;

	/*
	 * These events are always reported.
	 */
	flags |= (UTRACE_EVENT(DEATH) | UTRACE_EVENT(EXEC)
		  | UTRACE_EVENT_SIGNAL_ALL | UTRACE_EVENT(JCTL));

	/*
	 * We always have to examine clone events to check for CLONE_PTRACE.
	 */
	flags |= UTRACE_EVENT(CLONE);

	/*
	 * PTRACE_SETOPTIONS can request more events.
	 */
	if (state->options & PTRACE_O_TRACEEXIT)
		flags |= UTRACE_EVENT(EXIT);
	if (state->options & PTRACE_O_TRACEVFORKDONE)
		flags |= UTRACE_EVENT(VFORK_DONE);

	/*
	 * ptrace always inhibits normal parent reaping.
	 * But for a corner case we sometimes see the REAP event anyway.
	 */
	flags |= UTRACE_ACTION_NOREAP | UTRACE_EVENT(REAP);

	if (from_stopped && !(flags & UTRACE_ACTION_QUIESCE)) {
		/*
		 * We're letting the thread resume from ptrace stop.
		 * If SIGKILL is waking it up, it can be racing with us here
		 * to set its own exit_code in do_exit.  Though we clobber
		 * it here, we check for the case in ptrace_report_death.
		 */
		if (!unlikely(target->flags & PF_SIGNALED))
			target->exit_code = 0;

		if (!state->have_eventmsg)
			state->u.siginfo = NULL;

		if (target->state == TASK_STOPPED) {
			/*
			 * We have to double-check for naughty de_thread
			 * reaping despite NOREAP, before we can get siglock.
			 */
			read_lock(&tasklist_lock);
			if (!target->exit_state) {
				spin_lock_irq(&target->sighand->siglock);
				if (target->state == TASK_STOPPED)
					target->signal->flags &=
						~SIGNAL_STOP_STOPPED;
				spin_unlock_irq(&target->sighand->siglock);
			}
			read_unlock(&tasklist_lock);
		}
	}

	ret = utrace_set_flags(target, state->engine, flags);

	END_CHECK;

	return ret;
}

/*
 * This does ptrace_update and also installs state in engine->data.
 * Only after utrace_set_flags succeeds (in ptrace_update) inside
 * rcu_read_lock() can we be sure state->engine is still valid.
 * Otherwise a quick death could have come along and cleaned it up
 * already.  Note that from ptrace_update we can get event callbacks
 * that will see engine->data still NULL before we set it.  This is
 * fine, as they will just act as if we had not been attached yet.
 */
static int __must_check
ptrace_setup_finish(struct task_struct *target, struct ptrace_state *state)
{
	int ret;

	NO_LOCKS;

	rcu_read_lock();
	ret = ptrace_update(target, state, 0, 0);
	if (likely(ret == 0)) {
		struct utrace_attached_engine *engine = state->engine;
		BUG_ON(engine->data != NULL);
		rcu_assign_pointer(engine->data, state);
	}
	rcu_read_unlock();

	NO_LOCKS;

	return ret;
}


static int ptrace_traceme(void)
{
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	int retval;

	NO_LOCKS;

	engine = utrace_attach(current, (UTRACE_ATTACH_CREATE
					 | UTRACE_ATTACH_EXCLUSIVE
					 | UTRACE_ATTACH_MATCH_OPS),
			       &ptrace_utrace_ops, NULL);

	if (IS_ERR(engine)) {
		retval = PTR_ERR(engine);
		if (retval == -EEXIST)
			retval = -EPERM;
	}
	else {
		task_lock(current);
		retval = security_ptrace(current->parent, current);
		task_unlock(current);

		if (retval) {
			(void) utrace_detach(current, engine);
		}
		else {
			state = ptrace_setup(current, engine, NULL, 0, 0);
			if (IS_ERR(state))
				retval = PTR_ERR(state);
		}

		if (!retval) {
			/*
			 * This can't fail because we can't die while we
			 * are here doing this.
			 */
			retval = ptrace_setup_finish(current, state);
			BUG_ON(retval);
		}
		else if (unlikely(retval == -EALREADY))
			/*
			 * We raced with our parent's exit, which would
			 * have detached us just after our attach if
			 * we'd won the race.  Pretend we got attached
			 * and then detached immediately, no error.
			 */
			retval = 0;
	}

	NO_LOCKS;

	return retval;
}

static int ptrace_attach(struct task_struct *task)
{
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	int retval;

	audit_ptrace(task);

	NO_LOCKS;

	retval = -EPERM;
	if (task->pid <= 1)
		goto bad;
	if (task->tgid == current->tgid)
		goto bad;
	if (!task->mm)		/* kernel threads */
		goto bad;

	pr_debug("%d ptrace_attach %d state %lu exit_code %x\n",
		 current->pid, task->pid, task->state, task->exit_code);

	engine = utrace_attach(task, (UTRACE_ATTACH_CREATE
				      | UTRACE_ATTACH_EXCLUSIVE
				      | UTRACE_ATTACH_MATCH_OPS),
			       &ptrace_utrace_ops, NULL);
	if (IS_ERR(engine)) {
		retval = PTR_ERR(engine);
		if (retval == -EEXIST)
			retval = -EPERM;
		goto bad;
	}

	pr_debug("%d ptrace_attach %d after utrace_attach: %lu exit_code %x\n",
		 current->pid, task->pid, task->state, task->exit_code);

	NO_LOCKS;
	if (ptrace_may_attach(task)) {
		state = ptrace_setup(task, engine, current, 0,
				     capable(CAP_SYS_PTRACE));
		if (IS_ERR(state))
			retval = PTR_ERR(state);
		else {
			retval = ptrace_setup_finish(task, state);

			pr_debug("%d ptrace_attach %d after ptrace_update (%d)"
				 " %lu exit_code %x\n",
				 current->pid, task->pid, retval,
				 task->state, task->exit_code);

			if (retval) {
				/*
				 * It died before we enabled any callbacks.
				 */
				if (retval == -EALREADY)
					retval = -ESRCH;
				BUG_ON(retval != -ESRCH);
				ptrace_state_unlink(state);
				ptrace_done(state);
			}
		}
	}
	NO_LOCKS;
	if (retval)
		(void) utrace_detach(task, engine);
	else {
		NO_LOCKS;

		/*
		 * We must double-check that task has not just died and
		 * been reaped (after ptrace_update succeeded).
		 * This happens when exec (de_thread) ignores NOREAP.
		 * We cannot call into the signal code if it's dead.
		 */
		read_lock(&tasklist_lock);
		if (likely(!task->exit_state))
			force_sig_specific(SIGSTOP, task);
		read_unlock(&tasklist_lock);

		pr_debug("%d ptrace_attach %d complete (%sstopped)"
			 " state %lu code %x",
			 current->pid, task->pid,
			 task->state == TASK_STOPPED ? "" : "not ",
			 task->state, task->exit_code);
	}

bad:
	NO_LOCKS;
	return retval;
}

/*
 * The task might be dying or being reaped in parallel, in which case
 * engine and state may no longer be valid.  utrace_detach checks for us.
 */
static int ptrace_detach(struct task_struct *task,
			 struct utrace_attached_engine *engine,
			 struct ptrace_state *state)
{

	int error;

	NO_LOCKS;

#ifdef HAVE_ARCH_PTRACE_DETACH
	/*
	 * Some funky compatibility code in arch_ptrace may have
	 * needed to install special state it should clean up now.
	 */
	arch_ptrace_detach(task);
#endif

	/*
	 * Traditional ptrace behavior does wake_up_process no matter what
	 * in ptrace_detach.  But utrace_detach will not do a wakeup if
	 * it's in a proper job control stop.  We need it to wake up from
	 * TASK_STOPPED and either resume or process more signals.  A
	 * pending stop signal will just leave it stopped again, but will
	 * consume the signal, and reset task->exit_code for the next wait
	 * call to see.  This is important to userland if ptrace_do_wait
	 * "stole" the previous unwaited-for-ness (clearing exit_code), but
	 * there is a pending SIGSTOP, e.g. sent by a PTRACE_ATTACH done
	 * while already in job control stop.
	 */
	read_lock(&tasklist_lock);
	if (likely(task->signal != NULL)) {
		spin_lock_irq(&task->sighand->siglock);
		task->signal->flags &= ~SIGNAL_STOP_STOPPED;
		spin_unlock_irq(&task->sighand->siglock);
	}
	read_unlock(&tasklist_lock);

	error = utrace_detach(task, engine);
	NO_LOCKS;
	if (!error) {
		/*
		 * We can only get here from the ptracer itself or via
		 * detach_zombie from another thread in its group.
		 */
		BUG_ON(state->parent->tgid != current->tgid);
		ptrace_state_unlink(state);
		ptrace_done(state);

		/*
		 * Wake up any other threads that might be blocked in
		 * wait.  Though traditional ptrace does not guarantee
		 * this wakeup on PTRACE_DETACH, it does prevent
		 * erroneous blocking in wait when another racing
		 * thread's wait call reap-detaches the last child.
		 * Without this wakeup, another thread might stay
		 * blocked when it should return -ECHILD.
		 */
		spin_lock_irq(&current->sighand->siglock);
		wake_up_interruptible(&current->signal->wait_chldexit);
		spin_unlock_irq(&current->sighand->siglock);
	}
	return error;
}


/*
 * This is called when we are exiting.  We must stop all our ptracing.
 */
void
ptrace_exit(struct task_struct *tsk)
{
	struct list_head *pos, *n;
	int restart;

	NO_LOCKS;

	/*
	 * Taking the task_lock after PF_EXITING is set ensures that a
	 * child in ptrace_traceme will not put itself on our list when
	 * we might already be tearing it down.
	 */
	task_lock(tsk);
	if (likely(list_empty(&tsk->ptracees))) {
		task_unlock(tsk);
		return;
	}
	task_unlock(tsk);

	do {
		struct ptrace_state *state;
		struct task_struct *p;
		int error;

		START_CHECK;

		rcu_read_lock();

		restart = 0;
		list_for_each_safe_rcu(pos, n, &tsk->ptracees) {
			state = list_entry(pos, struct ptrace_state, entry);
			/*
			 * Here rcu_read_lock() keeps live any task_struct
			 * that state->task still points to.  If state->task
			 * was cleared already, then state itself is on the
			 * way to be freed by RCU and we are just seeing a
			 * stale list element here.
			 */
			p = rcu_dereference(state->task);
			if (unlikely(p == NULL))
				continue;
			error = utrace_detach(p, state->engine);
			BUG_ON(state->parent != tsk);
			if (likely(error == 0)) {
				ptrace_state_unlink(state);
				ptrace_done(state);
			}
			else if (unlikely(error == -EALREADY)) {
				/*
				 * It's still doing report_death callbacks.
				 * Just wait for it to settle down.
				 * Since wait_task_inactive might yield,
				 * we must go out of rcu_read_lock and restart.
				 */
				get_task_struct(p);
				rcu_read_unlock();
				wait_task_inactive(p);
				put_task_struct(p);
				restart = 1;
				goto loop_unlocked;
			}
			else {
				BUG_ON(error != -ESRCH);
				restart = -1;
			}
		}

		rcu_read_unlock();

	loop_unlocked:
		END_CHECK;

		cond_resched();
	} while (unlikely(restart > 0));

	if (likely(restart == 0))
		/*
		 * If we had an -ESRCH error from utrace_detach, we might
		 * still be racing with the thread in ptrace_state_unlink,
		 * but things are OK.
		 */
		BUG_ON(!list_empty(&tsk->ptracees));
}

static int
ptrace_induce_signal(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     struct ptrace_state *state,
		     long signr)
{
	if (signr == 0)
		return 0;

	if (!valid_signal(signr))
		return -EIO;

	if (state->syscall) {
		/*
		 * This is the traditional ptrace behavior when given
		 * a signal to resume from a syscall tracing stop.
		 */
		send_sig(signr, target, 1);
	}
	else if (!state->have_eventmsg && state->u.siginfo) {
		siginfo_t *info = state->u.siginfo;

		/* Update the siginfo structure if the signal has
		   changed.  If the debugger wanted something
		   specific in the siginfo structure then it should
		   have updated *info via PTRACE_SETSIGINFO.  */
		if (signr != info->si_signo) {
			info->si_signo = signr;
			info->si_errno = 0;
			info->si_code = SI_USER;
			info->si_pid = current->pid;
			info->si_uid = current->uid;
		}

		return utrace_inject_signal(target, engine,
					    UTRACE_ACTION_RESUME, info, NULL);
	}

	return 0;
}

int
ptrace_regset_access(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     const struct utrace_regset_view *view,
		     int setno, unsigned long offset, unsigned int size,
		     void __user *data, int write)
{
	const struct utrace_regset *regset = utrace_regset(target, engine,
							   view, setno);
	int ret;

	if (unlikely(regset == NULL))
		return -EIO;

	if (size == (unsigned int) -1)
		size = regset->size * regset->n;

	if (write) {
		if (!access_ok(VERIFY_READ, data, size))
			ret = -EIO;
		else
			ret = (*regset->set)(target, regset,
					     offset, size, NULL, data);
	}
	else {
		if (!access_ok(VERIFY_WRITE, data, size))
			ret = -EIO;
		else
			ret = (*regset->get)(target, regset,
					     offset, size, NULL, data);
	}

	return ret;
}

int
ptrace_onereg_access(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     const struct utrace_regset_view *view,
		     int setno, unsigned long regno,
		     void __user *udata, void *kdata, int write)
{
	const struct utrace_regset *regset = utrace_regset(target, engine,
							   view, setno);
	unsigned int pos;
	int ret;

	if (unlikely(regset == NULL))
		return -EIO;

	if (regno < regset->bias || regno >= regset->bias + regset->n)
		return -EINVAL;

	pos = (regno - regset->bias) * regset->size;

	if (write) {
		if (kdata == NULL &&
		    !access_ok(VERIFY_READ, udata, regset->size))
			ret = -EIO;
		else
			ret = (*regset->set)(target, regset, pos, regset->size,
					     kdata, udata);
	}
	else {
		if (kdata == NULL &&
		    !access_ok(VERIFY_WRITE, udata, regset->size))
			ret = -EIO;
		else
			ret = (*regset->get)(target, regset, pos, regset->size,
					     kdata, udata);
	}

	return ret;
}

int
ptrace_layout_access(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     const struct utrace_regset_view *view,
		     const struct ptrace_layout_segment layout[],
		     unsigned long addr, unsigned int size,
		     void __user *udata, void *kdata, int write)
{
	const struct ptrace_layout_segment *seg;
	int ret = -EIO;

	if (kdata == NULL &&
	    !access_ok(write ? VERIFY_READ : VERIFY_WRITE, udata, size))
		return -EIO;

	seg = layout;
	do {
		unsigned int pos, n;

		while (addr >= seg->end && seg->end != 0)
			++seg;

		if (addr < seg->start || addr >= seg->end)
			return -EIO;

		pos = addr - seg->start + seg->offset;
		n = min(size, seg->end - (unsigned int) addr);

		if (unlikely(seg->regset == (unsigned int) -1)) {
			/*
			 * This is a no-op/zero-fill portion of struct user.
			 */
			ret = 0;
			if (!write && seg->offset == 0) {
				if (kdata)
					memset(kdata, 0, n);
				else if (clear_user(udata, n))
					ret = -EFAULT;
			}
		}
		else {
			unsigned int align;
			const struct utrace_regset *regset = utrace_regset(
				target, engine, view, seg->regset);
			if (unlikely(regset == NULL))
				return -EIO;

			/*
			 * A ptrace compatibility layout can do a misaligned
			 * regset access, e.g. word access to larger data.
			 * An arch's compat layout can be this way only if
			 * it is actually ok with the regset code despite the
			 * regset->align setting.
			 */
			align = min(regset->align, size);
			if ((pos & (align - 1))
			    || pos >= regset->n * regset->size)
				return -EIO;

			if (write)
				ret = (*regset->set)(target, regset,
						     pos, n, kdata, udata);
			else
				ret = (*regset->get)(target, regset,
						     pos, n, kdata, udata);
		}

		if (kdata)
			kdata += n;
		else
			udata += n;
		addr += n;
		size -= n;
	} while (ret == 0 && size > 0);

	return ret;
}


static int
ptrace_start(long pid, long request,
	     struct task_struct **childp,
	     struct utrace_attached_engine **enginep,
	     struct ptrace_state **statep)

{
	struct task_struct *child;
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	int ret;

	NO_LOCKS;

	if (request == PTRACE_TRACEME)
		return ptrace_traceme();

	ret = -ESRCH;
	read_lock(&tasklist_lock);
	child = find_task_by_pid(pid);
	if (child)
		get_task_struct(child);
	read_unlock(&tasklist_lock);
	pr_debug("ptrace pid %ld => %p\n", pid, child);
	if (!child)
		goto out;

	ret = -EPERM;
	if (pid == 1)		/* you may not mess with init */
		goto out_tsk;

	if (request == PTRACE_ATTACH) {
		ret = ptrace_attach(child);
		goto out_tsk;
	}

	rcu_read_lock();
	engine = utrace_attach(child, UTRACE_ATTACH_MATCH_OPS,
			       &ptrace_utrace_ops, NULL);
	ret = -ESRCH;
	if (IS_ERR(engine) || engine == NULL)
		goto out_tsk_rcu;
	state = rcu_dereference(engine->data);
	if (state == NULL || state->parent != current)
		goto out_tsk_rcu;
	/*
	 * Traditional ptrace behavior demands that the target already be
	 * quiescent, but not dead.
	 */
	if (request != PTRACE_KILL
	    && !(engine->flags & UTRACE_ACTION_QUIESCE)) {
		/*
		 * If it's in job control stop, turn it into proper quiescence.
		 */
		struct sighand_struct *sighand;
		unsigned long flags;
		sighand = lock_task_sighand(child, &flags);
		if (likely(sighand != NULL)) {
			if (child->state == TASK_STOPPED)
				ret = 0;
			unlock_task_sighand(child, &flags);
		}
		if (ret == 0) {
			ret = ptrace_update(child, state,
					    UTRACE_ACTION_QUIESCE, 0);
			if (unlikely(ret == -EALREADY))
				ret = -ESRCH;
			if (unlikely(ret))
				BUG_ON(ret != -ESRCH);
		}

		if (ret) {
			pr_debug("%d not stopped (%lu)\n",
				 child->pid, child->state);
			goto out_tsk_rcu;
		}

		ret = -ESRCH;  /* Return value for exit_state bail-out.  */
	}

	atomic_inc(&state->refcnt);
	rcu_read_unlock();

	NO_LOCKS;

	/*
	 * We do this for all requests to match traditional ptrace behavior.
	 * If the machine state synchronization done at context switch time
	 * includes e.g. writing back to user memory, we want to make sure
	 * that has finished before a PTRACE_PEEKDATA can fetch the results.
	 * On most machines, only regset data is affected by context switch
	 * and calling utrace_regset later on will take care of that, so
	 * this is superfluous.
	 *
	 * To do this purely in utrace terms, we could do:
	 *  (void) utrace_regset(child, engine, utrace_native_view(child), 0);
	 */
	wait_task_inactive(child);
	while (child->state != TASK_TRACED && child->state != TASK_STOPPED) {
		if (child->exit_state) {
			__ptrace_state_free(state);
			goto out_tsk;
		}
		/*
		 * This is a dismal kludge, but it only comes up on ia64.
		 * It might be blocked inside regset->writeback() called
		 * from ptrace_report(), when it's on its way to quiescing
		 * in TASK_TRACED real soon now.  We actually need that
		 * writeback call to have finished, before a PTRACE_PEEKDATA
		 * here, for example.  So keep waiting until it's really there.
		 */
		yield();
		wait_task_inactive(child);
	}
	wait_task_inactive(child);

	*childp = child;
	*enginep = engine;
	*statep = state;
	return -EIO;

out_tsk_rcu:
	rcu_read_unlock();
out_tsk:
	NO_LOCKS;
	put_task_struct(child);
out:
	return ret;
}

static inline int is_sysemu(long req)
{
#ifdef PTRACE_SYSEMU
	if (req == PTRACE_SYSEMU || req == PTRACE_SYSEMU_SINGLESTEP)
		return 1;
#endif
	return 0;
}

static inline int is_singlestep(long req)
{
#ifdef PTRACE_SYSEMU_SINGLESTEP
	if (req == PTRACE_SYSEMU_SINGLESTEP)
		return 1;
#endif
#ifdef PTRACE_SINGLESTEP
	if (req == PTRACE_SINGLESTEP)
		return 1;
#endif
	return 0;
}

static inline int is_blockstep(long req)
{
#ifdef PTRACE_SINGLEBLOCK
	if (req == PTRACE_SINGLEBLOCK)
		return 1;
#endif
	return 0;
}

static int
ptrace_common(long request, struct task_struct *child,
	      struct utrace_attached_engine *engine,
	      struct ptrace_state *state,
	      unsigned long addr, long data)
{
	unsigned long flags;
	int ret = -EIO;

	NO_LOCKS;

	switch (request) {
	case PTRACE_DETACH:
		/*
		 * Detach a process that was attached.
		 */
		ret = ptrace_induce_signal(child, engine, state, data);
		if (!ret) {
			ret = ptrace_detach(child, engine, state);
			if (ret == -EALREADY) /* Already a zombie.  */
				ret = -ESRCH;
			if (ret)
				BUG_ON(ret != -ESRCH);
		}
		break;

		/*
		 * These are the operations that resume the child running.
		 */
	case PTRACE_KILL:
		data = SIGKILL;
	case PTRACE_CONT:
	case PTRACE_SYSCALL:
#ifdef PTRACE_SYSEMU
	case PTRACE_SYSEMU:
	case PTRACE_SYSEMU_SINGLESTEP:
#endif
#ifdef PTRACE_SINGLEBLOCK
	case PTRACE_SINGLEBLOCK:
# ifdef ARCH_HAS_BLOCK_STEP
		if (! ARCH_HAS_BLOCK_STEP)
# endif
			if (is_blockstep(request))
				break;
#endif
	case PTRACE_SINGLESTEP:
#ifdef ARCH_HAS_SINGLE_STEP
		if (! ARCH_HAS_SINGLE_STEP)
#endif
			if (is_singlestep(request))
				break;

		ret = ptrace_induce_signal(child, engine, state, data);
		if (ret)
			break;

		/*
		 * Reset the action flags without QUIESCE, so it resumes.
		 */
		flags = 0;
#ifdef PTRACE_SYSEMU
		state->sysemu = is_sysemu(request);
#endif
		if (request == PTRACE_SYSCALL || is_sysemu(request))
			flags |= UTRACE_EVENT_SYSCALL;
		if (is_singlestep(request))
			flags |= UTRACE_ACTION_SINGLESTEP;
		else if (is_blockstep(request))
			flags |= UTRACE_ACTION_BLOCKSTEP;
		ret = ptrace_update(child, state, flags, 1);
		if (ret)
			BUG_ON(ret != -ESRCH && ret != -EALREADY);
		ret = 0;
		break;

#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
#endif
	case PTRACE_SETOPTIONS:
		ret = -EINVAL;
		if (data & ~PTRACE_O_MASK)
			break;
		state->options = data;
		ret = ptrace_update(child, state, UTRACE_ACTION_QUIESCE, 1);
		if (ret)
			BUG_ON(ret != -ESRCH && ret != -EALREADY);
		ret = 0;
		break;
	}

	NO_LOCKS;

	return ret;
}


asmlinkage long sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child = NULL;
	struct utrace_attached_engine *engine = NULL;
	struct ptrace_state *state = NULL;
	long ret, val;

	pr_debug("%d sys_ptrace(%ld, %ld, %lx, %lx)\n",
		 current->pid, request, pid, addr, data);

	ret = ptrace_start(pid, request, &child, &engine, &state);
	if (ret != -EIO)
		goto out;

	val = 0;
	ret = arch_ptrace(&request, child, engine, addr, data, &val);
	if (ret != -ENOSYS) {
		if (ret == 0) {
			ret = val;
			force_successful_syscall_return();
		}
		goto out_tsk;
	}

	switch (request) {
	default:
		ret = ptrace_common(request, child, engine, state, addr, data);
		break;

	case PTRACE_PEEKTEXT: /* read word at location addr. */
	case PTRACE_PEEKDATA: {
		unsigned long tmp;
		int copied;

		copied = access_process_vm(child, addr, &tmp, sizeof(tmp), 0);
		ret = -EIO;
		if (copied != sizeof(tmp))
			break;
		ret = put_user(tmp, (unsigned long __user *) data);
		break;
	}

	case PTRACE_POKETEXT: /* write the word at location addr. */
	case PTRACE_POKEDATA:
		ret = 0;
		if (access_process_vm(child, addr, &data, sizeof(data), 1) == sizeof(data))
			break;
		ret = -EIO;
		break;

	case PTRACE_GETEVENTMSG:
		ret = put_user(state->have_eventmsg
			       ? state->u.eventmsg : 0L,
			       (unsigned long __user *) data);
		break;
	case PTRACE_GETSIGINFO:
		ret = -EINVAL;
		if (!state->have_eventmsg && state->u.siginfo)
			ret = copy_siginfo_to_user((siginfo_t __user *) data,
						   state->u.siginfo);
		break;
	case PTRACE_SETSIGINFO:
		ret = -EINVAL;
		if (!state->have_eventmsg && state->u.siginfo) {
			ret = 0;
			if (copy_from_user(state->u.siginfo,
					   (siginfo_t __user *) data,
					   sizeof(siginfo_t)))
				ret = -EFAULT;
		}
		break;
	}

out_tsk:
	NO_LOCKS;
	put_task_struct(child);
	__ptrace_state_free(state);
out:
	pr_debug("%d ptrace -> %lx\n", current->pid, ret);
	return ret;
}


#ifdef CONFIG_COMPAT
#include <linux/compat.h>

asmlinkage long compat_sys_ptrace(compat_long_t request, compat_long_t pid,
				  compat_ulong_t addr, compat_long_t cdata)
{
	const unsigned long data = (unsigned long) (compat_ulong_t) cdata;
	struct task_struct *child;
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	compat_long_t ret, val;

	pr_debug("%d compat_sys_ptrace(%d, %d, %x, %x)\n",
		 current->pid, request, pid, addr, cdata);
	ret = ptrace_start(pid, request, &child, &engine, &state);
	if (ret != -EIO)
		goto out;

	val = 0;
	ret = arch_compat_ptrace(&request, child, engine, addr, cdata, &val);
	if (ret != -ENOSYS) {
		if (ret == 0) {
			ret = val;
			force_successful_syscall_return();
		}
		goto out_tsk;
	}

	switch (request) {
	default:
		ret = ptrace_common(request, child, engine, state, addr, data);
		break;

	case PTRACE_PEEKTEXT: /* read word at location addr. */
	case PTRACE_PEEKDATA: {
		compat_ulong_t tmp;
		int copied;

		copied = access_process_vm(child, addr, &tmp, sizeof(tmp), 0);
		ret = -EIO;
		if (copied != sizeof(tmp))
			break;
		ret = put_user(tmp, (compat_ulong_t __user *) data);
		break;
	}

	case PTRACE_POKETEXT: /* write the word at location addr. */
	case PTRACE_POKEDATA:
		ret = 0;
		if (access_process_vm(child, addr, &cdata, sizeof(cdata), 1) == sizeof(cdata))
			break;
		ret = -EIO;
		break;

	case PTRACE_GETEVENTMSG:
		ret = put_user(state->have_eventmsg
			       ? state->u.eventmsg : 0L,
			       (compat_long_t __user *) data);
		break;
	case PTRACE_GETSIGINFO:
		ret = -EINVAL;
		if (!state->have_eventmsg && state->u.siginfo)
			ret = copy_siginfo_to_user32(
				(struct compat_siginfo __user *) data,
				state->u.siginfo);
		break;
	case PTRACE_SETSIGINFO:
		ret = -EINVAL;
		if (!state->have_eventmsg && state->u.siginfo
		    && copy_siginfo_from_user32(
			    state->u.siginfo,
			    (struct compat_siginfo __user *) data))
			ret = -EFAULT;
		break;
	}

out_tsk:
	put_task_struct(child);
	__ptrace_state_free(state);
out:
	pr_debug("%d ptrace -> %lx\n", current->pid, (long)ret);
	return ret;
}
#endif


/*
 * Detach the zombie being reported for wait.
 */
static inline void
detach_zombie(struct task_struct *tsk,
	      struct task_struct *p, struct ptrace_state *state)
{
	int detach_error;
	struct utrace_attached_engine *engine;

restart:
	NO_LOCKS;
	detach_error = 0;
	rcu_read_lock();
	if (tsk == current)
		engine = state->engine;
	else {
		/*
		 * We've excluded other ptrace_do_wait calls.  But the
		 * ptracer itself might have done ptrace_detach while we
		 * did not have rcu_read_lock.  So double-check that state
		 * is still valid.
		 */
		engine = utrace_attach(p, (UTRACE_ATTACH_MATCH_OPS
					   | UTRACE_ATTACH_MATCH_DATA),
				       &ptrace_utrace_ops, state);
		if (IS_ERR(engine) || state->parent != tsk)
			detach_error = -ESRCH;
		else
			BUG_ON(state->engine != engine);
	}
	rcu_read_unlock();
	NO_LOCKS;
	if (likely(!detach_error))
		detach_error = ptrace_detach(p, engine, state);
	if (unlikely(detach_error == -EALREADY)) {
		/*
		 * It's still doing report_death callbacks.
		 * Just wait for it to settle down.
		 */
		wait_task_inactive(p); /* Might block.  */
		goto restart;
	}
	/*
	 * A failure with -ESRCH means that report_reap is
	 * already running and will do the cleanup, or that
	 * we lost a race with ptrace_detach in another
	 * thread or with the automatic detach in
	 * report_death.
	 */
	if (detach_error)
		BUG_ON(detach_error != -ESRCH);
	NO_LOCKS;
}

/*
 * We're called with tasklist_lock held for reading.
 * If we return -ECHILD or zero, next_thread(tsk) must still be valid to use.
 * If we return another error code, or a successful PID value, we
 * release tasklist_lock first.
 */
int
ptrace_do_wait(struct task_struct *tsk,
	       pid_t pid, int options, struct siginfo __user *infop,
	       int __user *stat_addr, struct rusage __user *rusagep)
	__releases(tasklist_lock)
{
	struct ptrace_state *state;
	struct task_struct *p;
	int err = -ECHILD;
	int exit_code, why, status;

	rcu_read_lock();
	list_for_each_entry_rcu(state, &tsk->ptracees, entry) {
		p = rcu_dereference(state->task);
		if (unlikely(p == NULL))
			continue;

		if (pid > 0) {
			if (p->pid != pid)
				continue;
		} else if (!pid) {
			if (process_group(p) != process_group(current))
				continue;
		} else if (pid != -1) {
			if (process_group(p) != -pid)
				continue;
		}
		if (((p->exit_signal != SIGCHLD) ^ ((options & __WCLONE) != 0))
		    && !(options & __WALL))
			continue;
		if (security_task_wait(p))
			continue;

		/*
		 * This is a matching child.  If we don't win now, tell
		 * our caller to block and repeat.  From this point we
		 * must ensure that wait_chldexit will get a wakeup for
		 * any tracee stopping, dying, or being detached.
		 * For death, tasklist_lock guarantees this already.
		 */
		err = 0;

		switch (p->exit_state) {
		case EXIT_ZOMBIE:
			if (!likely(options & WEXITED))
				continue;
			if (delay_group_leader(p)) {
				struct task_struct *next = next_thread(p);
				pr_debug("%d ptrace_do_wait leaving %d "
					 "zombie code %x "
					 "delay_group_leader (%d/%lu)\n",
					 current->pid, p->pid, p->exit_code,
					 next->pid, next->state);
				continue;
			}
			exit_code = p->exit_code;
			goto found;
		case EXIT_DEAD:
			continue;
		default:
			/*
			 * tasklist_lock holds up any transitions to
			 * EXIT_ZOMBIE.  After releasing it we are
			 * guaranteed a wakeup on wait_chldexit after
			 * any new deaths.
			 */
			if (p->flags & PF_EXITING)
				/*
				 * It's in do_exit and might have set
				 * p->exit_code already, but it's not quite
				 * dead yet.  It will get to report_death
				 * and wakes us up when it finishes.
				 */
				continue;
			break;
		}

		/*
		 * This xchg atomically ensures that only one do_wait
		 * call can report this thread.  Because exit_code is
		 * always set before do_notify wakes us up, after this
		 * check fails we are sure to get a wakeup if it stops.
		 */
		exit_code = xchg(&p->exit_code, 0);
		if (exit_code & PTRACE_TRAPPED_MASK)
			goto found;

		/*
		 * If p was in job-control stop (TASK_STOPPED) rather than
		 * ptrace stop (TASK_TRACED), then SIGCONT can asynchronously
		 * clear it back to TASK_RUNNING.  Until it gets scheduled
		 * and clears its own ->exit_code, our xchg below will see
		 * its stop signal.  But, we must not report it if it's no
		 * longer in TASK_STOPPED, as vanilla wait would not--the
		 * caller can tell if it sent the SIGCONT before calling
		 * wait.  We must somehow distinguish this from the case
		 * where p is in TASK_RUNNING with p->exit_code set because
		 * it is on its way to entering TASK_TRACED (QUIESCE) for our
		 * stop.  So, ptrace_report sets the PTRACE_TRAPPED_MASK bit
		 * in exit_code when it's setting QUIESCE.  For a job control
		 * control stop, that bit will never have been set.  Since
		 * the bit's not set now, we should only report right now if
		 * p is still stopped.  For this case we are protected by
		 * races the same wait that vanilla do_wait (exit.c) is:
		 * wait_chldexit is woken after p->state is set to TASK_STOPPED.
		 */
		if (exit_code != 0) {
			if (p->state == TASK_STOPPED)
				goto found;
			xchg(&p->exit_code, exit_code);
		}
		// XXX should handle WCONTINUED

		pr_debug("%d ptrace_do_wait leaving %d state %lu code %x\n",
			 current->pid, p->pid, p->state, p->exit_code);
	}
	rcu_read_unlock();
	if (err == 0)
		pr_debug("%d ptrace_do_wait blocking\n", current->pid);

	return err;

found:
	BUG_ON(state->parent != tsk);
	rcu_read_unlock();

	pr_debug("%d ptrace_do_wait (%d) found %d code %x (%u/%d)\n",
		 current->pid, tsk->pid, p->pid, exit_code,
		 p->exit_state, p->exit_signal);

	if (p->exit_state) {
		if (unlikely(p->parent == tsk && p->exit_signal != -1))
			/*
			 * This is our natural child we were ptracing.
			 * When it dies it detaches (see ptrace_report_death).
			 * So we're seeing it here in a race.  When it
			 * finishes detaching it will become reapable in
			 * the normal wait_task_zombie path instead.
			 */
			return 0;

		/*
		 * If there was a group exit in progress, all threads
		 * report that status.  Most have SIGKILL in their exit_code.
		 */
		if (p->signal->flags & SIGNAL_GROUP_EXIT)
			exit_code = p->signal->group_exit_code;

		if ((exit_code & 0x7f) == 0) {
			why = CLD_EXITED;
			status = exit_code >> 8;
		}
		else {
			why = (exit_code & 0x80) ? CLD_DUMPED : CLD_KILLED;
			status = exit_code & 0x7f;
		}
	}
	else {
		why = CLD_TRAPPED;
		exit_code &= ~PTRACE_TRAPPED_MASK;
		status = exit_code;
		exit_code = (status << 8) | 0x7f;
	}

	/*
	 * At this point we are committed to a successful return
	 * or a user error return.  Release the tasklist_lock.
	 */
	get_task_struct(p);
	read_unlock(&tasklist_lock);

	NO_LOCKS;

	if (rusagep)
		err = getrusage(p, RUSAGE_BOTH, rusagep);
	if (infop) {
		if (!err)
			err = put_user(SIGCHLD, &infop->si_signo);
		if (!err)
			err = put_user(0, &infop->si_errno);
		if (!err)
			err = put_user((short)why, &infop->si_code);
		if (!err)
			err = put_user(p->pid, &infop->si_pid);
		if (!err)
			err = put_user(p->uid, &infop->si_uid);
		if (!err)
			err = put_user(status, &infop->si_status);
	}
	if (!err && stat_addr)
		err = put_user(exit_code, stat_addr);

	if (!err) {
		if (why != CLD_TRAPPED)
			/*
			 * This was a death report.  The ptracer's wait
			 * does an implicit detach, so the zombie reports
			 * to its real parent now.
			 */
			detach_zombie(tsk, p, state);
		err = p->pid;
	}

	put_task_struct(p);

	return err;
}


/*
 * All the report callbacks (except death and reap) are subject to a race
 * with ptrace_exit doing a quick detach and ptrace_done.  It can do this
 * even when the target is not quiescent, so a callback may already be in
 * progress when it does ptrace_done.  Callbacks use this function to fetch
 * the struct ptrace_state while ensuring it doesn't disappear until
 * put_ptrace_state is called.  This just uses RCU, since state and
 * anything we try to do to state->parent is safe under rcu_read_lock.
 */
static struct ptrace_state *
get_ptrace_state(struct utrace_attached_engine *engine,
		 struct task_struct *tsk)
	__acquires(RCU)
{
	struct ptrace_state *state;

	rcu_read_lock();
	state = rcu_dereference(engine->data);
	if (likely(state != NULL))
		return state;

	rcu_read_unlock();
	return NULL;
}

static inline void
put_ptrace_state(struct ptrace_state *state)
	__releases(RCU)
{
	BUG_ON(state == NULL);
	rcu_read_unlock();
}


static void
do_notify(struct task_struct *tsk, struct task_struct *parent, int why)
{
	struct siginfo info;
	unsigned long flags;
	struct sighand_struct *sighand;
	int sa_mask;

	info.si_signo = SIGCHLD;
	info.si_errno = 0;
	info.si_pid = tsk->pid;
	info.si_uid = tsk->uid;

	/* FIXME: find out whether or not this is supposed to be c*time. */
	info.si_utime = cputime_to_jiffies(tsk->utime);
	info.si_stime = cputime_to_jiffies(tsk->stime);

	sa_mask = SA_NOCLDSTOP;
 	info.si_code = why;
	info.si_status = tsk->exit_code & 0x7f;
	if (why == CLD_CONTINUED)
 		info.si_status = SIGCONT;
	else if (why == CLD_STOPPED)
		info.si_status = tsk->signal->group_exit_code & 0x7f;
	else if (why == CLD_EXITED) {
		sa_mask = SA_NOCLDWAIT;
		if (tsk->exit_code & 0x80)
			info.si_code = CLD_DUMPED;
		else if (tsk->exit_code & 0x7f)
			info.si_code = CLD_KILLED;
		else {
			info.si_code = CLD_EXITED;
			info.si_status = tsk->exit_code >> 8;
		}
	}

	read_lock(&tasklist_lock);
	if (unlikely(parent->signal == NULL))
		goto out;

	sighand = parent->sighand;
	spin_lock_irqsave(&sighand->siglock, flags);
	if (sighand->action[SIGCHLD-1].sa.sa_handler != SIG_IGN &&
	    !(sighand->action[SIGCHLD-1].sa.sa_flags & sa_mask))
		__group_send_sig_info(SIGCHLD, &info, parent);
	/*
	 * Even if SIGCHLD is not generated, we must wake up wait4 calls.
	 */
	wake_up_interruptible_sync(&parent->signal->wait_chldexit);
	spin_unlock_irqrestore(&sighand->siglock, flags);

out:
	read_unlock(&tasklist_lock);
}

static u32
ptrace_report(struct utrace_attached_engine *engine,
	      struct task_struct *tsk,
	      struct ptrace_state *state,
	      int code)
	__releases(RCU)
{
	const struct utrace_regset *regset;

	pr_debug("%d ptrace_report %d engine %p"
		 " state %p code %x parent %d (%p)\n",
		 current->pid, tsk->pid, engine, state, code,
		 state->parent->pid, state->parent);
	if (!state->have_eventmsg && state->u.siginfo) {
		const siginfo_t *si = state->u.siginfo;
		pr_debug("  si %d code %x errno %d addr %p\n",
			 si->si_signo, si->si_code, si->si_errno,
			 si->si_addr);
	}

	/*
	 * Set our QUIESCE flag right now, before notifying the tracer.
	 * We do this before setting tsk->exit_code rather than
	 * by using UTRACE_ACTION_NEWSTATE in our return value, to
	 * ensure that the tracer can't get the notification and then
	 * try to resume us with PTRACE_CONT before we set the flag.
	 */
	utrace_set_flags(tsk, engine, engine->flags | UTRACE_ACTION_QUIESCE);

	/*
	 * The PTRACE_TRAPPED_MASK bit distinguishes to ptrace_do_wait that
	 * this is a ptrace report, so we expect to enter TASK_TRACED but
	 * might not be there yet when examined.
	 */
	BUG_ON(code == 0);
	WARN_ON(code &~ 0x7ff);
	tsk->exit_code = code | PTRACE_TRAPPED_MASK;
	do_notify(tsk, state->parent, CLD_TRAPPED);

	pr_debug("%d ptrace_report quiescing exit_code %x\n",
		 current->pid, current->exit_code);

	put_ptrace_state(state);

	NO_LOCKS;

	/*
	 * If regset 0 has a writeback call, do it now.  On register window
	 * machines, this makes sure the user memory backing the register
	 * data is up to date by the time wait_task_inactive returns to
	 * ptrace_start in our tracer doing a PTRACE_PEEKDATA or the like.
	 */
	regset = utrace_regset(tsk, engine, utrace_native_view(tsk), 0);
	if (regset->writeback)
		(*regset->writeback)(tsk, regset, 0);

	return UTRACE_ACTION_RESUME;
}

static inline u32
ptrace_event(struct utrace_attached_engine *engine,
	     struct task_struct *tsk,
	     struct ptrace_state *state,
	     int event)
	__releases(RCU)
{
	state->syscall = 0;
	return ptrace_report(engine, tsk, state, (event << 8) | SIGTRAP);
}

/*
 * Unlike other report callbacks, this can't be called while ptrace_exit
 * is doing ptrace_done in parallel, so we don't need get_ptrace_state.
 */
static u32
ptrace_report_death(struct utrace_attached_engine *engine,
		    struct task_struct *tsk)
{
	struct ptrace_state *state = engine->data;

	if (tsk->exit_code == 0 && unlikely(tsk->flags & PF_SIGNALED))
		/*
		 * This can only mean that tsk->exit_code was clobbered
		 * by ptrace_update or ptrace_do_wait in a race with
		 * an asynchronous wakeup and exit for SIGKILL.
		 */
		tsk->exit_code = SIGKILL;

	if (unlikely(state == NULL)) {
		/*
		 * We can be called before ptrace_setup_finish is done,
		 * if we're dying before attaching really finished.
		 */
		printk("XXX ptrace_report_death leak\n");
		return UTRACE_ACTION_RESUME;
	}

	if (tsk->parent == state->parent && tsk->exit_signal != -1) {
		/*
		 * This is a natural child (excluding clone siblings of a
		 * child group_leader), so we detach and let the normal
		 * reporting happen once our NOREAP action is gone.  But
		 * first, generate a SIGCHLD for those cases where normal
		 * behavior won't.  A ptrace'd child always generates SIGCHLD.
		 */
		pr_debug("ptrace %d death natural parent %d exit_code %x\n",
			 tsk->pid, state->parent->pid, tsk->exit_code);
		if (!thread_group_empty(tsk))
			do_notify(tsk, state->parent, CLD_EXITED);
		ptrace_state_unlink(state);
		rcu_assign_pointer(engine->data, NULL);
		ptrace_done(state);
		return UTRACE_ACTION_DETACH;
	}

	/*
	 * This might be a second report_death callback for a group leader
	 * that was delayed when its original report_death callback was made.
	 * Repeating do_notify is exactly what we need for that case too.
	 * After the wakeup, ptrace_do_wait will see delay_group_leader false.
	 */

	pr_debug("ptrace %d death notify %d exit_code %x: ",
		 tsk->pid, state->parent->pid, tsk->exit_code);
	do_notify(tsk, state->parent, CLD_EXITED);
	pr_debug("%d notified %d\n", tsk->pid, state->parent->pid);
	return UTRACE_ACTION_RESUME;
}

/*
 * We get this only in the case where our UTRACE_ACTION_NOREAP was ignored.
 * That happens solely when a non-leader exec reaps the old leader.
 */
static void
ptrace_report_reap(struct utrace_attached_engine *engine,
		   struct task_struct *tsk)
{
	struct ptrace_state *state = engine->data;

	if (unlikely(state == NULL)) { /* Not fully attached.  */
		printk("XXX ptrace_report_reap leak\n");
		return;
	}

	NO_LOCKS;

	ptrace_state_unlink(state);
	rcu_assign_pointer(engine->data, NULL);
	ptrace_done(state);

	NO_LOCKS;
}

/*
 * Start tracing the child.  This has to do put_ptrace_state before it can
 * do allocation that might block.
 */
static void
ptrace_clone_setup(struct utrace_attached_engine *engine,
		   struct task_struct *parent,
		   struct ptrace_state *state,
		   struct task_struct *child)
	__releases(RCU)
{
	struct task_struct *tracer;
	struct utrace_attached_engine *child_engine;
	struct ptrace_state *child_state;
	int ret;
	u8 options;
	int cap_sys_ptrace;

	tracer = state->parent;
	options = state->options;
	cap_sys_ptrace = state->cap_sys_ptrace;
	get_task_struct(tracer);
	put_ptrace_state(state);

	NO_LOCKS;

	child_engine = utrace_attach(child, (UTRACE_ATTACH_CREATE
					     | UTRACE_ATTACH_EXCLUSIVE
					     | UTRACE_ATTACH_MATCH_OPS),
				     &ptrace_utrace_ops, NULL);
	if (unlikely(IS_ERR(child_engine))) {
		BUG_ON(PTR_ERR(child_engine) != -ENOMEM);
		put_task_struct(tracer);
		goto nomem;
	}

	child_state = ptrace_setup(child, child_engine,
				   tracer, options, cap_sys_ptrace);

	put_task_struct(tracer);

	if (unlikely(IS_ERR(child_state))) {
		(void) utrace_detach(child, child_engine);

		if (PTR_ERR(child_state) == -ENOMEM)
			goto nomem;

		/*
		 * Our tracer has started exiting.  It's
		 * too late to set it up tracing the child.
		 */
		BUG_ON(PTR_ERR(child_state) != -EALREADY);
	}
	else {
		sigaddset(&child->pending.signal, SIGSTOP);
		set_tsk_thread_flag(child, TIF_SIGPENDING);
		ret = ptrace_setup_finish(child, child_state);

		/*
		 * The child hasn't run yet, it can't have died already.
		 */
		BUG_ON(ret);
	}

	NO_LOCKS;

	return;

nomem:
	NO_LOCKS;
	printk(KERN_ERR "ptrace out of memory, lost child %d of %d",
	       child->pid, parent->pid);
}

static u32
ptrace_report_clone(struct utrace_attached_engine *engine,
		    struct task_struct *parent,
		    unsigned long clone_flags, struct task_struct *child)
{
	int event, option;
	struct ptrace_state *state;

	NO_LOCKS;

	state = get_ptrace_state(engine, parent);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

	pr_debug("%d (%p) engine %p"
		 " ptrace_report_clone child %d (%p) fl %lx\n",
		 parent->pid, parent, engine, child->pid, child, clone_flags);

	event = PTRACE_EVENT_FORK;
	option = PTRACE_O_TRACEFORK;
	if (clone_flags & CLONE_VFORK) {
		event = PTRACE_EVENT_VFORK;
		option = PTRACE_O_TRACEVFORK;
	}
	else if ((clone_flags & CSIGNAL) != SIGCHLD) {
		event = PTRACE_EVENT_CLONE;
		option = PTRACE_O_TRACECLONE;
	}

	if (state->options & option) {
		state->have_eventmsg = 1;
		state->u.eventmsg = child->pid;
	}
	else
		event = 0;

	if (!(clone_flags & CLONE_UNTRACED)
	    && (event || (clone_flags & CLONE_PTRACE))) {
		/*
		 * Have our tracer start following the child too.
		 */
		ptrace_clone_setup(engine, parent, state, child);

		NO_LOCKS;

		/*
		 * That did put_ptrace_state, so we have to check
		 * again in case our tracer just started exiting.
		 */
		state = get_ptrace_state(engine, parent);
		if (unlikely(state == NULL))
			return UTRACE_ACTION_RESUME;
	}

	if (event)
		return ptrace_event(engine, parent, state, event);

	put_ptrace_state(state);

	NO_LOCKS;

	return UTRACE_ACTION_RESUME;
}


static u32
ptrace_report_vfork_done(struct utrace_attached_engine *engine,
			 struct task_struct *parent, pid_t child_pid)
{
	struct ptrace_state *state = get_ptrace_state(engine, parent);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

	state->have_eventmsg = 1;
	state->u.eventmsg = child_pid;
	return ptrace_event(engine, parent, state, PTRACE_EVENT_VFORK_DONE);
}


static u32
ptrace_report_signal(struct utrace_attached_engine *engine,
		     struct task_struct *tsk, struct pt_regs *regs,
		     u32 action, siginfo_t *info,
		     const struct k_sigaction *orig_ka,
		     struct k_sigaction *return_ka)
{
	int signo = info == NULL ? SIGTRAP : info->si_signo;
	struct ptrace_state *state = get_ptrace_state(engine, tsk);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

	state->syscall = 0;
	state->have_eventmsg = 0;
	state->u.siginfo = info;
	return ptrace_report(engine, tsk, state, signo) | UTRACE_SIGNAL_IGN;
}

static u32
ptrace_report_jctl(struct utrace_attached_engine *engine,
		   struct task_struct *tsk, int type)
{
	struct ptrace_state *state = get_ptrace_state(engine, tsk);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

	pr_debug("ptrace %d jctl notify %d type %x exit_code %x\n",
		 tsk->pid, state->parent->pid, type, tsk->exit_code);

	do_notify(tsk, state->parent, type);
	put_ptrace_state(state);

	return UTRACE_JCTL_NOSIGCHLD;
}

static u32
ptrace_report_exec(struct utrace_attached_engine *engine,
		   struct task_struct *tsk,
		   const struct linux_binprm *bprm,
		   struct pt_regs *regs)
{
	struct ptrace_state *state = get_ptrace_state(engine, tsk);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

	if (state->options & PTRACE_O_TRACEEXEC)
		return ptrace_event(engine, tsk, state, PTRACE_EVENT_EXEC);

	/*
	 * Without PTRACE_O_TRACEEXEC, this is not a stop in the
	 * ptrace_notify() style.  Instead, it's a regular signal.
	 * The difference is in where the real stop takes place and
	 * what ptrace can do with tsk->exit_code there.
	 */
	send_sig(SIGTRAP, tsk, 0);
	return UTRACE_ACTION_RESUME;
}

static u32
ptrace_report_syscall(struct utrace_attached_engine *engine,
		      struct task_struct *tsk, struct pt_regs *regs,
		      int entry)
{
	struct ptrace_state *state = get_ptrace_state(engine, tsk);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

#ifdef PTRACE_SYSEMU
	if (state->sysemu) {
		/*
		 * A syscall under PTRACE_SYSEMU gets just one stop and
		 * report.  But at that stop, the syscall number is
		 * expected to reside in the pseudo-register.  We need to
		 * reset it to prevent the actual syscall from happening.
		 *
		 * At the entry tracing stop, the return value register has
		 * been primed to -ENOSYS, and the syscall pseudo-register
		 * has the syscall number.  We squirrel away the syscall
		 * number in the return value register long enough to skip
		 * the actual syscall and get to the exit tracing stop.
		 * There, we swap the registers back and do ptrace_report.
		 */

		long *scno = tracehook_syscall_callno(regs);
		long *retval = tracehook_syscall_retval(regs);
		if (entry) {
			*retval = *scno;
			*scno = -1;
			return UTRACE_ACTION_RESUME;
		}
		else {
			*scno = *retval;
			*retval = -ENOSYS;
		}
	}
#endif

	state->syscall = 1;
	return ptrace_report(engine, tsk, state,
			     ((state->options & PTRACE_O_TRACESYSGOOD)
			      ? 0x80 : 0) | SIGTRAP);
}

static u32
ptrace_report_syscall_entry(struct utrace_attached_engine *engine,
			    struct task_struct *tsk, struct pt_regs *regs)
{
	return ptrace_report_syscall(engine, tsk, regs, 1);
}

static u32
ptrace_report_syscall_exit(struct utrace_attached_engine *engine,
			   struct task_struct *tsk, struct pt_regs *regs)
{
	return ptrace_report_syscall(engine, tsk, regs, 0);
}

static u32
ptrace_report_exit(struct utrace_attached_engine *engine,
		   struct task_struct *tsk, long orig_code, long *code)
{
	struct ptrace_state *state = get_ptrace_state(engine, tsk);
	if (unlikely(state == NULL))
		return UTRACE_ACTION_RESUME;

	state->have_eventmsg = 1;
	state->u.eventmsg = *code;
	return ptrace_event(engine, tsk, state, PTRACE_EVENT_EXIT);
}

static int
ptrace_unsafe_exec(struct utrace_attached_engine *engine,
		   struct task_struct *tsk)
{
	int unsafe = LSM_UNSAFE_PTRACE;
	struct ptrace_state *state;

	START_CHECK;

	state = get_ptrace_state(engine, tsk);
	if (likely(state != NULL)) {
		if (state->cap_sys_ptrace)
			unsafe = LSM_UNSAFE_PTRACE_CAP;
		put_ptrace_state(state);
	}

	END_CHECK;

	return unsafe;
}

static struct task_struct *
ptrace_tracer_task(struct utrace_attached_engine *engine,
		   struct task_struct *target)
{
	struct task_struct *parent = NULL;
	struct ptrace_state *state;

	START_CHECK;

	state = get_ptrace_state(engine, target);
	if (likely(state != NULL)) {
		parent = state->parent;
		put_ptrace_state(state);
	}

	END_CHECK;

	return parent;
}

static int
ptrace_allow_access_process_vm(struct utrace_attached_engine *engine,
			       struct task_struct *target,
			       struct task_struct *caller)
{
	struct ptrace_state *state;
	int ours = 0;

	START_CHECK;

	state = get_ptrace_state(engine, target);
	if (likely(state != NULL)) {
		ours = (((engine->flags & UTRACE_ACTION_QUIESCE)
			 || target->state == TASK_STOPPED)
			&& state->parent == caller);
		put_ptrace_state(state);
	}

	if (ours)
		ours = security_ptrace(caller, target) == 0;

	END_CHECK;

	return ours;
}


static const struct utrace_engine_ops ptrace_utrace_ops =
{
	.report_syscall_entry = ptrace_report_syscall_entry,
	.report_syscall_exit = ptrace_report_syscall_exit,
	.report_exec = ptrace_report_exec,
	.report_jctl = ptrace_report_jctl,
	.report_signal = ptrace_report_signal,
	.report_vfork_done = ptrace_report_vfork_done,
	.report_clone = ptrace_report_clone,
	.report_exit = ptrace_report_exit,
	.report_death = ptrace_report_death,
	.report_reap = ptrace_report_reap,
	.unsafe_exec = ptrace_unsafe_exec,
	.tracer_task = ptrace_tracer_task,
	.allow_access_process_vm = ptrace_allow_access_process_vm,
};
