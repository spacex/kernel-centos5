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

#include <asm/pgtable.h>
#include <asm/uaccess.h>

#ifdef CONFIG_PTRACE
#include <linux/utrace.h>
#include <linux/tracehook.h>
#include <asm/tracehook.h>
#endif

int getrusage(struct task_struct *, int, struct rusage __user *);

//#define PTRACE_DEBUG

int __ptrace_may_attach(struct task_struct *task)
{
	/* May we inspect the given task?
	 * This check is used both for attaching with ptrace
	 * and for allowing access to sensitive information in /proc.
	 *
	 * ptrace_attach denies several cases that /proc allows
	 * because setting up the necessary parent/child relationship
	 * or halting the specified task is impossible.
	 */
	int dumpable = 0;
	/* Don't let security modules deny introspection */
	if (task == current)
		return 0;
	if (((current->uid != task->euid) ||
	     (current->uid != task->suid) ||
	     (current->uid != task->uid) ||
	     (current->gid != task->egid) ||
	     (current->gid != task->sgid) ||
	     (current->gid != task->gid)) && !capable(CAP_SYS_PTRACE))
		return -EPERM;
	smp_rmb();
	if (task->mm)
		dumpable = task->mm->dumpable;
	if (!dumpable && !capable(CAP_SYS_PTRACE))
		return -EPERM;

	return security_ptrace(current, task);
}

int ptrace_may_attach(struct task_struct *task)
{
	int err;
	task_lock(task);
	err = __ptrace_may_attach(task);
	task_unlock(task);
	return !err;
}

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


#ifndef CONFIG_PTRACE

asmlinkage long sys_ptrace(long request, long pid, long addr, long data)
{
	return -ENOSYS;
}

#else

struct ptrace_state
{
	/*
	 * These elements are always available, even when the struct is
	 * awaiting destruction at the next RCU callback point.
	 */
	struct utrace_attached_engine *engine;
	struct task_struct *task; /* Target task.  */
	struct task_struct *parent; /* Whom we report to.  */
	struct list_head entry;	/* Entry on parent->ptracees list.  */

	union {
		struct rcu_head dead;
		struct {
			u8 options; /* PTRACE_SETOPTIONS bits.  */
			unsigned int syscall:1;	/* Reporting for syscall.  */
#ifdef PTRACE_SYSEMU
			unsigned int sysemu:1; /* PTRACE_SYSEMU in progress. */
#endif
			unsigned int have_eventmsg:1; /* u.eventmsg valid. */
			unsigned int cap_sys_ptrace:1; /* Tracer capable.  */

			union
			{
				unsigned long eventmsg;
				siginfo_t *siginfo;
			} u;
		} live;
	} u;
};

static const struct utrace_engine_ops ptrace_utrace_ops; /* Initialized below. */

static void
ptrace_state_unlink(struct ptrace_state *state)
{
	task_lock(state->parent);
	list_del_rcu(&state->entry);
	task_unlock(state->parent);
}

static struct ptrace_state *
ptrace_setup(struct task_struct *target, struct utrace_attached_engine *engine,
	     struct task_struct *parent, u8 options, int cap_sys_ptrace,
	     struct ptrace_state *state)
{
	if (state == NULL) {
		state = kzalloc(sizeof *state, GFP_USER);
		if (unlikely(state == NULL))
			return ERR_PTR(-ENOMEM);
	}

	state->engine = engine;
	state->task = target;
	state->parent = parent;
	state->u.live.options = options;
	state->u.live.cap_sys_ptrace = cap_sys_ptrace;

	task_lock(parent);
	if (unlikely(parent->flags & PF_EXITING)) {
		task_unlock(parent);
		kfree(state);
		return ERR_PTR(-EALREADY);
	}
	list_add_rcu(&state->entry, &state->parent->ptracees);
	task_unlock(state->parent);

	BUG_ON(engine->data != 0);
	rcu_assign_pointer(engine->data, (unsigned long) state);

	return state;
}

static void
ptrace_state_free(struct rcu_head *rhead)
{
	struct ptrace_state *state = container_of(rhead,
						  struct ptrace_state, u.dead);
	kfree(state);
}

static void
ptrace_done(struct ptrace_state *state)
{
	INIT_RCU_HEAD(&state->u.dead);
	call_rcu(&state->u.dead, ptrace_state_free);
}

/*
 * Update the tracing engine state to match the new ptrace state.
 */
static int __must_check
ptrace_update(struct task_struct *target,
	      struct utrace_attached_engine *engine,
	      unsigned long flags)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;

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
	if (state->u.live.options & PTRACE_O_TRACEEXIT)
		flags |= UTRACE_EVENT(EXIT);
	if (state->u.live.options & PTRACE_O_TRACEVFORKDONE)
		flags |= UTRACE_EVENT(VFORK_DONE);

	/*
	 * ptrace always inhibits normal parent reaping.
	 * But for a corner case we sometimes see the REAP event anyway.
	 */
	flags |= UTRACE_ACTION_NOREAP | UTRACE_EVENT(REAP);

	if (!(flags & UTRACE_ACTION_QUIESCE)) {
		/*
		 * We're letting the thread resume from ptrace stop.
		 * If SIGKILL is waking it up, it can be racing with us here
		 * to set its own exit_code in do_exit.  Though we clobber
		 * it here, we check for the case in ptrace_report_death.
		 */
		if (!unlikely(target->flags & PF_SIGNALED))
			target->exit_code = 0;

		if (!state->u.live.have_eventmsg)
			state->u.live.u.siginfo = NULL;

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

	return utrace_set_flags(target, engine, flags);
}

static int ptrace_traceme(void)
{
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	struct task_struct *parent;
	int retval;

	engine = utrace_attach(current, (UTRACE_ATTACH_CREATE
					 | UTRACE_ATTACH_EXCLUSIVE
					 | UTRACE_ATTACH_MATCH_OPS),
			       &ptrace_utrace_ops, 0UL);

	if (IS_ERR(engine)) {
		retval = PTR_ERR(engine);
		if (retval == -EEXIST)
			retval = -EPERM;
	}
	else {
		/*
		 * We need to preallocate so that we can hold
		 * rcu_read_lock from extracting ->parent through
		 * ptrace_setup using it.
		 */
		state = kzalloc(sizeof *state, GFP_USER);
		if (unlikely(state == NULL)) {
			(void) utrace_detach(current, engine);
			printk(KERN_ERR
			       "ptrace out of memory, lost child %d of %d",
			       current->pid, current->parent->pid);
			return -ENOMEM;
		}

		rcu_read_lock();
		parent = rcu_dereference(current->parent);

		task_lock(current);
		retval = security_ptrace(parent, current);
		task_unlock(current);

		if (retval) {
			kfree(state);
			(void) utrace_detach(current, engine);
		}
		else {
			state = ptrace_setup(current, engine, parent, 0, 0,
					     state);
			if (IS_ERR(state))
				retval = PTR_ERR(state);
		}
		rcu_read_unlock();

		if (!retval) {
			/*
			 * This can't fail because we can't die while we
			 * are here doing this.
			 */
			retval = ptrace_update(current, engine, 0);
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

	return retval;
}

static int ptrace_attach(struct task_struct *task)
{
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	int retval;

	retval = -EPERM;
	if (task->pid <= 1)
		goto bad;
	if (task->tgid == current->tgid)
		goto bad;
	if (!task->mm)		/* kernel threads */
		goto bad;

	engine = utrace_attach(task, (UTRACE_ATTACH_CREATE
				      | UTRACE_ATTACH_EXCLUSIVE
				      | UTRACE_ATTACH_MATCH_OPS),
			       &ptrace_utrace_ops, 0);
	if (IS_ERR(engine)) {
		retval = PTR_ERR(engine);
		if (retval == -EEXIST)
			retval = -EPERM;
		goto bad;
	}

	if (ptrace_may_attach(task)) {
		state = ptrace_setup(task, engine, current, 0,
				     capable(CAP_SYS_PTRACE), NULL);
		if (IS_ERR(state))
			retval = PTR_ERR(state);
		else {
			retval = ptrace_update(task, engine, 0);
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
	if (retval)
		(void) utrace_detach(task, engine);
	else {
		int stopped = 0;

		/*
		 * We must double-check that task has not just died and
		 * been reaped (after ptrace_update succeeded).
		 * This happens when exec (de_thread) ignores NOREAP.
		 * We cannot call into the signal code if it's dead.
		 */
		read_lock(&tasklist_lock);
		if (likely(!task->exit_state)) {
			force_sig_specific(SIGSTOP, task);

			spin_lock_irq(&task->sighand->siglock);
			stopped = (task->state == TASK_STOPPED);
			spin_unlock_irq(&task->sighand->siglock);
		}
		read_unlock(&tasklist_lock);

		if (stopped) {
			/*
			 * Do now the regset 0 writeback that we do on every
			 * stop, since it's never been done.  On register
			 * window machines, this makes sure the user memory
			 * backing the register data is up to date.
			 */
			const struct utrace_regset *regset;
			regset = utrace_regset(task, engine,
					       utrace_native_view(task), 0);
			if (regset->writeback)
				(*regset->writeback)(task, regset, 1);
		}
	}

bad:
	return retval;
}

static int ptrace_detach(struct task_struct *task,
			 struct utrace_attached_engine *engine)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	int error = utrace_detach(task, engine);
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

restart:
	rcu_read_lock();

	list_for_each_safe_rcu(pos, n, &tsk->ptracees) {
		struct ptrace_state *state = list_entry(pos,
							struct ptrace_state,
							entry);
		int error = utrace_detach(state->task, state->engine);
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
			struct task_struct *p = state->task;
			get_task_struct(p);
			rcu_read_unlock();
			wait_task_inactive(p);
			put_task_struct(p);
			goto restart;
		}
		else
			BUG_ON(error != -ESRCH);
	}

	rcu_read_unlock();

	BUG_ON(!list_empty(&tsk->ptracees));
}

static int
ptrace_induce_signal(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     long signr)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;

	if (signr == 0)
		return 0;

	if (!valid_signal(signr))
		return -EIO;

	if (state->u.live.syscall) {
		/*
		 * This is the traditional ptrace behavior when given
		 * a signal to resume from a syscall tracing stop.
		 */
		send_sig(signr, target, 1);
	}
	else if (!state->u.live.have_eventmsg && state->u.live.u.siginfo) {
		siginfo_t *info = state->u.live.u.siginfo;

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

fastcall int
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

fastcall int
ptrace_onereg_access(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     const struct utrace_regset_view *view,
		     int setno, unsigned long regno,
		     void __user *data, int write)
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
		if (!access_ok(VERIFY_READ, data, regset->size))
			ret = -EIO;
		else
			ret = (*regset->set)(target, regset, pos, regset->size,
					     NULL, data);
	}
	else {
		if (!access_ok(VERIFY_WRITE, data, regset->size))
			ret = -EIO;
		else
			ret = (*regset->get)(target, regset, pos, regset->size,
					     NULL, data);
	}

	return ret;
}

fastcall int
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
			if (!write) {
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

	if (request == PTRACE_TRACEME)
		return ptrace_traceme();

	ret = -ESRCH;
	read_lock(&tasklist_lock);
	child = find_task_by_pid(pid);
	if (child)
		get_task_struct(child);
	read_unlock(&tasklist_lock);
#ifdef PTRACE_DEBUG
	printk("ptrace pid %ld => %p\n", pid, child);
#endif
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
			       &ptrace_utrace_ops, 0);
	ret = -ESRCH;
	if (IS_ERR(engine) || engine == NULL)
		goto out_tsk_rcu;
	state = rcu_dereference((struct ptrace_state *) engine->data);
	if (state == NULL || state->parent != current)
		goto out_tsk_rcu;
	rcu_read_unlock();

	/*
	 * Traditional ptrace behavior demands that the target already be
	 * quiescent, but not dead.
	 */
	if (request != PTRACE_KILL
	    && !(engine->flags & UTRACE_ACTION_QUIESCE)) {
#ifdef PTRACE_DEBUG
		printk("%d not stopped (%lx)\n", child->pid, child->state);
#endif
		goto out_tsk;
	}

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

	if (child->exit_state)
		goto out_tsk;

	*childp = child;
	*enginep = engine;
	*statep = state;
	return -EIO;

out_tsk_rcu:
	rcu_read_unlock();
out_tsk:
	put_task_struct(child);
out:
	return ret;
}

static int
ptrace_common(long request, struct task_struct *child,
	      struct utrace_attached_engine *engine,
	      struct ptrace_state *state,
	      unsigned long addr, long data)
{
	unsigned long flags;
	int ret = -EIO;

	switch (request) {
	case PTRACE_DETACH:
		/*
		 * Detach a process that was attached.
		 */
		ret = ptrace_induce_signal(child, engine, data);
		if (!ret) {
			ret = ptrace_detach(child, engine);
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
			if (request == PTRACE_SINGLEBLOCK)
				break;
#endif
	case PTRACE_SINGLESTEP:
#ifdef ARCH_HAS_SINGLE_STEP
		if (! ARCH_HAS_SINGLE_STEP)
#endif
			if (request == PTRACE_SINGLESTEP
#ifdef PTRACE_SYSEMU_SINGLESTEP
			    || request == PTRACE_SYSEMU_SINGLESTEP
#endif
				)
				break;

		ret = ptrace_induce_signal(child, engine, data);
		if (ret)
			break;


		/*
		 * Reset the action flags without QUIESCE, so it resumes.
		 */
		flags = 0;
#ifdef PTRACE_SYSEMU
		state->u.live.sysemu = (request == PTRACE_SYSEMU_SINGLESTEP
					|| request == PTRACE_SYSEMU);
#endif
		if (request == PTRACE_SINGLESTEP
#ifdef PTRACE_SYSEMU
		    || request == PTRACE_SYSEMU_SINGLESTEP
#endif
			)
			flags |= UTRACE_ACTION_SINGLESTEP;
#ifdef PTRACE_SINGLEBLOCK
		else if (request == PTRACE_SINGLEBLOCK)
			flags |= UTRACE_ACTION_BLOCKSTEP;
#endif
		if (request == PTRACE_SYSCALL)
			flags |= UTRACE_EVENT_SYSCALL;
#ifdef PTRACE_SYSEMU
		else if (request == PTRACE_SYSEMU
			 || request == PTRACE_SYSEMU_SINGLESTEP)
			flags |= UTRACE_EVENT(SYSCALL_ENTRY);
#endif
		ret = ptrace_update(child, engine, flags);
		if (ret)
			BUG_ON(ret != -ESRCH);
		ret = 0;
		break;

#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
#endif
	case PTRACE_SETOPTIONS:
		ret = -EINVAL;
		if (data & ~PTRACE_O_MASK)
			break;
		state->u.live.options = data;
		ret = ptrace_update(child, engine, UTRACE_ACTION_QUIESCE);
		if (ret)
			BUG_ON(ret != -ESRCH);
		ret = 0;
		break;
	}

	return ret;
}


asmlinkage long sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child;
	struct utrace_attached_engine *engine;
	struct ptrace_state *state;
	long ret, val;

#ifdef PTRACE_DEBUG
	printk("%d sys_ptrace(%ld, %ld, %lx, %lx)\n",
	       current->pid, request, pid, addr, data);
#endif

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
		ret = put_user(state->u.live.have_eventmsg
			       ? state->u.live.u.eventmsg : 0L,
			       (unsigned long __user *) data);
		break;
	case PTRACE_GETSIGINFO:
		ret = -EINVAL;
		if (!state->u.live.have_eventmsg && state->u.live.u.siginfo)
			ret = copy_siginfo_to_user((siginfo_t __user *) data,
						   state->u.live.u.siginfo);
		break;
	case PTRACE_SETSIGINFO:
		ret = -EINVAL;
		if (!state->u.live.have_eventmsg && state->u.live.u.siginfo) {
			ret = 0;
			if (copy_from_user(state->u.live.u.siginfo,
					   (siginfo_t __user *) data,
					   sizeof(siginfo_t)))
				ret = -EFAULT;
		}
		break;
	}

out_tsk:
	put_task_struct(child);
out:
#ifdef PTRACE_DEBUG
	printk("%d ptrace -> %lx\n", current->pid, ret);
#endif
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

#ifdef PTRACE_DEBUG
	printk("%d compat_sys_ptrace(%d, %d, %x, %x)\n",
	       current->pid, request, pid, addr, cdata);
#endif
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
		ret = put_user(state->u.live.have_eventmsg
			       ? state->u.live.u.eventmsg : 0L,
			       (compat_long_t __user *) data);
		break;
	case PTRACE_GETSIGINFO:
		ret = -EINVAL;
		if (!state->u.live.have_eventmsg && state->u.live.u.siginfo)
			ret = copy_siginfo_to_user32(
				(struct compat_siginfo __user *) data,
				state->u.live.u.siginfo);
		break;
	case PTRACE_SETSIGINFO:
		ret = -EINVAL;
		if (!state->u.live.have_eventmsg && state->u.live.u.siginfo
		    && copy_siginfo_from_user32(
			    state->u.live.u.siginfo,
			    (struct compat_siginfo __user *) data))
			ret = -EFAULT;
		break;
	}

out_tsk:
	put_task_struct(child);
out:
#ifdef PTRACE_DEBUG
	printk("%d ptrace -> %lx\n", current->pid, ret);
#endif
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
restart:
	detach_error = 0;
	rcu_read_lock();
	if (tsk != current) {
		/*
		 * We've excluded other ptrace_do_wait calls.  But the
		 * ptracer itself might have done ptrace_detach while we
		 * did not have rcu_read_lock.  So double-check that state
		 * is still valid.
		 */
		struct utrace_attached_engine *engine;
		engine = utrace_attach(
			p, (UTRACE_ATTACH_MATCH_OPS
			    | UTRACE_ATTACH_MATCH_DATA),
			&ptrace_utrace_ops,
			(unsigned long) state);
		if (IS_ERR(engine) || state->parent != tsk)
			detach_error = -ESRCH;
		else
			BUG_ON(state->engine != engine);
	}
	if (likely(!detach_error))
		detach_error = ptrace_detach(p, state->engine);
	if (unlikely(detach_error == -EALREADY)) {
		/*
		 * It's still doing report_death callbacks.
		 * Just wait for it to settle down.
		 */
		rcu_read_unlock();
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
	rcu_read_unlock();
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
{
	struct ptrace_state *state;
	struct task_struct *p;
	int err = -ECHILD;
	int exit_code, why, status;

	rcu_read_lock();
	list_for_each_entry_rcu(state, &tsk->ptracees, entry) {
		p = state->task;

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
			if (delay_group_leader(p))
				continue;
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
			break;
		}

		/*
		 * This xchg atomically ensures that only one do_wait
		 * call can report this thread.  Because exit_code is
		 * always set before do_notify wakes us up, after this
		 * check fails we are sure to get a wakeup if it stops.
		 */
		exit_code = xchg(&p->exit_code, 0);
		if (exit_code)
			goto found;

		// XXX should handle WCONTINUED
	}
	rcu_read_unlock();
	return err;

found:
	BUG_ON(state->parent != tsk);
	rcu_read_unlock();

#ifdef PTRACE_DEBUG
	printk("%d ptrace_do_wait (%d) found %d code %x (%lu)\n", current->pid, tsk->pid, p->pid, exit_code, p->exit_state);
#endif

	if (p->exit_state) {
		if (unlikely(p->parent == tsk))
			/*
			 * This is our natural child we were ptracing.
			 * When it dies it detaches (see ptrace_report_death).
			 * So we're seeing it here in a race.  When it
			 * finishes detaching it will become reapable in
			 * the normal wait_task_zombie path instead.
			 */
			return 0;
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
		status = exit_code;
		exit_code = (status << 8) | 0x7f;
	}

	/*
	 * At this point we are committed to a successful return
	 * or a user error return.  Release the tasklist_lock.
	 */
	get_task_struct(p);
	read_unlock(&tasklist_lock);

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
}

static u32
ptrace_report(struct utrace_attached_engine *engine, struct task_struct *tsk,
	      int code)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	const struct utrace_regset *regset;

#ifdef PTRACE_DEBUG
	printk("%d ptrace_report %d engine %p state %p code %x parent %d (%p)\n",
	       current->pid, tsk->pid, engine, state, code,
	       state->parent->pid, state->parent);
	if (!state->u.live.have_eventmsg && state->u.live.u.siginfo) {
		const siginfo_t *si = state->u.live.u.siginfo;
		printk("  si %d code %x errno %d addr %p\n",
		       si->si_signo, si->si_code, si->si_errno,
		       si->si_addr);
	}
#endif

	/*
	 * Set our QUIESCE flag right now, before notifying the tracer.
	 * We do this before setting tsk->exit_code rather than
	 * by using UTRACE_ACTION_NEWSTATE in our return value, to
	 * ensure that the tracer can't get the notification and then
	 * try to resume us with PTRACE_CONT before we set the flag.
	 */
	utrace_set_flags(tsk, engine, engine->flags | UTRACE_ACTION_QUIESCE);

	/*
	 * If regset 0 has a writeback call, do it now.  On register window
	 * machines, this makes sure the user memory backing the register
	 * data is up to date by the time wait_task_inactive returns to
	 * ptrace_start in our tracer doing a PTRACE_PEEKDATA or the like.
	 */
	regset = utrace_regset(tsk, engine, utrace_native_view(tsk), 0);
	if (regset->writeback)
		(*regset->writeback)(tsk, regset, 0);

	BUG_ON(code == 0);
	tsk->exit_code = code;
	do_notify(tsk, state->parent, CLD_TRAPPED);

#ifdef PTRACE_DEBUG
	printk("%d ptrace_report quiescing exit_code %x\n",
	       current->pid, current->exit_code);
#endif

	return UTRACE_ACTION_RESUME;
}

static inline u32
ptrace_event(struct utrace_attached_engine *engine, struct task_struct *tsk,
	     int event)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	state->u.live.syscall = 0;
	return ptrace_report(engine, tsk, (event << 8) | SIGTRAP);
}


static u32
ptrace_report_death(struct utrace_attached_engine *engine,
		    struct task_struct *tsk)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;

	if (tsk->exit_code == 0 && unlikely(tsk->flags & PF_SIGNALED))
		/*
		 * This can only mean that tsk->exit_code was clobbered
		 * by ptrace_update or ptrace_do_wait in a race with
		 * an asynchronous wakeup and exit for SIGKILL.
		 */
		tsk->exit_code = SIGKILL;

	if (tsk->parent == state->parent) {
		/*
		 * This is a natural child, so we detach and let the normal
		 * reporting happen once our NOREAP action is gone.  But
		 * first, generate a SIGCHLD for those cases where normal
		 * behavior won't.  A ptrace'd child always generates SIGCHLD.
		 */
		if (tsk->exit_signal == -1 || !thread_group_empty(tsk))
			do_notify(tsk, state->parent, CLD_EXITED);
		ptrace_state_unlink(state);
		rcu_assign_pointer(engine->data, 0UL);
		ptrace_done(state);
		return UTRACE_ACTION_DETACH;
	}

	do_notify(tsk, state->parent, CLD_EXITED);
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
	struct ptrace_state *state;
	rcu_read_lock();
	state = rcu_dereference((struct ptrace_state *) engine->data);
	if (state != NULL) {
		ptrace_state_unlink(state);
		rcu_assign_pointer(engine->data, 0UL);
		ptrace_done(state);
	}
	rcu_read_unlock();
}


static u32
ptrace_report_clone(struct utrace_attached_engine *engine,
		    struct task_struct *parent,
		    unsigned long clone_flags, struct task_struct *child)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	struct utrace_attached_engine *child_engine;
	int event = PTRACE_EVENT_FORK;
	int option = PTRACE_O_TRACEFORK;

#ifdef PTRACE_DEBUG
	printk("%d (%p) engine %p ptrace_report_clone child %d (%p) fl %lx\n",
	       parent->pid, parent, engine, child->pid, child, clone_flags);
#endif

	if (clone_flags & CLONE_UNTRACED)
		goto out;

	if (clone_flags & CLONE_VFORK) {
		event = PTRACE_EVENT_VFORK;
		option = PTRACE_O_TRACEVFORK;
	}
	else if ((clone_flags & CSIGNAL) != SIGCHLD) {
		event = PTRACE_EVENT_CLONE;
		option = PTRACE_O_TRACECLONE;
	}

	if (!(clone_flags & CLONE_PTRACE) && !(state->u.live.options & option))
		goto out;

	child_engine = utrace_attach(child, (UTRACE_ATTACH_CREATE
					     | UTRACE_ATTACH_EXCLUSIVE
					     | UTRACE_ATTACH_MATCH_OPS),
				     &ptrace_utrace_ops, 0UL);
	if (unlikely(IS_ERR(child_engine))) {
		BUG_ON(PTR_ERR(child_engine) != -ENOMEM);
		printk(KERN_ERR
		       "ptrace out of memory, lost child %d of %d",
		       child->pid, parent->pid);
	}
	else {
		struct ptrace_state *child_state;
		child_state = ptrace_setup(child, child_engine,
					   state->parent,
					   state->u.live.options,
					   state->u.live.cap_sys_ptrace,
					   NULL);
		if (unlikely(IS_ERR(child_state))) {
			BUG_ON(PTR_ERR(child_state) != -ENOMEM);
			(void) utrace_detach(child, child_engine);
			printk(KERN_ERR
			       "ptrace out of memory, lost child %d of %d",
			       child->pid, parent->pid);
		}
		else {
			int ret;
			sigaddset(&child->pending.signal, SIGSTOP);
			set_tsk_thread_flag(child, TIF_SIGPENDING);
			ret = ptrace_update(child, child_engine, 0);
			/*
			 * The child hasn't run yet,
			 * it can't have died already.
			 */
			BUG_ON(ret);
		}
	}

	if (state->u.live.options & option) {
		state->u.live.have_eventmsg = 1;
		state->u.live.u.eventmsg = child->pid;
		return ptrace_event(engine, parent, event);
	}

out:
	return UTRACE_ACTION_RESUME;
}


static u32
ptrace_report_vfork_done(struct utrace_attached_engine *engine,
			 struct task_struct *parent, pid_t child_pid)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	state->u.live.have_eventmsg = 1;
	state->u.live.u.eventmsg = child_pid;
	return ptrace_event(engine, parent, PTRACE_EVENT_VFORK_DONE);
}


static u32
ptrace_report_signal(struct utrace_attached_engine *engine,
		     struct task_struct *tsk, struct pt_regs *regs,
		     u32 action, siginfo_t *info,
		     const struct k_sigaction *orig_ka,
		     struct k_sigaction *return_ka)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	int signo = info == NULL ? SIGTRAP : info->si_signo;
	state->u.live.syscall = 0;
	state->u.live.have_eventmsg = 0;
	state->u.live.u.siginfo = info;
	return ptrace_report(engine, tsk, signo) | UTRACE_SIGNAL_IGN;
}

static u32
ptrace_report_jctl(struct utrace_attached_engine *engine,
		   struct task_struct *tsk, int type)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
#ifdef PTRACE_DEBUG
	printk("ptrace %d jctl notify %d type %x exit_code %x\n",
	       tsk->pid, state->parent->pid, type, tsk->exit_code);
#endif
	do_notify(tsk, state->parent, type);
	return UTRACE_JCTL_NOSIGCHLD;
}

static u32
ptrace_report_exec(struct utrace_attached_engine *engine,
		   struct task_struct *tsk,
		   const struct linux_binprm *bprm,
		   struct pt_regs *regs)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	if (state->u.live.options & PTRACE_O_TRACEEXEC)
		return ptrace_event(engine, tsk, PTRACE_EVENT_EXEC);
	state->u.live.syscall = 0;
	return ptrace_report(engine, tsk, SIGTRAP);
}

static u32
ptrace_report_syscall(struct utrace_attached_engine *engine,
		      struct task_struct *tsk, struct pt_regs *regs,
		      int entry)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
#ifdef PTRACE_SYSEMU
	if (entry && state->u.live.sysemu)
		tracehook_abort_syscall(regs);
#endif
	state->u.live.syscall = 1;
	return ptrace_report(engine, tsk,
			     ((state->u.live.options & PTRACE_O_TRACESYSGOOD)
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
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	state->u.live.have_eventmsg = 1;
	state->u.live.u.eventmsg = *code;
	return ptrace_event(engine, tsk, PTRACE_EVENT_EXIT);
}

static int
ptrace_unsafe_exec(struct utrace_attached_engine *engine,
		   struct task_struct *tsk)
{
	struct ptrace_state *state = (struct ptrace_state *) engine->data;
	int unsafe = LSM_UNSAFE_PTRACE;
	if (state->u.live.cap_sys_ptrace)
		unsafe = LSM_UNSAFE_PTRACE_CAP;
	return unsafe;
}

static struct task_struct *
ptrace_tracer_task(struct utrace_attached_engine *engine,
		   struct task_struct *target)
{
	struct ptrace_state *state;

	/*
	 * This call is not necessarily made by the target task,
	 * so ptrace might be getting detached while we run here.
	 * The state pointer will be NULL if that happens.
	 */
	state = rcu_dereference((struct ptrace_state *) engine->data);

	return state == NULL ? NULL : state->parent;
}

static int
ptrace_allow_access_process_vm(struct utrace_attached_engine *engine,
			       struct task_struct *target,
			       struct task_struct *caller)
{
	struct ptrace_state *state;
	int ours;

	/*
	 * This call is not necessarily made by the target task,
	 * so ptrace might be getting detached while we run here.
	 * The state pointer will be NULL if that happens.
	 */
	rcu_read_lock();
	state = rcu_dereference((struct ptrace_state *) engine->data);
	ours = (state != NULL
		&& ((engine->flags & UTRACE_ACTION_QUIESCE)
		    || (target->state == TASK_STOPPED))
		&& state->parent == caller);
	rcu_read_unlock();

	return ours && security_ptrace(caller, target) == 0;
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

#endif
