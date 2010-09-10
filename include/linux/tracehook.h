/*
 * Tracing hooks
 *
 * This file defines hook entry points called by core code where
 * user tracing/debugging support might need to do something.
 * These entry points are called tracehook_*.  Each hook declared below
 * has a detailed comment giving the context (locking et al) from
 * which it is called, and the meaning of its return value (if any).
 *
 * We also declare here tracehook_* functions providing access to low-level
 * interrogation and control of threads.  These functions must be called
 * on either the current thread or on a quiescent thread.  We say a
 * thread is "quiescent" if it is in TASK_STOPPED or TASK_TRACED state,
 * we are guaranteed it will not be woken up and return to user mode, and
 * we have called wait_task_inactive on it.
 */

#ifndef _LINUX_TRACEHOOK_H
#define _LINUX_TRACEHOOK_H	1

#include <linux/sched.h>
#include <linux/uaccess.h>
struct linux_binprm;
struct pt_regs;


/*
 * The machine-specific asm/tracehook.h file is responsible for declaring
 * the following entry points.  These can be called only on a quiescent thread,
 * or the current thread when it is about to return to user mode.
 *
 * Single-step control.  When enabled, the next instruction or syscall exit
 * produces a SIGTRAP.  Enabling or disabling redundantly is harmless.
 *
 *	void tracehook_enable_single_step(struct task_struct *tsk);
 *	void tracehook_disable_single_step(struct task_struct *tsk);
 *	int tracehook_single_step_enabled(struct task_struct *tsk);
 *
 * If those calls are defined, #define ARCH_HAS_SINGLE_STEP to nonzero.
 * Do not #define it if these calls are never available in this kernel config.
 * If defined, the value of ARCH_HAS_SINGLE_STEP can be constant or variable.
 * It should evaluate to nonzero if the hardware is able to support
 * tracehook_enable_single_step.  If it's a variable expression, it
 * should be one that can be evaluated in modules, i.e. uses exported symbols.
 *
 * Block-step control (trap on control transfer), when available.
 * tracehook_disable_block_step will be called after tracehook_enable_single_step.
 * When enabled, the next jump, or other control transfer or syscall exit,
 * produces a SIGTRAP.  Enabling or disabling redundantly is harmless.
 *
 *	void tracehook_enable_block_step(struct task_struct *tsk);
 *	void tracehook_disable_block_step(struct task_struct *tsk);
 *	int tracehook_block_step_enabled(struct task_struct *tsk);
 *
 * If those calls are defined, #define ARCH_HAS_BLOCK_STEP to nonzero.
 * Do not #define it if these calls are never available in this kernel config.
 * If defined, the value of ARCH_HAS_BLOCK_STEP can be constant or variable.
 * It should evaluate to nonzero if the hardware is able to support
 * tracehook_enable_block_step.  If it's a variable expression, it
 * should be one that can be evaluated in modules, i.e. uses exported symbols.
 *
 * Control system call tracing.  When enabled a syscall entry or exit
 * produces a call to tracehook_report_syscall, below.
 *
 *	void tracehook_enable_syscall_trace(struct task_struct *tsk);
 *	void tracehook_disable_syscall_trace(struct task_struct *tsk);
 *
 * When stopped in tracehook_report_syscall for syscall entry,
 * abort the syscall so no kernel function is called.
 * If the register state was not otherwise updated before,
 * this produces an -ENOSYS error return as for an invalid syscall number.
 *
 *	void tracehook_abort_syscall(struct pt_regs *regs);
 *
 * Return the regset view (see below) that is native for the given process.
 * For example, what it would access when it called ptrace.
 * Throughout the life of the process, this only changes at exec.
 *
 *	const struct utrace_regset_view *utrace_native_view(struct task_struct *);
 *
 ***/


/*
 * This data structure describes a machine resource we call a register set.
 * This is part of the state of an individual thread, not necessarily
 * actual CPU registers per se.  A register set consists of a number of
 * similar slots, given by ->n.  Each slot is ->size bytes, and aligned to
 * ->align bytes (which is at least ->size).
 *
 * As described above, these entry points can be called on the current
 * thread or on a quiescent thread.  The pos argument must be aligned
 * according to ->align; the count argument must be a multiple of ->size.
 * These functions are not responsible for checking for invalid arguments.
 *
 * When there is a natural value to use as an index, ->bias gives the
 * difference between the natural index and the slot index for the
 * register set.  For example, x86 GDT segment descriptors form a regset;
 * the segment selector produces a natural index, but only a subset of
 * that index space is available as a regset (the TLS slots); subtracting
 * ->bias from a segment selector index value computes the regset slot.
 */
struct utrace_regset {
	unsigned int n;		/* Number of slots (registers).  */
	unsigned int size;	/* Size in bytes of a slot (register).  */
	unsigned int align;	/* Required alignment, in bytes.  */
	unsigned int bias;	/* Bias from natural indexing.  */

	/*
	 * Return -ENODEV if not available on the hardware found.
	 * Return 0 if no interesting state in this thread.
	 * Return >0 number of ->size units of interesting state.
	 * Any get call fetching state beyond that number will
	 * see the default initialization state for this data,
	 * so a caller that knows that the default state is need
	 * not copy it all out.
	 * This call is optional; the pointer is NULL if there
	 * so no inexpensive check to yield a value < .n.
	 */
	int (*active)(struct task_struct *, const struct utrace_regset *);

	/*
	 * Fetch and store register values.  Return 0 on success; -EIO or
	 * -ENODEV are usual failure returns.  The pos and count values are
	 * in bytes, but must be properly aligned.  If kbuf is non-null,
	 * that buffer is used and ubuf is ignored.  If kbuf is NULL, then
	 * ubuf gives a userland pointer to access directly, and an -EFAULT
	 * return value is possible.
	 */
	int (*get)(struct task_struct *, const struct utrace_regset *,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf);
	int (*set)(struct task_struct *, const struct utrace_regset *,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf);

	/*
	 * This call is optional; usually the pointer is NULL.
	 * When provided, there is some user memory associated
	 * with this regset's hardware, such as memory backing
	 * cached register data on register window machines; the
	 * regset's data controls what user memory is used
	 * (e.g. via the stack pointer value).
	 *
	 * Write register data back to user memory.  If the
	 * immediate flag is nonzero, it must be written to the
	 * user memory so uaccess/access_process_vm can see it
	 * when this call returns; if zero, then it must be
	 * written back by the time the task completes a context
	 * switch (as synchronized with wait_task_inactive).
	 * Return 0 on success or if there was nothing to do,
	 * -EFAULT for a memory problem (bad stack pointer or
	 * whatever), or -EIO for a hardware problem.
	 */
	int (*writeback)(struct task_struct *, const struct utrace_regset *,
			 int immediate);
};

/*
 * A regset view is a collection of regsets (struct utrace_regset, above).
 * This describes all the state of a thread that can be seen from a given
 * architecture/ABI environment.  More than one view might refer to the
 * same utrace_regset, or more than one regset might refer to the same
 * machine-specific state in the thread.  For example, a 32-bit thread's
 * state could be examined from the 32-bit view or from the 64-bit view.
 * Either method reaches the same thread register state, doing appropriate
 * widening or truncation.
 */
struct utrace_regset_view {
	const char *name;	/* Identifier, e.g. ELF_PLATFORM string.  */

	const struct utrace_regset *regsets;
	unsigned int n;

	/*
	 * EM_* value for which this is the native view, if any.
	 */
	u16 e_machine;
};


/*
 * These two are helpers for writing regset get/set functions in arch code.
 * Use one or more calls sequentially for each chunk of regset data stored
 * contiguously in memory.  Call with constants for start_pos and end_pos,
 * giving the range of byte positions in the regset that data corresponds
 * to; end_pos can be -1 if this chunk is at the end of the regset layout.
 * Each call updates the arguments to point past its chunk.
 */

static inline int
utrace_regset_copyout(unsigned int *pos, unsigned int *count,
		      void **kbuf, void __user **ubuf,
		      const void *data, int start_pos, int end_pos)
{
	if (*count == 0)
		return 0;
	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = (end_pos < 0 ? *count
				     : min(*count, end_pos - *pos));
		data += *pos - start_pos;
		if (*kbuf) {
			memcpy(*kbuf, data, copy);
			*kbuf += copy;
		}
		else if (copy_to_user(*ubuf, data, copy))
			return -EFAULT;
		else
			*ubuf += copy;
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

static inline int
utrace_regset_copyin(unsigned int *pos, unsigned int *count,
		     const void **kbuf, const void __user **ubuf,
		     void *data, int start_pos, int end_pos)
{
	if (*count == 0)
		return 0;
	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = (end_pos < 0 ? *count
				     : min(*count, end_pos - *pos));
		data += *pos - start_pos;
		if (*kbuf) {
			memcpy(data, *kbuf, copy);
			*kbuf += copy;
		}
		else if (copy_from_user(data, *ubuf, copy))
			return -EFAULT;
		else
			*ubuf += copy;
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

/*
 * These two parallel the two above, but for portions of a regset layout
 * that always read as all-zero or for which writes are ignored.
 */
static inline int
utrace_regset_copyout_zero(unsigned int *pos, unsigned int *count,
			   void **kbuf, void __user **ubuf,
			   int start_pos, int end_pos)
{
	if (*count == 0)
		return 0;
	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = (end_pos < 0 ? *count
				     : min(*count, end_pos - *pos));
		if (*kbuf) {
			memset(*kbuf, 0, copy);
			*kbuf += copy;
		}
		else if (clear_user(*ubuf, copy))
			return -EFAULT;
		else
			*ubuf += copy;
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

static inline int
utrace_regset_copyin_ignore(unsigned int *pos, unsigned int *count,
			    const void **kbuf, const void __user **ubuf,
			    int start_pos, int end_pos)
{
	if (*count == 0)
		return 0;
	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = (end_pos < 0 ? *count
				     : min(*count, end_pos - *pos));
		if (*kbuf)
			*kbuf += copy;
		else
			*ubuf += copy;
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

/**/


/***
 ***
 *** Following are entry points from core code, where the user debugging
 *** support can affect the normal behavior.  The locking situation is
 *** described for each call.
 ***
 ***/

#ifdef CONFIG_UTRACE
#include <linux/utrace.h>
#endif


/*
 * Called in copy_process when setting up the copied task_struct,
 * with tasklist_lock held for writing.
 */
static inline void tracehook_init_task(struct task_struct *child)
{
#ifdef CONFIG_UTRACE
	child->utrace_flags = 0;
	child->utrace = NULL;
#endif
}

/*
 * Called from release_task, no locks held.
 * After this, there should be no tracing entanglements.
 */
static inline void tracehook_release_task(struct task_struct *p)
{
#ifdef CONFIG_UTRACE
	smp_mb();
	if (p->utrace != NULL)
		utrace_release_task(p);
#endif
}

/*
 * Return nonzero to trigger a BUG_ON crash in release_task.
 * This should verify that there is no tracing-related state
 * still affecting the task_struct about to be released.
 * Called with tasklist_lock held for writing.
 */
static inline int tracehook_check_released(struct task_struct *p)
{
#ifdef CONFIG_UTRACE
	return unlikely(p->utrace != NULL);
#endif
	return 0;
}

/*
 * do_notify_parent_cldstop calls this when it's about to generate a SIGCHLD
 * for a job control stop.  Return nonzero to prevent that signal generation.
 * Called with tasklist_lock held for reading, sometimes with irqs disabled.
 */
static inline int tracehook_notify_cldstop(struct task_struct *tsk,
					   const siginfo_t *info)
{
#ifdef CONFIG_UTRACE
	if (tsk->utrace_flags & UTRACE_ACTION_NOREAP)
		return 1;
#endif
	return 0;
}

/*
 * exit_notify calls this with tasklist_lock held for writing.
 * Return nonzero to prevent any normal SIGCHLD generation for this
 * thread's death (i.e. when it is not ignored and its thread group is
 * empty).  This call must set *noreap to 0, or to 1 to force this thread
 * to become a zombie when it would normally reap itself.
 * The *death_cookie is passed to tracehook_report_death (below).
 */
static inline int tracehook_notify_death(struct task_struct *tsk,
					 int *noreap, void **death_cookie)
{
	*death_cookie = NULL;
#ifdef CONFIG_UTRACE
	*death_cookie = tsk->utrace;
	if (tsk->utrace_flags & UTRACE_ACTION_NOREAP) {
		*noreap = 1;
		return 1;
	}
#endif
	*noreap = 0;
	return 0;
}

/*
 * Return zero iff tracing doesn't care to examine this fatal signal,
 * so it can short-circuit normal delivery directly to a group exit.
 * Called with tsk->sighand->siglock held.
 */
static inline int tracehook_consider_fatal_signal(struct task_struct *tsk,
						  int sig)
{
#ifdef CONFIG_UTRACE
	return (tsk->utrace_flags & (UTRACE_EVENT(SIGNAL_TERM)
				     | UTRACE_EVENT(SIGNAL_CORE)));
#endif
	return 0;
}

/*
 * Return zero iff tracing doesn't care to examine this ignored signal,
 * so it can short-circuit normal delivery and never even get queued.
 * Either the handler is SIG_DFL and sig's default is ignore, or it's SIG_IGN.
 * Called with tsk->sighand->siglock held.
 */
static inline int tracehook_consider_ignored_signal(struct task_struct *tsk,
						    int sig, void *handler)
{
#ifdef CONFIG_UTRACE
	return (tsk->utrace_flags & UTRACE_EVENT(SIGNAL_IGN));
#endif
	return 0;
}


/*
 * Called with the siglock held when computing tsk's signal_pending flag.
 * Return nonzero to force the signal_pending flag on, so that
 * tracehook_induce_signal will be called before the next return to user mode.
 */
static inline int tracehook_induce_sigpending(struct task_struct *tsk)
{
#ifdef CONFIG_UTRACE
	return unlikely(tsk->utrace_flags & UTRACE_ACTION_QUIESCE);
#endif
	return 0;
}

/*
 * Called with the siglock held before dequeuing pending signals.
 * Return zero to check for a real pending signal normally.
 * Return -1 after releasing the siglock to repeat the check.
 * Return a signal number to induce an artifical signal delivery,
 * setting *info and *return_ka to specify its details and behavior.
 */
static inline int tracehook_get_signal(struct task_struct *tsk,
				       struct pt_regs *regs,
				       siginfo_t *info,
				       struct k_sigaction *return_ka)
{
#ifdef CONFIG_UTRACE
	if (unlikely(tsk->utrace_flags))
		return utrace_get_signal(tsk, regs, info, return_ka);
#endif
	return 0;
}

/*
 * Called with no locks held when about to stop for job control;
 * we are already in TASK_STOPPED state, about to call schedule.
 * Return zero if the normal SIGCHLD should be generated, which
 * will happen if last_one is true meaning this is the last thread
 * in the thread group to stop.
 */
static inline int tracehook_finish_stop(int last_one)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & UTRACE_EVENT(JCTL))
		return utrace_report_jctl(CLD_STOPPED);
#endif

	return 0;
}

/*
 * Called with tasklist_lock held for reading, for an event notification stop.
 * We are already in TASK_TRACED.  Return zero to go back to running,
 * or nonzero to actually stop until resumed.
 */
static inline int tracehook_stop_now(void)
{
	return 0;
}


/*
 * Return nonzero if the child's parent (current) should be prevented
 * from seeing its child in TASK_STOPPED state when it waits with WSTOPPED.
 * Called with tasklist_lock held for reading.
 */
static inline int tracehook_inhibit_wait_stopped(struct task_struct *child)
{
#ifdef CONFIG_UTRACE
	return (child->utrace_flags & UTRACE_ACTION_NOREAP);
#endif
	return 0;
}

/*
 * Return nonzero if the child's parent (current) should be prevented
 * from seeing its child in TASK_ZOMBIE state when it waits with WEXITED.
 * Called with tasklist_lock held for reading.
 */
static inline int tracehook_inhibit_wait_zombie(struct task_struct *child)
{
#ifdef CONFIG_UTRACE
	return (child->utrace_flags & UTRACE_ACTION_NOREAP);
#endif
	return 0;
}

/*
 * Return nonzero if the child's parent (current) should be prevented
 * from seeing its child resuming after job stop when it waits with WCONTINUED.
 * Called with tasklist_lock held for reading.
 */
static inline int tracehook_inhibit_wait_continued(struct task_struct *child)
{
#ifdef CONFIG_UTRACE
	return (child->utrace_flags & UTRACE_ACTION_NOREAP);
#endif
	return 0;
}


/*
 * Return LSM_UNSAFE_* bits applied to an exec because of tracing.
 * Called with task_lock(tsk) held.
 */
static inline int tracehook_unsafe_exec(struct task_struct *tsk)
{
#ifdef CONFIG_UTRACE
	if (tsk->utrace_flags)
		return utrace_unsafe_exec(tsk);
#endif
	return 0;
}

/*
 * Return the task_struct for the task using ptrace on this one, or NULL.
 * Must be called with rcu_read_lock held to keep the returned struct alive.
 *
 * At exec time, this may be called with task_lock(p) still held from when
 * tracehook_unsafe_exec was just called.
 *
 * The value is also used to display after "TracerPid:" in /proc/PID/status,
 * where it is called with only rcu_read_lock held.
 */
static inline struct task_struct *tracehook_tracer_task(struct task_struct *p)
{
#ifdef CONFIG_UTRACE
	if (p->utrace_flags)
		return utrace_tracer_task(p);
#endif
	return NULL;
}

/*
 * Return nonzero if the current task should be allowed to use
 * access_process_vm on the given task.
 */
static inline int tracehook_allow_access_process_vm(struct task_struct *tsk)
{
	if (tsk == current)
		return 1;
#ifdef CONFIG_UTRACE
	if (tsk->utrace_flags)
		return utrace_allow_access_process_vm(tsk);
#endif
	return 0;
}


/***
 ***
 *** Following decelarations are hook stubs where core code reports
 *** events.  These are called without locks, from the thread having the
 *** event.  In all tracehook_report_* calls, no locks are held and the thread
 *** is in a state close to returning to user mode with little baggage to
 *** unwind, except as noted below for tracehook_report_clone.  It is generally
 *** OK to block in these places if you want the user thread to be suspended.
 ***
 ***/

/*
 * Thread has just become a zombie (exit_state==TASK_ZOMBIE) or is about to
 * self-reap (exit_state==EXIT_DEAD).  If normal reaping is not inhibited,
 * tsk->exit_state might be changing in parallel.  The death_cookie was
 * passed back by tracehook_notify_death (above).
 */
static inline void tracehook_report_death(struct task_struct *tsk,
					  int exit_state, void *death_cookie)
{
#ifdef CONFIG_UTRACE
	smp_mb();
	if (tsk->utrace_flags & (UTRACE_EVENT(DEATH) | UTRACE_ACTION_QUIESCE))
		utrace_report_death(tsk, death_cookie);
#endif
}

/*
 * exec completed, we are shortly going to return to user mode.
 * The freshly initialized register state can be seen and changed here.
 */
static inline void tracehook_report_exec(struct linux_binprm *bprm,
				    struct pt_regs *regs)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & UTRACE_EVENT(EXEC))
		utrace_report_exec(bprm, regs);
#endif
}

/*
 * Called from do_exit, we are about to exit.  The code returned to the
 * parent for wait can be changed here.
 */
static inline void tracehook_report_exit(long *exit_code)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & UTRACE_EVENT(EXIT))
		utrace_report_exit(exit_code);
#endif
}

/*
 * Called after a child is set up, but before it has been started or
 * been given its CLONE_STOPPED initial stop.  (See also tracehook_init_task.)
 * This is not a good place to block, because the child has not started yet.
 * Suspend the child here if desired, and block in clone_complete (below).
 * This must prevent the child from self-reaping if clone_complete uses
 * the task_struct pointer; otherwise it might have died and been released
 * by the time tracehook_report_clone_complete is called.
 */
static inline void tracehook_report_clone(unsigned long clone_flags,
					  struct task_struct *child)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & UTRACE_EVENT(CLONE))
		utrace_report_clone(clone_flags, child);
#endif
}

/*
 * Called after the child has started running, shortly after
 * tracehook_report_clone.  This is just before the clone/fork syscall
 * returns, or blocks for vfork child completion if (clone_flags &
 * CLONE_VFORK).  The child pointer may be invalid if a self-reaping
 * child died and tracehook_report_clone took no action to prevent it
 * from self-reaping.
 */
static inline void tracehook_report_clone_complete(unsigned long clone_flags,
						   pid_t pid,
						   struct task_struct *child)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & UTRACE_ACTION_QUIESCE)
		utrace_quiescent(current, NULL);
#endif
}

/*
 * Called after a CLONE_VFORK parent has waited for the child to complete.
 * The clone/vfork system call will return immediately after this.
 * The child pointer may be invalid if a self-reaping child died and
 * tracehook_report_clone took no action to prevent it from self-reaping.
 */
static inline void tracehook_report_vfork_done(struct task_struct *child,
					       pid_t child_pid)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & UTRACE_EVENT(VFORK_DONE))
		utrace_report_vfork_done(child_pid);
#endif
}

/*
 * Called for system call entry or exit.
 */
static inline void tracehook_report_syscall(struct pt_regs *regs, int is_exit)
{
#ifdef CONFIG_UTRACE
	if (current->utrace_flags & (is_exit ? UTRACE_EVENT(SYSCALL_EXIT)
				     : UTRACE_EVENT(SYSCALL_ENTRY)))
		utrace_report_syscall(regs, is_exit);
#endif
}

/*
 * Called after system call exit if single/block-stepped into the syscall.
 */
static inline void tracehook_report_syscall_step(struct pt_regs *regs)
{
}

/*
 * Called when a signal handler has been set up.
 * Register and stack state reflects the user handler about to run.
 * Signal mask changes have already been made.
 */
static inline void tracehook_report_handle_signal(int sig,
						  const struct k_sigaction *ka,
						  const sigset_t *oldset,
						  struct pt_regs *regs)
{
#ifdef CONFIG_UTRACE
	struct task_struct *tsk = current;
	if ((tsk->utrace_flags & UTRACE_EVENT_SIGNAL_ALL)
	    && (tsk->utrace_flags & (UTRACE_ACTION_SINGLESTEP
				     | UTRACE_ACTION_BLOCKSTEP)))
		utrace_signal_handler_singlestep(tsk, regs);
#endif
}


#endif	/* <linux/tracehook.h> */
