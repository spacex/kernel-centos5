/*
 * utrace infrastructure interface for debugging user processes
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * Red Hat Author: Roland McGrath.
 *
 * This interface allows for notification of interesting events in a thread.
 * It also mediates access to thread state such as registers.
 * Multiple unrelated users can be associated with a single thread.
 * We call each of these a tracing engine.
 *
 * A tracing engine starts by calling utrace_attach() on the chosen thread,
 * passing in a set of hooks (&struct utrace_engine_ops), and some
 * associated data.  This produces a &struct utrace_attached_engine, which
 * is the handle used for all other operations.  An attached engine has its
 * ops vector, its data, and a flags word controlled by utrace_set_flags().
 *
 * Each engine's flags word contains two kinds of flags: events of
 * interest, and action state flags.
 *
 * For each event flag that is set, that engine will get the
 * appropriate ops->report_*() callback when the event occurs.  The
 * &struct utrace_engine_ops need not provide callbacks for an event
 * unless the engine sets one of the associated event flags.
 *
 * Action state flags change the normal behavior of the thread.
 * These bits are in %UTRACE_ACTION_STATE_MASK; these can be OR'd into
 * flags set with utrace_set_flags().  Also, every callback that return
 * an action value can reset these bits for the engine (see below).
 *
 * The bits %UTRACE_ACTION_STATE_MASK of all attached engines are OR'd
 * together, so each action is in force as long as any engine requests it.
 * As long as some engine sets the %UTRACE_ACTION_QUIESCE flag, the thread
 * will block and not resume running user code.  When the last engine
 * clears its %UTRACE_ACTION_QUIESCE flag, the thread will resume running.
 */

#ifndef _LINUX_UTRACE_H
#define _LINUX_UTRACE_H	1

#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/signal.h>
#include <linux/sched.h>

struct linux_binprm;
struct pt_regs;
struct utrace;
struct utrace_signal;
struct utrace_regset;
struct utrace_regset_view;

#ifdef __GENKSYMS__		/* RHEL-5 GA KABI compatibility */
struct utrace
{
	union {
		struct rcu_head dead;
		struct {
			struct task_struct *cloning;
			struct utrace_signal *signal;
		} live;
		struct {
			int report_death; /* report_death running */
			int reap; /* release_task called */
		} exit;
	} u;

	struct list_head engines;
	spinlock_t lock;
};
#endif

/*
 * Flags in &struct task_struct.utrace_flags and
 * &struct utrace_attached_engine.flags.
 * Low four bits are %UTRACE_ACTION_STATE_MASK bits (below).
 * Higher bits are events of interest.
 */
#define UTRACE_FIRST_EVENT	4
#define UTRACE_EVENT_BITS	(BITS_PER_LONG - UTRACE_FIRST_EVENT)
#define UTRACE_EVENT_MASK	(-1UL &~ UTRACE_ACTION_STATE_MASK)

enum utrace_events {
	_UTRACE_EVENT_QUIESCE,	/* Tracing requests stop.  */
	_UTRACE_EVENT_REAP,  	/* Zombie reaped, no more tracing possible.  */
	_UTRACE_EVENT_CLONE,	/* Successful clone/fork/vfork just done.  */
	_UTRACE_EVENT_VFORK_DONE, /* vfork woke from waiting for child.  */
	_UTRACE_EVENT_EXEC,	/* Successful execve just completed.  */
	_UTRACE_EVENT_EXIT,	/* Thread exit in progress.  */
	_UTRACE_EVENT_DEATH,	/* Thread has died.  */
	_UTRACE_EVENT_SYSCALL_ENTRY, /* User entered kernel for system call. */
	_UTRACE_EVENT_SYSCALL_EXIT, /* Returning to user after system call.  */
	_UTRACE_EVENT_SIGNAL,	/* Signal delivery will run a user handler.  */
	_UTRACE_EVENT_SIGNAL_IGN, /* No-op signal to be delivered.  */
	_UTRACE_EVENT_SIGNAL_STOP, /* Signal delivery will suspend.  */
	_UTRACE_EVENT_SIGNAL_TERM, /* Signal delivery will terminate.  */
	_UTRACE_EVENT_SIGNAL_CORE, /* Signal delivery will dump core.  */
	_UTRACE_EVENT_JCTL,	/* Job control stop or continue completed.  */
	_UTRACE_NEVENTS
};
#define UTRACE_EVENT_BIT(type)	(UTRACE_FIRST_EVENT + _UTRACE_EVENT_##type)
#define UTRACE_EVENT(type)	(1UL << UTRACE_EVENT_BIT(type))

/*
 * All the kinds of signal events.  These all use the report_signal callback.
 */
#define UTRACE_EVENT_SIGNAL_ALL	(UTRACE_EVENT(SIGNAL) \
				 | UTRACE_EVENT(SIGNAL_IGN) \
				 | UTRACE_EVENT(SIGNAL_STOP) \
				 | UTRACE_EVENT(SIGNAL_TERM) \
				 | UTRACE_EVENT(SIGNAL_CORE))
/*
 * Both kinds of syscall events; these call the report_syscall_entry and
 * report_syscall_exit callbacks, respectively.
 */
#define UTRACE_EVENT_SYSCALL	\
	(UTRACE_EVENT(SYSCALL_ENTRY) | UTRACE_EVENT(SYSCALL_EXIT))


/*
 * Action flags, in return value of callbacks.
 *
 * %UTRACE_ACTION_RESUME (zero) is the return value to do nothing special.
 * For each particular callback, some bits in %UTRACE_ACTION_OP_MASK can
 * be set in the return value to change the thread's behavior (see below).
 *
 * If %UTRACE_ACTION_NEWSTATE is set, then the %UTRACE_ACTION_STATE_MASK
 * bits in the return value replace the engine's flags as in utrace_set_flags
 * (but the event flags remained unchanged).
 *
 * If %UTRACE_ACTION_HIDE is set, then the callbacks to other engines
 * should be suppressed for this event.  This is appropriate only when
 * the event was artificially provoked by something this engine did,
 * such as setting a breakpoint.
 *
 * If %UTRACE_ACTION_DETACH is set, this engine is detached as by
 * utrace_detach().  The action bits in %UTRACE_ACTION_OP_MASK work as
 * normal, but the engine's %UTRACE_ACTION_STATE_MASK bits will no longer
 * affect the thread.
 */
#define UTRACE_ACTION_RESUME	0x0000 /* Continue normally after event.  */
#define UTRACE_ACTION_HIDE	0x0010 /* Hide event from other tracing.  */
#define UTRACE_ACTION_DETACH	0x0020 /* Detach me, state flags ignored.  */
#define UTRACE_ACTION_NEWSTATE	0x0040 /* Replace state bits.  */

/*
 * These flags affect the state of the thread until they are changed via
 * utrace_set_flags() or by the next callback to the same engine that uses
 * %UTRACE_ACTION_NEWSTATE.
 */
#define UTRACE_ACTION_QUIESCE	0x0001 /* Stay quiescent after callbacks.  */
#define UTRACE_ACTION_SINGLESTEP 0x0002 /* Resume for one instruction.  */
#define UTRACE_ACTION_BLOCKSTEP 0x0004 /* Resume until next branch.  */
#define UTRACE_ACTION_NOREAP	0x0008 /* Inhibit parent SIGCHLD and wait.  */
#define UTRACE_ACTION_STATE_MASK 0x000f /* Lasting state bits.  */

/*
 * These flags have meanings specific to the particular event report hook.
 */
#define UTRACE_ACTION_OP_MASK	0xff00

/*
 * Action flags in return value and argument of report_signal() callback.
 */
#define UTRACE_SIGNAL_DELIVER	0x0100 /* Deliver according to sigaction.  */
#define UTRACE_SIGNAL_IGN	0x0200 /* Ignore the signal.  */
#define UTRACE_SIGNAL_TERM	0x0300 /* Terminate the process.  */
#define UTRACE_SIGNAL_CORE	0x0400 /* Terminate with core dump.  */
#define UTRACE_SIGNAL_STOP	0x0500 /* Deliver as absolute stop.  */
#define UTRACE_SIGNAL_TSTP	0x0600 /* Deliver as job control stop.  */
#define UTRACE_SIGNAL_HOLD	0x1000 /* Flag, push signal back on queue.  */
/*
 * This value is passed to a report_signal() callback after a signal
 * handler is entered while %UTRACE_ACTION_SINGLESTEP is in force.
 * For this callback, no signal will never actually be delivered regardless
 * of the return value, and the other callback parameters are null.
 */
#define UTRACE_SIGNAL_HANDLER	0x0700

/*
 * Action flag in return value of report_jctl().
 */
#define UTRACE_JCTL_NOSIGCHLD	0x0100 /* Do not notify the parent.  */


/*
 * Flags for utrace_attach().
 */
#define UTRACE_ATTACH_CREATE		0x0010 /* Attach a new engine.  */
#define UTRACE_ATTACH_EXCLUSIVE		0x0020 /* Refuse if existing match.  */
#define UTRACE_ATTACH_MATCH_OPS		0x0001 /* Match engines on ops.  */
#define UTRACE_ATTACH_MATCH_DATA	0x0002 /* Match engines on data.  */
#define UTRACE_ATTACH_MATCH_MASK	0x000f


#ifdef CONFIG_UTRACE
/**
 * struct utrace_attached_engine - Per-engine per-thread structure.
 * @ops: &struct utrace_engine_ops pointer passed to utrace_attach()
 * @data: engine-private void * passed to utrace_attach()
 * @flags: current flags set by utrace_set_flags()
 *
 * The task itself never has to worry about engines detaching while
 * it's doing event callbacks.  These structures are freed only when
 * the task is quiescent.  For other parties, the list is protected
 * by RCU and utrace->lock.
 */
struct utrace_attached_engine
{
/* private: */
	struct list_head entry;	/* Entry on thread's utrace.engines list.  */
	struct rcu_head rhead;
	atomic_t check_dead;

/* public: */
	const struct utrace_engine_ops *ops;
	void *data;

	unsigned long flags;
};


struct utrace_engine_ops
{
	/*
	 * Event reporting hooks.
	 *
	 * Return values contain %UTRACE_ACTION_* flag bits.
	 * The %UTRACE_ACTION_OP_MASK bits are specific to each kind of event.
	 *
	 * All report_*() hooks are called with no locks held, in a generally
	 * safe environment when we will be returning to user mode soon.
	 * It is fine to block for memory allocation and the like, but all
	 * hooks are *asynchronous* and must not block on external events.
	 * If you want the thread to block, request %UTRACE_ACTION_QUIESCE in
	 * your hook; then later wake it up with utrace_set_flags().
	 */

	/*
	 * Event reported for parent, before child might run.
	 * The %PF_STARTING flag prevents other engines from attaching
	 * before this one has its chance.
	 */
	u32 (*report_clone)(struct utrace_attached_engine *engine,
			    struct task_struct *parent,
			    unsigned long clone_flags,
			    struct task_struct *child);

	/*
	 * Event reported for parent using %CLONE_VFORK or vfork() system call.
	 * The child has died or exec'd, so the vfork parent has unblocked
	 * and is about to return @child_pid.
	 */
	u32 (*report_vfork_done)(struct utrace_attached_engine *engine,
				 struct task_struct *parent, pid_t child_pid);

	/*
	 * Event reported after %UTRACE_ACTION_QUIESCE is set, when the target
	 * thread is quiescent.  Either it's the current thread, or it's in
	 * %TASK_TRACED or %TASK_STOPPED and will not resume running until the
	 * %UTRACE_ACTION_QUIESCE flag is no longer asserted by any engine.
	 */
	u32 (*report_quiesce)(struct utrace_attached_engine *engine,
			      struct task_struct *tsk);

	/*
	 * Thread dequeuing a signal to be delivered.
	 * The @action and @return_ka values say what %UTRACE_ACTION_RESUME
	 * will do (possibly already influenced by another tracing engine).
	 * An %UTRACE_SIGNAL_* return value overrides the signal disposition.
	 * The @info data (including @info->si_signo) can be changed at will.
	 * Changing @return_ka affects the sigaction that will be used.
	 * The @orig_ka value is the one in force before other tracing
	 * engines intervened.
	 */
	u32 (*report_signal)(struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     struct pt_regs *regs,
			     u32 action, siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka);

	/*
	 * Job control event completing, about to send %SIGCHLD to parent
	 * with %CLD_STOPPED or %CLD_CONTINUED as given in type.
	 * %UTRACE_JOBSTOP_NOSIGCHLD in the return value inhibits that.
	 */
	u32 (*report_jctl)(struct utrace_attached_engine *engine,
			   struct task_struct *tsk,
			   int type);

	/*
	 * Thread has just completed an exec.
	 * The initial user register state is handy to be tweaked directly.
	 */
	u32 (*report_exec)(struct utrace_attached_engine *engine,
			   struct task_struct *tsk,
			   const struct linux_binprm *bprm,
			   struct pt_regs *regs);

	/*
	 * Thread has entered the kernel to request a system call.
	 * The user register state is handy to be tweaked directly.
	 */
	u32 (*report_syscall_entry)(struct utrace_attached_engine *engine,
				    struct task_struct *tsk,
				    struct pt_regs *regs);

	/*
	 * Thread is about to leave the kernel after a system call request.
	 * The user register state is handy to be tweaked directly.
	 */
	u32 (*report_syscall_exit)(struct utrace_attached_engine *engine,
				   struct task_struct *tsk,
				   struct pt_regs *regs);

	/*
	 * Thread is exiting and cannot be prevented from doing so,
	 * but all its state is still live.  The @code value will be
	 * the wait result seen by the parent, and can be changed by
	 * this engine or others.  The @orig_code value is the real
	 * status, not changed by any tracing engine.
	 */
	u32 (*report_exit)(struct utrace_attached_engine *engine,
			   struct task_struct *tsk,
			   long orig_code, long *code);

	/*
	 * Thread is really dead now.  If %UTRACE_ACTION_NOREAP is in force,
	 * it remains an unreported zombie.  Otherwise, it might be reaped
	 * by its parent, or self-reap immediately.  Though the actual
	 * reaping may happen in parallel, a report_reap() callback will
	 * always be ordered after a report_death() callback.
	 *
	 * If %UTRACE_ACTION_NOREAP is in force and this was a group_leader
	 * dying with threads still in the group (delayed_group_leader()),
	 * then there can be a second report_death() callback later when
	 * the group_leader is no longer delayed.  This second callback can
	 * be made from another thread's context, but it will always be
	 * serialized after the first report_death() callback and before
	 * the report_reap() callback.  It's possible that
	 * delayed_group_leader() will already be true by the time it can
	 * be checked inside the first report_death callback made at the
	 * time of death, but that a second callback will be made almost
	 * immediately thereafter.
	 */
	u32 (*report_death)(struct utrace_attached_engine *engine,
			    struct task_struct *tsk);

	/*
	 * Called when someone reaps the dead task (parent, init, or self).
	 * No more callbacks are made after this one.
	 * The engine is always detached.
	 * There is nothing more a tracing engine can do about this thread.
	 */
	void (*report_reap)(struct utrace_attached_engine *engine,
			    struct task_struct *tsk);

	/*
	 * Miscellaneous hooks.  These are not associated with event reports.
	 * Any of these may be null if the engine has nothing to say.
	 * These hooks are called in more constrained environments and should
	 * not block or do very much.
	 */

	/*
	 * Return nonzero iff the @caller task should be allowed to access
	 * the memory of the target task via /proc/PID/mem and so forth,
	 * by dint of this engine's attachment to the target.
	 */
	int (*allow_access_process_vm)(struct utrace_attached_engine *engine,
				       struct task_struct *target,
				       struct task_struct *caller);

	/*
	 * Return %LSM_UNSAFE_* bits that apply to the exec in progress
	 * due to tracing done by this engine.  These bits indicate that
	 * someone is able to examine the process and so a set-UID or similar
	 * privilege escalation may not be safe to permit.
	 *
	 * Called with task_lock() held.
	 */
	int (*unsafe_exec)(struct utrace_attached_engine *engine,
			   struct task_struct *target);

	/*
	 * Return the &struct task_struct for the task using ptrace on this
	 * one, or %NULL.  Always called with rcu_read_lock() held to keep the
	 * returned struct alive.
	 *
	 * At exec time, this may be called with task_lock(target) still
	 * held from when unsafe_exec() was just called.  In that case it
	 * must give results consistent with those unsafe_exec() results,
	 * i.e. non-%NULL if any %LSM_UNSAFE_PTRACE_* bits were set.
	 *
	 * The value is also used to display after "TracerPid:" in
	 * /proc/PID/status, where it is called with only rcu_read_lock held.
	 *
	 * If this engine returns %NULL, another engine may supply the result.
	 */
	struct task_struct *(*tracer_task)(struct utrace_attached_engine *,
					   struct task_struct *target);
};


/*
 * These are the exported entry points for tracing engines to use.
 */
struct utrace_attached_engine *utrace_attach(struct task_struct *target,
					     int flags,
					     const struct utrace_engine_ops *,
					     void *data);
int utrace_detach(struct task_struct *target,
		  struct utrace_attached_engine *engine);
int utrace_set_flags(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     unsigned long flags);
int utrace_inject_signal(struct task_struct *target,
			 struct utrace_attached_engine *engine,
			 u32 action, siginfo_t *info,
			 const struct k_sigaction *ka);
const struct utrace_regset *utrace_regset(struct task_struct *target,
					  struct utrace_attached_engine *,
					  const struct utrace_regset_view *,
					  int which);


/*
 * Hooks in <linux/tracehook.h> call these entry points to the utrace dispatch.
 */
int utrace_quiescent(struct task_struct *, struct utrace_signal *);
void utrace_release_task(struct task_struct *);
int utrace_get_signal(struct task_struct *, struct pt_regs *,
		      siginfo_t *, struct k_sigaction *);
void utrace_report_clone(unsigned long clone_flags, struct task_struct *child);
void utrace_report_vfork_done(pid_t child_pid);
void utrace_report_exit(long *exit_code);
void utrace_report_death(struct task_struct *, struct utrace *);
void utrace_report_delayed_group_leader(struct task_struct *);
int utrace_report_jctl(int type);
void utrace_report_exec(struct linux_binprm *bprm, struct pt_regs *regs);
void utrace_report_syscall(struct pt_regs *regs, int is_exit);
struct task_struct *utrace_tracer_task(struct task_struct *);
int utrace_allow_access_process_vm(struct task_struct *);
int utrace_unsafe_exec(struct task_struct *);
void utrace_signal_handler_singlestep(struct task_struct *, struct pt_regs *);

/*
 * <linux/tracehook.h> uses these accessors to avoid #ifdef CONFIG_UTRACE.
 */
static inline unsigned long tsk_utrace_flags(struct task_struct *tsk)
{
	return tsk->utrace_flags;
}
static inline struct utrace *tsk_utrace_struct(struct task_struct *tsk)
{
	return tsk->utrace;
}
static inline void utrace_init_task(struct task_struct *child)
{
	child->utrace_flags = 0;
	child->utrace = NULL;
}

#else  /* !CONFIG_UTRACE */

static unsigned long tsk_utrace_flags(struct task_struct *tsk)
{
	return 0;
}
static struct utrace *tsk_utrace_struct(struct task_struct *tsk)
{
	return NULL;
}
static inline void utrace_init_task(struct task_struct *child)
{
}

/*
 * The calls to these should all be in if (0) and optimized out entirely.
 * We have stubs here only so tracehook.h doesn't need to #ifdef them
 * to avoid external references in case of unoptimized compilation.
 */
static inline int utrace_quiescent(struct task_struct *tsk, void *ignored)
{
	BUG();
	return 0;
}
static inline void utrace_release_task(struct task_struct *tsk)
{
	BUG();
}
static inline int utrace_get_signal(struct task_struct *tsk,
				    struct pt_regs *regs,
				    siginfo_t *info, struct k_sigaction *ka)
{
	BUG();
	return 0;
}
static inline void utrace_report_clone(unsigned long clone_flags,
				       struct task_struct *child)
{
	BUG();
}
static inline void utrace_report_vfork_done(pid_t child_pid)
{
	BUG();
}
static inline void utrace_report_exit(long *exit_code)
{
	BUG();
}
static inline void utrace_report_death(struct task_struct *tsk, void *ignored)
{
	BUG();
}
static inline void utrace_report_delayed_group_leader(struct task_struct *tsk)
{
	BUG();
}
static inline int utrace_report_jctl(int type)
{
	BUG();
	return 0;
}
static inline void utrace_report_exec(struct linux_binprm *bprm,
				      struct pt_regs *regs)
{
	BUG();
}
static inline void utrace_report_syscall(struct pt_regs *regs, int is_exit)
{
	BUG();
}
static inline struct task_struct *utrace_tracer_task(struct task_struct *tsk)
{
	BUG();
	return NULL;
}
static inline int utrace_allow_access_process_vm(struct task_struct *tsk)
{
	BUG();
	return 0;
}
static inline int utrace_unsafe_exec(struct task_struct *tsk)
{
	BUG();
	return 0;
}
static inline void utrace_signal_handler_singlestep(struct task_struct *tsk,
						    struct pt_regs *regs)
{
	BUG();
}

#endif  /* CONFIG_UTRACE */

#endif	/* linux/utrace.h */
