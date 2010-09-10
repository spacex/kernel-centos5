/*
 * User Debugging Data & Event Rendezvous
 *
 * This interface allows for notification of interesting events in a thread.
 * It also mediates access to thread state such as registers.
 * Multiple unrelated users can be associated with a single thread.
 * We call each of these a tracing engine.
 *
 * A tracing engine starts by calling utrace_attach on the chosen thread,
 * passing in a set of hooks (struct utrace_engine_ops), and some associated
 * data.  This produces a struct utrace_attached_engine, which is the handle
 * used for all other operations.  An attached engine has its ops vector,
 * its data, and a flags word controlled by utrace_set_flags.
 *
 * Each engine's flags word contains two kinds of flags: events of
 * interest, and action state flags.
 *
 * For each event flag that is set, that engine will get the
 * appropriate ops->report_* callback when the event occurs.  The
 * struct utrace_engine_ops need not provide callbacks for an event
 * unless the engine sets one of the associated event flags.
 *
 * Action state flags change the normal behavior of the thread.
 * These bits are in UTRACE_ACTION_STATE_MASK; these can be OR'd into
 * flags set with utrace_set_flags.  Also, every callback that return
 * an action value can reset these bits for the engine (see below).
 *
 * The bits UTRACE_ACTION_STATE_MASK of all attached engines are OR'd
 * together, so each action is in force as long as any engine requests it.
 * As long as some engine sets the UTRACE_ACTION_QUIESCE flag, the thread
 * will block and not resume running user code.  When the last engine
 * clears its UTRACE_ACTION_QUIESCE flag, the thread will resume running.
 */

#ifndef _LINUX_UTRACE_H
#define _LINUX_UTRACE_H	1

#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/signal.h>

struct linux_binprm;
struct pt_regs;
struct utrace_regset;
struct utrace_regset_view;


/*
 * Flags in task_struct.utrace_flags and utrace_attached_engine.flags.
 * Low four bits are UTRACE_ACTION_STATE_MASK bits (below).
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
 * UTRACE_ACTION_RESUME (zero) is the return value to do nothing special.
 * For each particular callback, some bits in UTRACE_ACTION_OP_MASK can
 * be set in the return value to change the thread's behavior (see below).
 *
 * If UTRACE_ACTION_NEWSTATE is set, then the UTRACE_ACTION_STATE_MASK
 * bits in the return value replace the engine's flags as in utrace_set_flags
 * (but the event flags remained unchanged).
 *
 * If UTRACE_ACTION_HIDE is set, then the callbacks to other engines
 * should be suppressed for this event.  This is appropriate only when
 * the event was artificially provoked by something this engine did,
 * such as setting a breakpoint.
 *
 * If UTRACE_ACTION_DETACH is set, this engine is detached as by utrace_detach.
 * The action bits in UTRACE_ACTION_OP_MASK work as normal, but the engine's
 * UTRACE_ACTION_STATE_MASK bits will no longer affect the thread.
 */
#define UTRACE_ACTION_RESUME	0x0000 /* Continue normally after event.  */
#define UTRACE_ACTION_HIDE	0x0010 /* Hide event from other tracing.  */
#define UTRACE_ACTION_DETACH	0x0020 /* Detach me, state flags ignored.  */
#define UTRACE_ACTION_NEWSTATE	0x0040 /* Replace state bits.  */

/*
 * These flags affect the state of the thread until they are changed via
 * utrace_set_flags or by the next callback to the same engine that uses
 * UTRACE_ACTION_NEWSTATE.
 */
#define UTRACE_ACTION_QUIESCE	0x0001 /* Stay quiescent after callbacks.  */
#define UTRACE_ACTION_SINGLESTEP 0x0002 /* Resume for one instruction.  */
#define UTRACE_ACTION_BLOCKSTEP 0x0004 /* Resume until next branch.  */
#define UTRACE_ACTION_NOREAP	0x0008 /* Inhibit parent SIGCHLD and wait.  */
#define UTRACE_ACTION_STATE_MASK 0x000f /* Lasting state bits.  */

/* These flags have meanings specific to the particular event report hook.  */
#define UTRACE_ACTION_OP_MASK	0xff00

/*
 * Action flags in return value and argument of report_signal callback.
 */
#define UTRACE_SIGNAL_DELIVER	0x0100 /* Deliver according to sigaction.  */
#define UTRACE_SIGNAL_IGN	0x0200 /* Ignore the signal.  */
#define UTRACE_SIGNAL_TERM	0x0300 /* Terminate the process.  */
#define UTRACE_SIGNAL_CORE	0x0400 /* Terminate with core dump.  */
#define UTRACE_SIGNAL_STOP	0x0500 /* Deliver as absolute stop.  */
#define UTRACE_SIGNAL_TSTP	0x0600 /* Deliver as job control stop.  */
#define UTRACE_SIGNAL_HOLD	0x1000 /* Flag, push signal back on queue.  */
/*
 * This value is passed to a report_signal callback after a signal
 * handler is entered while UTRACE_ACTION_SINGLESTEP is in force.
 * For this callback, no signal will never actually be delivered regardless
 * of the return value, and the other callback parameters are null.
 */
#define UTRACE_SIGNAL_HANDLER	0x0700

/* Action flag in return value of report_jctl.  */
#define UTRACE_JCTL_NOSIGCHLD	0x0100 /* Do not notify the parent.  */


/*
 * Flags for utrace_attach.  If UTRACE_ATTACH_CREATE is not specified,
 * you only look up an existing engine already attached to the
 * thread.  If UTRACE_ATTACH_MATCH_* bits are set, only consider
 * matching engines.  If UTRACE_ATTACH_EXCLUSIVE is set, attempting to
 * attach a second (matching) engine fails with -EEXIST.
 */
#define UTRACE_ATTACH_CREATE		0x0010 /* Attach a new engine.  */
#define UTRACE_ATTACH_EXCLUSIVE		0x0020 /* Refuse if existing match.  */
#define UTRACE_ATTACH_MATCH_OPS		0x0001 /* Match engines on ops.  */
#define UTRACE_ATTACH_MATCH_DATA	0x0002 /* Match engines on data.  */
#define UTRACE_ATTACH_MATCH_MASK	0x000f


/*
 * Per-thread structure task_struct.utrace points to.
 *
 * The task itself never has to worry about this going away after
 * some event is found set in task_struct.utrace_flags.
 * Once created, this pointer is changed only when the task is quiescent
 * (TASK_TRACED or TASK_STOPPED with the siglock held, or dead).
 *
 * For other parties, the pointer to this is protected by RCU and
 * task_lock.  Since call_rcu is never used while the thread is alive and
 * using this struct utrace, we can overlay the RCU data structure used
 * only for a dead struct with some local state used only for a live utrace
 * on an active thread.
 */
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
#define utrace_lock(utrace)	spin_lock(&(utrace)->lock)
#define utrace_unlock(utrace)	spin_unlock(&(utrace)->lock)


/*
 * Per-engine per-thread structure.
 *
 * The task itself never has to worry about engines detaching while
 * it's doing event callbacks.  These structures are freed only when
 * the task is quiescent.  For other parties, the list is protected
 * by RCU and utrace_lock.
 */
struct utrace_attached_engine
{
	struct list_head entry;	/* Entry on thread's utrace.engines list.  */
	struct rcu_head rhead;

	const struct utrace_engine_ops *ops;
	unsigned long data;

	unsigned long flags;
};


struct utrace_engine_ops
{
	/*
	 * Event reporting hooks.
	 *
	 * Return values contain UTRACE_ACTION_* flag bits.
	 * The UTRACE_ACTION_OP_MASK bits are specific to each kind of event.
	 *
	 * All report_* hooks are called with no locks held, in a generally
	 * safe environment when we will be returning to user mode soon.
	 * It is fine to block for memory allocation and the like, but all
	 * hooks are *asynchronous* and must not block on external events.
	 * If you want the thread to block, request UTRACE_ACTION_QUIESCE in
	 * your hook; then later wake it up with utrace_set_flags.
	 *
	 */

	/*
	 * Event reported for parent, before child might run.
	 * The PF_STARTING flag prevents other engines from attaching
	 * before this one has its chance.
	 */
	u32 (*report_clone)(struct utrace_attached_engine *engine,
			    struct task_struct *parent,
			    unsigned long clone_flags,
			    struct task_struct *child);

	/*
	 * Event reported for parent using CLONE_VFORK or vfork system call.
	 * The child has died or exec'd, so the vfork parent has unblocked
	 * and is about to return child_pid.
	 */
	u32 (*report_vfork_done)(struct utrace_attached_engine *engine,
				 struct task_struct *parent, pid_t child_pid);

	/*
	 * Event reported after UTRACE_ACTION_QUIESCE is set, when the target
	 * thread is quiescent.  Either it's the current thread, or it's in
	 * TASK_TRACED or TASK_STOPPED and will not resume running until the
	 * UTRACE_ACTION_QUIESCE flag is no longer asserted by any engine.
	 */
	u32 (*report_quiesce)(struct utrace_attached_engine *engine,
			      struct task_struct *tsk);

	/*
	 * Thread dequeuing a signal to be delivered.
	 * The action and *return_ka values say what UTRACE_ACTION_RESUME
	 * will do (possibly already influenced by another tracing engine).
	 * An UTRACE_SIGNAL_* return value overrides the signal disposition.
	 * The *info data (including info->si_signo) can be changed at will.
	 * Changing *return_ka affects the sigaction that be used.
	 * The *orig_ka value is the one in force before other tracing
	 * engines intervened.
	 */
	u32 (*report_signal)(struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     struct pt_regs *regs,
			     u32 action, siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka);

	/*
	 * Job control event completing, about to send SIGCHLD to parent
	 * with CLD_STOPPED or CLD_CONTINUED as given in type.
	 * UTRACE_JOBSTOP_NOSIGCHLD in the return value inhibits that.
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
	 * but all its state is still live.  The *code value will be
	 * the wait result seen by the parent, and can be changed by
	 * this engine or others.  The orig_code value is the real
	 * status, not changed by any tracing engine.
	 */
	u32 (*report_exit)(struct utrace_attached_engine *engine,
			   struct task_struct *tsk,
			   long orig_code, long *code);

	/*
	 * Thread is really dead now.  If UTRACE_ACTION_NOREAP is in force,
	 * it remains an unreported zombie.  Otherwise, it might be reaped
	 * by its parent, or self-reap immediately.  Though the actual
	 * reaping may happen in parallel, a report_reap callback will
	 * always be ordered after a report_death callback.
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
	 * Return nonzero iff the caller task should be allowed to access
	 * the memory of the target task via /proc/PID/mem and so forth,
	 * by dint of this engine's attachment to the target.
	 */
	int (*allow_access_process_vm)(struct utrace_attached_engine *engine,
				       struct task_struct *target,
				       struct task_struct *caller);

	/*
	 * Return LSM_UNSAFE_* bits that apply to the exec in progress
	 * due to tracing done by this engine.  These bits indicate that
	 * someone is able to examine the process and so a set-UID or similar
	 * privilege escalation may not be safe to permit.
	 *
	 * Called with task_lock held.
	 */
	int (*unsafe_exec)(struct utrace_attached_engine *engine,
			   struct task_struct *target);

	/*
	 * Return the task_struct for the task using ptrace on this one, or
	 * NULL.  Always called with rcu_read_lock held to keep the
	 * returned struct alive.
	 *
	 * At exec time, this may be called with task_lock(target) still
	 * held from when unsafe_exec was just called.  In that case it
	 * must give results consistent with those unsafe_exec results,
	 * i.e. non-NULL if any LSM_UNSAFE_PTRACE_* bits were set.
	 *
	 * The value is also used to display after "TracerPid:" in
	 * /proc/PID/status, where it is called with only rcu_read_lock held.
	 *
	 * If this engine returns NULL, another engine may supply the result.
	 */
	struct task_struct *(*tracer_task)(struct utrace_attached_engine *,
					   struct task_struct *target);
};


/***
 *** These are the exported entry points for tracing engines to use.
 ***/

/*
 * Attach a new tracing engine to a thread, or look up attached engines.
 * See UTRACE_ATTACH_* flags, above.  The caller must ensure that the
 * target thread does not get freed, i.e. hold a ref or be its parent.
 */
struct utrace_attached_engine *utrace_attach(struct task_struct *target,
					     int flags,
					     const struct utrace_engine_ops *,
					     unsigned long data);

/*
 * Detach a tracing engine from a thread.  After this, the engine
 * data structure is no longer accessible, and the thread might be reaped.
 * The thread will start running again if it was being kept quiescent
 * and no longer has any attached engines asserting UTRACE_ACTION_QUIESCE.
 *
 * If the target thread is not already quiescent, then a callback to this
 * engine might be in progress or about to start on another CPU.  If it's
 * quiescent when utrace_detach is called, then after successful return
 * it's guaranteed that no more callbacks to the ops vector will be done.
 * The only exception is SIGKILL (and exec by another thread in the group),
 * which breaks quiescence and can cause asynchronous DEATH and/or REAP
 * callbacks even when UTRACE_ACTION_QUIESCE is set.  In that event,
 * utrace_detach fails with -ESRCH or -EALREADY to indicate that the
 * report_reap or report_death callbacks have begun or will run imminently.
 */
int utrace_detach(struct task_struct *target,
		  struct utrace_attached_engine *engine);

/*
 * Change the flags for a tracing engine.
 * This resets the event flags and the action state flags.
 * If UTRACE_ACTION_QUIESCE and UTRACE_EVENT(QUIESCE) are set,
 * this will cause a report_quiesce callback soon, maybe immediately.
 * If UTRACE_ACTION_QUIESCE was set before and is no longer set by
 * any engine, this will wake the thread up.
 *
 * This fails with -EALREADY and does nothing if you try to clear
 * UTRACE_EVENT(DEATH) when the report_death callback may already have
 * begun, if you try to clear UTRACE_EVENT(REAP) when the report_reap
 * callback may already have begun, if you try to newly set
 * UTRACE_ACTION_NOREAP when the target may already have sent its
 * parent SIGCHLD, or if you try to newly set UTRACE_EVENT(DEATH),
 * UTRACE_EVENT(QUIESCE), or UTRACE_ACTION_QUIESCE, when the target is
 * already dead or dying.  It can fail with -ESRCH when the target has
 * already been detached (including forcible detach on reaping).  If
 * the target was quiescent before the call, then after a successful
 * call, no event callbacks not requested in the new flags will be
 * made, and a report_quiesce callback will always be made if
 * requested.  These rules provide for coherent synchronization based
 * on quiescence, even when SIGKILL is breaking quiescence.
 */
int utrace_set_flags(struct task_struct *target,
		     struct utrace_attached_engine *engine,
		     unsigned long flags);

/*
 * Cause a specified signal delivery in the target thread, which must be
 * quiescent (or the current thread).  The action has UTRACE_SIGNAL_* bits
 * as returned from a report_signal callback.  If ka is non-null, it gives
 * the sigaction to follow for UTRACE_SIGNAL_DELIVER; otherwise, the
 * installed sigaction at the time of delivery is used.
 */
int utrace_inject_signal(struct task_struct *target,
			 struct utrace_attached_engine *engine,
			 u32 action, siginfo_t *info,
			 const struct k_sigaction *ka);

/*
 * Prepare to access thread's machine state, see <linux/tracehook.h>.
 * The given thread must be quiescent (or the current thread).
 * When this returns, the struct utrace_regset calls may be used to
 * interrogate or change the thread's state.  Do not cache the returned
 * pointer when the thread can resume.  You must call utrace_regset to
 * ensure that context switching has completed and consistent state is
 * available.
 */
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
int utrace_report_jctl(int type);
void utrace_report_exec(struct linux_binprm *bprm, struct pt_regs *regs);
void utrace_report_syscall(struct pt_regs *regs, int is_exit);
struct task_struct *utrace_tracer_task(struct task_struct *);
int utrace_allow_access_process_vm(struct task_struct *);
int utrace_unsafe_exec(struct task_struct *);
void utrace_signal_handler_singlestep(struct task_struct *, struct pt_regs *);


#endif	/* linux/utrace.h */
