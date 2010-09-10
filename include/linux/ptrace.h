#ifndef _LINUX_PTRACE_H
#define _LINUX_PTRACE_H
/* ptrace.h */
/* structs and defines to help the user use the ptrace system call. */

/* has the defines to get at the registers. */

#define PTRACE_TRACEME		   0
#define PTRACE_PEEKTEXT		   1
#define PTRACE_PEEKDATA		   2
#define PTRACE_PEEKUSR		   3
#define PTRACE_POKETEXT		   4
#define PTRACE_POKEDATA		   5
#define PTRACE_POKEUSR		   6
#define PTRACE_CONT		   7
#define PTRACE_KILL		   8
#define PTRACE_SINGLESTEP	   9

#define PTRACE_ATTACH		0x10
#define PTRACE_DETACH		0x11

#define PTRACE_SYSCALL		  24

/* 0x4200-0x4300 are reserved for architecture-independent additions.  */
#define PTRACE_SETOPTIONS	0x4200
#define PTRACE_GETEVENTMSG	0x4201
#define PTRACE_GETSIGINFO	0x4202
#define PTRACE_SETSIGINFO	0x4203

/* options set using PTRACE_SETOPTIONS */
#define PTRACE_O_TRACESYSGOOD	0x00000001
#define PTRACE_O_TRACEFORK	0x00000002
#define PTRACE_O_TRACEVFORK	0x00000004
#define PTRACE_O_TRACECLONE	0x00000008
#define PTRACE_O_TRACEEXEC	0x00000010
#define PTRACE_O_TRACEVFORKDONE	0x00000020
#define PTRACE_O_TRACEEXIT	0x00000040

#define PTRACE_O_MASK		0x0000007f

/* Wait extended result codes for the above trace options.  */
#define PTRACE_EVENT_FORK	1
#define PTRACE_EVENT_VFORK	2
#define PTRACE_EVENT_CLONE	3
#define PTRACE_EVENT_EXEC	4
#define PTRACE_EVENT_VFORK_DONE	5
#define PTRACE_EVENT_EXIT	6

#include <asm/ptrace.h>

#ifdef __KERNEL__
#include <linux/compiler.h>
#include <linux/types.h>
struct task_struct;
struct siginfo;
struct rusage;


extern int ptrace_may_attach(struct task_struct *task);
extern int __ptrace_may_attach(struct task_struct *task);


#ifdef CONFIG_PTRACE
#include <asm/tracehook.h>
struct utrace_attached_engine;
struct utrace_regset_view;

/*
 * These must be defined by arch code to handle machine-specific ptrace
 * requests such as PTRACE_PEEKUSR and PTRACE_GETREGS.  Returns -ENOSYS for
 * any request it does not handle, then handled by machine-independent code.
 * This can change *request and then return -ENOSYS to handle a
 * machine-specific alias for a generic request.
 *
 * This code should NOT access task machine state directly.  Instead it
 * should use the utrace_regset accessors.  The functions below make this easy.
 *
 * Any nonzero return value should be for an error.  If the return value of
 * the ptrace syscall should be a nonzero success value, this returns zero
 * and sets *retval to the value--which might have any bit pattern at all,
 * including one that looks like -ENOSYS or another error code.
 */
extern fastcall int arch_ptrace(long *request, struct task_struct *child,
				struct utrace_attached_engine *engine,
				unsigned long addr, unsigned long data,
				long *retval);
#ifdef CONFIG_COMPAT
#include <linux/compat.h>

extern fastcall int arch_compat_ptrace(compat_long_t *request,
				       struct task_struct *child,
				       struct utrace_attached_engine *engine,
				       compat_ulong_t a, compat_ulong_t d,
				       compat_long_t *retval);
#endif

/*
 * Convenience function doing access to a single utrace_regset for ptrace.
 * The offset and size are in bytes, giving the location in the regset data.
 */
extern fastcall int ptrace_regset_access(struct task_struct *child,
					 struct utrace_attached_engine *engine,
					 const struct utrace_regset_view *view,
					 int setno, unsigned long offset,
					 unsigned int size, void __user *data,
					 int write);

/*
 * Convenience wrapper for doing access to a whole utrace_regset for ptrace.
 */
static inline int ptrace_whole_regset(struct task_struct *child,
				      struct utrace_attached_engine *engine,
				      long data, int setno, int write)
{
	return ptrace_regset_access(child, engine, utrace_native_view(current),
				    setno, 0, -1, (void __user *)data, write);
}

/*
 * Convenience function doing access to a single slot in a utrace_regset.
 * The regno value gives a slot number plus regset->bias.
 * The value accessed is regset->size bytes long.
 */
extern fastcall int ptrace_onereg_access(struct task_struct *child,
					 struct utrace_attached_engine *engine,
					 const struct utrace_regset_view *view,
					 int setno, unsigned long regno,
					 void __user *data, int write);


/*
 * An array of these describes the layout of the virtual struct user
 * accessed by PEEKUSR/POKEUSR, or the structure used by GETREGS et al.
 * The array is terminated by an element with .end of zero.
 * An element describes the range [.start, .end) of struct user offsets,
 * measured in bytes; it maps to the regset in the view's regsets array
 * at the index given by .regset, at .offset bytes into that regset's data.
 * If .regset is -1, then the [.start, .end) range reads as zero.
 */
struct ptrace_layout_segment {
	unsigned int start, end, regset, offset;
};

/*
 * Convenience function for doing access to a ptrace compatibility layout.
 * The offset and size are in bytes.
 */
extern fastcall int ptrace_layout_access(
	struct task_struct *child, struct utrace_attached_engine *engine,
	const struct utrace_regset_view *view,
	const struct ptrace_layout_segment layout[],
	unsigned long offset, unsigned int size,
	void __user *data, void *kdata, int write);


/* Convenience wrapper for the common PTRACE_PEEKUSR implementation.  */
static inline int ptrace_peekusr(struct task_struct *child,
				 struct utrace_attached_engine *engine,
				 const struct ptrace_layout_segment layout[],
				 unsigned long addr, long data)
{
	return ptrace_layout_access(child, engine, utrace_native_view(current),
				    layout, addr, sizeof(long),
				    (unsigned long __user *)data, NULL, 0);
}

/* Convenience wrapper for the common PTRACE_PEEKUSR implementation.  */
static inline int ptrace_pokeusr(struct task_struct *child,
				 struct utrace_attached_engine *engine,
				 const struct ptrace_layout_segment layout[],
				 unsigned long addr, long data)
{
	return ptrace_layout_access(child, engine, utrace_native_view(current),
				    layout, addr, sizeof(long),
				    NULL, &data, 1);
}

#ifdef CONFIG_COMPAT
/* Convenience wrapper for the common PTRACE_PEEKUSR implementation.  */
static inline int ptrace_compat_peekusr(
	struct task_struct *child, struct utrace_attached_engine *engine,
	const struct ptrace_layout_segment layout[],
	compat_ulong_t addr, compat_ulong_t data)
{
	compat_ulong_t *udata = (compat_ulong_t __user *) (unsigned long) data;
	return ptrace_layout_access(child, engine, utrace_native_view(current),
				    layout, addr, sizeof(compat_ulong_t),
				    udata, NULL, 0);
}

/* Convenience wrapper for the common PTRACE_PEEKUSR implementation.  */
static inline int ptrace_compat_pokeusr(
	struct task_struct *child, struct utrace_attached_engine *engine,
	const struct ptrace_layout_segment layout[],
	compat_ulong_t addr, compat_ulong_t data)
{
	return ptrace_layout_access(child, engine, utrace_native_view(current),
				    layout, addr, sizeof(compat_ulong_t),
				    NULL, &data, 1);
}
#endif


/*
 * Called in do_exit, after setting PF_EXITING, no locks are held.
 */
void ptrace_exit(struct task_struct *tsk);

/*
 * Called in do_wait, with tasklist_lock held for reading.
 * This reports any ptrace-child that is ready as do_wait would a normal child.
 * If there are no ptrace children, returns -ECHILD.
 * If there are some ptrace children but none reporting now, returns 0.
 * In those cases the tasklist_lock is still held so next_thread(tsk) works.
 * For any other return value, tasklist_lock is released before return.
 */
int ptrace_do_wait(struct task_struct *tsk,
		   pid_t pid, int options, struct siginfo __user *infop,
		   int __user *stat_addr, struct rusage __user *rusagep);
#else
static inline void ptrace_exit(struct task_struct *tsk) { }
static inline int ptrace_do_wait(struct task_struct *tsk,
				 pid_t pid, int options,
				 struct siginfo __user *infop,
				 int __user *stat_addr,
				 struct rusage __user *rusagep)
{
	return -ECHILD;
}
#endif


#ifndef force_successful_syscall_return
/*
 * System call handlers that, upon successful completion, need to return a
 * negative value should call force_successful_syscall_return() right before
 * returning.  On architectures where the syscall convention provides for a
 * separate error flag (e.g., alpha, ia64, ppc{,64}, sparc{,64}, possibly
 * others), this macro can be used to ensure that the error flag will not get
 * set.  On architectures which do not support a separate error flag, the macro
 * is a no-op and the spurious error condition needs to be filtered out by some
 * other means (e.g., in user-level, by passing an extra argument to the
 * syscall handler, or something along those lines).
 */
#define force_successful_syscall_return() do { } while (0)
#endif

#endif

#endif
