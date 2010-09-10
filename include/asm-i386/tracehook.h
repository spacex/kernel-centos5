/*
 * Tracing hooks, i386 CPU support
 */

#ifndef _ASM_TRACEHOOK_H
#define _ASM_TRACEHOOK_H	1

#include <linux/sched.h>
#include <asm/ptrace.h>

/*
 * See linux/tracehook.h for the descriptions of what these need to do.
 */

#define ARCH_HAS_SINGLE_STEP	(1)

/* These two are defined in arch/i386/kernel/ptrace.c.  */
void tracehook_enable_single_step(struct task_struct *tsk);
void tracehook_disable_single_step(struct task_struct *tsk);

static inline int tracehook_single_step_enabled(struct task_struct *tsk)
{
	return test_tsk_thread_flag(tsk, TIF_SINGLESTEP);
}

static inline void tracehook_enable_syscall_trace(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk, TIF_SYSCALL_TRACE);
}

static inline void tracehook_disable_syscall_trace(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk, TIF_SYSCALL_TRACE);
}

static inline void tracehook_abort_syscall(struct pt_regs *regs)
{
	regs->orig_eax = -1;
}

extern const struct utrace_regset_view utrace_i386_native;
static inline const struct utrace_regset_view *
utrace_native_view(struct task_struct *tsk)
{
	return &utrace_i386_native;
}


#endif
