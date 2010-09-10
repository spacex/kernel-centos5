/*
 * Tracing hooks, SPARC64 CPU support
 */

#ifndef _ASM_TRACEHOOK_H
#define _ASM_TRACEHOOK_H	1


#include <linux/sched.h>
#include <asm/ptrace.h>

/*
 * See linux/tracehook.h for the descriptions of what these need to do.
 */


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
	regs->u_regs[UREG_G1] = -1L;
}

extern const struct utrace_regset_view utrace_sparc64_native_view;
static inline const struct utrace_regset_view *
utrace_native_view(struct task_struct *tsk)
{
#ifdef CONFIG_COMPAT
	extern const struct utrace_regset_view utrace_sparc32_view;
	if (test_tsk_thread_flag(tsk, TIF_32BIT))
		return &utrace_sparc32_view;
#endif
	return &utrace_sparc64_native_view;
}

#endif
