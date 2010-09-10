/*
 * Copyright (C)2006 Intel Co
 *	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *	and Bibo Mao <bibo.mao@intel.com> adapted from i386.
 *
 * 	Tracing hooks, ia64 CPU support
 */

#ifndef _ASM_TRACEHOOK_H
#define _ASM_TRACEHOOK_H	1

#include <linux/sched.h>
#include <asm/ptrace.h>

/*
 * See linux/tracehook.h for the descriptions of what these need to do.
 */

#define ARCH_HAS_SINGLE_STEP	(1)
#define ARCH_HAS_BLOCK_STEP	(1)

static inline void tracehook_enable_single_step(struct task_struct *tsk)
{
	struct pt_regs *pt = task_pt_regs(tsk);
	ia64_psr(pt)->ss = 1;
}

static inline void tracehook_disable_single_step(struct task_struct *tsk)
{
	struct pt_regs *pt = task_pt_regs(tsk);
	ia64_psr(pt)->ss = 0;
}

static inline void tracehook_enable_block_step(struct task_struct *tsk)
{
	struct pt_regs *pt = task_pt_regs(tsk);
	ia64_psr(pt)->tb = 1;
}

static inline void tracehook_disable_block_step(struct task_struct *tsk)
{
	struct pt_regs *pt = task_pt_regs(tsk);
	ia64_psr(pt)->tb = 0;
}

static inline void tracehook_enable_syscall_trace(struct task_struct *tsk)
{
	set_tsk_thread_flag(tsk, TIF_SYSCALL_TRACE);
}

static inline void tracehook_disable_syscall_trace(struct task_struct *tsk)
{
	clear_tsk_thread_flag(tsk, TIF_SYSCALL_TRACE);
}

static inline int tracehook_single_step_enabled(struct task_struct *tsk)
{
	struct pt_regs *pt = task_pt_regs(tsk);
	return ia64_psr(pt)->ss;
}

static inline void tracehook_abort_syscall(struct pt_regs *regs)
{
	if (IS_IA32_PROCESS(regs))
		regs->r1 = -1UL;
	else
		regs->r15 = -1UL;
}

extern const struct utrace_regset_view utrace_ia64_native;
static inline const struct utrace_regset_view *
utrace_native_view(struct task_struct *tsk)
{
#ifdef CONFIG_IA32_SUPPORT
	extern const struct utrace_regset_view utrace_ia32_view;
	if (IS_IA32_PROCESS(task_pt_regs(tsk)))
		return &utrace_ia32_view;
#endif
	return &utrace_ia64_native;
}


#endif	/* asm/tracehook.h */
