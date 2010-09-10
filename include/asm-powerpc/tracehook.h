/*
 * Tracing hooks, PowerPC CPU support
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 * Red Hat Author: Roland McGrath.
 */

#ifndef _ASM_TRACEHOOK_H
#define _ASM_TRACEHOOK_H	1

#include <linux/sched.h>
#include <asm/ptrace.h>

/*
 * See linux/tracehook.h for the descriptions of what these need to do.
 */

#define ARCH_HAS_SINGLE_STEP	(1)

static inline void tracehook_enable_single_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;
	if (regs != NULL) {
#if defined(CONFIG_PPC32) && (defined(CONFIG_40x) || defined(CONFIG_BOOKE))
		task->thread.dbcr0 = DBCR0_IDM | DBCR0_IC;
		regs->msr |= MSR_DE;
#else
		regs->msr |= MSR_SE;
#endif
	}
	set_tsk_thread_flag(task, TIF_SINGLESTEP);
}

static inline void tracehook_disable_single_step(struct task_struct *task)
{
	struct pt_regs *regs = task->thread.regs;
	if (regs != NULL) {
#if defined(CONFIG_PPC32) && (defined(CONFIG_40x) || defined(CONFIG_BOOKE))
		task->thread.dbcr0 = 0;
		regs->msr &= ~MSR_DE;
#else
		regs->msr &= ~MSR_SE;
#endif
	}
	clear_tsk_thread_flag(task, TIF_SINGLESTEP);
}

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
	regs->orig_gpr3 = -1L;
}


#endif
