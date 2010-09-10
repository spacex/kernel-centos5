/*
 * Tracing hooks, x86-64 CPU support
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
#include <asm/proto.h>

/*
 * See linux/tracehook.h for the descriptions of what these need to do.
 */

#define ARCH_HAS_SINGLE_STEP	(1)

/* These two are defined in arch/x86_64/kernel/ptrace.c.  */
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

#define tracehook_syscall_callno(regs)	(&(regs)->orig_rax)
#define tracehook_syscall_retval(regs)	(&(regs)->rax)
static inline void tracehook_abort_syscall(struct pt_regs *regs)
{
	regs->orig_rax = -1L;
}

/*
 * These are used directly by some of the regset code.
 */
extern const struct utrace_regset_view utrace_x86_64_native;
#ifdef CONFIG_IA32_EMULATION
extern const struct utrace_regset_view utrace_ia32_view;
#endif

#endif
