/*
 * Tracing hooks, s390/s390x support.
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

/* These three are defined in arch/s390/kernel/ptrace.c.  */
void tracehook_enable_single_step(struct task_struct *tsk);
void tracehook_disable_single_step(struct task_struct *tsk);
int tracehook_single_step_enabled(struct task_struct *tsk);


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
	regs->gprs[2] = -1L;
}

#endif
