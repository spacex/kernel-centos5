/* ptrace.c */
/* By Ross Biro 1/23/92 */
/*
 * Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 * 
 * x86-64 port 2000-2002 Andi Kleen
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/tracehook.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/signal.h>
#include <linux/module.h>
#include <linux/elf.h>

#include <asm/tracehook.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/i387.h>
#include <asm/debugreg.h>
#include <asm/ldt.h>
#include <asm/desc.h>
#include <asm/proto.h>
#include <asm/ia32.h>
#include <asm/prctl.h>

/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/*
 * Determines which flags the user has access to [1 = access, 0 = no access].
 * Prohibits changing ID(21), VIP(20), VIF(19), VM(17), IOPL(12-13), IF(9).
 * Also masks reserved bits (63-22, 15, 5, 3, 1).
 */
#define FLAG_MASK 0x54dd5UL

/* set's the trap flag. */
#define TRAP_FLAG 0x100UL

/*
 * eflags and offset of eflags on child stack..
 */
#define EFLAGS offsetof(struct pt_regs, eflags)
#define EFL_OFFSET ((int)(EFLAGS-sizeof(struct pt_regs)))

/*
 * this routine will get a word off of the processes privileged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */   
static inline unsigned long get_stack_long(struct task_struct *task, int offset)
{
	unsigned char *stack;

	stack = (unsigned char *)task->thread.rsp0;
	stack += offset;
	return (*((unsigned long *)stack));
}

/*
 * this routine will put a word on the processes privileged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */
static inline long put_stack_long(struct task_struct *task, int offset,
	unsigned long data)
{
	unsigned char * stack;

	stack = (unsigned char *) task->thread.rsp0;
	stack += offset;
	*(unsigned long *) stack = data;
	return 0;
}

#define LDT_SEGMENT 4

unsigned long convert_rip_to_linear(struct task_struct *child, struct pt_regs *regs)
{
	unsigned long addr, seg;

	addr = regs->rip;
	seg = regs->cs & 0xffff;

	/*
	 * We'll assume that the code segments in the GDT
	 * are all zero-based. That is largely true: the
	 * TLS segments are used for data, and the PNPBIOS
	 * and APM bios ones we just ignore here.
	 */
	if (seg & LDT_SEGMENT) {
		u32 *desc;
		unsigned long base;

		seg &= ~7UL;
		
		down(&child->mm->context.sem);
		if (unlikely((seg >> 3) >= child->mm->context.size))
			addr = -1L; /* bogus selector, access would fault */
		else {
			desc = child->mm->context.ldt + seg;
			base = ((desc[0] >> 16) |
				((desc[1] & 0xff) << 16) |
				(desc[1] & 0xff000000));

		/* 16-bit code segment? */
		if (!((desc[1] >> 22) & 1))
			addr &= 0xffff;
		addr += base;
		}
		up(&child->mm->context.sem);
	}
	return addr;
}

static int is_at_popf(struct task_struct *child, struct pt_regs *regs)
{
	int i, copied;
	unsigned char opcode[16];
	unsigned long addr = convert_rip_to_linear(child, regs);

	copied = access_process_vm(child, addr, opcode, sizeof(opcode), 0);
	for (i = 0; i < copied; i++) {
		switch (opcode[i]) {
		/* popf */
		case 0x9d:
			return 1;

			/* CHECKME: 64 65 */

		/* opcode and address size prefixes */
		case 0x66: case 0x67:
			continue;
		/* irrelevant prefixes (segment overrides and repeats) */
		case 0x26: case 0x2e:
		case 0x36: case 0x3e:
		case 0x64: case 0x65:
		case 0xf0: case 0xf2: case 0xf3:
			continue;

		/* REX prefixes */
		case 0x40 ... 0x4f:
			continue;

			/* CHECKME: f0, f2, f3 */

		/*
		 * pushf: NOTE! We should probably not let
		 * the user see the TF bit being set. But
		 * it's more pain than it's worth to avoid
		 * it, and a debugger could emulate this
		 * all in user space if it _really_ cares.
		 */
		case 0x9c:
		default:
			return 0;
		}
	}
	return 0;
}

void tracehook_enable_single_step(struct task_struct *child)
{
	struct pt_regs *regs = task_pt_regs(child);

	/*
	 * Always set TIF_SINGLESTEP - this guarantees that
	 * we single-step system calls etc..  This will also
	 * cause us to set TF when returning to user mode.
	 */
	set_tsk_thread_flag(child, TIF_SINGLESTEP);

	/*
	 * If TF was already set, don't do anything else
	 */
	if (regs->eflags & TRAP_FLAG)
		return;

	/* Set TF on the kernel stack.. */
	regs->eflags |= TRAP_FLAG;

	/*
	 * ..but if TF is changed by the instruction we will trace,
	 * don't mark it as being "us" that set it, so that we
	 * won't clear it by hand later.
	 *
	 * AK: this is not enough, LAHF and IRET can change TF in user space too.
	 */
	if (is_at_popf(child, regs))
		return;

	set_tsk_thread_flag(child, TIF_FORCED_TF);
}

void tracehook_disable_single_step(struct task_struct *child)
{
	/* Always clear TIF_SINGLESTEP... */
	clear_tsk_thread_flag(child, TIF_SINGLESTEP);

	/* But touch TF only if it was set by us.. */
	if (test_and_clear_tsk_thread_flag(child, TIF_FORCED_TF)) {
		struct pt_regs *regs = task_pt_regs(child);
		regs->eflags &= ~TRAP_FLAG;
	}
}

/*
 * Called by kernel/ptrace.c when detaching..
 *
 * Make sure the single step bit is not set.
 */
void ptrace_disable(struct task_struct *child)
{ 
	tracehook_disable_single_step(child);
}

static int putreg(struct task_struct *child,
	unsigned long regno, unsigned long value)
{
	unsigned long tmp; 
	
	switch (regno) {
	case offsetof(struct user_regs_struct,fs):
		if (value && (value & 3) != 3)
			return -EIO;
		child->thread.fsindex = value &= 0xffff;
		if (child == current)
			loadsegment(fs, value);
		return 0;
	case offsetof(struct user_regs_struct,gs):
		if (value && (value & 3) != 3)
			return -EIO;
		child->thread.gsindex = value &= 0xffff;
		if (child == current)
			load_gs_index(value);
		return 0;
	case offsetof(struct user_regs_struct,ds):
		if (value && (value & 3) != 3)
			return -EIO;
		child->thread.ds = value &= 0xffff;
		if (child == current)
			loadsegment(ds, value);
		return 0;
	case offsetof(struct user_regs_struct,es):
		if (value && (value & 3) != 3)
			return -EIO;
		child->thread.es = value &= 0xffff;
		if (child == current)
			loadsegment(es, value);
		return 0;
	case offsetof(struct user_regs_struct,ss):
		if ((value & 3) != 3)
			return -EIO;
		value &= 0xffff;
		return 0;
	case offsetof(struct user_regs_struct,fs_base):
		if (value >= TASK_SIZE_OF(child))
			return -EIO;
		child->thread.fs = value;
		return 0;
	case offsetof(struct user_regs_struct,gs_base):
		if (value >= TASK_SIZE_OF(child))
			return -EIO;
		child->thread.gs = value;
		return 0;
	case offsetof(struct user_regs_struct, orig_rax):
		/*
		 * Orig_rax is really just a flag with small positive
		 * and negative values, so make sure to always
		 * sign-extend it from 32 bits so that it works
		 * correctly regardless of whether we come from a
		 * 32-bit environment or not.
		 */
		value = (long) (s32) value;
		break;
	case offsetof(struct user_regs_struct, eflags):
		value &= FLAG_MASK;
		tmp = get_stack_long(child, EFL_OFFSET);
		tmp &= ~FLAG_MASK;
		value |= tmp;
		clear_tsk_thread_flag(child, TIF_FORCED_TF);
		break;
	case offsetof(struct user_regs_struct,cs):
		if ((value & 3) != 3)
			return -EIO;
		value &= 0xffff;
		break;
	}
	put_stack_long(child, regno - sizeof(struct pt_regs), value);
	return 0;
}

static unsigned long getreg(struct task_struct *child, unsigned long regno)
{
	unsigned long val;
	unsigned int seg;
	switch (regno) {
	case offsetof(struct user_regs_struct, fs):
		if (child == current) {
			/* Older gas can't assemble movq %?s,%r?? */
			asm("movl %%fs,%0" : "=r" (seg));
			return seg;
		}
		return child->thread.fsindex;
	case offsetof(struct user_regs_struct, gs):
		if (child == current) {
			asm("movl %%gs,%0" : "=r" (seg));
			return seg;
		}
		return child->thread.gsindex;
	case offsetof(struct user_regs_struct, ds):
		if (child == current) {
			asm("movl %%ds,%0" : "=r" (seg));
			return seg;
		}
		return child->thread.ds;
	case offsetof(struct user_regs_struct, es):
		if (child == current) {
			asm("movl %%es,%0" : "=r" (seg));
			return seg;
		}
		return child->thread.es;
	case offsetof(struct user_regs_struct, fs_base):
		return child->thread.fs;
	case offsetof(struct user_regs_struct, gs_base):
		return child->thread.gs;
	default:
		regno = regno - sizeof(struct pt_regs);
		val = get_stack_long(child, regno);
		if (test_tsk_thread_flag(child, TIF_IA32))
			val &= 0xffffffff;
		if (regno == (offsetof(struct user_regs_struct, eflags)
			      - sizeof(struct pt_regs))
		    && test_tsk_thread_flag(child, TIF_FORCED_TF))
			val &= ~X86_EFLAGS_TF;
		return val;
	}

}

static int
genregs_get(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    void *kbuf, void __user *ubuf)
{
	if (kbuf) {
		unsigned long *kp = kbuf;
		while (count > 0) {
			*kp++ = getreg(target, pos);
			pos += sizeof(long);
			count -= sizeof(long);
		}
	}
	else {
		unsigned long __user *up = ubuf;
		while (count > 0) {
			if (__put_user(getreg(target, pos), up++))
				return -EFAULT;
			pos += sizeof(long);
			count -= sizeof(long);
		}
	}

	return 0;
}

static int
genregs_set(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    const void *kbuf, const void __user *ubuf)
{
	int ret = 0;

	if (kbuf) {
		const unsigned long *kp = kbuf;
		while (!ret && count > 0) {
			ret = putreg(target, pos, *kp++);
			pos += sizeof(long);
			count -= sizeof(long);
		}
	}
	else {
		int ret = 0;
		const unsigned long __user *up = ubuf;
		while (!ret && count > 0) {
			unsigned long val;
			ret = __get_user(val, up++);
			if (!ret)
				ret = putreg(target, pos, val);
			pos += sizeof(long);
			count -= sizeof(long);
		}
	}

	return ret;
}


static int
dbregs_active(struct task_struct *tsk, const struct utrace_regset *regset)
{
	if (tsk->thread.debugreg6 | tsk->thread.debugreg7)
		return 8;
	return 0;
}

static int
dbregs_get(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   void *kbuf, void __user *ubuf)
{
	for (pos >>= 3, count >>= 3; count > 0; --count, ++pos) {
		unsigned long val;

		/*
		 * The hardware updates the status register on a debug trap,
		 * but do_debug (traps.c) saves it for us when that happens.
		 * So whether the target is current or not, debugregN is good.
		 */
		val = 0;
		switch (pos) {
		case 0:	val = target->thread.debugreg0; break;
		case 1:	val = target->thread.debugreg1; break;
		case 2:	val = target->thread.debugreg2; break;
		case 3:	val = target->thread.debugreg3; break;
		case 6:	val = target->thread.debugreg6; break;
		case 7:	val = target->thread.debugreg7; break;
		}

		if (kbuf) {
			*(unsigned long *) kbuf = val;
			kbuf += sizeof(unsigned long);
		}
		else {
			if (__put_user(val, (unsigned long __user *) ubuf))
				return -EFAULT;
			ubuf += sizeof(unsigned long);
		}
	}

	return 0;
}

static int
dbregs_set(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   const void *kbuf, const void __user *ubuf)
{

	unsigned long maxaddr = TASK_SIZE_OF(target);
	maxaddr -= test_tsk_thread_flag(target, TIF_IA32) ? 3 : 7;

	for (pos >>= 3, count >>= 3; count > 0; --count, ++pos) {
		unsigned long val;
		unsigned int i;

		if (kbuf) {
			val = *(const unsigned long *) kbuf;
			kbuf += sizeof(unsigned long);
		}
		else {
			if (__get_user(val, (unsigned long __user *) ubuf))
				return -EFAULT;
			ubuf += sizeof(unsigned long);
		}

		switch (pos) {
#define SET_DBREG(n)							\
			target->thread.debugreg##n = val;		\
			if (target == current)				\
				set_debugreg(target->thread.debugreg##n, n)

		case 0:
			if (val >= maxaddr)
				return -EIO;
			SET_DBREG(0);
			break;
		case 1:
			if (val >= maxaddr)
				return -EIO;
			SET_DBREG(1);
			break;
		case 2:
			if (val >= maxaddr)
				return -EIO;
			SET_DBREG(2);
			break;
		case 3:
			if (val >= maxaddr)
				return -EIO;
			SET_DBREG(3);
			break;
		case 4:
		case 5:
			if (val != 0)
				return -EIO;
			break;
		case 6:
			if (val >> 32)
				return -EIO;
			SET_DBREG(6);
			break;
		case 7:
			/*
			 * See arch/i386/kernel/ptrace.c for an explanation
			 * of this awkward check.
			 */
			val &= ~DR_CONTROL_RESERVED;
			for (i = 0; i < 4; i++)
				if ((0x5554 >> ((val >> (16 + 4*i)) & 0xf))
				    & 1)
					return -EIO;
			SET_DBREG(7);
			break;
#undef	SET_DBREG
		}
	}

	return 0;
}


static int
fpregs_active(struct task_struct *target, const struct utrace_regset *regset)
{
	return tsk_used_math(target) ? regset->n : 0;
}

static int
fpregs_get(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   void *kbuf, void __user *ubuf)
{
	if (tsk_used_math(target)) {
		if (target == current)
			unlazy_fpu(target);
	}
	else
		init_fpu(target);

	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     &target->thread.i387.fxsave, 0, -1);
}

static int
fpregs_set(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   const void *kbuf, const void __user *ubuf)
{
	int ret;

	if (tsk_used_math(target)) {
		if (target == current)
			unlazy_fpu(target);
	}
	else if (pos == 0 && count == sizeof(struct user_i387_struct))
		set_stopped_child_used_math(target);
	else
		init_fpu(target);

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   &target->thread.i387.fxsave, 0, -1);

	target->thread.i387.fxsave.mxcsr &= mxcsr_feature_mask;

	return ret;
}

static int
fsgs_active(struct task_struct *tsk, const struct utrace_regset *regset)
{
	if (tsk->thread.gsindex == GS_TLS_SEL || tsk->thread.gs)
		return 2;
	if (tsk->thread.fsindex == FS_TLS_SEL || tsk->thread.fs)
		return 1;
	return 0;
}

static inline u32 read_32bit_tls(struct task_struct *t, int tls)
{
	struct desc_struct *desc = (void *)t->thread.tls_array;
	desc += tls;
	return desc->base0 |
		(((u32)desc->base1) << 16) |
		(((u32)desc->base2) << 24);
}

static int
fsgs_get(struct task_struct *target,
	 const struct utrace_regset *regset,
	 unsigned int pos, unsigned int count,
	 void *kbuf, void __user *ubuf)
{
	const unsigned long *kaddr = kbuf;
	const unsigned long __user *uaddr = ubuf;
	unsigned long addr;

	/*
	 * XXX why the MSR reads here?
	 * Can anything change the MSRs without changing thread.fs first?
	 */
	if (pos == 0) {		/* FS */
		if (kaddr)
			addr = *kaddr++;
		else if (__get_user(addr, uaddr++))
			return -EFAULT;
		if (target->thread.fsindex == FS_TLS_SEL)
			addr = read_32bit_tls(target, FS_TLS);
		else if (target == current) {
			rdmsrl(MSR_FS_BASE, addr);
		}
		else
			addr = target->thread.fs;
	}

	if (count > sizeof(unsigned long)) { /* GS */
		if (kaddr)
			addr = *kaddr;
		else if (__get_user(addr, uaddr))
			return -EFAULT;
		if (target->thread.fsindex == GS_TLS_SEL)
			addr = read_32bit_tls(target, GS_TLS);
		else if (target == current) {
			rdmsrl(MSR_GS_BASE, addr);
		}
		else
			addr = target->thread.fs;
	}

	return 0;
}

static int
fsgs_set(struct task_struct *target,
	 const struct utrace_regset *regset,
	 unsigned int pos, unsigned int count,
	 const void *kbuf, const void __user *ubuf)
{
	const unsigned long *kaddr = kbuf;
	const unsigned long __user *uaddr = ubuf;
	unsigned long addr;
	int ret = 0;

	if (pos == 0) {		/* FS */
		if (kaddr)
			addr = *kaddr++;
		else if (__get_user(addr, uaddr++))
			return -EFAULT;
		ret = do_arch_prctl(target, ARCH_SET_FS, addr);
	}

	if (!ret && count > sizeof(unsigned long)) { /* GS */
		if (kaddr)
			addr = *kaddr;
		else if (__get_user(addr, uaddr))
			return -EFAULT;
		ret = do_arch_prctl(target, ARCH_SET_GS, addr);
	}

	return ret;
}


/*
 * These are our native regset flavors.
 * XXX ioperm? vm86?
 */
static const struct utrace_regset native_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_regs_struct)/8, .size = 8, .align = 8,
		.get = genregs_get, .set = genregs_set
	},
	{
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_i387_struct) / sizeof(long),
		.size = sizeof(long), .align = sizeof(long),
		.active = fpregs_active,
		.get = fpregs_get, .set = fpregs_set
	},
	{
		.n = 2, .size = sizeof(long), .align = sizeof(long),
		.active = fsgs_active,
		.get = fsgs_get, .set = fsgs_set
	},
	{
		.n = 8, .size = sizeof(long), .align = sizeof(long),
		.active = dbregs_active,
		.get = dbregs_get, .set = dbregs_set
	},
};

const struct utrace_regset_view utrace_x86_64_native = {
	.name = "x86-64", .e_machine = EM_X86_64,
	.regsets = native_regsets, .n = ARRAY_SIZE(native_regsets)
};

const struct utrace_regset_view *utrace_native_view(struct task_struct *tsk)
{
#ifdef CONFIG_IA32_EMULATION
	if (test_tsk_thread_flag(tsk, TIF_IA32))
		return &utrace_ia32_view;
#endif
	return &utrace_x86_64_native;
}


#ifdef CONFIG_PTRACE
static const struct ptrace_layout_segment x86_64_uarea[] = {
	{0, sizeof(struct user_regs_struct), 0, 0},
	{sizeof(struct user_regs_struct),
	 offsetof(struct user, u_debugreg[0]), -1, 0},
	{offsetof(struct user, u_debugreg[0]),
	 offsetof(struct user, u_debugreg[8]), 3, 0},
	{0, 0, -1, 0}
};

int arch_ptrace(long *req, struct task_struct *child,
		struct utrace_attached_engine *engine,
		unsigned long addr, unsigned long data, long *val)
{
	switch (*req) {
	case PTRACE_PEEKUSR:
		return ptrace_peekusr(child, engine, x86_64_uarea, addr, data);
	case PTRACE_POKEUSR:
		return ptrace_pokeusr(child, engine, x86_64_uarea, addr, data);
	case PTRACE_GETREGS:
		return ptrace_whole_regset(child, engine, data, 0, 0);
	case PTRACE_SETREGS:
		return ptrace_whole_regset(child, engine, data, 0, 1);
	case PTRACE_GETFPREGS:
		return ptrace_whole_regset(child, engine, data, 1, 0);
	case PTRACE_SETFPREGS:
		return ptrace_whole_regset(child, engine, data, 1, 1);
#ifdef CONFIG_IA32_EMULATION
	case PTRACE_GET_THREAD_AREA:
	case PTRACE_SET_THREAD_AREA:
		return ptrace_onereg_access(child, engine,
					    &utrace_ia32_view, 3,
					    addr, (void __user *)data, NULL,
					    *req == PTRACE_SET_THREAD_AREA);
#endif
		/* normal 64bit interface to access TLS data.
		   Works just like arch_prctl, except that the arguments
		   are reversed. */
	case PTRACE_ARCH_PRCTL:
		return do_arch_prctl(child, data, addr);
	}
	return -ENOSYS;
}
#endif	/* CONFIG_PTRACE */

#if defined CONFIG_IA32_EMULATION
# define IS_IA32	is_compat_task()
#else
# define IS_IA32	0
#endif

asmlinkage void syscall_trace_enter(struct pt_regs *regs)
{
	/* do the secure computing check first */
	secure_computing(regs->orig_rax);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(regs, 0);

	if (unlikely(current->audit_context)) {
		if (IS_IA32) {
			audit_syscall_entry(AUDIT_ARCH_I386,
					    regs->orig_rax,
					    regs->rbx, regs->rcx,
					    regs->rdx, regs->rsi);
		} else {
			audit_syscall_entry(AUDIT_ARCH_X86_64,
					    regs->orig_rax,
					    regs->rdi, regs->rsi,
					    regs->rdx, regs->r10);
		}
	}
}

asmlinkage void syscall_trace_leave(struct pt_regs *regs)
{
	if (unlikely(current->audit_context))
		audit_syscall_exit(AUDITSC_RESULT(regs->rax), regs->rax);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(regs, 1);

	if (test_thread_flag(TIF_SINGLESTEP)) {
		force_sig(SIGTRAP, current); /* XXX */
		tracehook_report_syscall_step(regs);
	}
}
