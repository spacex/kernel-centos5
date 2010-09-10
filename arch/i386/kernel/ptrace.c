/* ptrace.c */
/* By Ross Biro 1/23/92 */
/*
 * Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
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
#include <asm/tracehook.h>


/*
 * Determines which flags the user has access to [1 = access, 0 = no access].
 * Prohibits changing ID(21), VIP(20), VIF(19), VM(17), NT(14), IOPL(12-13), IF(9).
 * Also masks reserved bits (31-22, 15, 5, 3, 1).
 */
#define FLAG_MASK 0x00050dd5

/*
 * Offset of eflags on child stack..
 */
#define EFL_OFFSET ((EFL-2)*4-sizeof(struct pt_regs))

static inline struct pt_regs *get_child_regs(struct task_struct *task)
{
	void *stack_top = (void *)task->thread.esp0;
	return stack_top - sizeof(struct pt_regs);
}

/*
 * this routine will get a word off of the processes privileged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */   
static inline int get_stack_long(struct task_struct *task, int offset)
{
	unsigned char *stack;

	stack = (unsigned char *)task->thread.esp0;
	stack += offset;
	return (*((int *)stack));
}

/*
 * this routine will put a word on the processes privileged stack. 
 * the offset is how far from the base addr as stored in the TSS.  
 * this routine assumes that all the privileged stacks are in our
 * data space.
 */
static inline int put_stack_long(struct task_struct *task, int offset,
	unsigned long data)
{
	unsigned char * stack;

	stack = (unsigned char *) task->thread.esp0;
	stack += offset;
	*(unsigned long *) stack = data;
	return 0;
}

static int putreg(struct task_struct *child,
	unsigned long regno, unsigned long value)
{
	switch (regno >> 2) {
	case FS:
		if (value && (value & 3) != 3)
			return -EIO;
		child->thread.fs = value;
		if (child == current)
			/*
			 * The user-mode %gs is not affected by
			 * kernel entry, so we must update the CPU.
			 */
			loadsegment(fs, value);
		return 0;
	case GS:
		if (value && (value & 3) != 3)
			return -EIO;
		child->thread.gs = value;
		if (child == current)
			/*
			 * The user-mode %gs is not affected by
			 * kernel entry, so we must update the CPU.
			 */
			loadsegment(gs, value);
		return 0;
	case DS:
	case ES:
		if (value && (value & 3) != 3)
			return -EIO;
		value &= 0xffff;
		break;
	case SS:
	case CS:
		if ((value & 3) != 3)
			return -EIO;
		value &= 0xffff;
		break;
	case EFL:
		value &= FLAG_MASK;
		value |= get_stack_long(child, EFL_OFFSET) & ~FLAG_MASK;
		clear_tsk_thread_flag(child, TIF_FORCED_TF);
		break;
	}
	if (regno > GS*4)
		regno -= 2*4;
	put_stack_long(child, regno - sizeof(struct pt_regs), value);
	return 0;
}

static unsigned long getreg(struct task_struct *child,
	unsigned long regno)
{
	unsigned long retval = ~0UL;

	switch (regno >> 2) {
	case FS:
		retval = child->thread.fs;
		if (child == current)
			savesegment(fs, retval);
		break;
	case GS:
		retval = child->thread.gs;
		if (child == current)
			savesegment(gs, retval);
		break;
	case EFL:
		if (test_tsk_thread_flag(child, TIF_FORCED_TF))
			retval &= ~X86_EFLAGS_TF;
		goto fetch;
	case DS:
	case ES:
	case SS:
	case CS:
		retval = 0xffff;
		/* fall through */
	default:
	fetch:
		if (regno > GS*4)
			regno -= 2*4;
		regno = regno - sizeof(struct pt_regs);
		retval &= get_stack_long(child, regno);
	}
	return retval;
}

#define LDT_SEGMENT 4

static unsigned long convert_eip_to_linear(struct task_struct *child, struct pt_regs *regs)
{
	unsigned long addr, seg;

	addr = regs->eip;
	seg = regs->xcs & 0xffff;
	if (regs->eflags & VM_MASK) {
		addr = (addr & 0xffff) + (seg << 4);
		return addr;
	}

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

static inline int is_at_popf(struct task_struct *child, struct pt_regs *regs)
{
	int i, copied;
	unsigned char opcode[16];
	unsigned long addr = convert_eip_to_linear(child, regs);

	copied = access_process_vm(child, addr, opcode, sizeof(opcode), 0);
	for (i = 0; i < copied; i++) {
		switch (opcode[i]) {
		/* popf */
		case 0x9d:
			return 1;
		/* opcode and address size prefixes */
		case 0x66: case 0x67:
			continue;
		/* irrelevant prefixes (segment overrides and repeats) */
		case 0x26: case 0x2e:
		case 0x36: case 0x3e:
		case 0x64: case 0x65:
		case 0xf0: case 0xf2: case 0xf3:
			continue;

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
	struct pt_regs *regs = get_child_regs(child);

	/*
	 * Always set TIF_SINGLESTEP - this guarantees that 
	 * we single-step system calls etc..  This will also
	 * cause us to set TF when returning to user mode.
	 */
	set_tsk_thread_flag(child, TIF_SINGLESTEP);

	/*
	 * If TF was already set, don't do anything else
	 */
	if (regs->eflags & X86_EFLAGS_TF)
		return;

	/* Set TF on the kernel stack.. */
	regs->eflags |= X86_EFLAGS_TF;

	/*
	 * ..but if TF is changed by the instruction we will trace,
	 * don't mark it as being "us" that set it, so that we
	 * won't clear it by hand later.
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
		struct pt_regs *regs = get_child_regs(child);
		regs->eflags &= ~X86_EFLAGS_TF;
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
			pos += 4;
			count -= 4;
		}
	}
	else {
		unsigned long __user *up = ubuf;
		while (count > 0) {
			if (__put_user(getreg(target, pos), up++))
				return -EFAULT;
			pos += 4;
			count -= 4;
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
			pos += 4;
			count -= 4;
		}
	}
	else {
		const unsigned long __user *up = ubuf;
		while (!ret && count > 0) {
			unsigned long val;
			ret = __get_user(val, up++);
			if (!ret)
				ret = putreg(target, pos, val);
			pos += 4;
			count -= 4;
		}
	}

	return ret;
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
	struct user_i387_struct fp;
	int ret;

	if (tsk_used_math(target)) {
		if (target == current)
			unlazy_fpu(target);
	}
	else
		init_fpu(target);

	ret = get_fpregs(&fp, target);
	if (ret == 0)
		ret = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    &fp, 0, -1);

	return ret;
}

static int
fpregs_set(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   const void *kbuf, const void __user *ubuf)
{
	struct user_i387_struct fp;
	int ret;

	if (tsk_used_math(target)) {
		if (target == current)
			unlazy_fpu(target);
	}
	else if (pos == 0 && count == sizeof(fp))
		set_stopped_child_used_math(target);
	else
		init_fpu(target);

	if (pos > 0 || count < sizeof(fp)) {
		ret = get_fpregs(&fp, target);
		if (ret == 0)
			ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
						   &fp, 0, -1);
		if (ret)
			return ret;
		kbuf = &fp;
	}
	else if (kbuf == NULL) {
		if (__copy_from_user(&fp, ubuf, sizeof(fp)))
			return -EFAULT;
		kbuf = &fp;
	}

	return set_fpregs(target, kbuf);
}

static int
fpxregs_active(struct task_struct *target, const struct utrace_regset *regset)
{
	return !cpu_has_fxsr ? -ENODEV : tsk_used_math(target) ? regset->n : 0;
}

static int
fpxregs_get(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    void *kbuf, void __user *ubuf)
{
	if (!cpu_has_fxsr)
		return -ENODEV;

	if (tsk_used_math(target))
		unlazy_fpu(target);
	else
		init_fpu(target);

	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     &target->thread.i387.fxsave, 0, -1);
}

static int
fpxregs_set(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   const void *kbuf, const void __user *ubuf)
{
	int ret;

	if (!cpu_has_fxsr)
		return -ENODEV;

	if (tsk_used_math(target))
		unlazy_fpu(target);
	else if (pos == 0 && count == sizeof(target->thread.i387.fxsave))
		set_stopped_child_used_math(target);
	else
		init_fpu(target);

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   &target->thread.i387.fxsave, 0, -1);

	updated_fpxregs(target);

	return ret;
}


static int
dbregs_active(struct task_struct *tsk, const struct utrace_regset *regset)
{
	if (tsk->thread.debugreg[DR_CONTROL] | tsk->thread.debugreg[DR_STATUS])
		return 8;
	return 0;
}

static int
dbregs_get(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   void *kbuf, void __user *ubuf)
{ 
	/*
	 * The hardware updates the status register on a debug trap,
	 * but do_debug (traps.c) save it for us when that happens.
	 * So whether the target is current or not, thread.debugreg is good.
	 */

	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     target->thread.debugreg, 0, -1);
}

static int
dbregs_set(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   const void *kbuf, const void __user *ubuf)
{
	for (pos >>= 2, count >>= 2; count > 0; --count, ++pos) {
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

		if (pos < 4) {
			if (val >= TASK_SIZE - 3)
				return -EIO;
			goto set;
		}
		else if (pos < 6) {
			if (val != 0)
				return -EIO;
			continue;
		}
		else if (pos < 7)
			goto set;

		/* Sanity-check data. Take one half-byte at once with
		 * check = (val >> (16 + 4*i)) & 0xf. It contains the
		 * R/Wi and LENi bits; bits 0 and 1 are R/Wi, and bits
		 * 2 and 3 are LENi. Given a list of invalid values,
		 * we do mask |= 1 << invalid_value, so that
		 * (mask >> check) & 1 is a correct test for invalid
		 * values.
		 *
		 * R/Wi contains the type of the breakpoint /
		 * watchpoint, LENi contains the length of the watched
		 * data in the watchpoint case.
		 *
		 * The invalid values are:
		 * - LENi == 0x10 (undefined), so mask |= 0x0f00.
		 * - R/Wi == 0x10 (break on I/O reads or writes), so
		 *   mask |= 0x4444.
		 * - R/Wi == 0x00 && LENi != 0x00, so we have mask |=
		 *   0x1110.
		 *
		 * Finally, mask = 0x0f00 | 0x4444 | 0x1110 == 0x5f54.
		 *
		 * See the Intel Manual "System Programming Guide",
		 * 15.2.4
		 *
		 * Note that LENi == 0x10 is defined on x86_64 in long
		 * mode (i.e. even for 32-bit userspace software, but
		 * 64-bit kernel), so the x86_64 mask value is 0x5454.
		 * See the AMD manual no. 24593 (AMD64 System
		 * Programming)*/
		val &= ~DR_CONTROL_RESERVED;
		for (i = 0; i < 4; i++)
			if ((0x5f54 >> ((val >> (16 + 4*i)) & 0xf)) & 1)
				return -EIO;
		if (val)
			set_tsk_thread_flag(target, TIF_DEBUG);
		else
			clear_tsk_thread_flag(target, TIF_DEBUG);

set:
		target->thread.debugreg[pos] = val;
		if (target == current)
			switch (pos) {
#define DBREG(n) case n: set_debugreg(target->thread.debugreg[n], n); break
				DBREG(0);
				DBREG(1);
				DBREG(2);
				DBREG(3);
				DBREG(6);
				DBREG(7);
#undef	DBREG
			}
	}

	return 0;
}


/*
 * Perform get_thread_area on behalf of the traced child.
 */
static int
tls_get(struct task_struct *target,
	const struct utrace_regset *regset,
	unsigned int pos, unsigned int count,
	void *kbuf,  void __user *ubuf)
{
	struct user_desc info, *ip;
	const struct desc_struct *desc;

/*
 * Get the current Thread-Local Storage area:
 */

#define GET_BASE(desc) ( \
	(((desc)->a >> 16) & 0x0000ffff) | \
	(((desc)->b << 16) & 0x00ff0000) | \
	( (desc)->b        & 0xff000000)   )

#define GET_LIMIT(desc) ( \
	((desc)->a & 0x0ffff) | \
	 ((desc)->b & 0xf0000) )

#define GET_32BIT(desc)		(((desc)->b >> 22) & 1)
#define GET_CONTENTS(desc)	(((desc)->b >> 10) & 3)
#define GET_WRITABLE(desc)	(((desc)->b >>  9) & 1)
#define GET_LIMIT_PAGES(desc)	(((desc)->b >> 23) & 1)
#define GET_PRESENT(desc)	(((desc)->b >> 15) & 1)
#define GET_USEABLE(desc)	(((desc)->b >> 20) & 1)

	desc = &target->thread.tls_array[pos / sizeof(struct user_desc)];
	ip = kbuf ?: &info;
	memset(ip, 0, sizeof *ip);
	for (; count > 0; count -= sizeof(struct user_desc), ++desc) {
		ip->entry_number = (desc - &target->thread.tls_array[0]
				    + GDT_ENTRY_TLS_MIN);
		ip->base_addr = GET_BASE(desc);
		ip->limit = GET_LIMIT(desc);
		ip->seg_32bit = GET_32BIT(desc);
		ip->contents = GET_CONTENTS(desc);
		ip->read_exec_only = !GET_WRITABLE(desc);
		ip->limit_in_pages = GET_LIMIT_PAGES(desc);
		ip->seg_not_present = !GET_PRESENT(desc);
		ip->useable = GET_USEABLE(desc);

		if (kbuf)
			++ip;
		else {
			if (__copy_to_user(ubuf, &info, sizeof(info)))
				return -EFAULT;
			ubuf += sizeof(info);
		}
	}

	return 0;
}

/*
 * Perform set_thread_area on behalf of the traced child.
 */
static int
tls_set(struct task_struct *target,
	const struct utrace_regset *regset,
	unsigned int pos, unsigned int count,
	const void *kbuf, const void __user *ubuf)
{
	struct user_desc info;
	struct desc_struct *desc;
	struct desc_struct newtls[GDT_ENTRY_TLS_ENTRIES];
	unsigned int i;
	int cpu;

	pos /= sizeof(struct user_desc);
	count /= sizeof(struct user_desc);

	desc = newtls;
	for (i = 0; i < count; ++i, ++desc) {
		const struct user_desc *ip;
		if (kbuf) {
			ip = kbuf;
			kbuf += sizeof(struct user_desc);
		}
		else {
			ip = &info;
			if (__copy_from_user(&info, ubuf, sizeof(info)))
				return -EFAULT;
			ubuf += sizeof(struct user_desc);
		}

		if (LDT_empty(ip)) {
			desc->a = 0;
			desc->b = 0;
		} else {
			desc->a = LDT_entry_a(ip);
			desc->b = LDT_entry_b(ip);
		}
	}

	/*
	 * We must not get preempted while modifying the TLS.
	 */
	cpu = get_cpu();
	memcpy(&target->thread.tls_array[pos], newtls,
	       count * sizeof(newtls[0]));
	if (target == current)
		load_TLS(&target->thread, cpu);
	put_cpu();

	return 0;
}


/*
 * Determine how many TLS slots are in use.
 */
static int
tls_active(struct task_struct *target, const struct utrace_regset *regset)
{
	int i;
	for (i = GDT_ENTRY_TLS_ENTRIES; i > 0; --i) {
		struct desc_struct *desc = &target->thread.tls_array[i - 1];
		if ((desc->a | desc->b) != 0)
			break;
	}
	return i;
}


/*
 * These are our native regset flavors.
 * XXX ioperm? vm86?
 */
static const struct utrace_regset native_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = FRAME_SIZE, .size = sizeof(long), .align = sizeof(long),
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
		.core_note_type = NT_PRXFPREG,
		.n = sizeof(struct user_fxsr_struct) / sizeof(long),
		.size = sizeof(long), .align = sizeof(long),
		.active = fpxregs_active,
		.get = fpxregs_get, .set = fpxregs_set
	},
	{
		.n = GDT_ENTRY_TLS_ENTRIES,
		.bias = GDT_ENTRY_TLS_MIN,
		.size = sizeof(struct user_desc),
		.align = sizeof(struct user_desc),
		.active = tls_active, .get = tls_get, .set = tls_set
	},
	{
		.n = 8, .size = sizeof(long), .align = sizeof(long),
		.active = dbregs_active,
		.get = dbregs_get, .set = dbregs_set
	},
};


static const struct utrace_regset_view utrace_i386_native = {
	.name = "i386", .e_machine = EM_386,
	.regsets = native_regsets, .n = ARRAY_SIZE(native_regsets)
};

const struct utrace_regset_view *utrace_native_view(struct task_struct *tsk)
{
	return &utrace_i386_native;
}

#ifdef CONFIG_PTRACE
static const struct ptrace_layout_segment i386_uarea[] = {
	{0, FRAME_SIZE*4, 0, 0},
	{FRAME_SIZE*4, offsetof(struct user, u_debugreg[0]), -1, 0},
	{offsetof(struct user, u_debugreg[0]),
	 offsetof(struct user, u_debugreg[8]), 4, 0},
	{0, 0, -1, 0}
};

int arch_ptrace(long *req, struct task_struct *child,
		struct utrace_attached_engine *engine,
		unsigned long addr, unsigned long data, long *val)
{
	switch (*req) {
	case PTRACE_PEEKUSR:
		return ptrace_peekusr(child, engine, i386_uarea, addr, data);
	case PTRACE_POKEUSR:
		return ptrace_pokeusr(child, engine, i386_uarea, addr, data);
	case PTRACE_GETREGS:
		return ptrace_whole_regset(child, engine, data, 0, 0);
	case PTRACE_SETREGS:
		return ptrace_whole_regset(child, engine, data, 0, 1);
	case PTRACE_GETFPREGS:
		return ptrace_whole_regset(child, engine, data, 1, 0);
	case PTRACE_SETFPREGS:
		return ptrace_whole_regset(child, engine, data, 1, 1);
	case PTRACE_GETFPXREGS:
		return ptrace_whole_regset(child, engine, data, 2, 0);
	case PTRACE_SETFPXREGS:
		return ptrace_whole_regset(child, engine, data, 2, 1);
	case PTRACE_GET_THREAD_AREA:
	case PTRACE_SET_THREAD_AREA:
		return ptrace_onereg_access(child, engine,
					    utrace_native_view(current), 3,
					    addr, (void __user *)data, NULL,
					    *req == PTRACE_SET_THREAD_AREA);
	}
	return -ENOSYS;
}
#endif

void send_sigtrap(struct task_struct *tsk, struct pt_regs *regs, int error_code)
{
	struct siginfo info;

	tsk->thread.trap_no = 1;
	tsk->thread.error_code = error_code;

	memset(&info, 0, sizeof(info));
	info.si_signo = SIGTRAP;
	info.si_code = TRAP_BRKPT;

	/* User-mode eip? */
	info.si_addr = user_mode_vm(regs) ? (void __user *) regs->eip : NULL;

	/* Send us the fakey SIGTRAP */
	force_sig_info(SIGTRAP, &info, tsk);
}

/* notification of system call entry/exit
 * - triggered by current->work.syscall_trace
 */
__attribute__((regparm(3)))
void do_syscall_trace(struct pt_regs *regs, int entryexit)
{
	/* do the secure computing check first */
	if (!entryexit)
		secure_computing(regs->orig_eax);

	if (unlikely(current->audit_context) && entryexit)
		audit_syscall_exit(AUDITSC_RESULT(regs->eax), regs->eax);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(regs, entryexit);

	if (test_thread_flag(TIF_SINGLESTEP) && entryexit) {
		send_sigtrap(current, regs, 0);	/* XXX */
		tracehook_report_syscall_step(regs);
	}

	if (unlikely(current->audit_context) && !entryexit)
		audit_syscall_entry(AUDIT_ARCH_I386, regs->orig_eax,
				    regs->ebx, regs->ecx, regs->edx, regs->esi);
}
