/*
 *  PowerPC version
 *    Copyright (C) 1995-1996 Gary Thomas (gdt@linuxppc.org)
 *
 *  Derived from "arch/m68k/kernel/ptrace.c"
 *  Copyright (C) 1994 by Hamish Macdonald
 *  Taken from linux/kernel/ptrace.c and modified for M680x0.
 *  linux/kernel/ptrace.c is by Ross Biro 1/23/92, edited by Linus Torvalds
 *
 * Modified by Cort Dougan (cort@hq.fsmlabs.com)
 * and Paul Mackerras (paulus@samba.org).
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file README.legal in the main directory of
 * this archive for more details.
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
#include <linux/signal.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/elf.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/tracehook.h>

/*
 * Set of msr bits that gdb can change on behalf of a process.
 */
#ifdef CONFIG_PPC64
#define MSR_DEBUGCHANGE	(MSR_FE0 | MSR_SE | MSR_BE | MSR_FE1)
#elif defined(CONFIG_40x) || defined(CONFIG_BOOKE)
#define MSR_DEBUGCHANGE	0
#else  /* CONFIG_PPC32 */
#define MSR_DEBUGCHANGE	(MSR_SE | MSR_BE)
#endif /* CONFIG_PPC64 */

/*
 * Last register that can be changed via ptrace.
 */
#ifdef CONFIG_PPC64
#define PT_LAST	PT_SOFTE
#else
#define PT_LAST	PT_MQ
#endif

static int
genregs_get(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    void *kbuf, void __user *ubuf)
{
	if (target->thread.regs == NULL)
		return -EIO;

#ifdef CONFIG_PPC32
	CHECK_FULL_REGS(target->thread.regs);
#endif

	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     target->thread.regs, 0, -1);
}

static int
genregs_set(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    const void *kbuf, const void __user *ubuf)
{
	unsigned long msr_save;
	int ret = 0;

	if (target->thread.regs == NULL)
		return -EIO;

#ifdef CONFIG_PPC32
	CHECK_FULL_REGS(target->thread.regs);
#endif

	/*
	 * Just ignore attempts to set the registers beyond PT_LAST.
	 * They are read-only.
	 */

	msr_save = target->thread.regs->msr &~ MSR_DEBUGCHANGE;

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   target->thread.regs, 0,
				   (PT_LAST + 1) * sizeof(long));

	target->thread.regs->msr &= MSR_DEBUGCHANGE;
	target->thread.regs->msr |= msr_save;

	return ret;
}

static int
fpregs_get(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   void *kbuf, void __user *ubuf)
{
	BUILD_BUG_ON(offsetof(struct thread_struct, fpscr)
		     != offsetof(struct thread_struct, fpr[32]));

	flush_fp_to_thread(target);

	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     &target->thread.fpr, 0, -1);
}

static int
fpregs_set(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    const void *kbuf, const void __user *ubuf)
{
	return utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				    &target->thread.fpr, 0, -1);
}

#ifdef CONFIG_ALTIVEC
/*
 * Get/set all the altivec registers vr0..vr31, vscr, vrsave, in one go.
 * The transfer totals 34 quadword.  Quadwords 0-31 contain the
 * corresponding vector registers.  Quadword 32 contains the vscr as the
 * last word (offset 12) within that quadword.  Quadword 33 contains the
 * vrsave as the first word (offset 0) within the quadword.
 *
 * This definition of the VMX state is compatible with the current PPC32
 * ptrace interface.  This allows signal handling and ptrace to use the
 * same structures.  This also simplifies the implementation of a bi-arch
 * (combined (32- and 64-bit) gdb.
 */

static int
vrregs_active(struct task_struct *target, const struct utrace_regset *regset)
{
	flush_altivec_to_thread(target);
	return target->thread.used_vr ? regset->n : 0;
}

static int
vrregs_get(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   void *kbuf, void __user *ubuf)
{
	int ret;

	BUILD_BUG_ON(offsetof(struct thread_struct, vscr)
		     != offsetof(struct thread_struct, vr[32]));

	flush_altivec_to_thread(target);

	ret = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				    &target->thread.vr,
				    0, 33 * sizeof(vector128));
	if (ret == 0 && count > 0) {
		/*
		 * Copy out only the low-order word of vrsave.
		 */
		u32 vrsave = target->thread.vrsave;
		ret = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf, &vrsave,
					    33 * sizeof(vector128), -1);
	}

	return ret;
}

static int
vrregs_set(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    const void *kbuf, const void __user *ubuf)
{
	int ret;

	flush_altivec_to_thread(target);

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   &target->thread.vr,
				   0, 33 * sizeof(vector128));
	if (ret == 0 && count > 0) {
		/*
		 * Copy in only the low-order word of vrsave.
		 */
		u32 vrsave;
		ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf, &vrsave,
					   33 * sizeof(vector128), -1);
		if (ret == 0)
			target->thread.vrsave = vrsave;
	}

	return ret;
}
#endif	/* CONFIG_ALTIVEC */

#ifdef CONFIG_PPC64
/* We only support one DABR and no IABRS at the moment */

static int
set_thread_dabr(struct task_struct *tsk, unsigned long dabr)
{
	/* The bottom 3 bits are flags */
	if ((dabr & ~0x7UL) >= TASK_SIZE)
		return -EIO;

	/* Ensure translation is on */
	if (dabr && !(dabr & DABR_TRANSLATION))
		return -EIO;

	tsk->thread.dabr = dabr;
	return 0;
}

static int
debugreg_get(struct task_struct *target,
	     const struct utrace_regset *regset,
	     unsigned int pos, unsigned int count,
	     void *kbuf, void __user *ubuf)
{
	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     &target->thread.dabr, 0, -1);
}

static int
debugreg_set(struct task_struct *target,
	     const struct utrace_regset *regset,
	     unsigned int pos, unsigned int count,
	     const void *kbuf, const void __user *ubuf)
{
	unsigned long dabr;
	int ret;

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf, &dabr, 0, -1);
	if (ret == 0)
		ret = set_thread_dabr(target, dabr);

	return ret;
}

static int
ppc32_dabr_get(struct task_struct *target,
	       const struct utrace_regset *regset,
	       unsigned int pos, unsigned int count,
	       void *kbuf, void __user *ubuf)
{
	u32 dabr = target->thread.dabr;
	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf, &dabr, 0, -1);
}

static int
ppc32_dabr_set(struct task_struct *target,
	       const struct utrace_regset *regset,
	       unsigned int pos, unsigned int count,
	       const void *kbuf, const void __user *ubuf)
{
	u32 dabr;
	int ret;

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf, &dabr, 0, -1);
	if (ret == 0)
		ret = set_thread_dabr(target, dabr);

	return ret;
}
#endif	/* CONFIG_PPC64 */

#ifdef CONFIG_SPE
/*
 * For get_evrregs/set_evrregs functions 'data' has the following layout:
 *
 * struct {
 *   u32 evr[32];
 *   u64 acc;
 *   u32 spefscr;
 * }
 */

static int
evrregs_active(struct task_struct *target, const struct utrace_regset *regset)
{
	if (target->thread.regs->msr & MSR_SPE)
		giveup_spe(target);
	return target->thread.used_spe ? regset->n : 0;
}

static int
evrregs_get(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    void *kbuf, void __user *ubuf)
{
	BUILD_BUG_ON(offsetof(struct thread_struct, acc)
		     != offsetof(struct thread_struct, evr[32]));
	BUILD_BUG_ON(offsetof(struct thread_struct, acc) + sizeof(u64)
		     != offsetof(struct thread_struct, spefscr));

	if (target->thread.regs->msr & MSR_SPE)
		giveup_spe(target);

	return utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				     &target->thread.evr, 0, -1);
}

static int
evrregs_set(struct task_struct *target,
	    const struct utrace_regset *regset,
	    unsigned int pos, unsigned int count,
	    const void *kbuf, const void __user *ubuf)
{
	/* this is to clear the MSR_SPE bit to force a reload
	 * of register state from memory */
	if (target->thread.regs->msr & MSR_SPE)
		giveup_spe(target);

	return utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				    &target->thread.evr, 0, -1);
}
#endif /* CONFIG_SPE */


/*
 * These are our native regset flavors.
 */
static const struct utrace_regset native_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = ELF_NGREG, .size = sizeof(long), .align = sizeof(long),
		.get = genregs_get, .set = genregs_set
	},
	{
		.core_note_type = NT_PRFPREG,
		.n = ELF_NFPREG,
		.size = sizeof(double), .align = sizeof(double),
		.get = fpregs_get, .set = fpregs_set
	},
#ifdef CONFIG_ALTIVEC
	{
		.n = 33*4+1, .size = sizeof(u32), .align = sizeof(u32),
		.active = vrregs_active, .get = vrregs_get, .set = vrregs_set
	},
#endif
#ifdef CONFIG_SPE
	{
		.n = 35, .size = sizeof(long), .align = sizeof(long),
		.active = evrregs_active,
		.get = evrregs_get, .set = evrregs_set
	},
#endif
#ifdef CONFIG_PPC64
	{
		.n = 1, .size = sizeof(long), .align = sizeof(long),
		.get = debugreg_get, .set = debugreg_set
	},
#endif
};

static const struct utrace_regset_view utrace_ppc_native_view = {
	.name = UTS_MACHINE, .e_machine = ELF_ARCH,
	.regsets = native_regsets, .n = ARRAY_SIZE(native_regsets)
};


#ifdef CONFIG_PPC64
#include <linux/compat.h>

static int
ppc32_gpr_get(struct task_struct *target,
	      const struct utrace_regset *regset,
	      unsigned int pos, unsigned int count,
	      void *kbuf, void __user *ubuf)
{
	unsigned long *regs = (unsigned long *) target->thread.regs;

	if (regs == NULL)
		return -EIO;

	regs += pos / sizeof(u32);

	if (kbuf) {
		u32 *out = kbuf;
		for (; count > 0; count -= sizeof(u32))
			*out++ = *regs++;
	}
	else {
		u32 __user *out = ubuf;
		for (; count > 0; count -= sizeof(u32))
			if (put_user((u32) *regs++, out++))
				return -EFAULT;
	}

	return 0;
}

static int
ppc32_gpr_set(struct task_struct *target,
	      const struct utrace_regset *regset,
	      unsigned int pos, unsigned int count,
	      const void *kbuf, const void __user *ubuf)
{
	unsigned long *regs = (unsigned long *) target->thread.regs;

	if (regs == NULL)
		return -EIO;

	/*
	 * Just ignore attempts to set the registers beyond PT_LAST.
	 * They are read-only.
	 */
	if (count > (PT_LAST + 1) * sizeof(u32) - pos)
		count = (PT_LAST + 1) * sizeof(u32) - pos;

	pos /= sizeof(u32);

	if (kbuf) {
		const u32 *in = kbuf;
		for (; count > 0; count -= sizeof(u32), ++pos, ++in) {
			if (pos == PT_MSR)
				regs[pos] = ((regs[pos] &~ MSR_DEBUGCHANGE)
					     | (*in & MSR_DEBUGCHANGE));
			else
				regs[pos] = *in;
		}
	}
	else {
		const u32 __user *in = kbuf;
		for (; count > 0; count -= sizeof(u32), ++pos) {
			u32 val;
			if (get_user(val, in++))
				return -EFAULT;
			else if (pos == PT_MSR)
				regs[pos] = ((regs[pos] &~ MSR_DEBUGCHANGE)
					     | (val & MSR_DEBUGCHANGE));
			else
				regs[pos] = val;
		}
	}

	return 0;
}

/*
 * These are the regset flavors matching the CONFIG_PPC32 native set.
 */
static const struct utrace_regset ppc32_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = ELF_NGREG,
		.size = sizeof(compat_long_t), .align = sizeof(compat_long_t),
		.get = ppc32_gpr_get, .set = ppc32_gpr_set
	},
	{
		.core_note_type = NT_PRFPREG,
		.n = ELF_NFPREG,
		.size = sizeof(double), .align = sizeof(double),
		.get = fpregs_get, .set = fpregs_set
	},
#ifdef CONFIG_ALTIVEC
	{
		.n = 33*4+1, .size = sizeof(u32), .align = sizeof(u32),
		.active = vrregs_active, .get = vrregs_get, .set = vrregs_set
	},
#endif
	{
		.n = 1,
		.size = sizeof(compat_long_t), .align = sizeof(compat_long_t),
		.get = ppc32_dabr_get, .set = ppc32_dabr_set
	},
};

static const struct utrace_regset_view utrace_ppc32_view = {
	.name = "ppc", .e_machine = EM_PPC,
	.regsets = ppc32_regsets, .n = ARRAY_SIZE(ppc32_regsets)
};
#endif

const struct utrace_regset_view *utrace_native_view(struct task_struct *tsk)
{
#ifdef CONFIG_PPC64
	if (test_tsk_thread_flag(tsk, TIF_32BIT))
		return &utrace_ppc32_view;
#endif
	return &utrace_ppc_native_view;
}


#ifdef CONFIG_PTRACE
static const struct ptrace_layout_segment ppc_uarea[] = {
	{0, PT_FPR0 * sizeof(long), 0, 0},
	{PT_FPR0 * sizeof(long), (PT_FPSCR + 1) * sizeof(long), 1, 0},
	{0, 0, -1, 0}
};

int arch_ptrace(long *request, struct task_struct *child,
		struct utrace_attached_engine *engine,
		unsigned long addr, unsigned long data, long *val)
{
	switch (*request) {
	case PTRACE_PEEKUSR:
		return ptrace_peekusr(child, engine, ppc_uarea, addr, data);
	case PTRACE_POKEUSR:
		return ptrace_pokeusr(child, engine, ppc_uarea, addr, data);
	case PPC_PTRACE_GETREGS: /* Get GPRs 0 - 31. */
	case PPC_PTRACE_SETREGS: /* Set GPRs 0 - 31. */
		return ptrace_regset_access(child, engine,
					    utrace_native_view(current), 0,
					    0, 32 * sizeof(long),
					    (void __user *)addr,
					    *request == PPC_PTRACE_SETREGS);
	case PPC_PTRACE_GETFPREGS: /* Get FPRs 0 - 31. */
	case PPC_PTRACE_SETFPREGS: /* Get FPRs 0 - 31. */
		return ptrace_regset_access(child, engine,
					    utrace_native_view(current), 1,
					    0, 32 * sizeof(double),
					    (void __user *)addr,
					    *request == PPC_PTRACE_SETFPREGS);
#ifdef CONFIG_PPC64
	case PTRACE_GET_DEBUGREG:
		return ptrace_onereg_access(child, engine,
					    utrace_native_view(current), 3,
					    addr, (unsigned long __user *)data,
					    NULL, 0);
	case PTRACE_SET_DEBUGREG:
		return ptrace_onereg_access(child, engine,
					    utrace_native_view(current), 3,
					    addr, NULL, &data, 1);
#endif /* CONFIG_PPC64 */
#ifdef CONFIG_ALTIVEC
	case PTRACE_GETVRREGS:
		return ptrace_whole_regset(child, engine, data, 2, 0);
	case PTRACE_SETVRREGS:
		return ptrace_whole_regset(child, engine, data, 2, 1);
#endif
#ifdef CONFIG_SPE
#ifdef CONFIG_ALTIVEC
#define REGSET_EVR 3
#else
#define REGSET_EVR 2
#endif
	case PTRACE_GETEVRREGS:
		return ptrace_whole_regset(child, engine, data, REGSET_EVR, 0);
	case PTRACE_SETEVRREGS:
		return ptrace_whole_regset(child, engine, data, REGSET_EVR, 1);
#endif
	}
	return -ENOSYS;
}

#ifdef CONFIG_COMPAT
#include <linux/mm.h>
#include <asm/uaccess.h>

static const struct ptrace_layout_segment ppc32_uarea[] = {
	{0, PT_FPR0 * sizeof(u32), 0, 0},
	{PT_FPR0 * sizeof(u32), (PT_FPSCR32 + 1) * sizeof(u32), 1, 0},
	{0, 0, -1, 0}
};

int arch_compat_ptrace(compat_long_t *request,
		       struct task_struct *child,
		       struct utrace_attached_engine *engine,
		       compat_ulong_t addr, compat_ulong_t data,
		       compat_long_t *val)
{
	void __user *uaddr = (void __user *) (unsigned long) addr;
	int ret = -ENOSYS;

	switch (*request) {
	case PTRACE_PEEKUSR:
		return ptrace_compat_peekusr(child, engine, ppc32_uarea,
					     addr, data);
	case PTRACE_POKEUSR:
		return ptrace_compat_pokeusr(child, engine, ppc32_uarea,
					     addr, data);

	case PPC_PTRACE_GETREGS: /* Get GPRs 0 - 31. */
	case PPC_PTRACE_SETREGS: /* Set GPRs 0 - 31. */
		return ptrace_regset_access(child, engine,
					    utrace_native_view(current), 0,
					    0, 32 * sizeof(compat_long_t),
					    uaddr,
					    *request == PPC_PTRACE_SETREGS);
	case PPC_PTRACE_GETFPREGS: /* Get FPRs 0 - 31. */
	case PPC_PTRACE_SETFPREGS: /* Get FPRs 0 - 31. */
		return ptrace_regset_access(child, engine,
					    utrace_native_view(current), 1,
					    0, 32 * sizeof(double),
					    uaddr,
					    *request == PPC_PTRACE_SETFPREGS);
#ifdef CONFIG_ALTIVEC
	case PTRACE_GETVRREGS:
		return ptrace_whole_regset(child, engine, data, 2, 0);
	case PTRACE_SETVRREGS:
		return ptrace_whole_regset(child, engine, data, 2, 1);
#endif
	case PTRACE_GET_DEBUGREG:
		return ptrace_onereg_access(child, engine,
					    utrace_native_view(current), 3,
					    addr,
					    (unsigned long __user *)
					    (unsigned long) data,
					    NULL, 0);
	case PTRACE_SET_DEBUGREG:
		return ptrace_onereg_access(child, engine,
					    utrace_native_view(current), 3,
					    addr, NULL, &data, 1);

	/*
	 * Read 4 bytes of the other process' storage
	 *  data is a pointer specifying where the user wants the
	 *	4 bytes copied into
	 *  addr is a pointer in the user's storage that contains an 8 byte
	 *	address in the other process of the 4 bytes that is to be read
	 * (this is run in a 32-bit process looking at a 64-bit process)
	 * when I and D space are separate, these will need to be fixed.
	 */
	case PPC_PTRACE_PEEKTEXT_3264:
	case PPC_PTRACE_PEEKDATA_3264: {
		u32 tmp;
		int copied;
		u32 __user * addrOthers;

		ret = -EIO;

		/* Get the addr in the other process that we want to read */
		if (get_user(addrOthers, ((u32 __user * __user *)
					  (unsigned long) addr)) != 0)
			break;

		copied = access_process_vm(child, (u64)addrOthers, &tmp,
				sizeof(tmp), 0);
		if (copied != sizeof(tmp))
			break;
		ret = put_user(tmp, (u32 __user *)(unsigned long)data);
		break;
	}

	/*
	 * Write 4 bytes into the other process' storage
	 *  data is the 4 bytes that the user wants written
	 *  addr is a pointer in the user's storage that contains an
	 *	8 byte address in the other process where the 4 bytes
	 *	that is to be written
	 * (this is run in a 32-bit process looking at a 64-bit process)
	 * when I and D space are separate, these will need to be fixed.
	 */
	case PPC_PTRACE_POKETEXT_3264:
	case PPC_PTRACE_POKEDATA_3264: {
		u32 tmp = data;
		u32 __user * addrOthers;

		/* Get the addr in the other process that we want to write into */
		ret = -EIO;
		if (get_user(addrOthers, ((u32 __user * __user *)
					  (unsigned long) addr)) != 0)
			break;
		ret = 0;
		if (access_process_vm(child, (u64)addrOthers, &tmp,
					sizeof(tmp), 1) == sizeof(tmp))
			break;
		ret = -EIO;
		break;
	}

	/*
	 * This is like PTRACE_PEEKUSR on a 64-bit process,
	 * but here we access only 4 bytes at a time.
	 */
	case PPC_PTRACE_PEEKUSR_3264: {
		union
		{
			u64 whole;
			u32 half[2];
		} reg;
		int setno;
		const struct utrace_regset *regset;

		ret = -EIO;
		if ((addr & 3) || addr > PT_FPSCR*8)
			break;

		setno = 0;
		if (addr >= PT_FPR0*8) {
			setno = 1;
			addr -= PT_FPR0*8;
		}
		regset = utrace_regset(child, NULL,
				       &utrace_ppc_native_view, setno);
		ret = (*regset->get)(child, regset, addr &~ 7,
				     sizeof(reg.whole), &reg.whole, NULL);
		if (ret == 0)
			ret = put_user(reg.half[(addr >> 2) & 1],
				       (u32 __user *)(unsigned long)data);
		break;
	}

	/*
	 * This is like PTRACE_POKEUSR on a 64-bit process,
	 * but here we access only 4 bytes at a time.
	 */
	case PPC_PTRACE_POKEUSR_3264: {
		union
		{
			u64 whole;
			u32 half[2];
		} reg;
		int setno;
		const struct utrace_regset *regset;

		ret = -EIO;
		if ((addr & 3) || addr > PT_FPSCR*8)
			break;

		setno = 0;
		if (addr >= PT_FPR0*8) {
			setno = 1;
			addr -= PT_FPR0*8;
		}
		regset = utrace_regset(child, NULL,
				       &utrace_ppc_native_view, setno);
		ret = (*regset->get)(child, regset, addr &~ 7,
				     sizeof(reg.whole), &reg.whole, NULL);
		BUG_ON(ret);
		reg.half[(addr >> 2) & 1] = data;
		ret = (*regset->set)(child, regset, addr &~ 7,
				     sizeof(reg.whole), &reg.whole, NULL);
		break;
	}
	}
	return ret;
}
#endif	/* CONFIG_COMPAT */
#endif	/* CONFIG_PTRACE */


void do_syscall_trace_enter(struct pt_regs *regs)
{
	secure_computing(regs->gpr[0]);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(regs, 0);

	if (unlikely(current->audit_context)) {
#ifdef CONFIG_PPC64
		if (!test_thread_flag(TIF_32BIT))
			audit_syscall_entry(AUDIT_ARCH_PPC64,
					    regs->gpr[0],
					    regs->gpr[3], regs->gpr[4],
					    regs->gpr[5], regs->gpr[6]);
		else
#endif
			audit_syscall_entry(AUDIT_ARCH_PPC,
					    regs->gpr[0],
					    regs->gpr[3] & 0xffffffff,
					    regs->gpr[4] & 0xffffffff,
					    regs->gpr[5] & 0xffffffff,
					    regs->gpr[6] & 0xffffffff);
	}
}

void do_syscall_trace_leave(struct pt_regs *regs)
{
	if (unlikely(current->audit_context))
		audit_syscall_exit((regs->ccr&0x10000000)?AUDITSC_FAILURE:AUDITSC_SUCCESS,
				   regs->result);

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(regs, 1);

	if (test_thread_flag(TIF_SINGLESTEP)) {
		force_sig(SIGTRAP, current); /* XXX */
		tracehook_report_syscall_step(regs);
	}
}
