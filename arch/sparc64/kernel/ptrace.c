/* ptrace.c: Sparc64 process tracing support.
 *
 * Copyright (C) 1996, 2006 David S. Miller (davem@davemloft.net)
 * Copyright (C) 1997 Jakub Jelinek (jj@sunsite.mff.cuni.cz)
 *
 * Based upon code written by Ross Biro, Linus Torvalds, Bob Manson,
 * and David Mosberger.
 *
 * Added Linux support -miguel (weird, eh?, the original code was meant
 * to emulate SunOS).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/tracehook.h>
#include <linux/elf.h>
#include <linux/ptrace.h>

#include <asm/asi.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/spitfire.h>
#include <asm/page.h>
#include <asm/cpudata.h>
#include <asm/psrcompat.h>

#define GENREG_G0	0
#define GENREG_O0	8
#define GENREG_L0	16
#define GENREG_I0	24
#define GENREG_TSTATE	32
#define GENREG_TPC	33
#define GENREG_TNPC	34
#define GENREG_Y	35

#define SPARC64_NGREGS	36

static int genregs_get(struct task_struct *target,
		       const struct utrace_regset *regset,
		       unsigned int pos, unsigned int count,
		       void *kbuf, void __user *ubuf)
{
	struct pt_regs *regs = task_pt_regs(target);
	int err;

	err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf, regs->u_regs,
				    GENREG_G0 * 8, GENREG_L0 * 8);

	if (err == 0 && count > 0 && pos < (GENREG_TSTATE * 8)) {
		struct thread_info *t = task_thread_info(target);
		unsigned long rwindow[16], fp, *win;
		int wsaved;

		if (target == current)
			flushw_user();

		wsaved = __thread_flag_byte_ptr(t)[TI_FLAG_BYTE_WSAVED];
		fp = regs->u_regs[UREG_FP] + STACK_BIAS;
		if (wsaved && t->rwbuf_stkptrs[wsaved - 1] == fp)
			win = &t->reg_window[wsaved - 1].locals[0];
		else {
			if (target == current) {
				if (copy_from_user(rwindow,
						   (void __user *) fp,
						   16 * sizeof(long)))
					err = -EFAULT;
			} else
				err = access_process_vm(target, fp, rwindow,
							16 * sizeof(long), 0);
			if (err)
				return err;
			win = rwindow;
		}

		err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    win, GENREG_L0 * 8,
					    GENREG_TSTATE * 8);
	}

	if (err == 0)
		err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    &regs->tstate, GENREG_TSTATE * 8,
					    GENREG_Y * 8);
	if (err == 0 && count > 0) {
		if (kbuf)
			*(unsigned long *) kbuf = regs->y;
		else if (put_user(regs->y, (unsigned long __user *) ubuf))
			return -EFAULT;
	}

	return err;
}

/* Consistent with signal handling, we only allow userspace to
 * modify the %asi, %icc, and %xcc fields of the %tstate register.
 */
#define TSTATE_DEBUGCHANGE	(TSTATE_ASI | TSTATE_ICC | TSTATE_XCC)

static int genregs_set(struct task_struct *target,
		       const struct utrace_regset *regset,
		       unsigned int pos, unsigned int count,
		       const void *kbuf, const void __user *ubuf)
{
	struct pt_regs *regs = task_pt_regs(target);
	unsigned long tstate_save;
	int err;

	err = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf, regs->u_regs,
				   GENREG_G0 * 8, GENREG_L0 * 8);

	if (err == 0 && count > 0 && pos < (GENREG_TSTATE * 8)) {
		unsigned long fp = regs->u_regs[UREG_FP] + STACK_BIAS;
		unsigned long rwindow[16], *winbuf;
		unsigned int copy = (GENREG_TSTATE * 8) - pos;
		unsigned int off;
		int err;

		if (target == current)
			flushw_user();

		if (count < copy)
			copy = count;
		off = pos - (GENREG_L0 * 8);

		if (kbuf) {
			winbuf = (unsigned long *) kbuf;
			kbuf += copy;
		}
		else {
			winbuf = rwindow;
			if (copy_from_user(winbuf, ubuf, copy))
				return -EFAULT;
			ubuf += copy;
		}
		count -= copy;
		pos += copy;

		if (target == current)
			err = copy_to_user((void __user *) fp + off,
					   winbuf, copy);
		else
			err = access_process_vm(target, fp + off,
						winbuf, copy, 1);
	}

	tstate_save = regs->tstate &~ TSTATE_DEBUGCHANGE;

	if (err == 0)
		err = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
					    &regs->tstate, GENREG_TSTATE * 8,
					    GENREG_Y * 8);

	regs->tstate &= TSTATE_DEBUGCHANGE;
	regs->tstate |= tstate_save;

	if (err == 0 && count > 0) {
		if (kbuf)
			regs->y = *(unsigned long *) kbuf;
		else if (get_user(regs->y, (unsigned long __user *) ubuf))
			return -EFAULT;
	}

	return err;
}

#define FPREG_F0	0
#define FPREG_FSR	32
#define FPREG_GSR	33
#define FPREG_FPRS	34

#define SPARC64_NFPREGS	35

static int fpregs_get(struct task_struct *target,
		      const struct utrace_regset *regset,
		      unsigned int pos, unsigned int count,
		      void *kbuf, void __user *ubuf)
{
	struct thread_info *t = task_thread_info(target);
	int err;

	err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				    t->fpregs, FPREG_F0 * 8, FPREG_FSR * 8);

	if (err == 0)
		err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    &t->xfsr[0], FPREG_FSR * 8,
					    FPREG_GSR * 8);

	if (err == 0)
		err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    &t->gsr[0], FPREG_GSR * 8,
					    FPREG_FPRS * 8);

	if (err == 0 && count > 0) {
		struct pt_regs *regs = task_pt_regs(target);

		if (kbuf)
			*(unsigned long *) kbuf = regs->fprs;
		else if (put_user(regs->fprs, (unsigned long __user *) ubuf))
			return -EFAULT;
	}

	return err;
}

static int fpregs_set(struct task_struct *target,
		      const struct utrace_regset *regset,
		      unsigned int pos, unsigned int count,
		      const void *kbuf, const void __user *ubuf)
{
	struct thread_info *t = task_thread_info(target);
	int err;

	err = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   t->fpregs, FPREG_F0 * 8, FPREG_FSR * 8);

	if (err == 0)
		err = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
					   &t->xfsr[0], FPREG_FSR * 8,
					   FPREG_GSR * 8);

	if (err == 0)
		err = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
					   &t->gsr[0], FPREG_GSR * 8,
					   FPREG_FPRS * 8);

	if (err == 0 && count > 0) {
		struct pt_regs *regs = task_pt_regs(target);

		if (kbuf)
			regs->fprs = *(unsigned long *) kbuf;
		else if (get_user(regs->fprs, (unsigned long __user *) ubuf))
			return -EFAULT;
	}

	return err;
}

static const struct utrace_regset native_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = SPARC64_NGREGS,
		.size = sizeof(long), .align = sizeof(long),
		.get = genregs_get, .set = genregs_set
	},
	{
		.core_note_type = NT_PRFPREG,
		.n = SPARC64_NFPREGS,
		.size = sizeof(long), .align = sizeof(long),
		.get = fpregs_get, .set = fpregs_set
	},
};

static const struct utrace_regset_view utrace_sparc64_native_view = {
	.name = UTS_MACHINE, .e_machine = ELF_ARCH,
	.regsets = native_regsets, .n = ARRAY_SIZE(native_regsets)
};

#ifdef CONFIG_COMPAT

#define GENREG32_G0	0
#define GENREG32_O0	8
#define GENREG32_L0	16
#define GENREG32_I0	24
#define GENREG32_PSR	32
#define GENREG32_PC	33
#define GENREG32_NPC	34
#define GENREG32_Y	35
#define GENREG32_WIM	36
#define GENREG32_TBR	37

#define SPARC32_NGREGS	38

static int genregs32_get(struct task_struct *target,
			 const struct utrace_regset *regset,
			 unsigned int pos, unsigned int count,
			 void *kbuf, void __user *ubuf)
{
	struct pt_regs *regs = task_pt_regs(target);

	while (count > 0 && pos < (GENREG32_L0 * 4)) {
		u32 val = regs->u_regs[(pos - (GENREG32_G0*4))/sizeof(u32)];
		if (kbuf) {
			*(u32 *) kbuf = val;
			kbuf += sizeof(u32);
		} else if (put_user(val, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos < (GENREG32_PSR * 4)) {
		struct thread_info *t = task_thread_info(target);
		unsigned long fp;
		u32 rwindow[16];
		int wsaved;

		if (target == current)
			flushw_user();

		wsaved = __thread_flag_byte_ptr(t)[TI_FLAG_BYTE_WSAVED];
		fp = regs->u_regs[UREG_FP] & 0xffffffffUL;
		if (wsaved && t->rwbuf_stkptrs[wsaved - 1] == fp) {
			int i;
			for (i = 0; i < 8; i++)
				rwindow[i + 0] =
					t->reg_window[wsaved-1].locals[i];
			for (i = 0; i < 8; i++)
				rwindow[i + 8] =
					t->reg_window[wsaved-1].ins[i];
		} else {
			int err;

			if (target == current) {
				err = 0;
				if (copy_from_user(rwindow, (void __user *) fp,
						   16 * sizeof(u32)))
					err = -EFAULT;
			} else
				err = access_process_vm(target, fp, rwindow,
							16 * sizeof(u32), 0);
			if (err)
				return err;
		}

		while (count > 0 && pos < (GENREG32_PSR * 4)) {
			u32 val = rwindow[(pos - (GENREG32_L0*4))/sizeof(u32)];

			if (kbuf) {
				*(u32 *) kbuf = val;
				kbuf += sizeof(u32);
			} else if (put_user(val, (u32 __user *) ubuf))
				return -EFAULT;
			else
				ubuf += sizeof(u32);
			pos += sizeof(u32);
			count -= sizeof(u32);
		}
	}

	if (count > 0 && pos == (GENREG32_PSR * 4)) {
		u32 psr = tstate_to_psr(regs->tstate);

		if (kbuf) {
			*(u32 *) kbuf = psr;
			kbuf += sizeof(u32);
		} else if (put_user(psr, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos == (GENREG32_PC * 4)) {
		u32 val = regs->tpc;

		if (kbuf) {
			*(u32 *) kbuf = val;
			kbuf += sizeof(u32);
		} else if (put_user(val, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos == (GENREG32_NPC * 4)) {
		u32 val = regs->tnpc;

		if (kbuf) {
			*(u32 *) kbuf = val;
			kbuf += sizeof(u32);
		} else if (put_user(val, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos == (GENREG32_Y * 4)) {
		if (kbuf) {
			*(u32 *) kbuf = regs->y;
			kbuf += sizeof(u32);
		} else if (put_user(regs->y, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0) {
		if (kbuf)
			memset(kbuf, 0, count);
		else if (clear_user(ubuf, count))
			return -EFAULT;
	}

	return 0;
}

static int genregs32_set(struct task_struct *target,
			 const struct utrace_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	struct pt_regs *regs = task_pt_regs(target);

	while (count > 0 && pos < (GENREG32_L0 * 4)) {
		unsigned long *loc;
		loc = &regs->u_regs[(pos - (GENREG32_G0*4))/sizeof(u32)];
		if (kbuf) {
			*loc = *(u32 *) kbuf;
			kbuf += sizeof(u32);
		} else if (get_user(*loc, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos < (GENREG32_PSR * 4)) {
		unsigned long fp;
		u32 regbuf[16];
		unsigned int off, copy;
		int err;

		if (target == current)
			flushw_user();

		copy = (GENREG32_PSR * 4) - pos;
		if (count < copy)
			copy = count;
		BUG_ON(copy > 16 * sizeof(u32));

		fp = regs->u_regs[UREG_FP] & 0xffffffffUL;
		off = pos - (GENREG32_L0 * 4);
		if (kbuf) {
			memcpy(regbuf, kbuf, copy);
			kbuf += copy;
		} else if (copy_from_user(regbuf, ubuf, copy))
			return -EFAULT;
		else
			ubuf += copy;
		pos += copy;
		count -= copy;

		if (target == current) {
			err = 0;
			if (copy_to_user((void __user *) fp + off,
					 regbuf, count))
				err = -EFAULT;
		} else
			err = access_process_vm(target, fp + off,
						regbuf, count, 1);
		if (err)
			return err;
	}

	if (count > 0 && pos == (GENREG32_PSR * 4)) {
		unsigned long tstate, tstate_save;
		u32 psr;

		tstate_save = regs->tstate&~(TSTATE_ICC|TSTATE_XCC);

		if (kbuf) {
			psr = *(u32 *) kbuf;
			kbuf += sizeof(u32);
		} else if (get_user(psr, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);

		tstate = psr_to_tstate_icc(psr);
		regs->tstate = tstate_save | tstate;
	}

	if (count > 0 && pos == (GENREG32_PC * 4)) {
		if (kbuf) {
			regs->tpc = *(u32 *) kbuf;
			kbuf += sizeof(u32);
		} else if (get_user(regs->tpc, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos == (GENREG32_NPC * 4)) {
		if (kbuf) {
			regs->tnpc = *(u32 *) kbuf;
			kbuf += sizeof(u32);
		} else if (get_user(regs->tnpc, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	if (count > 0 && pos == (GENREG32_Y * 4)) {
		if (kbuf) {
			regs->y = *(u32 *) kbuf;
			kbuf += sizeof(u32);
		} else if (get_user(regs->y, (u32 __user *) ubuf))
			return -EFAULT;
		else
			ubuf += sizeof(u32);
		pos += sizeof(u32);
		count -= sizeof(u32);
	}

	/* Ignore WIM and TBR */

	return 0;
}

#define FPREG32_F0	0
#define FPREG32_FSR	32

#define SPARC32_NFPREGS	33

static int fpregs32_get(struct task_struct *target,
			const struct utrace_regset *regset,
			unsigned int pos, unsigned int count,
			void *kbuf, void __user *ubuf)
{
	struct thread_info *t = task_thread_info(target);
	int err;

	err = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
				    t->fpregs, FPREG32_F0 * 4,
				    FPREG32_FSR * 4);

	if (err == 0 && count > 0) {
		if (kbuf) {
			*(u32 *) kbuf = t->xfsr[0];
		} else if (put_user(t->xfsr[0], (u32 __user *) ubuf))
			return -EFAULT;
	}

	return err;
}

static int fpregs32_set(struct task_struct *target,
			const struct utrace_regset *regset,
			unsigned int pos, unsigned int count,
			const void *kbuf, const void __user *ubuf)
{
	struct thread_info *t = task_thread_info(target);
	int err;

	err = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   t->fpregs, FPREG32_F0 * 4,
				   FPREG32_FSR * 4);

	if (err == 0 && count > 0) {
		u32 fsr;
		if (kbuf) {
			fsr = *(u32 *) kbuf;
		} else if (get_user(fsr, (u32 __user *) ubuf))
			return -EFAULT;
		t->xfsr[0] = (t->xfsr[0] & 0xffffffff00000000UL) | fsr;
	}

	return 0;
}

static const struct utrace_regset sparc32_regsets[] = {
	{
		.core_note_type = NT_PRSTATUS,
		.n = SPARC32_NGREGS,
		.size = sizeof(u32), .align = sizeof(u32),
		.get = genregs32_get, .set = genregs32_set
	},
	{
		.core_note_type = NT_PRFPREG,
		.n = SPARC32_NFPREGS,
		.size = sizeof(u32), .align = sizeof(u32),
		.get = fpregs32_get, .set = fpregs32_set
	},
};

static const struct utrace_regset_view utrace_sparc32_view = {
	.name = "sparc", .e_machine = EM_SPARC,
	.regsets = sparc32_regsets, .n = ARRAY_SIZE(sparc32_regsets)
};

#endif	/* CONFIG_COMPAT */

const struct utrace_regset_view *utrace_native_view(struct task_struct *tsk)
{
#ifdef CONFIG_COMPAT
	if (test_tsk_thread_flag(tsk, TIF_32BIT))
		return &utrace_sparc32_view;
#endif
	return &utrace_sparc64_native_view;
}


/* To get the necessary page struct, access_process_vm() first calls
 * get_user_pages().  This has done a flush_dcache_page() on the
 * accessed page.  Then our caller (copy_{to,from}_user_page()) did
 * to memcpy to read/write the data from that page.
 *
 * Now, the only thing we have to do is:
 * 1) flush the D-cache if it's possible than an illegal alias
 *    has been created
 * 2) flush the I-cache if this is pre-cheetah and we did a write
 */
void flush_ptrace_access(struct vm_area_struct *vma, struct page *page,
			 unsigned long uaddr, void *kaddr,
			 unsigned long len, int write)
{
	BUG_ON(len > PAGE_SIZE);

	if (tlb_type == hypervisor)
		return;

#ifdef DCACHE_ALIASING_POSSIBLE
	/* If bit 13 of the kernel address we used to access the
	 * user page is the same as the virtual address that page
	 * is mapped to in the user's address space, we can skip the
	 * D-cache flush.
	 */
	if ((uaddr ^ (unsigned long) kaddr) & (1UL << 13)) {
		unsigned long start = __pa(kaddr);
		unsigned long end = start + len;
		unsigned long dcache_line_size;

		dcache_line_size = local_cpu_data().dcache_line_size;

		if (tlb_type == spitfire) {
			for (; start < end; start += dcache_line_size)
				spitfire_put_dcache_tag(start & 0x3fe0, 0x0);
		} else {
			start &= ~(dcache_line_size - 1);
			for (; start < end; start += dcache_line_size)
				__asm__ __volatile__(
					"stxa %%g0, [%0] %1\n\t"
					"membar #Sync"
					: /* no outputs */
					: "r" (start),
					"i" (ASI_DCACHE_INVALIDATE));
		}
	}
#endif
	if (write && tlb_type == spitfire) {
		unsigned long start = (unsigned long) kaddr;
		unsigned long end = start + len;
		unsigned long icache_line_size;

		icache_line_size = local_cpu_data().icache_line_size;

		for (; start < end; start += icache_line_size)
			flushi(start);
	}
}

#ifdef CONFIG_PTRACE
static const struct ptrace_layout_segment sparc64_getregs_layout[] = {
	{ 0, offsetof(struct pt_regs, u_regs[15]), 0, sizeof(long) },
	{ offsetof(struct pt_regs, u_regs[15]),
	  offsetof(struct pt_regs, tstate),
	  -1, 0 },
	{ offsetof(struct pt_regs, tstate), offsetof(struct pt_regs, y),
	  0, 32 * sizeof(long) },
	{0, 0, -1, 0}
};

int arch_ptrace(long *request, struct task_struct *child,
		struct utrace_attached_engine *engine,
		unsigned long addr, unsigned long data,
		long *retval)
{
	void __user *uaddr = (void __user *) addr;
	struct pt_regs *uregs = uaddr;
	int err = -ENOSYS;

	switch (*request) {
	case PTRACE_GETREGS64:
		err = ptrace_layout_access(child, engine,
					   &utrace_sparc64_native_view,
					   sparc64_getregs_layout,
					   0, offsetof(struct pt_regs, y),
					   uaddr, NULL, 0);
		if (!err &&
		    (put_user(task_pt_regs(child)->y, &uregs->y) ||
		     put_user(task_pt_regs(child)->fprs, &uregs->fprs)))
			err = -EFAULT;
		break;

	case PTRACE_SETREGS64:
		err = ptrace_layout_access(child, engine,
					   &utrace_sparc64_native_view,
					   sparc64_getregs_layout,
					   0, offsetof(struct pt_regs, y),
					   uaddr, NULL, 1);
		if (!err &&
		    (get_user(task_pt_regs(child)->y, &uregs->y) ||
		     get_user(task_pt_regs(child)->fprs, &uregs->fprs)))
			err = -EFAULT;
		break;

	case PTRACE_GETFPREGS64:
	case PTRACE_SETFPREGS64:
		err = ptrace_regset_access(child, engine,
					   utrace_native_view(current),
					   2, 0, 34 * sizeof(long), uaddr,
					   (*request == PTRACE_SETFPREGS64));
		break;

	case PTRACE_SUNDETACH:
		*request = PTRACE_DETACH;
		break;
		       
	default:
		break;
	};
	return err;
}

#ifdef CONFIG_COMPAT
static const struct ptrace_layout_segment sparc32_getregs_layout[] = {
	{ 0, offsetof(struct pt_regs32, u_regs[0]),
	  0, GENREG32_PSR * sizeof(u32) },
	{ offsetof(struct pt_regs32, u_regs[0]),
	  offsetof(struct pt_regs32, u_regs[15]),
	  0, 1 * sizeof(u32) },
	{ offsetof(struct pt_regs32, u_regs[15]), sizeof(struct pt_regs32),
	  -1, 0 },
	{0, 0, -1, 0}
};

int arch_compat_ptrace(compat_long_t *request, struct task_struct *child,
		       struct utrace_attached_engine *engine,
		       compat_ulong_t addr, compat_ulong_t data,
		       compat_long_t *retval)
{
	void __user *uaddr = (void __user *) (unsigned long) addr;
	int err = -ENOSYS;

	switch (*request) {
	case PTRACE_GETREGS:
	case PTRACE_SETREGS:
		err = ptrace_layout_access(child, engine,
					   &utrace_sparc32_view,
					   sparc32_getregs_layout,
					   0, sizeof(struct pt_regs32),
					   uaddr, NULL,
					   (*request ==
					    PTRACE_SETREGS));
		break;

	case PTRACE_GETFPREGS:
	case PTRACE_SETFPREGS:
		err = ptrace_whole_regset(child, engine, addr, 1,
					  (*request == PTRACE_SETFPREGS));
		break;

	case PTRACE_SUNDETACH:
		*request = PTRACE_DETACH;
		break;

	default:
		break;
	};
	return err;
}
#endif	/* CONFIG_COMPAT */
#endif /* CONFIG_PTRACE */

asmlinkage void syscall_trace(struct pt_regs *regs, int syscall_exit_p)
{
	/* do the secure computing check first */
	if (!syscall_exit_p)
		secure_computing(regs->u_regs[UREG_G1]);

	if (unlikely(current->audit_context) && syscall_exit_p) {
		unsigned long tstate = regs->tstate;
		int result = AUDITSC_SUCCESS;

		if (unlikely(tstate & (TSTATE_XCARRY | TSTATE_ICARRY)))
			result = AUDITSC_FAILURE;

		audit_syscall_exit(result, regs->u_regs[UREG_I0]);
	}

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(regs, syscall_exit_p);

	if (unlikely(current->audit_context) && !syscall_exit_p)
		audit_syscall_entry((test_thread_flag(TIF_32BIT) ?
				     AUDIT_ARCH_SPARC :
				     AUDIT_ARCH_SPARC64),
				    regs->u_regs[UREG_G1],
				    regs->u_regs[UREG_I0],
				    regs->u_regs[UREG_I1],
				    regs->u_regs[UREG_I2],
				    regs->u_regs[UREG_I3]);
}
