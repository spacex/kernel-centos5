/* 
 * 32bit ptrace for x86-64.
 *
 * Copyright 2001,2002 Andi Kleen, SuSE Labs.
 * Some parts copied from arch/i386/kernel/ptrace.c. See that file for earlier 
 * copyright.
 * 
 * This allows to access 64bit processes too; but there is no way to see the extended 
 * register contents.
 */ 

#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/module.h>
#include <linux/elf.h>
#include <asm/ptrace.h>
#include <asm/tracehook.h>
#include <asm/compat.h>
#include <asm/uaccess.h>
#include <asm/user32.h>
#include <asm/user.h>
#include <asm/errno.h>
#include <asm/debugreg.h>
#include <asm/i387.h>
#include <asm/fpu32.h>
#include <asm/ldt.h>
#include <asm/desc.h>

/*
 * Determines which flags the user has access to [1 = access, 0 = no access].
 * Prohibits changing ID(21), VIP(20), VIF(19), VM(17), IOPL(12-13), IF(9).
 * Also masks reserved bits (31-22, 15, 5, 3, 1).
 */
#define FLAG_MASK 0x54dd5UL

#define R32(l,q) \
	case offsetof(struct user_regs_struct32, l): stack[offsetof(struct pt_regs, q)/8] = val; break

static int putreg32(struct task_struct *child, unsigned regno, u32 val)
{
	__u64 *stack = (__u64 *)task_pt_regs(child);

	switch (regno) {
	case offsetof(struct user_regs_struct32, fs):
		if (val && (val & 3) != 3) return -EIO; 
		child->thread.fsindex = val & 0xffff;
		break;
	case offsetof(struct user_regs_struct32, gs):
		if (val && (val & 3) != 3) return -EIO; 
		child->thread.gsindex = val & 0xffff;
		break;
	case offsetof(struct user_regs_struct32, ds):
		if (val && (val & 3) != 3) return -EIO; 
		child->thread.ds = val & 0xffff;
		break;
	case offsetof(struct user_regs_struct32, es):
		child->thread.es = val & 0xffff;
		break;
	case offsetof(struct user_regs_struct32, ss):
		if ((val & 3) != 3) return -EIO;
        	stack[offsetof(struct pt_regs, ss)/8] = val & 0xffff;
		break;
	case offsetof(struct user_regs_struct32, cs):
		if ((val & 3) != 3) return -EIO;
		stack[offsetof(struct pt_regs, cs)/8] = val & 0xffff;
		break;

	R32(ebx, rbx); 
	R32(ecx, rcx);
	R32(edx, rdx);
	R32(edi, rdi);
	R32(esi, rsi);
	R32(ebp, rbp);
	R32(eax, rax);
	R32(orig_eax, orig_rax);
	R32(eip, rip);
	R32(esp, rsp);

	case offsetof(struct user_regs_struct32, eflags): {
		__u64 *flags = &stack[offsetof(struct pt_regs, eflags)/8];
		val &= FLAG_MASK;
		*flags = val | (*flags & ~FLAG_MASK);
		clear_tsk_thread_flag(child, TIF_FORCED_TF);
		break;
	}

	default:
		BUG();
	}
	return 0;
}

#undef R32

#define R32(l,q) \
	case offsetof(struct user_regs_struct32, l): val = stack[offsetof(struct pt_regs, q)/8]; break

static int getreg32(struct task_struct *child, unsigned regno)
{
	__u64 *stack = (__u64 *)task_pt_regs(child);
	u32 val;

	switch (regno) {
	case offsetof(struct user_regs_struct32, fs):
	        val = child->thread.fsindex;
		break;
	case offsetof(struct user_regs_struct32, gs):
		val = child->thread.gsindex;
		break;
	case offsetof(struct user_regs_struct32, ds):
		val = child->thread.ds;
		break;
	case offsetof(struct user_regs_struct32, es):
		val = child->thread.es;
		break;

	R32(cs, cs);
	R32(ss, ss);
	R32(ebx, rbx); 
	R32(ecx, rcx);
	R32(edx, rdx);
	R32(edi, rdi);
	R32(esi, rsi);
	R32(ebp, rbp);
	R32(eax, rax);
	R32(orig_eax, orig_rax);
	R32(eip, rip);
	R32(esp, rsp);

	case offsetof(struct user_regs_struct32, eflags):
		val = stack[offsetof(struct pt_regs, eflags) / 8];
		if (test_tsk_thread_flag(child, TIF_FORCED_TF))
			val &= ~X86_EFLAGS_TF;
		break; 
		    
	default:
		BUG();
		val = -1;
		break; 		
	}

	return val;
}

#undef R32

static int
ia32_genregs_get(struct task_struct *target,
		 const struct utrace_regset *regset,
		 unsigned int pos, unsigned int count,
		 void *kbuf, void __user *ubuf)
{
	if (kbuf) {
		u32 *kp = kbuf;
		while (count > 0) {
			*kp++ = getreg32(target, pos);
			pos += 4;
			count -= 4;
		}
	}
	else {
		u32 __user *up = ubuf;
		while (count > 0) {
			if (__put_user(getreg32(target, pos), up++))
				return -EFAULT;
			pos += 4;
			count -= 4;
		}
	}

	return 0;
}

static int
ia32_genregs_set(struct task_struct *target,
		 const struct utrace_regset *regset,
		 unsigned int pos, unsigned int count,
		 const void *kbuf, const void __user *ubuf)
{
	int ret = 0;

	if (kbuf) {
		const u32 *kp = kbuf;
		while (!ret && count > 0) {
			ret = putreg32(target, pos, *kp++);
			pos += 4;
			count -= 4;
		}
	}
	else {
		int ret = 0;
		const u32 __user *up = ubuf;
		while (!ret && count > 0) {
			u32 val;
			ret = __get_user(val, up++);
			if (!ret)
				ret = putreg32(target, pos, val);
			pos += 4;
			count -= 4;
		}
	}

	return ret;
}

static int
ia32_fpregs_active(struct task_struct *target,
		   const struct utrace_regset *regset)
{
	return tsk_used_math(target) ? regset->n : 0;
}

static int
ia32_fpregs_get(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		void *kbuf, void __user *ubuf)
{
	struct user_i387_ia32_struct fp;
	int ret;

	if (tsk_used_math(target)) {
		if (target == current)
			unlazy_fpu(target);
	}
	else
		init_fpu(target);

	ret = get_fpregs32(&fp, target);
	if (ret == 0)
		ret = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    &fp, 0, -1);

	return ret;
}

static int
ia32_fpregs_set(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		const void *kbuf, const void __user *ubuf)
{
	struct user_i387_ia32_struct fp;
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
		ret = get_fpregs32(&fp, target);
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

	return set_fpregs32(target, kbuf);
}

static int
ia32_fpxregs_active(struct task_struct *target,
		    const struct utrace_regset *regset)
{
	return tsk_used_math(target) ? regset->n : 0;
}

static int
ia32_fpxregs_get(struct task_struct *target,
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
ia32_fpxregs_set(struct task_struct *target,
		 const struct utrace_regset *regset,
		 unsigned int pos, unsigned int count,
		 const void *kbuf, const void __user *ubuf)

{
	int ret;

	if (tsk_used_math(target)) {
		if (target == current)
			unlazy_fpu(target);
	}
	else if (pos == 0 && count == sizeof(struct i387_fxsave_struct))
		set_stopped_child_used_math(target);
	else
		init_fpu(target);

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   &target->thread.i387.fxsave, 0, -1);

	target->thread.i387.fxsave.mxcsr &= mxcsr_feature_mask;

	return ret;
}

static int
ia32_dbregs_active(struct task_struct *tsk, const struct utrace_regset *regset)
{
	if (tsk->thread.debugreg6 | tsk->thread.debugreg7)
		return 8;
	return 0;
}

static int
ia32_dbregs_get(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		void *kbuf, void __user *ubuf)
{
	for (pos >>= 2, count >>= 2; count > 0; --count, ++pos) {
		u32 val;

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
			*(u32 *) kbuf = val;
			kbuf += sizeof(u32);
		}
		else {
			if (__put_user(val, (u32 __user *) ubuf))
				return -EFAULT;
			ubuf += sizeof(u32);
		}
	}

	return 0;
}

static int
ia32_dbregs_set(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		const void *kbuf, const void __user *ubuf)
{
	/*
	 * We'll just hijack the native setter to do the real work for us.
	 */
	const struct utrace_regset *dbregset = &utrace_x86_64_native.regsets[2];

	int ret = 0;

	for (pos >>= 2, count >>= 2; count > 0; --count, ++pos) {
		unsigned long val;

		if (kbuf) {
			val = *(const u32 *) kbuf;
			kbuf += sizeof(u32);
		}
		else {
			if (__get_user(val, (u32 __user *) ubuf))
				return -EFAULT;
			ubuf += sizeof(u32);
		}

		ret = (*dbregset->set)(target, dbregset, pos * sizeof(long),
				       sizeof(val), &val, NULL);
		if (ret)
			break;
	}

	return ret;
}


/*
 * Perform get_thread_area on behalf of the traced child.
 */
static int
ia32_tls_get(struct task_struct *target,
	     const struct utrace_regset *regset,
	     unsigned int pos, unsigned int count,
	     void *kbuf,  void __user *ubuf)
{
	struct user_desc info, *ip;
	const struct n_desc_struct *desc;
	const struct n_desc_struct *tls;

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

	tls = (struct n_desc_struct *) target->thread.tls_array;
	desc = &tls[pos];
	ip = kbuf ?: &info;
	memset(ip, 0, sizeof *ip);
	for (; count > 0; count -= sizeof(struct user_desc), ++desc) {
		ip->entry_number = desc - tls + GDT_ENTRY_TLS_MIN;
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
ia32_tls_set(struct task_struct *target,
	     const struct utrace_regset *regset,
	     unsigned int pos, unsigned int count,
	     const void *kbuf, const void __user *ubuf)
{
	struct user_desc info;
	struct n_desc_struct *desc;
	struct n_desc_struct newtls[GDT_ENTRY_TLS_ENTRIES];
	unsigned int i;
	int cpu;

	pos /= sizeof(struct user_desc);
	count /= sizeof(struct user_desc);

	desc = &newtls[pos];
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
ia32_tls_active(struct task_struct *target, const struct utrace_regset *regset)
{
	int i;
	for (i = GDT_ENTRY_TLS_ENTRIES; i > 0; --i) {
		struct n_desc_struct *desc = (struct n_desc_struct *)
			&target->thread.tls_array[i - 1];
		if ((desc->a | desc->b) != 0)
			break;
	}
	return i;
}


/*
 * This should match arch/i386/kernel/ptrace.c:native_regsets.
 * XXX ioperm? vm86?
 */
static const struct utrace_regset ia32_regsets[] = {
	{
		.n = sizeof(struct user_regs_struct32)/4,
		.size = 4, .align = 4,
		.get = ia32_genregs_get, .set = ia32_genregs_set
	},
	{
		.n = sizeof(struct user_i387_ia32_struct) / 4,
		.size = 4, .align = 4,
		.active = ia32_fpregs_active,
		.get = ia32_fpregs_get, .set = ia32_fpregs_set
	},
	{
		.n = sizeof(struct user32_fxsr_struct) / 4,
		.size = 4, .align = 4,
		.active = ia32_fpxregs_active,
		.get = ia32_fpxregs_get, .set = ia32_fpxregs_set
	},
	{
		.n = GDT_ENTRY_TLS_ENTRIES,
		.bias = GDT_ENTRY_TLS_MIN,
		.size = sizeof(struct user_desc),
		.align = sizeof(struct user_desc),
		.active = ia32_tls_active,
		.get = ia32_tls_get, .set = ia32_tls_set
	},
	{
		.n = 8, .size = 4, .align = 4,
		.active = ia32_dbregs_active,
		.get = ia32_dbregs_get, .set = ia32_dbregs_set
	},
};

const struct utrace_regset_view utrace_ia32_view = {
	.name = "i386", .e_machine = EM_386,
	.regsets = ia32_regsets,
	.n = sizeof ia32_regsets / sizeof ia32_regsets[0],
};
EXPORT_SYMBOL_GPL(utrace_ia32_view);


#ifdef CONFIG_PTRACE
/*
 * This matches the arch/i386/kernel/ptrace.c definitions.
 */

static const struct ptrace_layout_segment ia32_uarea[] = {
	{0, sizeof(struct user_regs_struct32), 0, 0},
	{offsetof(struct user32, u_debugreg[0]),
	 offsetof(struct user32, u_debugreg[8]), 4, 0},
	{0, 0, -1, 0}
};

fastcall int arch_compat_ptrace(compat_long_t *req, struct task_struct *child,
				struct utrace_attached_engine *engine,
				compat_ulong_t addr, compat_ulong_t data,
				compat_long_t *val)
{
	switch (*req) {
	case PTRACE_PEEKUSR:
		return ptrace_compat_peekusr(child, engine, ia32_uarea,
					     addr, data);
	case PTRACE_POKEUSR:
		return ptrace_compat_pokeusr(child, engine, ia32_uarea,
					     addr, data);
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
					    &utrace_ia32_view, 3,
					    addr,
					    (void __user *)(unsigned long)data,
					    *req == PTRACE_SET_THREAD_AREA);
	}
	return -ENOSYS;
}
#endif	/* CONFIG_PTRACE */
