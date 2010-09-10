/*
 * Kernel support for the ptrace() and syscall tracing interfaces.
 *
 * Copyright (C) 1999-2005 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 * Copyright (C) 2006 Intel Co
 *  2006-08-12	- IA64 Native Utrace implementation support added by
 *	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *
 * Derived from the x86 and Alpha versions.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/tracehook.h>
#include <linux/smp_lock.h>
#include <linux/user.h>
#include <linux/security.h>
#include <linux/audit.h>
#include <linux/signal.h>
#include <linux/module.h>

#include <asm/tracehook.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/ptrace_offsets.h>
#include <asm/rse.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/elf.h>
#include <asm/unwind.h>
#ifdef CONFIG_PERFMON
#include <asm/perfmon.h>
#endif

#include "entry.h"

/*
 * Bits in the PSR that we allow ptrace() to change:
 *	be, up, ac, mfl, mfh (the user mask; five bits total)
 *	db (debug breakpoint fault; one bit)
 *	id (instruction debug fault disable; one bit)
 *	dd (data debug fault disable; one bit)
 *	ri (restart instruction; two bits)
 *	is (instruction set; one bit)
 */
#define IPSR_MASK (IA64_PSR_UM | IA64_PSR_DB | IA64_PSR_IS	\
		   | IA64_PSR_ID | IA64_PSR_DD | IA64_PSR_RI)

#define MASK(nbits)	((1UL << (nbits)) - 1)	/* mask with NBITS bits set */
#define PFM_MASK	MASK(38)

#define PTRACE_DEBUG	0

#if PTRACE_DEBUG
# define dprintk(format...)	printk(format)
# define inline
#else
# define dprintk(format...)
#endif

/* Return TRUE if PT was created due to kernel-entry via a system-call.  */

static inline int
in_syscall (struct pt_regs *pt)
{
	return (long) pt->cr_ifs >= 0;
}

/*
 * Collect the NaT bits for r1-r31 from scratch_unat and return a NaT
 * bitset where bit i is set iff the NaT bit of register i is set.
 */
unsigned long
ia64_get_scratch_nat_bits (struct pt_regs *pt, unsigned long scratch_unat)
{
#	define GET_BITS(first, last, unat)				\
	({								\
		unsigned long bit = ia64_unat_pos(&pt->r##first);	\
		unsigned long nbits = (last - first + 1);		\
		unsigned long mask = MASK(nbits) << first;		\
		unsigned long dist;					\
		if (bit < first)					\
			dist = 64 + bit - first;			\
		else							\
			dist = bit - first;				\
		ia64_rotr(unat, dist) & mask;				\
	})
	unsigned long val;

	/*
	 * Registers that are stored consecutively in struct pt_regs
	 * can be handled in parallel.  If the register order in
	 * struct_pt_regs changes, this code MUST be updated.
	 */
	val  = GET_BITS( 1,  1, scratch_unat);
	val |= GET_BITS( 2,  3, scratch_unat);
	val |= GET_BITS(12, 13, scratch_unat);
	val |= GET_BITS(14, 14, scratch_unat);
	val |= GET_BITS(15, 15, scratch_unat);
	val |= GET_BITS( 8, 11, scratch_unat);
	val |= GET_BITS(16, 31, scratch_unat);
	return val;

#	undef GET_BITS
}

/*
 * Set the NaT bits for the scratch registers according to NAT and
 * return the resulting unat (assuming the scratch registers are
 * stored in PT).
 */
unsigned long
ia64_put_scratch_nat_bits (struct pt_regs *pt, unsigned long nat)
{
#	define PUT_BITS(first, last, nat)				\
	({								\
		unsigned long bit = ia64_unat_pos(&pt->r##first);	\
		unsigned long nbits = (last - first + 1);		\
		unsigned long mask = MASK(nbits) << first;		\
		long dist;						\
		if (bit < first)					\
			dist = 64 + bit - first;			\
		else							\
			dist = bit - first;				\
		ia64_rotl(nat & mask, dist);				\
	})
	unsigned long scratch_unat;

	/*
	 * Registers that are stored consecutively in struct pt_regs
	 * can be handled in parallel.  If the register order in
	 * struct_pt_regs changes, this code MUST be updated.
	 */
	scratch_unat  = PUT_BITS( 1,  1, nat);
	scratch_unat |= PUT_BITS( 2,  3, nat);
	scratch_unat |= PUT_BITS(12, 13, nat);
	scratch_unat |= PUT_BITS(14, 14, nat);
	scratch_unat |= PUT_BITS(15, 15, nat);
	scratch_unat |= PUT_BITS( 8, 11, nat);
	scratch_unat |= PUT_BITS(16, 31, nat);

	return scratch_unat;

#	undef PUT_BITS
}

#define IA64_MLX_TEMPLATE	0x2
#define IA64_MOVL_OPCODE	6

void
ia64_increment_ip (struct pt_regs *regs)
{
	unsigned long w0, ri = ia64_psr(regs)->ri + 1;

	if (ri > 2) {
		ri = 0;
		regs->cr_iip += 16;
	} else if (ri == 2) {
		get_user(w0, (char __user *) regs->cr_iip + 0);
		if (((w0 >> 1) & 0xf) == IA64_MLX_TEMPLATE) {
			/*
			 * rfi'ing to slot 2 of an MLX bundle causes
			 * an illegal operation fault.  We don't want
			 * that to happen...
			 */
			ri = 0;
			regs->cr_iip += 16;
		}
	}
	ia64_psr(regs)->ri = ri;
}

void
ia64_decrement_ip (struct pt_regs *regs)
{
	unsigned long w0, ri = ia64_psr(regs)->ri - 1;

	if (ia64_psr(regs)->ri == 0) {
		regs->cr_iip -= 16;
		ri = 2;
		get_user(w0, (char __user *) regs->cr_iip + 0);
		if (((w0 >> 1) & 0xf) == IA64_MLX_TEMPLATE) {
			/*
			 * rfi'ing to slot 2 of an MLX bundle causes
			 * an illegal operation fault.  We don't want
			 * that to happen...
			 */
			ri = 1;
		}
	}
	ia64_psr(regs)->ri = ri;
}

/*
 * This routine is used to read an rnat bits that are stored on the
 * kernel backing store.  Since, in general, the alignment of the user
 * and kernel are different, this is not completely trivial.  In
 * essence, we need to construct the user RNAT based on up to two
 * kernel RNAT values and/or the RNAT value saved in the child's
 * pt_regs.
 *
 * user rbs
 *
 * +--------+ <-- lowest address
 * | slot62 |
 * +--------+
 * |  rnat  | 0x....1f8
 * +--------+
 * | slot00 | \
 * +--------+ |
 * | slot01 | > child_regs->ar_rnat
 * +--------+ |
 * | slot02 | /				kernel rbs
 * +--------+				+--------+
 *	    <- child_regs->ar_bspstore	| slot61 | <-- krbs
 * +- - - - +				+--------+
 *					| slot62 |
 * +- - - - +				+--------+
 *					|  rnat	 |
 * +- - - - +				+--------+
 *   vrnat				| slot00 |
 * +- - - - +				+--------+
 *					=	 =
 *					+--------+
 *					| slot00 | \
 *					+--------+ |
 *					| slot01 | > child_stack->ar_rnat
 *					+--------+ |
 *					| slot02 | /
 *					+--------+
 *						  <--- child_stack->ar_bspstore
 *
 * The way to think of this code is as follows: bit 0 in the user rnat
 * corresponds to some bit N (0 <= N <= 62) in one of the kernel rnat
 * value.  The kernel rnat value holding this bit is stored in
 * variable rnat0.  rnat1 is loaded with the kernel rnat value that
 * form the upper bits of the user rnat value.
 *
 * Boundary cases:
 *
 * o when reading the rnat "below" the first rnat slot on the kernel
 *   backing store, rnat0/rnat1 are set to 0 and the low order bits are
 *   merged in from pt->ar_rnat.
 *
 * o when reading the rnat "above" the last rnat slot on the kernel
 *   backing store, rnat0/rnat1 gets its value from sw->ar_rnat.
 */
static unsigned long
get_rnat (struct task_struct *task, struct switch_stack *sw,
	  unsigned long *krbs, unsigned long *urnat_addr,
	  unsigned long *urbs_end)
{
	unsigned long rnat0 = 0, rnat1 = 0, urnat = 0, *slot0_kaddr;
	unsigned long umask = 0, mask, m;
	unsigned long *kbsp, *ubspstore, *rnat0_kaddr, *rnat1_kaddr, shift;
	long num_regs, nbits;
	struct pt_regs *pt;

	pt = task_pt_regs(task);
	kbsp = (unsigned long *) sw->ar_bspstore;
	ubspstore = (unsigned long *) pt->ar_bspstore;

	if (urbs_end < urnat_addr)
		nbits = ia64_rse_num_regs(urnat_addr - 63, urbs_end);
	else
		nbits = 63;
	mask = MASK(nbits);
	/*
	 * First, figure out which bit number slot 0 in user-land maps
	 * to in the kernel rnat.  Do this by figuring out how many
	 * register slots we're beyond the user's backingstore and
	 * then computing the equivalent address in kernel space.
	 */
	num_regs = ia64_rse_num_regs(ubspstore, urnat_addr + 1);
	slot0_kaddr = ia64_rse_skip_regs(krbs, num_regs);
	shift = ia64_rse_slot_num(slot0_kaddr);
	rnat1_kaddr = ia64_rse_rnat_addr(slot0_kaddr);
	rnat0_kaddr = rnat1_kaddr - 64;

	if (ubspstore + 63 > urnat_addr) {
		/* some bits need to be merged in from pt->ar_rnat */
		umask = MASK(ia64_rse_slot_num(ubspstore)) & mask;
		urnat = (pt->ar_rnat & umask);
		mask &= ~umask;
		if (!mask)
			return urnat;
	}

	m = mask << shift;
	if (rnat0_kaddr >= kbsp)
		rnat0 = sw->ar_rnat;
	else if (rnat0_kaddr > krbs)
		rnat0 = *rnat0_kaddr;
	urnat |= (rnat0 & m) >> shift;

	m = mask >> (63 - shift);
	if (rnat1_kaddr >= kbsp)
		rnat1 = sw->ar_rnat;
	else if (rnat1_kaddr > krbs)
		rnat1 = *rnat1_kaddr;
	urnat |= (rnat1 & m) << (63 - shift);
	return urnat;
}

/*
 * The reverse of get_rnat.
 */
static void
put_rnat (struct task_struct *task, struct switch_stack *sw,
	  unsigned long *krbs, unsigned long *urnat_addr, unsigned long urnat,
	  unsigned long *urbs_end)
{
	unsigned long rnat0 = 0, rnat1 = 0, *slot0_kaddr, umask = 0, mask, m;
	unsigned long *kbsp, *ubspstore, *rnat0_kaddr, *rnat1_kaddr, shift;
	long num_regs, nbits;
	struct pt_regs *pt;
	unsigned long cfm, *urbs_kargs;

	pt = task_pt_regs(task);
	kbsp = (unsigned long *) sw->ar_bspstore;
	ubspstore = (unsigned long *) pt->ar_bspstore;

	urbs_kargs = urbs_end;
	if (in_syscall(pt)) {
		/*
		 * If entered via syscall, don't allow user to set rnat bits
		 * for syscall args.
		 */
		cfm = pt->cr_ifs;
		urbs_kargs = ia64_rse_skip_regs(urbs_end, -(cfm & 0x7f));
	}

	if (urbs_kargs >= urnat_addr)
		nbits = 63;
	else {
		if ((urnat_addr - 63) >= urbs_kargs)
			return;
		nbits = ia64_rse_num_regs(urnat_addr - 63, urbs_kargs);
	}
	mask = MASK(nbits);

	/*
	 * First, figure out which bit number slot 0 in user-land maps
	 * to in the kernel rnat.  Do this by figuring out how many
	 * register slots we're beyond the user's backingstore and
	 * then computing the equivalent address in kernel space.
	 */
	num_regs = ia64_rse_num_regs(ubspstore, urnat_addr + 1);
	slot0_kaddr = ia64_rse_skip_regs(krbs, num_regs);
	shift = ia64_rse_slot_num(slot0_kaddr);
	rnat1_kaddr = ia64_rse_rnat_addr(slot0_kaddr);
	rnat0_kaddr = rnat1_kaddr - 64;

	if (ubspstore + 63 > urnat_addr) {
		/* some bits need to be place in pt->ar_rnat: */
		umask = MASK(ia64_rse_slot_num(ubspstore)) & mask;
		pt->ar_rnat = (pt->ar_rnat & ~umask) | (urnat & umask);
		mask &= ~umask;
		if (!mask)
			return;
	}
	/*
	 * Note: Section 11.1 of the EAS guarantees that bit 63 of an
	 * rnat slot is ignored. so we don't have to clear it here.
	 */
	rnat0 = (urnat << shift);
	m = mask << shift;
	if (rnat0_kaddr >= kbsp)
		sw->ar_rnat = (sw->ar_rnat & ~m) | (rnat0 & m);
	else if (rnat0_kaddr > krbs)
		*rnat0_kaddr = ((*rnat0_kaddr & ~m) | (rnat0 & m));

	rnat1 = (urnat >> (63 - shift));
	m = mask >> (63 - shift);
	if (rnat1_kaddr >= kbsp)
		sw->ar_rnat = (sw->ar_rnat & ~m) | (rnat1 & m);
	else if (rnat1_kaddr > krbs)
		*rnat1_kaddr = ((*rnat1_kaddr & ~m) | (rnat1 & m));
}

static inline int
on_kernel_rbs (unsigned long addr, unsigned long bspstore,
	       unsigned long urbs_end)
{
	unsigned long *rnat_addr = ia64_rse_rnat_addr((unsigned long *)
						      urbs_end);
	return (addr >= bspstore && addr <= (unsigned long) rnat_addr);
}

/*
 * Read a word from the user-level backing store of task CHILD.  ADDR
 * is the user-level address to read the word from, VAL a pointer to
 * the return value, and USER_BSP gives the end of the user-level
 * backing store (i.e., it's the address that would be in ar.bsp after
 * the user executed a "cover" instruction).
 *
 * This routine takes care of accessing the kernel register backing
 * store for those registers that got spilled there.  It also takes
 * care of calculating the appropriate RNaT collection words.
 */
long
ia64_peek (struct task_struct *child, struct switch_stack *child_stack,
	   unsigned long user_rbs_end, unsigned long addr, long *val)
{
	unsigned long *bspstore, *krbs, regnum, *laddr, *urbs_end, *rnat_addr;
	struct pt_regs *child_regs;
	size_t copied;
	long ret;

	urbs_end = (long *) user_rbs_end;
	laddr = (unsigned long *) addr;
	child_regs = task_pt_regs(child);
	bspstore = (unsigned long *) child_regs->ar_bspstore;
	krbs = (unsigned long *) child + IA64_RBS_OFFSET/8;
	if (on_kernel_rbs(addr, (unsigned long) bspstore,
			  (unsigned long) urbs_end))
	{
		/*
		 * Attempt to read the RBS in an area that's actually
		 * on the kernel RBS => read the corresponding bits in
		 * the kernel RBS.
		 */
		rnat_addr = ia64_rse_rnat_addr(laddr);
		ret = get_rnat(child, child_stack, krbs, rnat_addr, urbs_end);

		if (laddr == rnat_addr) {
			/* return NaT collection word itself */
			*val = ret;
			return 0;
		}

		if (((1UL << ia64_rse_slot_num(laddr)) & ret) != 0) {
			/*
			 * It is implementation dependent whether the
			 * data portion of a NaT value gets saved on a
			 * st8.spill or RSE spill (e.g., see EAS 2.6,
			 * 4.4.4.6 Register Spill and Fill).  To get
			 * consistent behavior across all possible
			 * IA-64 implementations, we return zero in
			 * this case.
			 */
			*val = 0;
			return 0;
		}

		if (laddr < urbs_end) {
			/*
			 * The desired word is on the kernel RBS and
			 * is not a NaT.
			 */
			regnum = ia64_rse_num_regs(bspstore, laddr);
			*val = *ia64_rse_skip_regs(krbs, regnum);
			return 0;
		}
	}
	copied = access_process_vm(child, addr, &ret, sizeof(ret), 0);
	if (copied != sizeof(ret))
		return -EIO;
	*val = ret;
	return 0;
}

long
ia64_poke (struct task_struct *child, struct switch_stack *child_stack,
	   unsigned long user_rbs_end, unsigned long addr, long val)
{
	unsigned long *bspstore, *krbs, regnum, *laddr;
	unsigned long *urbs_end = (long *) user_rbs_end;
	struct pt_regs *child_regs;

	laddr = (unsigned long *) addr;
	child_regs = task_pt_regs(child);
	bspstore = (unsigned long *) child_regs->ar_bspstore;
	krbs = (unsigned long *) child + IA64_RBS_OFFSET/8;
	if (on_kernel_rbs(addr, (unsigned long) bspstore,
			  (unsigned long) urbs_end))
	{
		/*
		 * Attempt to write the RBS in an area that's actually
		 * on the kernel RBS => write the corresponding bits
		 * in the kernel RBS.
		 */
		if (ia64_rse_is_rnat_slot(laddr))
			put_rnat(child, child_stack, krbs, laddr, val,
				 urbs_end);
		else {
			if (laddr < urbs_end) {
				regnum = ia64_rse_num_regs(bspstore, laddr);
				*ia64_rse_skip_regs(krbs, regnum) = val;
			}
		}
	} else if (access_process_vm(child, addr, &val, sizeof(val), 1)
		   != sizeof(val))
		return -EIO;
	return 0;
}

/*
 * Calculate the address of the end of the user-level register backing
 * store.  This is the address that would have been stored in ar.bsp
 * if the user had executed a "cover" instruction right before
 * entering the kernel.  If CFMP is not NULL, it is used to return the
 * "current frame mask" that was active at the time the kernel was
 * entered.
 */
unsigned long
ia64_get_user_rbs_end (struct task_struct *child, struct pt_regs *pt,
		       unsigned long *cfmp)
{
	unsigned long *krbs, *bspstore, cfm = pt->cr_ifs;
	long ndirty;

	krbs = (unsigned long *) child + IA64_RBS_OFFSET/8;
	bspstore = (unsigned long *) pt->ar_bspstore;
	ndirty = ia64_rse_num_regs(krbs, krbs + (pt->loadrs >> 19));

	if (in_syscall(pt))
		ndirty += (cfm & 0x7f);
	else
		cfm &= ~(1UL << 63);	/* clear valid bit */

	if (cfmp)
		*cfmp = cfm;
	return (unsigned long) ia64_rse_skip_regs(bspstore, ndirty);
}

/*
 * Synchronize (i.e, write) the RSE backing store living in kernel
 * space to the VM of the CHILD task.  SW and PT are the pointers to
 * the switch_stack and pt_regs structures, respectively.
 * USER_RBS_END is the user-level address at which the backing store
 * ends.
 */
long
ia64_sync_user_rbs (struct task_struct *child, struct switch_stack *sw,
		    unsigned long user_rbs_start, unsigned long user_rbs_end)
{
	unsigned long addr, val;
	long ret;

	/* now copy word for word from kernel rbs to user rbs: */
	for (addr = user_rbs_start; addr < user_rbs_end; addr += 8) {
		ret = ia64_peek(child, sw, user_rbs_end, addr, &val);
		if (ret < 0)
			return ret;
		if (access_process_vm(child, addr, &val, sizeof(val), 1)
		    != sizeof(val))
			return -EIO;
	}
	return 0;
}

/*
 * Write f32-f127 back to task->thread.fph if it has been modified.
 */
inline void
ia64_flush_fph (struct task_struct *task)
{
	struct ia64_psr *psr = ia64_psr(task_pt_regs(task));

	/*
	 * Prevent migrating this task while
	 * we're fiddling with the FPU state
	 */
	preempt_disable();
	if (ia64_is_local_fpu_owner(task) && psr->mfh) {
		psr->mfh = 0;
		task->thread.flags |= IA64_THREAD_FPH_VALID;
		ia64_save_fpu(&task->thread.fph[0]);
	}
	preempt_enable();
}

/*
 * Sync the fph state of the task so that it can be manipulated
 * through thread.fph.  If necessary, f32-f127 are written back to
 * thread.fph or, if the fph state hasn't been used before, thread.fph
 * is cleared to zeroes.  Also, access to f32-f127 is disabled to
 * ensure that the task picks up the state from thread.fph when it
 * executes again.
 */
void
ia64_sync_fph (struct task_struct *task)
{
	struct ia64_psr *psr = ia64_psr(task_pt_regs(task));

	ia64_flush_fph(task);
	if (!(task->thread.flags & IA64_THREAD_FPH_VALID)) {
		task->thread.flags |= IA64_THREAD_FPH_VALID;
		memset(&task->thread.fph, 0, sizeof(task->thread.fph));
	}
	ia64_drop_fpu(task);
	psr->dfh = 1;
}

#if 0
static int
access_fr (struct unw_frame_info *info, int regnum, int hi,
	   unsigned long *data, int write_access)
{
	struct ia64_fpreg fpval;
	int ret;

	ret = unw_get_fr(info, regnum, &fpval);
	if (ret < 0)
		return ret;

	if (write_access) {
		fpval.u.bits[hi] = *data;
		ret = unw_set_fr(info, regnum, fpval);
	} else
		*data = fpval.u.bits[hi];
	return ret;
}
#endif /* access_fr() */

/*
 * Change the machine-state of CHILD such that it will return via the normal
 * kernel exit-path, rather than the syscall-exit path.
 */
static void
convert_to_non_syscall (struct task_struct *child, struct pt_regs  *pt,
			unsigned long cfm)
{
	struct unw_frame_info info, prev_info;
	unsigned long ip, sp, pr;

	unw_init_from_blocked_task(&info, child);
	while (1) {
		prev_info = info;
		if (unw_unwind(&info) < 0)
			return;

		unw_get_sp(&info, &sp);
		if ((long)((unsigned long)child + IA64_STK_OFFSET - sp)
		    < IA64_PT_REGS_SIZE) {
			dprintk("ptrace.%s: ran off the top of the kernel "
				"stack\n", __FUNCTION__);
			return;
		}
		if (unw_get_pr (&prev_info, &pr) < 0) {
			unw_get_rp(&prev_info, &ip);
			dprintk("ptrace.%s: failed to read "
				"predicate register (ip=0x%lx)\n",
				__FUNCTION__, ip);
			return;
		}
		if (unw_is_intr_frame(&info)
		    && (pr & (1UL << PRED_USER_STACK)))
			break;
	}

	/*
	 * Note: at the time of this call, the target task is blocked
	 * in notify_resume_user() and by clearling PRED_LEAVE_SYSCALL
	 * (aka, "pLvSys") we redirect execution from
	 * .work_pending_syscall_end to .work_processed_kernel.
	 */
	unw_get_pr(&prev_info, &pr);
	pr &= ~((1UL << PRED_SYSCALL) | (1UL << PRED_LEAVE_SYSCALL));
	pr |=  (1UL << PRED_NON_SYSCALL);
	unw_set_pr(&prev_info, pr);

	pt->cr_ifs = (1UL << 63) | cfm;
	/*
	 * Clear the memory that is NOT written on syscall-entry to
	 * ensure we do not leak kernel-state to user when execution
	 * resumes.
	 */
	pt->r2 = 0;
	pt->r3 = 0;
	pt->r14 = 0;
	memset(&pt->r16, 0, 16*8);	/* clear r16-r31 */
	memset(&pt->f6, 0, 6*16);	/* clear f6-f11 */
	pt->b7 = 0;
	pt->ar_ccv = 0;
	pt->ar_csd = 0;
	pt->ar_ssd = 0;
}

static int
access_nat_bits (struct task_struct *child, struct pt_regs *pt,
		 struct unw_frame_info *info,
		 unsigned long *data, int write_access)
{
	unsigned long regnum, nat_bits, scratch_unat, dummy = 0;
	char nat = 0;

	if (write_access) {
		nat_bits = *data;
		scratch_unat = ia64_put_scratch_nat_bits(pt, nat_bits);
		if (unw_set_ar(info, UNW_AR_UNAT, scratch_unat) < 0) {
			dprintk("ptrace: failed to set ar.unat\n");
			return -1;
		}
		for (regnum = 4; regnum <= 7; ++regnum) {
			unw_get_gr(info, regnum, &dummy, &nat);
			unw_set_gr(info, regnum, dummy,
				   (nat_bits >> regnum) & 1);
		}
	} else {
		if (unw_get_ar(info, UNW_AR_UNAT, &scratch_unat) < 0) {
			dprintk("ptrace: failed to read ar.unat\n");
			return -1;
		}
		nat_bits = ia64_get_scratch_nat_bits(pt, scratch_unat);
		for (regnum = 4; regnum <= 7; ++regnum) {
			unw_get_gr(info, regnum, &dummy, &nat);
			nat_bits |= (nat != 0) << regnum;
		}
		*data = nat_bits;
	}
	return 0;
}


/* "asmlinkage" so the input arguments are preserved... */

asmlinkage void
syscall_trace_enter (long arg0, long arg1, long arg2, long arg3,
		     long arg4, long arg5, long arg6, long arg7,
		     struct pt_regs regs)
{
	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(&regs, 0);

	if (unlikely(current->audit_context)) {
		long syscall;
		int arch;

		if (IS_IA32_PROCESS(&regs)) {
			syscall = regs.r1;
			arch = AUDIT_ARCH_I386;
		} else {
			syscall = regs.r15;
			arch = AUDIT_ARCH_IA64;
		}

		audit_syscall_entry(arch, syscall, arg0, arg1, arg2, arg3);
	}

}

/* "asmlinkage" so the input arguments are preserved... */

asmlinkage void
syscall_trace_leave (long arg0, long arg1, long arg2, long arg3,
		     long arg4, long arg5, long arg6, long arg7,
		     struct pt_regs regs)
{
	if (unlikely(current->audit_context)) {
		int success = AUDITSC_RESULT(regs.r10);
		long result = regs.r8;

		if (success != AUDITSC_SUCCESS)
			result = -result;
		audit_syscall_exit(success, result);
	}

	if (test_thread_flag(TIF_SYSCALL_TRACE))
		tracehook_report_syscall(&regs, 1);
}


#ifdef CONFIG_UTRACE

/* Utrace implementation starts here */

typedef struct utrace_get {
	void *kbuf;
	void __user *ubuf;
} utrace_get_t;

typedef struct utrace_set {
	const void *kbuf;
	const void __user *ubuf;
} utrace_set_t;

typedef struct utrace_getset {
	struct task_struct *target;
	const struct utrace_regset *regset;
	union {
		utrace_get_t get;
		utrace_set_t set;
	} u;
	unsigned int pos;
	unsigned int count;
	int ret;
} utrace_getset_t;

static int
access_elf_gpreg(struct task_struct *target, struct unw_frame_info *info,
		unsigned long addr, unsigned long *data, int write_access)
{
	struct pt_regs *pt;
	unsigned long *ptr = NULL;
	int ret;
	char nat=0;

	pt = task_pt_regs(target);
	switch (addr) {
		case ELF_GR_OFFSET(1):
			ptr = &pt->r1;
			break;
		case ELF_GR_OFFSET(2):
		case ELF_GR_OFFSET(3):
			ptr = (void *)&pt->r2 + (addr - ELF_GR_OFFSET(2));
			break;
		case ELF_GR_OFFSET(4) ... ELF_GR_OFFSET(7):
			if (write_access) {
				/* read NaT bit first: */
				unsigned long dummy;

				ret = unw_get_gr(info, addr/8, &dummy, &nat);
				if (ret < 0)
					return ret;
			}
			return unw_access_gr(info, addr/8, data, &nat, write_access);
		case ELF_GR_OFFSET(8) ... ELF_GR_OFFSET(11):
			ptr = (void *)&pt->r8 + addr - ELF_GR_OFFSET(8);
			break;
		case ELF_GR_OFFSET(12):
		case ELF_GR_OFFSET(13):
			ptr = (void *)&pt->r12 + addr - ELF_GR_OFFSET(12);
			break;
		case ELF_GR_OFFSET(14):
			ptr = &pt->r14;
			break;
		case ELF_GR_OFFSET(15):
			ptr = &pt->r15;
	}
	if (write_access)
		*ptr = *data;
	else
		*data = *ptr;
	return 0;
}

static int
access_elf_breg(struct task_struct *target, struct unw_frame_info *info,
		unsigned long addr, unsigned long *data, int write_access)
{
	struct pt_regs *pt;
	unsigned long *ptr = NULL;

	pt = task_pt_regs(target);
	switch (addr) {
		case ELF_BR_OFFSET(0):
			ptr = &pt->b0;
			break;
		case ELF_BR_OFFSET(1) ... ELF_BR_OFFSET(5):
			return unw_access_br(info, (addr - ELF_BR_OFFSET(0))/8,
					data, write_access);
		case ELF_BR_OFFSET(6):
			ptr = &pt->b6;
			break;
		case ELF_BR_OFFSET(7):
			ptr = &pt->b7;
	}
	if (write_access)
		*ptr = *data;
	else
		*data = *ptr;
	return 0;
}

static int
access_elf_areg(struct task_struct *target, struct unw_frame_info *info,
		unsigned long addr, unsigned long *data, int write_access)
{
	struct pt_regs *pt;
	unsigned long cfm, urbs_end, rnat_addr;
	unsigned long *ptr = NULL;

	pt = task_pt_regs(target);
	if (addr >= ELF_AR_RSC_OFFSET && addr <= ELF_AR_SSD_OFFSET) {
		switch (addr) {
			case ELF_AR_RSC_OFFSET:
				/* force PL3 */
				if (write_access)
					pt->ar_rsc = *data | (3 << 2);
				else
					*data = pt->ar_rsc;
				return 0;
			case ELF_AR_BSP_OFFSET:
				/*
				 * By convention, we use PT_AR_BSP to refer to
				 * the end of the user-level backing store.
				 * Use ia64_rse_skip_regs(PT_AR_BSP, -CFM.sof)
				 * to get the real value of ar.bsp at the time
				 * the kernel was entered.
				 *
				 * Furthermore, when changing the contents of
				 * PT_AR_BSP (or PT_CFM) we MUST copy any
				 * users-level stacked registers that are
				 * stored on the kernel stack back to
				 * user-space because otherwise, we might end
				 * up clobbering kernel stacked registers.
				 * Also, if this happens while the task is
				 * blocked in a system call, which convert the
				 * state such that the non-system-call exit
				 * path is used.  This ensures that the proper
				 * state will be picked up when resuming
				 * execution.  However, it *also* means that
				 * once we write PT_AR_BSP/PT_CFM, it won't be
				 * possible to modify the syscall arguments of
				 * the pending system call any longer.  This
				 * shouldn't be an issue because modifying
				 * PT_AR_BSP/PT_CFM generally implies that
				 * we're either abandoning the pending system
				 * call or that we defer it's re-execution
				 * (e.g., due to GDB doing an inferior
				 * function call).
				 */
				urbs_end = ia64_get_user_rbs_end(target, pt, &cfm);
				if (write_access) {
					if (*data != urbs_end) {
						if (ia64_sync_user_rbs(target, info->sw,
									pt->ar_bspstore,
									urbs_end) < 0)
							return -1;
						if (in_syscall(pt))
							convert_to_non_syscall(target,
									pt,
									cfm);
						/*
						 * Simulate user-level write
						 * of ar.bsp:
						 */
						pt->loadrs = 0;
						pt->ar_bspstore = *data;
					}
				} else
					*data = urbs_end;
				return 0;
			case ELF_AR_BSPSTORE_OFFSET: // ar_bsp_store
				ptr = &pt->ar_bspstore;
				break;
			case ELF_AR_RNAT_OFFSET:  // ar_rnat
				urbs_end = ia64_get_user_rbs_end(target, pt, NULL);
				rnat_addr = (long) ia64_rse_rnat_addr((long *)
						urbs_end);
				if (write_access)
					return ia64_poke(target, info->sw, urbs_end,
							rnat_addr, *data);
				else
					return ia64_peek(target, info->sw, urbs_end,
							rnat_addr, data);
			case ELF_AR_CCV_OFFSET:   // ar_ccv
				ptr = &pt->ar_ccv;
				break;
			case ELF_AR_UNAT_OFFSET:	// ar_unat
				ptr = &pt->ar_unat;
				break;
			case ELF_AR_FPSR_OFFSET:  // ar_fpsr
				ptr = &pt->ar_fpsr;
				break;
			case ELF_AR_PFS_OFFSET:  // ar_pfs
				ptr = &pt->ar_pfs;
				break;
			case ELF_AR_LC_OFFSET:   // ar_lc
				return unw_access_ar(info, UNW_AR_LC, data,
						write_access);
			case ELF_AR_EC_OFFSET:    // ar_ec
				return unw_access_ar(info, UNW_AR_EC, data,
						write_access);
			case ELF_AR_CSD_OFFSET:   // ar_csd
				ptr = &pt->ar_csd;
				break;
			case ELF_AR_SSD_OFFSET:   // ar_ssd
				ptr = &pt->ar_ssd;
		}
	} else if (addr >= ELF_CR_IIP_OFFSET && addr <= ELF_CR_IPSR_OFFSET) {
		switch (addr) {
			case ELF_CR_IIP_OFFSET:
				ptr = &pt->cr_iip;
				break;
			case ELF_CFM_OFFSET:
				urbs_end = ia64_get_user_rbs_end(target, pt, &cfm);
				if (write_access) {
					if (((cfm ^ *data) & PFM_MASK) != 0) {
						if (ia64_sync_user_rbs(target, info->sw,
									pt->ar_bspstore,
									urbs_end) < 0)
							return -1;
						if (in_syscall(pt))
							convert_to_non_syscall(target,
									pt,
									cfm);
						pt->cr_ifs = ((pt->cr_ifs & ~PFM_MASK)
								| (*data & PFM_MASK));
					}
				} else
					*data = cfm;
				return 0;
			case ELF_CR_IPSR_OFFSET:
				if (write_access)
					pt->cr_ipsr = ((*data & IPSR_MASK)
							| (pt->cr_ipsr & ~IPSR_MASK));
				else
					*data = (pt->cr_ipsr & IPSR_MASK);
				return 0;
		}
	} else if (addr == ELF_NAT_OFFSET)
			return access_nat_bits(target, pt, info,
					data, write_access);
	else if (addr == ELF_PR_OFFSET)
			ptr = &pt->pr;
	else
		return -1;

	if (write_access)
		*ptr = *data;
	else
		*data = *ptr;

	return 0;
}

static int
access_elf_reg(struct task_struct *target, struct unw_frame_info *info,
		unsigned long addr, unsigned long *data, int write_access)
{
	if (addr >= ELF_GR_OFFSET(1) && addr <= ELF_GR_OFFSET(15))
		return access_elf_gpreg(target, info, addr, data, write_access);
	else if (addr >= ELF_BR_OFFSET(0) && addr <= ELF_BR_OFFSET(7))
		return access_elf_breg(target, info, addr, data, write_access);
	else
		return access_elf_areg(target, info, addr, data, write_access);
}

void do_gpregs_get(struct unw_frame_info *info, void *arg)
{
	struct pt_regs *pt;
	utrace_getset_t *dst = arg;
	elf_greg_t tmp[16];
	unsigned int i, index, min_copy;

	if (unw_unwind_to_user(info) < 0)
		return;

	/*
	 * coredump format:
	 *      r0-r31
	 *      NaT bits (for r0-r31; bit N == 1 iff rN is a NaT)
	 *      predicate registers (p0-p63)
	 *      b0-b7
	 *      ip cfm user-mask
	 *      ar.rsc ar.bsp ar.bspstore ar.rnat
	 *      ar.ccv ar.unat ar.fpsr ar.pfs ar.lc ar.ec
	 */


	/* Skip r0 */
	if (dst->count > 0 && dst->pos < ELF_GR_OFFSET(1)) {
		dst->ret = utrace_regset_copyout_zero(&dst->pos, &dst->count,
						      &dst->u.get.kbuf,
						      &dst->u.get.ubuf,
						      0, ELF_GR_OFFSET(1));
		if (dst->ret || dst->count == 0)
			return;
	}

	/* gr1 - gr15 */
	if (dst->count > 0 && dst->pos < ELF_GR_OFFSET(16)) {
		index = (dst->pos - ELF_GR_OFFSET(1)) / sizeof(elf_greg_t);
		min_copy = ELF_GR_OFFSET(16) > (dst->pos + dst->count) ?
			 (dst->pos + dst->count) : ELF_GR_OFFSET(16);
		for (i = dst->pos; i < min_copy; i += sizeof(elf_greg_t), index++)
			if (access_elf_reg(dst->target, info, i,
						&tmp[index], 0) < 0) {
				dst->ret = -EIO;
				return;
			}
		dst->ret = utrace_regset_copyout(&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf, tmp,
				ELF_GR_OFFSET(1), ELF_GR_OFFSET(16));
		if (dst->ret || dst->count == 0)
			return;
	}

	/* r16-r31 */
	if (dst->count > 0 && dst->pos < ELF_NAT_OFFSET) {
		pt = task_pt_regs(dst->target);
		dst->ret = utrace_regset_copyout(&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf, &pt->r16,
				ELF_GR_OFFSET(16), ELF_NAT_OFFSET);
		if (dst->ret || dst->count == 0)
			return;
	}

	/* nat, pr, b0 - b7 */
	if (dst->count > 0 && dst->pos < ELF_CR_IIP_OFFSET) {
		index = (dst->pos - ELF_NAT_OFFSET) / sizeof(elf_greg_t);
		min_copy = ELF_CR_IIP_OFFSET > (dst->pos + dst->count) ?
			 (dst->pos + dst->count) : ELF_CR_IIP_OFFSET;
		for (i = dst->pos; i < min_copy; i += sizeof(elf_greg_t), index++)
			if (access_elf_reg(dst->target, info, i,
						&tmp[index], 0) < 0) {
				dst->ret = -EIO;
				return;
			}
		dst->ret = utrace_regset_copyout(&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf, tmp,
				ELF_NAT_OFFSET, ELF_CR_IIP_OFFSET);
		if (dst->ret || dst->count == 0)
			return;
	}

 	/* ip cfm psr ar.rsc ar.bsp ar.bspstore ar.rnat
	 * ar.ccv ar.unat ar.fpsr ar.pfs ar.lc ar.ec ar.csd ar.ssd
	 */
	if (dst->count > 0 && dst->pos < (ELF_AR_END_OFFSET)) {
		index = (dst->pos - ELF_CR_IIP_OFFSET) / sizeof(elf_greg_t);
		min_copy = ELF_AR_END_OFFSET > (dst->pos + dst->count) ?
			 (dst->pos + dst->count) : ELF_AR_END_OFFSET;
		for (i = dst->pos; i < min_copy; i += sizeof(elf_greg_t), index++)
			if (access_elf_reg(dst->target, info, i,
						&tmp[index], 0) < 0) {
				dst->ret = -EIO;
				return;
			}
		dst->ret = utrace_regset_copyout(&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf, tmp,
				ELF_CR_IIP_OFFSET, ELF_AR_END_OFFSET);
        }
}

void do_gpregs_set(struct unw_frame_info *info, void *arg)
{
	struct pt_regs *pt;
	utrace_getset_t *dst = arg;
	elf_greg_t tmp[16];
	unsigned int i, index;

	if (unw_unwind_to_user(info) < 0)
		return;

	/* Skip r0 */
	if (dst->count > 0 && dst->pos < ELF_GR_OFFSET(1)) {
		dst->ret = utrace_regset_copyin_ignore(&dst->pos, &dst->count,
						       &dst->u.set.kbuf,
						       &dst->u.set.ubuf,
						       0, ELF_GR_OFFSET(1));
		if (dst->ret || dst->count == 0)
			return;
	}

	/* gr1-gr15 */
	if (dst->count > 0 && dst->pos < ELF_GR_OFFSET(16)) {
		i = dst->pos;
		index = (dst->pos - ELF_GR_OFFSET(1)) / sizeof(elf_greg_t);
		dst->ret = utrace_regset_copyin(&dst->pos, &dst->count,
				&dst->u.set.kbuf, &dst->u.set.ubuf, tmp,
				ELF_GR_OFFSET(1), ELF_GR_OFFSET(16));
		if (dst->ret)
			return;
		for ( ; i < dst->pos; i += sizeof(elf_greg_t), index++)
			if (access_elf_reg(dst->target, info, i,
						&tmp[index], 1) < 0) {
				dst->ret = -EIO;
				return;
			}
		if (dst->count == 0)
			return;
	}

	/* gr16-gr31 */
	if (dst->count > 0 && dst->pos < ELF_NAT_OFFSET) {
		pt = task_pt_regs(dst->target);
		dst->ret = utrace_regset_copyin(&dst->pos, &dst->count,
				&dst->u.set.kbuf, &dst->u.set.ubuf, &pt->r16,
				ELF_GR_OFFSET(16), ELF_NAT_OFFSET);
		if (dst->ret || dst->count == 0)
			return;
	}

	/* nat, pr, b0 - b7 */
	if (dst->count > 0 && dst->pos < ELF_CR_IIP_OFFSET) {
		i = dst->pos;
		index = (dst->pos - ELF_NAT_OFFSET) / sizeof(elf_greg_t);
		dst->ret = utrace_regset_copyin(&dst->pos, &dst->count,
				&dst->u.set.kbuf, &dst->u.set.ubuf, tmp,
				ELF_NAT_OFFSET, ELF_CR_IIP_OFFSET);
		if (dst->ret)
			return;
		for (; i < dst->pos; i += sizeof(elf_greg_t), index++)
			if (access_elf_reg(dst->target, info, i,
						&tmp[index], 1) < 0) {
				dst->ret = -EIO;
				return;
			}
		if (dst->count == 0)
			return;
	}

 	/* ip cfm psr ar.rsc ar.bsp ar.bspstore ar.rnat
	 * ar.ccv ar.unat ar.fpsr ar.pfs ar.lc ar.ec ar.csd ar.ssd
	 */
	if (dst->count > 0 && dst->pos < (ELF_AR_END_OFFSET)) {
		i = dst->pos;
		index = (dst->pos - ELF_CR_IIP_OFFSET) / sizeof(elf_greg_t);
		dst->ret = utrace_regset_copyin(&dst->pos, &dst->count,
				&dst->u.set.kbuf, &dst->u.set.ubuf, tmp,
				ELF_CR_IIP_OFFSET, ELF_AR_END_OFFSET);
		if (dst->ret)
			return;
		for ( ; i < dst->pos; i += sizeof(elf_greg_t), index++)
			if (access_elf_reg(dst->target, info, i,
						&tmp[index], 1) < 0) {
				dst->ret = -EIO;
				return;
			}
	}
}

#define ELF_FP_OFFSET(i)	(i * sizeof(elf_fpreg_t))

void do_fpregs_get(struct unw_frame_info *info, void *arg)
{
	utrace_getset_t *dst = arg;
	struct task_struct *task = dst->target;
	elf_fpreg_t tmp[30];
	int index, min_copy, i;

	if (unw_unwind_to_user(info) < 0)
		return;

	/* Skip pos 0 and 1 */
	if (dst->count > 0 && dst->pos < ELF_FP_OFFSET(2)) {
		dst->ret = utrace_regset_copyout_zero(&dst->pos, &dst->count,
						      &dst->u.get.kbuf,
						      &dst->u.get.ubuf,
						      0, ELF_FP_OFFSET(2));
		if (dst->count == 0 || dst->ret)
			return;
	}

	/* fr2-fr31 */
	if (dst->count > 0 && dst->pos < ELF_FP_OFFSET(32)) {
		index = (dst->pos - ELF_FP_OFFSET(2)) / sizeof(elf_fpreg_t);
		min_copy = min(((unsigned int)ELF_FP_OFFSET(32)),
				dst->pos + dst->count);
		for (i = dst->pos; i < min_copy; i += sizeof(elf_fpreg_t), index++)
			if (unw_get_fr(info, i / sizeof(elf_fpreg_t),
					 &tmp[index])) {
				dst->ret = -EIO;
				return;
			}
		dst->ret = utrace_regset_copyout(&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf, tmp,
				ELF_FP_OFFSET(2), ELF_FP_OFFSET(32));
		if (dst->count == 0 || dst->ret)
			return;
	}

	/* fph */
	if (dst->count > 0) {
		ia64_flush_fph(dst->target);
		if (task->thread.flags & IA64_THREAD_FPH_VALID)
			dst->ret = utrace_regset_copyout(
				&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf,
				&dst->target->thread.fph,
				ELF_FP_OFFSET(32), -1);
		else
			/* Zero fill instead.  */
			dst->ret = utrace_regset_copyout_zero(
				&dst->pos, &dst->count,
				&dst->u.get.kbuf, &dst->u.get.ubuf,
				ELF_FP_OFFSET(32), -1);
	}
}

void do_fpregs_set(struct unw_frame_info *info, void *arg)
{
	utrace_getset_t *dst = arg;
	elf_fpreg_t fpreg, tmp[30];
	int index, start, end;

	if (unw_unwind_to_user(info) < 0)
		return;

	/* Skip pos 0 and 1 */
	if (dst->count > 0 && dst->pos < ELF_FP_OFFSET(2)) {
		dst->ret = utrace_regset_copyin_ignore(&dst->pos, &dst->count,
						       &dst->u.set.kbuf,
						       &dst->u.set.ubuf,
						       0, ELF_FP_OFFSET(2));
		if (dst->count == 0 || dst->ret)
			return;
	}

	/* fr2-fr31 */
	if (dst->count > 0 && dst->pos < ELF_FP_OFFSET(32)) {
		start = dst->pos;
		end = min(((unsigned int)ELF_FP_OFFSET(32)),
			 dst->pos + dst->count);
		dst->ret = utrace_regset_copyin(&dst->pos, &dst->count,
				&dst->u.set.kbuf, &dst->u.set.ubuf, tmp,
				ELF_FP_OFFSET(2), ELF_FP_OFFSET(32));
		if (dst->ret)
			return;

		if (start & 0xF) { //  only write high part
			if (unw_get_fr(info, start / sizeof(elf_fpreg_t),
					 &fpreg)) {
				dst->ret = -EIO;
				return;
			}
			tmp[start / sizeof(elf_fpreg_t) - 2].u.bits[0]
				= fpreg.u.bits[0];
			start &= ~0xFUL;
		}
		if (end & 0xF) { // only write low part
			if (unw_get_fr(info, end / sizeof(elf_fpreg_t), &fpreg)) {
				dst->ret = -EIO;
				return;
                       	}
			tmp[end / sizeof(elf_fpreg_t) -2].u.bits[1]
				= fpreg.u.bits[1];
			end = (end + 0xF) & ~0xFUL;
		}

		for ( ;	start < end ; start += sizeof(elf_fpreg_t)) {
			index = start / sizeof(elf_fpreg_t);
			if (unw_set_fr(info, index, tmp[index - 2])){
				dst->ret = -EIO;
				return;
			}
		}
		if (dst->ret || dst->count == 0)
			return;
	}

	/* fph */
	if (dst->count > 0 && dst->pos < ELF_FP_OFFSET(128)) {
		ia64_sync_fph(dst->target);
		dst->ret = utrace_regset_copyin(&dst->pos, &dst->count,
						&dst->u.set.kbuf,
						&dst->u.set.ubuf,
						&dst->target->thread.fph,
						ELF_FP_OFFSET(32), -1);
	}
}

static int
do_regset_call(void (*call)(struct unw_frame_info *, void *),
	       struct task_struct *target,
	       const struct utrace_regset *regset,
	       unsigned int pos, unsigned int count,
	       const void *kbuf, const void __user *ubuf)
{
	utrace_getset_t info = { .target = target, .regset = regset,
				 .pos = pos, .count = count,
				 .u.set = { .kbuf = kbuf, .ubuf = ubuf },
				 .ret = 0 };

	if (target == current)
		unw_init_running(call, &info);
	else {
		struct unw_frame_info ufi;
		memset(&ufi, 0, sizeof(ufi));
		unw_init_from_blocked_task(&ufi, target);
		(*call)(&ufi, &info);
	}

	return info.ret;
}

static int
gpregs_get(struct task_struct *target,
	   const struct utrace_regset *regset,
	   unsigned int pos, unsigned int count,
	   void *kbuf, void __user *ubuf)
{
	return do_regset_call(do_gpregs_get, target, regset, pos, count, kbuf, ubuf);
}

static int gpregs_set(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		const void *kbuf, const void __user *ubuf)
{
	return do_regset_call(do_gpregs_set, target, regset, pos, count, kbuf, ubuf);
}

static void do_gpregs_writeback(struct unw_frame_info *info, void *arg)
{
	struct pt_regs *pt;
	utrace_getset_t *dst = arg;
	unsigned long urbs_end;

	if (unw_unwind_to_user(info) < 0)
		return;
	pt = task_pt_regs(dst->target);
	urbs_end = ia64_get_user_rbs_end(dst->target, pt, NULL);
	dst->ret = ia64_sync_user_rbs(dst->target, info->sw, pt->ar_bspstore, urbs_end);
}
/*
 * This is called to write back the register backing store.
 * ptrace does this before it stops, so that a tracer reading the user
 * memory after the thread stops will get the current register data.
 */
static int
gpregs_writeback(struct task_struct *target,
		 const struct utrace_regset *regset,
		 int now)
{
	return do_regset_call(do_gpregs_writeback, target, regset, 0, 0, NULL, NULL);
}

static int
fpregs_active(struct task_struct *target, const struct utrace_regset *regset)
{
	return (target->thread.flags & IA64_THREAD_FPH_VALID) ? 128 : 32;
}

static int fpregs_get(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		void *kbuf, void __user *ubuf)
{
	return do_regset_call(do_fpregs_get, target, regset, pos, count, kbuf, ubuf);
}

static int fpregs_set(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		const void *kbuf, const void __user *ubuf)
{
	return do_regset_call(do_fpregs_set, target, regset, pos, count, kbuf, ubuf);
}

static int dbregs_get(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		void *kbuf, void __user *ubuf)
{
	int ret;

#ifdef CONFIG_PERFMON
	/*
	 * Check if debug registers are used by perfmon. This
	 * test must be done once we know that we can do the
	 * operation, i.e. the arguments are all valid, but
	 * before we start modifying the state.
	 *
	 * Perfmon needs to keep a count of how many processes
	 * are trying to modify the debug registers for system
	 * wide monitoring sessions.
	 *
	 * We also include read access here, because they may
	 * cause the PMU-installed debug register state
	 * (dbr[], ibr[]) to be reset. The two arrays are also
	 * used by perfmon, but we do not use
	 * IA64_THREAD_DBG_VALID. The registers are restored
	 * by the PMU context switch code.
	 */
	if (pfm_use_debug_registers(target))
		return -EIO;
#endif

	if (!(target->thread.flags & IA64_THREAD_DBG_VALID))
		ret = utrace_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
						 0, -1);
	else {
		preempt_disable();
		if (target == current)
			ia64_load_debug_regs(&target->thread.dbr[0]);
		preempt_enable_no_resched();
		ret = utrace_regset_copyout(&pos, &count, &kbuf, &ubuf,
					    &target->thread.dbr, 0, -1);
	}

	return ret;
}

static int dbregs_set(struct task_struct *target,
		const struct utrace_regset *regset,
		unsigned int pos, unsigned int count,
		const void *kbuf, const void __user *ubuf)
{
	int i, ret;

#ifdef CONFIG_PERFMON
	if (pfm_use_debug_registers(target))
		return -EIO;
#endif

	ret = 0;
	if (!(target->thread.flags & IA64_THREAD_DBG_VALID)){
		target->thread.flags |= IA64_THREAD_DBG_VALID;
		memset(target->thread.dbr, 0, 2 * sizeof(target->thread.dbr));
	} else if (target == current){
		preempt_disable();
		ia64_save_debug_regs(&target->thread.dbr[0]);
		preempt_enable_no_resched();
	}

	ret = utrace_regset_copyin(&pos, &count, &kbuf, &ubuf,
				   &target->thread.dbr, 0, -1);

	for (i = 1; i < IA64_NUM_DBG_REGS; i += 2) {
		target->thread.dbr[i] &= ~(7UL << 56);
		target->thread.ibr[i] &= ~(7UL << 56);
	}

	if (ret)
		return ret;

	if (target == current){
		preempt_disable();
		ia64_load_debug_regs(&target->thread.dbr[0]);
		preempt_enable_no_resched();
	}
	return 0;
}

static const struct utrace_regset native_regsets[] = {
	{
		.n = ELF_NGREG,
		.size = sizeof(elf_greg_t), .align = sizeof(elf_greg_t),
		.get = gpregs_get, .set = gpregs_set,
		.writeback = gpregs_writeback
	},
	{
		.n = ELF_NFPREG,
		.size = sizeof(elf_fpreg_t), .align = sizeof(elf_fpreg_t),
		.get = fpregs_get, .set = fpregs_set, .active = fpregs_active
	},
	{
		.n = 2 * IA64_NUM_DBG_REGS, .size = sizeof(long),
		.align = sizeof(long),
		.get = dbregs_get, .set = dbregs_set
	}
};

const struct utrace_regset_view utrace_ia64_native = {
	.name = "ia64",
	.e_machine = EM_IA_64,
	.regsets = native_regsets,
	.n = sizeof native_regsets / sizeof native_regsets[0],
};
EXPORT_SYMBOL_GPL(utrace_ia64_native);

#endif	/* CONFIG_UTRACE */


#ifdef CONFIG_PTRACE

#define WORD(member, num) \
	offsetof(struct pt_all_user_regs, member), \
	offsetof(struct pt_all_user_regs, member) + num * sizeof(long)
static const struct ptrace_layout_segment pt_all_user_regs_layout[] = {
	{WORD(nat, 1),			0,	ELF_NAT_OFFSET},
	{WORD(cr_iip, 1),		0,	ELF_CR_IIP_OFFSET},
	{WORD(cfm, 1),			0,	ELF_CFM_OFFSET},
	{WORD(cr_ipsr, 1),		0,	ELF_CR_IPSR_OFFSET},
	{WORD(pr, 1),			0,	ELF_PR_OFFSET},
	{WORD(gr[0], 32),		0,	ELF_GR_OFFSET(0)},
	{WORD(br[0], 8),		0, 	ELF_BR_OFFSET(0)},
	{WORD(ar[0], 16),		-1,	0},
	{WORD(ar[PT_AUR_RSC], 4),	0,	ELF_AR_RSC_OFFSET},
	{WORD(ar[PT_AUR_RNAT+1], 12),	-1,	0},
	{WORD(ar[PT_AUR_CCV], 1),	0,	ELF_AR_CCV_OFFSET},
	{WORD(ar[PT_AUR_CCV+1], 3),	-1,	0},
	{WORD(ar[PT_AUR_UNAT], 1), 	0,	ELF_AR_UNAT_OFFSET},
	{WORD(ar[PT_AUR_UNAT+1], 3),	-1,	0},
	{WORD(ar[PT_AUR_FPSR], 1), 	0,	ELF_AR_FPSR_OFFSET},
	{WORD(ar[PT_AUR_FPSR+1], 24), 	-1,	0},
	{WORD(ar[PT_AUR_PFS], 3),  	0,	ELF_AR_PFS_OFFSET},
	{WORD(ar[PT_AUR_EC+1], 62),	-1,	0},
	{offsetof(struct pt_all_user_regs, fr[0]),
	 offsetof(struct pt_all_user_regs, fr[128]),
	 1, 0},
	{0, 0, -1, 0}
};
#undef WORD

#define NEXT(addr, sum)	(addr + sum * sizeof(long))
static const struct ptrace_layout_segment pt_uarea_layout[] = {
	{PT_F32,	PT_NAT_BITS,		1,	ELF_FP_OFFSET(32)},
	{PT_NAT_BITS,	NEXT(PT_NAT_BITS, 1),	0,	ELF_NAT_OFFSET},
	{PT_F2, 	PT_F10,			1,	ELF_FP_OFFSET(2)},
	{PT_F10, 	PT_R4, 			1,	ELF_FP_OFFSET(10)},
	{PT_R4, 	PT_B1, 			0,	ELF_GR_OFFSET(4)},
	{PT_B1, 	PT_AR_EC, 		0,	ELF_BR_OFFSET(1)},
	{PT_AR_EC, 	PT_AR_LC,	 	0,	ELF_AR_EC_OFFSET},
	{PT_AR_LC, 	NEXT(PT_AR_LC, 1), 	0,	ELF_AR_LC_OFFSET},
	{PT_CR_IPSR,	PT_CR_IIP,		0,	ELF_CR_IPSR_OFFSET},
	{PT_CR_IIP,	PT_AR_UNAT,		0,	ELF_CR_IIP_OFFSET},
	{PT_AR_UNAT,	PT_AR_PFS,		0, 	ELF_AR_UNAT_OFFSET},
	{PT_AR_PFS,	PT_AR_RSC,		0,	ELF_AR_PFS_OFFSET},
	{PT_AR_RSC,	PT_AR_RNAT,		0,	ELF_AR_RSC_OFFSET},
	{PT_AR_RNAT,	PT_AR_BSPSTORE,		0,	ELF_AR_RNAT_OFFSET},
	{PT_AR_BSPSTORE,PT_PR,			0,	ELF_AR_BSPSTORE_OFFSET},
	{PT_PR,		PT_B6,			0,	ELF_PR_OFFSET},
	{PT_B6,		PT_AR_BSP,		0,	ELF_BR_OFFSET(6)},
	{PT_AR_BSP,	PT_R1,			0,	ELF_AR_BSP_OFFSET},
	{PT_R1,		PT_R12,			0,	ELF_GR_OFFSET(1)},
	{PT_R12,	PT_R8,			0,	ELF_GR_OFFSET(12)},
	{PT_R8,		PT_R16,			0,	ELF_GR_OFFSET(8)},
	{PT_R16,	PT_AR_CCV,		0,	ELF_GR_OFFSET(16)},
	{PT_AR_CCV,	PT_AR_FPSR,		0,	ELF_AR_CCV_OFFSET},
	{PT_AR_FPSR,	PT_B0,			0,	ELF_AR_FPSR_OFFSET},
	{PT_B0,		PT_B7,			0,	ELF_BR_OFFSET(0)},
	{PT_B7,		PT_F6,			0,	ELF_BR_OFFSET(7)},
	{PT_F6,		PT_AR_CSD,		1,	ELF_FP_OFFSET(6)},
	{PT_AR_CSD,	NEXT(PT_AR_CSD, 2),	0,	ELF_AR_CSD_OFFSET},
	{PT_DBR,	NEXT(PT_DBR, 8), 	2,	0},
	{PT_IBR,	NEXT(PT_IBR, 8),	2,	8 * sizeof(long)},
	{0, 0, -1, 0}
};
#undef NEXT

fastcall int arch_ptrace(long *request, struct task_struct *child,
			 struct utrace_attached_engine *engine,
			 unsigned long addr, unsigned long data, long *val)
{
	int ret = -ENOSYS;
	switch (*request) {
	case PTRACE_OLD_GETSIGINFO:
		*request = PTRACE_GETSIGINFO;
		break;
	case PTRACE_OLD_SETSIGINFO:
		*request = PTRACE_SETSIGINFO;
		break;

	case PTRACE_PEEKTEXT: /* read word at location addr. */
	case PTRACE_PEEKDATA:
		ret = access_process_vm(child, addr, val, sizeof(*val), 0);
		ret = ret == sizeof(*val) ? 0 : -EIO;
		break;

	case PTRACE_PEEKUSR:
		return ptrace_layout_access(child, engine,
					    utrace_native_view(current),
					    pt_uarea_layout,
					    addr, sizeof(long),
					    NULL, val, 0);
	case PTRACE_POKEUSR:
		return ptrace_pokeusr(child, engine,
				      pt_uarea_layout, addr, data);

	case PTRACE_GETREGS:
	case PTRACE_SETREGS:
		return ptrace_layout_access(child, engine,
					    utrace_native_view(current),
					    pt_all_user_regs_layout,
					    0, sizeof(struct pt_all_user_regs),
					    (void __user *) data, NULL,
					    *request == PTRACE_SETREGS);
	}
	return ret;
}

#endif	/* CONFIG_PTRACE */
