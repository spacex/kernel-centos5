/*
 *  linux/arch/i386/traps.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Pentium III FXSR, SSE support
 *	Gareth Hughes <gareth@valinux.com>, May 2000
 */

/*
 * 'Traps.c' handles hardware traps and faults after we have saved some
 * state in 'asm.s'.
 */
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/highmem.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/utsname.h>
#include <linux/kprobes.h>
#include <linux/kexec.h>
#include <linux/unwind.h>
#include <linux/nmi.h>

#ifdef CONFIG_EISA
#include <linux/ioport.h>
#include <linux/eisa.h>
#endif

#ifdef CONFIG_MCA
#include <linux/mca.h>
#endif

#include <asm/processor.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/atomic.h>
#include <asm/debugreg.h>
#include <asm/desc.h>
#include <asm/i387.h>
#include <asm/nmi.h>
#include <asm/unwind.h>
#include <asm/smp.h>
#include <asm/arch_hooks.h>
#include <asm/kdebug.h>
#include <asm/stacktrace.h>

#include <linux/module.h>

#include "mach_traps.h"

int panic_on_unrecovered_nmi;

asmlinkage int system_call(void);

struct desc_struct default_ldt[] = { { 0, 0 }, { 0, 0 }, { 0, 0 },
		{ 0, 0 }, { 0, 0 } };

/* Do we ignore FPU interrupts ? */
char ignore_fpu_irq = 0;

#ifndef CONFIG_X86_NO_IDT
/*
 * The IDT has to be page-aligned to simplify the Pentium
 * F0 0F bug workaround.. We have a special link segment
 * for this.
 */
struct desc_struct idt_table[256] __attribute__((__section__(".data.idt"))) = { {0, 0}, };
#endif

asmlinkage void divide_error(void);
asmlinkage void debug(void);
asmlinkage void nmi(void);
asmlinkage void int3(void);
asmlinkage void overflow(void);
asmlinkage void bounds(void);
asmlinkage void invalid_op(void);
asmlinkage void device_not_available(void);
asmlinkage void coprocessor_segment_overrun(void);
asmlinkage void invalid_TSS(void);
asmlinkage void segment_not_present(void);
asmlinkage void stack_segment(void);
asmlinkage void general_protection(void);
asmlinkage void page_fault(void);
asmlinkage void coprocessor_error(void);
asmlinkage void simd_coprocessor_error(void);
asmlinkage void alignment_check(void);
#ifndef CONFIG_XEN
asmlinkage void spurious_interrupt_bug(void);
#else
asmlinkage void fixup_4gb_segment(void);
#endif
asmlinkage void machine_check(void);

static int kstack_depth_to_print = 24;
ATOMIC_NOTIFIER_HEAD(i386die_chain);

extern char last_sysfs_file[];

int register_die_notifier(struct notifier_block *nb)
{
	vmalloc_sync_all();
	return atomic_notifier_chain_register(&i386die_chain, nb);
}
EXPORT_SYMBOL(register_die_notifier); /* used modular by kdb */

int unregister_die_notifier(struct notifier_block *nb)
{
	return atomic_notifier_chain_unregister(&i386die_chain, nb);
}
EXPORT_SYMBOL(unregister_die_notifier); /* used modular by kdb */

static inline int valid_stack_ptr(struct thread_info *tinfo, void *p)
{
	return	p > (void *)tinfo &&
		p < (void *)tinfo + THREAD_SIZE - 3;
}

static inline unsigned long print_context_stack(struct thread_info *tinfo,
				unsigned long *stack, unsigned long ebp,
				struct stacktrace_ops *ops, void *data)
{
	unsigned long addr;

#ifdef	CONFIG_FRAME_POINTER
	while (valid_stack_ptr(tinfo, (void *)ebp)) {
		addr = *(unsigned long *)(ebp + 4);
		ops->address(data, addr);
		/*
		 * break out of recursive entries (such as
		 * end_of_stack_stop_unwind_function):
	 	 */
		if (ebp == *(unsigned long *)ebp)
			break;
		ebp = *(unsigned long *)ebp;
	}
#else
	while (valid_stack_ptr(tinfo, stack)) {
		addr = *stack++;
		if (__kernel_text_address(addr))
			ops->address(data, addr);
	}
#endif
	return ebp;
}

void dump_trace(struct task_struct *task, struct pt_regs *regs,
	unsigned long *stack,
	struct stacktrace_ops *ops, void *data)
{
	unsigned long ebp;

	if (!task)
		task = current;

	if (!stack) {
		unsigned long dummy;
		stack = &dummy;
		if (task && task != current)
			stack = (unsigned long *)task->thread.esp;
	}

	if (task == current) {
		/* Grab ebp right from our regs */
		asm ("movl %%ebp, %0" : "=r" (ebp) : );
	} else {
		/* ebp is the last reg pushed by switch_to */
		ebp = *(unsigned long *) task->thread.esp;
	}

	while (1) {
		struct thread_info *context;
		context = (struct thread_info *)
			((unsigned long)stack & (~(THREAD_SIZE - 1)));
		ebp = print_context_stack(context, stack, ebp, ops, data);
		/* Should be after the line below, but somewhere
		   in early boot context comes out corrupted and we
		   can't reference it -AK */
		if (ops->stack(data, "IRQ") < 0)
			break;
		stack = (unsigned long*)context->previous_esp;
		if (!stack)
			break;
		touch_nmi_watchdog();
	}
}

EXPORT_SYMBOL(dump_trace);

static void
print_trace_warning_symbol(void *data, char *msg, unsigned long symbol)
{
	printk(data);
	print_symbol(msg, symbol);
	printk("\n");
}

static void print_trace_warning(void *data, char *msg)
{
	printk("%s%s\n", (char *)data, msg);
}

static int print_trace_stack(void *data, char *name)
{
	return 0;
}

/*
 * Print one address/symbol entries per line.
 */
static void print_trace_address(void *data, unsigned long addr)
{
	printk("%s [<%08lx>] ", (char *)data, addr);
	print_symbol("%s\n", addr);
}

static struct stacktrace_ops print_trace_ops = {
	.warning = print_trace_warning,
	.warning_symbol = print_trace_warning_symbol,
	.stack = print_trace_stack,
	.address = print_trace_address,
};

static void
show_trace_log_lvl(struct task_struct *task, struct pt_regs *regs,
	unsigned long * stack, char *log_lvl)
{
	dump_trace(task, regs, stack, &print_trace_ops, log_lvl);
	printk("%s =======================\n", log_lvl);
}

void show_trace(struct task_struct *task, struct pt_regs *regs,
		unsigned long * stack)
{
	show_trace_log_lvl(task, regs, stack, "");
}

static void show_stack_log_lvl(struct task_struct *task, struct pt_regs *regs,
			       unsigned long *esp, char *log_lvl)
{
	unsigned long *stack;
	int i;

	if (esp == NULL) {
		if (task)
			esp = (unsigned long*)task->thread.esp;
		else
			esp = (unsigned long *)&esp;
	}

	stack = esp;
	for(i = 0; i < kstack_depth_to_print; i++) {
		if (kstack_end(stack))
			break;
		if (i && ((i % 8) == 0))
			printk("\n%s       ", log_lvl);
		printk("%08lx ", *stack++);
	}
	printk("\n%sCall Trace:\n", log_lvl);
	show_trace_log_lvl(task, regs, esp, log_lvl);
}

void show_stack(struct task_struct *task, unsigned long *esp)
{
	printk("       ");
	show_stack_log_lvl(task, NULL, esp, "");
}

/*
 * The architecture-independent dump_stack generator
 */
void dump_stack(void)
{
	unsigned long stack;

	show_trace(current, NULL, &stack);
}

EXPORT_SYMBOL(dump_stack);

void show_registers(struct pt_regs *regs)
{
	int i;
	int in_kernel = 1;
	unsigned long esp;
	unsigned short ss;

	esp = (unsigned long) (&regs->esp);
	savesegment(ss, ss);
	if (user_mode_vm(regs)) {
		in_kernel = 0;
		esp = regs->esp;
		ss = regs->xss & 0xffff;
	}
	print_modules();
	printk(KERN_EMERG "CPU:    %d\nEIP:    %04x:[<%08lx>]    %s VLI\n"
			"EFLAGS: %08lx   (%s %.*s) \n",
		smp_processor_id(), 0xffff & regs->xcs, regs->eip,
		print_tainted(), regs->eflags, system_utsname.release,
		(int)strcspn(system_utsname.version, " "),
		system_utsname.version);
	print_symbol(KERN_EMERG "EIP is at %s\n", regs->eip);
	printk(KERN_EMERG "eax: %08lx   ebx: %08lx   ecx: %08lx   edx: %08lx\n",
		regs->eax, regs->ebx, regs->ecx, regs->edx);
	printk(KERN_EMERG "esi: %08lx   edi: %08lx   ebp: %08lx   esp: %08lx\n",
		regs->esi, regs->edi, regs->ebp, esp);
	printk(KERN_EMERG "ds: %04x   es: %04x   ss: %04x\n",
		regs->xds & 0xffff, regs->xes & 0xffff, ss);
	printk(KERN_EMERG "Process %.*s (pid: %d, ti=%p task=%p task.ti=%p)",
		TASK_COMM_LEN, current->comm, current->pid,
		current_thread_info(), current, current->thread_info);
	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (in_kernel) {
		u8 __user *eip;

		printk("\n" KERN_EMERG "Stack: ");
		show_stack_log_lvl(NULL, regs, (unsigned long *)esp, KERN_EMERG);

		printk(KERN_EMERG "Code: ");

		eip = (u8 __user *)regs->eip - 43;
		for (i = 0; i < 64; i++, eip++) {
			unsigned char c;

			if (eip < (u8 __user *)PAGE_OFFSET || __get_user(c, eip)) {
				printk(" Bad EIP value.");
				break;
			}
			if (eip == (u8 __user *)regs->eip)
				printk("<%02x> ", c);
			else
				printk("%02x ", c);
		}
	}
	printk("\n");
}	

static void handle_BUG(struct pt_regs *regs)
{
	unsigned long eip = regs->eip;
	unsigned short ud2;

	if (eip < PAGE_OFFSET)
		return;
	if (__get_user(ud2, (unsigned short __user *)eip))
		return;
	if (ud2 != 0x0b0f)
		return;

	printk(KERN_EMERG "------------[ cut here ]------------\n");
#ifdef CONFIG_DEBUG_BUGVERBOSE
	do {
		unsigned short line;
		char *file;
		char c;

		if (__get_user(line, (unsigned short __user *)(eip + 2)))
			break;
		if (__get_user(file, (char * __user *)(eip + 4)) ||
		    (unsigned long)file < PAGE_OFFSET || __get_user(c, file))
			file = "<bad filename>";

		printk(KERN_EMERG "kernel BUG at %s:%d!\n", file, line);
		return;
	} while (0);
#endif
	printk(KERN_EMERG "Kernel BUG at [verbose debug info unavailable]\n");
}

/* This is gone through when something in the kernel
 * has done something bad and is about to be terminated.
*/
void die(const char * str, struct pt_regs * regs, long err)
{
	static struct {
		spinlock_t lock;
		u32 lock_owner;
		int lock_owner_depth;
	} die = {
		.lock =			SPIN_LOCK_UNLOCKED,
		.lock_owner =		-1,
		.lock_owner_depth =	0
	};
	static int die_counter;
	unsigned long flags;

	oops_enter();

	if (die.lock_owner != raw_smp_processor_id()) {
		console_verbose();
		spin_lock_irqsave(&die.lock, flags);
		die.lock_owner = smp_processor_id();
		die.lock_owner_depth = 0;
		bust_spinlocks(1);
	}
	else
		local_save_flags(flags);

	if (++die.lock_owner_depth < 3) {
		int nl = 0;
		unsigned long esp;
		unsigned short ss;

		handle_BUG(regs);
		printk(KERN_EMERG "%s: %04lx [#%d]\n", str, err & 0xffff, ++die_counter);
#ifdef CONFIG_PREEMPT
		printk(KERN_EMERG "PREEMPT ");
		nl = 1;
#endif
#ifdef CONFIG_SMP
		if (!nl)
			printk(KERN_EMERG);
		printk("SMP ");
		nl = 1;
#endif
#ifdef CONFIG_DEBUG_PAGEALLOC
		if (!nl)
			printk(KERN_EMERG);
		printk("DEBUG_PAGEALLOC");
		nl = 1;
#endif
		if (nl)
			printk("\n");
#ifdef CONFIG_SYSFS
		printk(KERN_ALERT "last sysfs file: %s\n", last_sysfs_file);
#endif
		if (notify_die(DIE_OOPS, str, regs, err,
					current->thread.trap_no, SIGSEGV) !=
				NOTIFY_STOP) {
			show_registers(regs);
			/* Executive summary in case the oops scrolled away */
			esp = (unsigned long) (&regs->esp);
			savesegment(ss, ss);
			if (user_mode(regs)) {
				esp = regs->esp;
				ss = regs->xss & 0xffff;
			}
			printk(KERN_EMERG "EIP: [<%08lx>] ", regs->eip);
			print_symbol("%s", regs->eip);
			printk(" SS:ESP %04x:%08lx\n", ss, esp);
		}
		else
			regs = NULL;
  	} else
		printk(KERN_EMERG "Recursive die() failure, output suppressed\n");

	bust_spinlocks(0);
	die.lock_owner = -1;
	spin_unlock_irqrestore(&die.lock, flags);

	if (!regs)
		return;

	if (kexec_should_crash(current))
		crash_kexec(regs);

	if (in_interrupt())
		panic("Fatal exception in interrupt");

	if (panic_on_oops)
		panic("Fatal exception");

	oops_exit();
	do_exit(SIGSEGV);
}

static inline void die_if_kernel(const char * str, struct pt_regs * regs, long err)
{
	if (!user_mode_vm(regs))
		die(str, regs, err);
}

static void __kprobes do_trap(int trapnr, int signr, char *str, int vm86,
			      struct pt_regs * regs, long error_code,
			      siginfo_t *info)
{
	struct task_struct *tsk = current;
	tsk->thread.error_code = error_code;
	tsk->thread.trap_no = trapnr;

	if (regs->eflags & VM_MASK) {
		if (vm86)
			goto vm86_trap;
		goto trap_signal;
	}

	if (!user_mode(regs))
		goto kernel_trap;

	trap_signal: {
		if (info)
			force_sig_info(signr, info, tsk);
		else
			force_sig(signr, tsk);
		return;
	}

	kernel_trap: {
		if (!fixup_exception(regs))
			die(str, regs, error_code);
		return;
	}

	vm86_trap: {
		int ret = handle_vm86_trap((struct kernel_vm86_regs *) regs, error_code, trapnr);
		if (ret) goto trap_signal;
		return;
	}
}

#define DO_ERROR(trapnr, signr, str, name) \
fastcall void do_##name(struct pt_regs * regs, long error_code) \
{ \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 0, regs, error_code, NULL); \
}

#define DO_ERROR_INFO(trapnr, signr, str, name, sicode, siaddr) \
fastcall void do_##name(struct pt_regs * regs, long error_code) \
{ \
	siginfo_t info; \
	info.si_signo = signr; \
	info.si_errno = 0; \
	info.si_code = sicode; \
	info.si_addr = (void __user *)siaddr; \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 0, regs, error_code, &info); \
}

#define DO_VM86_ERROR(trapnr, signr, str, name) \
fastcall void do_##name(struct pt_regs * regs, long error_code) \
{ \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 1, regs, error_code, NULL); \
}

#define DO_VM86_ERROR_INFO(trapnr, signr, str, name, sicode, siaddr) \
fastcall void do_##name(struct pt_regs * regs, long error_code) \
{ \
	siginfo_t info; \
	info.si_signo = signr; \
	info.si_errno = 0; \
	info.si_code = sicode; \
	info.si_addr = (void __user *)siaddr; \
	if (notify_die(DIE_TRAP, str, regs, error_code, trapnr, signr) \
						== NOTIFY_STOP) \
		return; \
	do_trap(trapnr, signr, str, 1, regs, error_code, &info); \
}

DO_VM86_ERROR_INFO( 0, SIGFPE,  "divide error", divide_error, FPE_INTDIV, regs->eip)
#ifndef CONFIG_KPROBES
DO_VM86_ERROR( 3, SIGTRAP, "int3", int3)
#endif
DO_VM86_ERROR( 4, SIGSEGV, "overflow", overflow)
DO_VM86_ERROR( 5, SIGSEGV, "bounds", bounds)
DO_ERROR_INFO( 6, SIGILL,  "invalid opcode", invalid_op, ILL_ILLOPN, regs->eip)
DO_ERROR( 9, SIGFPE,  "coprocessor segment overrun", coprocessor_segment_overrun)
DO_ERROR(10, SIGSEGV, "invalid TSS", invalid_TSS)
DO_ERROR(11, SIGBUS,  "segment not present", segment_not_present)
DO_ERROR(12, SIGBUS,  "stack segment", stack_segment)
DO_ERROR_INFO(17, SIGBUS, "alignment check", alignment_check, BUS_ADRALN, 0)


/*
 * lazy-check for CS validity on exec-shield binaries:
 *
 * the original non-exec stack patch was written by
 * Solar Designer <solar at openwall.com>. Thanks!
 */
static int
check_lazy_exec_limit(int cpu, struct pt_regs *regs, long error_code)
{
	struct desc_struct *desc1, *desc2;
	struct vm_area_struct *vma;
	unsigned long limit;

	if (current->mm == NULL)
		return 0;

	limit = -1UL;
	if (current->mm->context.exec_limit != -1UL) {
		limit = PAGE_SIZE;
		spin_lock(&current->mm->page_table_lock);
		for (vma = current->mm->mmap; vma; vma = vma->vm_next)
			if ((vma->vm_flags & VM_EXEC) && (vma->vm_end > limit))
				limit = vma->vm_end;
		spin_unlock(&current->mm->page_table_lock);
		if (limit >= TASK_SIZE)
			limit = -1UL;
		current->mm->context.exec_limit = limit;
	}
	set_user_cs(&current->mm->context.user_cs, limit);

	desc1 = &current->mm->context.user_cs;
	desc2 = get_cpu_gdt_table(cpu) + GDT_ENTRY_DEFAULT_USER_CS;

	if ((desc1->a & 0xff0000ff) != (desc2->a & 0xff0000ff) ||
            desc1->b != desc2->b) {
		/*
		 * The CS was not in sync - reload it and retry the
		 * instruction. If the instruction still faults then
		 * we won't hit this branch next time around.
		 */
		if (print_fatal_signals >= 2) {
			printk("#GPF fixup (%ld[seg:%lx]) at %08lx, CPU#%d.\n", error_code, error_code/8, regs->eip, smp_processor_id());
			printk(" exec_limit: %08lx, user_cs: %08lx/%08lx, CPU_cs: %08lx/%08lx.\n", current->mm->context.exec_limit, desc1->a, desc1->b, desc2->a, desc2->b);
		}
		load_user_cs_desc(cpu, current->mm);
		return 1;
	}

	return 0;
}

/*
 * The fixup code for errors in iret jumps to here (iret_exc).  It loses
 * the original trap number and error code.  The bogus trap 32 and error
 * code 0 are what the vanilla kernel delivers via:
 * DO_ERROR_INFO(32, SIGSEGV, "iret exception", iret_error, ILL_BADSTK, 0)
 *
 * In case of a general protection fault in the iret instruction, we
 * need to check for a lazy CS update for exec-shield.
 */
fastcall void do_iret_error(struct pt_regs *regs, long error_code)
{
	int ok;
#ifndef CONFIG_XEN	
	local_irq_enable();
#endif
	ok = check_lazy_exec_limit(get_cpu(), regs, error_code);
	put_cpu();
	if (!ok && notify_die(DIE_TRAP, "iret exception", regs,
			      error_code, 32, SIGSEGV) != NOTIFY_STOP) {
		siginfo_t info;
		info.si_signo = SIGSEGV;
		info.si_errno = 0;
		info.si_code = ILL_BADSTK;
		info.si_addr = 0;
		do_trap(32, SIGSEGV, "iret exception", 0, regs, error_code,
			&info);
	}
}

fastcall void __kprobes do_general_protection(struct pt_regs * regs,
					      long error_code)
{
	int cpu = get_cpu();
	int ok;

	current->thread.error_code = error_code;
	current->thread.trap_no = 13;

	if (regs->eflags & VM_MASK)
		goto gp_in_vm86;

	if (!user_mode(regs))
		goto gp_in_kernel;

	ok = check_lazy_exec_limit(cpu, regs, error_code);

	put_cpu();

	if (ok)
		return;

	if (print_fatal_signals) {
		printk("#GPF(%ld[seg:%lx]) at %08lx, CPU#%d.\n", error_code, error_code/8, regs->eip, smp_processor_id());
		printk(" exec_limit: %08lx, user_cs: %08lx/%08lx.\n", current->mm->context.exec_limit, current->mm->context.user_cs.a, current->mm->context.user_cs.b);
	}

	current->thread.error_code = error_code;
	current->thread.trap_no = 13;
	force_sig(SIGSEGV, current);
	return;

gp_in_vm86:
	put_cpu();
	local_irq_enable();
	handle_vm86_fault((struct kernel_vm86_regs *) regs, error_code);
	return;

gp_in_kernel:
	put_cpu();
	if (!fixup_exception(regs)) {
		if (notify_die(DIE_GPF, "general protection fault", regs,
				error_code, 13, SIGSEGV) == NOTIFY_STOP)
			return;
		die("general protection fault", regs, error_code);
	}
}

static void mem_parity_error(unsigned char reason, struct pt_regs * regs)
{
	printk(KERN_EMERG "Uhhuh. NMI received for unknown reason %02x on "
		"CPU %d.\n", reason, smp_processor_id());
	printk(KERN_EMERG "You probably have a hardware problem with your RAM "
			"chips\n");
	if (panic_on_unrecovered_nmi)
                panic("NMI: Not continuing");

	printk(KERN_EMERG "Dazed and confused, but trying to continue\n");

	/* Clear and disable the memory parity error line. */
	clear_mem_error(reason);
}

static void io_check_error(unsigned char reason, struct pt_regs * regs)
{
	printk(KERN_EMERG "NMI: IOCK error (debug interrupt?)\n");
	show_registers(regs);

	/* Re-enable the IOCK line, wait for a few seconds */
	clear_io_check_error(reason);
}

static void unknown_nmi_error(unsigned char reason, struct pt_regs * regs)
{
#ifdef CONFIG_MCA
	/* Might actually be able to figure out what the guilty party
	* is. */
	if( MCA_bus ) {
		mca_handle_nmi();
		return;
	}
#endif
	printk(KERN_EMERG "Uhhuh. NMI received for unknown reason %02x on "
		"CPU %d.\n", reason, smp_processor_id());
	printk(KERN_EMERG "Do you have a strange power saving mode enabled?\n");
	if (panic_on_unrecovered_nmi)
                panic("NMI: Not continuing");

	printk(KERN_EMERG "Dazed and confused, but trying to continue\n");
}

static DEFINE_SPINLOCK(nmi_print_lock);

void die_nmi (struct pt_regs *regs, const char *msg)
{
	if (notify_die(DIE_NMIWATCHDOG, msg, regs, 0, 2, SIGINT) ==
	    NOTIFY_STOP)
		return;

	spin_lock(&nmi_print_lock);
	/*
	* We are in trouble anyway, lets at least try
	* to get a message out.
	*/
	bust_spinlocks(1);
	printk(KERN_EMERG "%s", msg);
	printk(" on CPU%d, eip %08lx, registers:\n",
		smp_processor_id(), regs->eip);
	show_registers(regs);
	printk(KERN_EMERG "console shuts up ...\n");
	console_silent();

	/* If we are in kernel we are probably nested up pretty bad
	 * and might aswell get out now while we still can.
	*/
	if (!user_mode_vm(regs)) {
		current->thread.trap_no = 2;
		crash_kexec(regs);
	}

	bust_spinlocks(0);
	spin_unlock(&nmi_print_lock);

	do_exit(SIGSEGV);
}

static void default_do_nmi(struct pt_regs * regs)
{
	unsigned char reason = 0;
	int cpu;

	cpu = smp_processor_id();

	/* Only the BSP gets external NMIs from the system.  */
	if (!cpu)
		reason = get_nmi_reason();
 
	if (!(reason & 0xc0)) {
		if (notify_die(DIE_NMI_IPI, "nmi_ipi", regs, reason, 2, SIGINT)
							== NOTIFY_STOP)
			return;
		/*
		 * Ok, so this is none of the documented NMI sources,
		 * so it must be the NMI watchdog.
		 */
		if (nmi_watchdog_tick(regs))
			return;

		if (!do_nmi_callback(regs, cpu))
			unknown_nmi_error(reason, regs);
		return;
	}
	if (notify_die(DIE_NMI, "nmi", regs, reason, 2, SIGINT) == NOTIFY_STOP)
		return;
	if (reason & 0x80)
		mem_parity_error(reason, regs);
	if (reason & 0x40)
		io_check_error(reason, regs);
	/*
	 * Reassert NMI in case it became active meanwhile
	 * as it's edge-triggered.
	 */
	reassert_nmi();
}

static int dummy_nmi_callback(struct pt_regs * regs, int cpu)
{
	return 0;
}
 
static nmi_callback_t nmi_callback = dummy_nmi_callback;
 
fastcall void do_nmi(struct pt_regs * regs, long error_code)
{
	int cpu;

	nmi_enter();

	cpu = smp_processor_id();

	++nmi_count(cpu);

	if (!rcu_dereference(nmi_callback)(regs, cpu))
		default_do_nmi(regs);

	nmi_exit();
}

void set_nmi_callback(nmi_callback_t callback)
{
	vmalloc_sync_all();
	rcu_assign_pointer(nmi_callback, callback);
}
EXPORT_SYMBOL_GPL(set_nmi_callback);

void unset_nmi_callback(void)
{
	nmi_callback = dummy_nmi_callback;
}
EXPORT_SYMBOL_GPL(unset_nmi_callback);

#ifdef CONFIG_KPROBES
fastcall void __kprobes do_int3(struct pt_regs *regs, long error_code)
{
	if (notify_die(DIE_INT3, "int3", regs, error_code, 3, SIGTRAP)
			== NOTIFY_STOP)
		return;
	/* This is an interrupt gate, because kprobes wants interrupts
	disabled.  Normal trap handlers don't. */
	restore_interrupts(regs);
	do_trap(3, SIGTRAP, "int3", 1, regs, error_code, NULL);
}
#endif

/*
 * Our handling of the processor debug registers is non-trivial.
 * We do not clear them on entry and exit from the kernel. Therefore
 * it is possible to get a watchpoint trap here from inside the kernel.
 * However, the code in ./ptrace.c has ensured that the user can
 * only set watchpoints on userspace addresses. Therefore the in-kernel
 * watchpoint trap can only occur in code which is reading/writing
 * from user space. Such code must not hold kernel locks (since it
 * can equally take a page fault), therefore it is safe to call
 * force_sig_info even though that claims and releases locks.
 * 
 * Code in ./signal.c ensures that the debug control register
 * is restored before we deliver any signal, and therefore that
 * user code runs with the correct debug control register even though
 * we clear it here.
 *
 * Being careful here means that we don't have to be as careful in a
 * lot of more complicated places (task switching can be a bit lazy
 * about restoring all the debug state, and ptrace doesn't have to
 * find every occurrence of the TF bit that could be saved away even
 * by user code)
 */
fastcall void __kprobes do_debug(struct pt_regs * regs, long error_code)
{
	unsigned int condition;
	struct task_struct *tsk = current;

	get_debugreg(condition, 6);

	if (notify_die(DIE_DEBUG, "debug", regs, condition, error_code,
					SIGTRAP) == NOTIFY_STOP)
		return;
	/* It's safe to allow irq's after DR6 has been saved */
	if (regs->eflags & X86_EFLAGS_IF)
		local_irq_enable();

	/* Mask out spurious debug traps due to lazy DR7 setting */
	if (condition & (DR_TRAP0|DR_TRAP1|DR_TRAP2|DR_TRAP3)) {
		if (!tsk->thread.debugreg[7])
			goto clear_dr7;
	}

	if (regs->eflags & VM_MASK)
		goto debug_vm86;

	/* Save debug status register where ptrace can see it */
	tsk->thread.debugreg[6] = condition;

	/*
	 * Single-stepping through TF: make sure we ignore any events in
	 * kernel space (but re-enable TF when returning to user mode).
	 */
	if (condition & DR_STEP) {
		/*
		 * We already checked v86 mode above, so we can
		 * check for kernel mode by just checking the CPL
		 * of CS.
		 */
		if (!user_mode(regs))
			goto clear_TF_reenable;
	}

	/* Ok, finally something we can handle */
	send_sigtrap(tsk, regs, error_code);

	/* Disable additional traps. They'll be re-enabled when
	 * the signal is delivered.
	 */
clear_dr7:
	set_debugreg(0, 7);
	return;

debug_vm86:
	handle_vm86_trap((struct kernel_vm86_regs *) regs, error_code, 1);
	return;

clear_TF_reenable:
	set_tsk_thread_flag(tsk, TIF_SINGLESTEP);
	regs->eflags &= ~TF_MASK;
	return;
}

/*
 * Note that we play around with the 'TS' bit in an attempt to get
 * the correct behaviour even in the presence of the asynchronous
 * IRQ13 behaviour
 */
void math_error(void __user *eip)
{
	struct task_struct * task;
	siginfo_t info;
	unsigned short cwd, swd;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	save_init_fpu(task);
	task->thread.trap_no = 16;
	task->thread.error_code = 0;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = __SI_FAULT;
	info.si_addr = eip;
	/*
	 * (~cwd & swd) will mask out exceptions that are not set to unmasked
	 * status.  0x3f is the exception bits in these regs, 0x200 is the
	 * C1 reg you need in case of a stack fault, 0x040 is the stack
	 * fault bit.  We should only be taking one exception at a time,
	 * so if this combination doesn't produce any single exception,
	 * then we have a bad program that isn't syncronizing its FPU usage
	 * and it will suffer the consequences since we won't be able to
	 * fully reproduce the context of the exception
	 */
	cwd = get_fpu_cwd(task);
	swd = get_fpu_swd(task);
	switch (swd & ~cwd & 0x3f) {
		case 0x000: /* No unmasked exception */
			return;
		default:    /* Multiple exceptions */
			break;
		case 0x001: /* Invalid Op */
			/*
			 * swd & 0x240 == 0x040: Stack Underflow
			 * swd & 0x240 == 0x240: Stack Overflow
			 * User must clear the SF bit (0x40) if set
			 */
			info.si_code = FPE_FLTINV;
			break;
		case 0x002: /* Denormalize */
		case 0x010: /* Underflow */
			info.si_code = FPE_FLTUND;
			break;
		case 0x004: /* Zero Divide */
			info.si_code = FPE_FLTDIV;
			break;
		case 0x008: /* Overflow */
			info.si_code = FPE_FLTOVF;
			break;
		case 0x020: /* Precision */
			info.si_code = FPE_FLTRES;
			break;
	}
	force_sig_info(SIGFPE, &info, task);
}

fastcall void do_coprocessor_error(struct pt_regs * regs, long error_code)
{
	ignore_fpu_irq = 1;
	math_error((void __user *)regs->eip);
}

static void simd_math_error(void __user *eip)
{
	struct task_struct * task;
	siginfo_t info;
	unsigned short mxcsr;

	/*
	 * Save the info for the exception handler and clear the error.
	 */
	task = current;
	save_init_fpu(task);
	task->thread.trap_no = 19;
	task->thread.error_code = 0;
	info.si_signo = SIGFPE;
	info.si_errno = 0;
	info.si_code = __SI_FAULT;
	info.si_addr = eip;
	/*
	 * The SIMD FPU exceptions are handled a little differently, as there
	 * is only a single status/control register.  Thus, to determine which
	 * unmasked exception was caught we must mask the exception mask bits
	 * at 0x1f80, and then use these to mask the exception bits at 0x3f.
	 */
	mxcsr = get_fpu_mxcsr(task);
	switch (~((mxcsr & 0x1f80) >> 7) & (mxcsr & 0x3f)) {
		case 0x000:
		default:
			break;
		case 0x001: /* Invalid Op */
			info.si_code = FPE_FLTINV;
			break;
		case 0x002: /* Denormalize */
		case 0x010: /* Underflow */
			info.si_code = FPE_FLTUND;
			break;
		case 0x004: /* Zero Divide */
			info.si_code = FPE_FLTDIV;
			break;
		case 0x008: /* Overflow */
			info.si_code = FPE_FLTOVF;
			break;
		case 0x020: /* Precision */
			info.si_code = FPE_FLTRES;
			break;
	}
	force_sig_info(SIGFPE, &info, task);
}

fastcall void do_simd_coprocessor_error(struct pt_regs * regs,
					  long error_code)
{
	if (cpu_has_xmm) {
		/* Handle SIMD FPU exceptions on PIII+ processors. */
		ignore_fpu_irq = 1;
		simd_math_error((void __user *)regs->eip);
	} else {
		/*
		 * Handle strange cache flush from user space exception
		 * in all other cases.  This is undocumented behaviour.
		 */
		if (regs->eflags & VM_MASK) {
			handle_vm86_fault((struct kernel_vm86_regs *)regs,
					  error_code);
			return;
		}
		current->thread.trap_no = 19;
		current->thread.error_code = error_code;
		die_if_kernel("cache flush denied", regs, error_code);
		force_sig(SIGSEGV, current);
	}
}

#ifndef CONFIG_XEN
fastcall void do_spurious_interrupt_bug(struct pt_regs * regs,
					  long error_code)
{
#if 0
	/* No need to warn about this any longer. */
	printk("Ignoring P6 Local APIC Spurious Interrupt Bug...\n");
#endif
}

fastcall void setup_x86_bogus_stack(unsigned char * stk)
{
	unsigned long *switch16_ptr, *switch32_ptr;
	struct pt_regs *regs;
	unsigned long stack_top, stack_bot;
	unsigned short iret_frame16_off;
	int cpu = smp_processor_id();
	/* reserve the space on 32bit stack for the magic switch16 pointer */
	memmove(stk, stk + 8, sizeof(struct pt_regs));
	switch16_ptr = (unsigned long *)(stk + sizeof(struct pt_regs));
	regs = (struct pt_regs *)stk;
	/* now the switch32 on 16bit stack */
	stack_bot = (unsigned long)&per_cpu(cpu_16bit_stack, cpu);
	stack_top = stack_bot +	CPU_16BIT_STACK_SIZE;
	switch32_ptr = (unsigned long *)(stack_top - 8);
	iret_frame16_off = CPU_16BIT_STACK_SIZE - 8 - 20;
	/* copy iret frame on 16bit stack */
	memcpy((void *)(stack_bot + iret_frame16_off), &regs->eip, 20);
	/* fill in the switch pointers */
	switch16_ptr[0] = (regs->esp & 0xffff0000) | iret_frame16_off;
	switch16_ptr[1] = __ESPFIX_SS;
	switch32_ptr[0] = (unsigned long)stk + sizeof(struct pt_regs) +
		8 - CPU_16BIT_STACK_SIZE;
	switch32_ptr[1] = __KERNEL_DS;
}

fastcall unsigned char * fixup_x86_bogus_stack(unsigned short sp)
{
	unsigned long *switch32_ptr;
	unsigned char *stack16, *stack32;
	unsigned long stack_top, stack_bot;
	int len;
	int cpu = smp_processor_id();
	stack_bot = (unsigned long)&per_cpu(cpu_16bit_stack, cpu);
	stack_top = stack_bot +	CPU_16BIT_STACK_SIZE;
	switch32_ptr = (unsigned long *)(stack_top - 8);
	/* copy the data from 16bit stack to 32bit stack */
	len = CPU_16BIT_STACK_SIZE - 8 - sp;
	stack16 = (unsigned char *)(stack_bot + sp);
	stack32 = (unsigned char *)
		(switch32_ptr[0] + CPU_16BIT_STACK_SIZE - 8 - len);
	memcpy(stack32, stack16, len);
	return stack32;
}
#endif

/*
 *  'math_state_restore()' saves the current math information in the
 * old math state array, and gets the new ones from the current task
 *
 * Careful.. There are problems with IBM-designed IRQ13 behaviour.
 * Don't touch unless you *really* know how it works.
 *
 * Must be called with kernel preemption disabled (in this case,
 * local interrupts are disabled at the call-site in entry.S).
 */
asmlinkage void math_state_restore(struct pt_regs regs)
{
	struct thread_info *thread = current_thread_info();
	struct task_struct *tsk = thread->task;

	/* NB. 'clts' is done for us by Xen during virtual trap. */
	if (!tsk_used_math(tsk))
		init_fpu(tsk);
	restore_fpu(tsk);
	thread->status |= TS_USEDFPU;	/* So we fnsave on switch_to() */
}

#ifndef CONFIG_MATH_EMULATION

asmlinkage void math_emulate(long arg)
{
	printk(KERN_EMERG "math-emulation not enabled and no coprocessor found.\n");
	printk(KERN_EMERG "killing %s.\n",current->comm);
	force_sig(SIGFPE,current);
	schedule();
}

#endif /* CONFIG_MATH_EMULATION */

#ifdef CONFIG_X86_F00F_BUG
void __init trap_init_f00f_bug(void)
{
	__set_fixmap(FIX_F00F_IDT, __pa_symbol(&idt_table), PAGE_KERNEL_RO);

	/*
	 * Update the IDT descriptor and reload the IDT so that
	 * it uses the read-only mapped virtual address.
	 */
	idt_descr.address = fix_to_virt(FIX_F00F_IDT);
	load_idt(&idt_descr);
}
#endif


/*
 * NB. All these are "trap gates" (i.e. events_mask isn't set) except
 * for those that specify <dpl>|4 in the second field.
 */
static trap_info_t trap_table[] = {
	{  0, 0, __KERNEL_CS, (unsigned long)divide_error		},
	{  1, 0|4, __KERNEL_CS, (unsigned long)debug			},
	{  3, 3|4, __KERNEL_CS, (unsigned long)int3			},
	{  4, 3, __KERNEL_CS, (unsigned long)overflow			},
	{  5, 0, __KERNEL_CS, (unsigned long)bounds			},
	{  6, 0, __KERNEL_CS, (unsigned long)invalid_op			},
	{  7, 0|4, __KERNEL_CS, (unsigned long)device_not_available	},
	{  9, 0, __KERNEL_CS, (unsigned long)coprocessor_segment_overrun },
	{ 10, 0, __KERNEL_CS, (unsigned long)invalid_TSS		},
	{ 11, 0, __KERNEL_CS, (unsigned long)segment_not_present	},
	{ 12, 0, __KERNEL_CS, (unsigned long)stack_segment		},
	{ 13, 0, __KERNEL_CS, (unsigned long)general_protection		},
	{ 14, 0|4, __KERNEL_CS, (unsigned long)page_fault		},
	{ 15, 0, __KERNEL_CS, (unsigned long)fixup_4gb_segment		},
	{ 16, 0, __KERNEL_CS, (unsigned long)coprocessor_error		},
	{ 17, 0, __KERNEL_CS, (unsigned long)alignment_check		},
#ifdef CONFIG_X86_MCE
	{ 18, 0, __KERNEL_CS, (unsigned long)machine_check		},
#endif
	{ 19, 0, __KERNEL_CS, (unsigned long)simd_coprocessor_error	},
	{ SYSCALL_VECTOR,  3, __KERNEL_CS, (unsigned long)system_call	},
	{  0, 0,	   0, 0						}
};

void __init trap_init(void)
{
	HYPERVISOR_set_trap_table(trap_table);

	if (cpu_has_fxsr) {
		/*
		 * Verify that the FXSAVE/FXRSTOR data will be 16-byte aligned.
		 * Generates a compile-time "error: zero width for bit-field" if
		 * the alignment is wrong.
		 */
		struct fxsrAlignAssert {
			int _:!(offsetof(struct task_struct,
					thread.i387.fxsave) & 15);
		};

		printk(KERN_INFO "Enabling fast FPU save and restore... ");
		set_in_cr4(X86_CR4_OSFXSR);
		printk("done.\n");
	}
	if (cpu_has_xmm) {
		printk(KERN_INFO "Enabling unmasked SIMD FPU exception "
				"support... ");
		set_in_cr4(X86_CR4_OSXMMEXCPT);
		printk("done.\n");
	}

	/*
	 * Should be a barrier for any external CPU state.
	 */
	cpu_init();
}

void smp_trap_init(trap_info_t *trap_ctxt)
{
	trap_info_t *t = trap_table;

	for (t = trap_table; t->address; t++) {
		trap_ctxt[t->vector].flags = t->flags;
		trap_ctxt[t->vector].cs = t->cs;
		trap_ctxt[t->vector].address = t->address;
	}
}

static int __init kstack_setup(char *s)
{
	kstack_depth_to_print = simple_strtoul(s, NULL, 0);
	return 1;
}
__setup("kstack=", kstack_setup);

