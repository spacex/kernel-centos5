/**
 * @file backtrace.c
 *
 * @remark Copyright 2002 OProfile authors
 * @remark Read the file COPYING
 *
 * @author John Levon
 * @author David Smith
 */

#include <linux/oprofile.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/ptrace.h>
#include <asm/uaccess.h>
#include <linux/compat.h>

struct frame_head {
	struct frame_head * ebp;
	unsigned long ret;
} __attribute__((packed));

static struct frame_head *
dump_kernel_backtrace(struct frame_head * head)
{
	oprofile_add_trace(head->ret);

	/* frame pointers should strictly progress back up the stack
	 * (towards higher addresses) */
	if (head >= head->ebp)
		return NULL;

	return head->ebp;
}

#ifdef CONFIG_COMPAT
struct stack_frame_ia32 {
	u32 next_frame;
	u32 return_address;
};

static struct stack_frame_ia32 *
dump_user_backtrace_32(struct stack_frame_ia32 *head)
{
	struct stack_frame_ia32 bufhead[2];
	struct stack_frame_ia32 *fp;

	/* Also check accessibility of one struct frame_head beyond */
	if (!access_ok(VERIFY_READ, head, sizeof(bufhead)))
		return NULL;
	if (__copy_from_user_inatomic(bufhead, head, sizeof(bufhead)))
		return NULL;

	fp = (struct stack_frame_ia32 *) compat_ptr(bufhead[0].next_frame);

	oprofile_add_trace(bufhead[0].return_address);

	/* frame pointers should strictly progress back up the stack
	* (towards higher addresses) */
	if (head >= fp)
		return NULL;

	return fp;
}

static inline int
x86_backtrace_32(struct pt_regs * const regs, unsigned int depth)
{
	struct stack_frame_ia32 *head;

	/* User process is 32-bit */
	if (!current || !test_thread_flag(TIF_IA32))
		return 0;

	head = (struct stack_frame_ia32 *) regs->rbp;
	while (depth-- && head)
		head = dump_user_backtrace_32(head);

	return 1;
}

#else
static inline int
x86_backtrace_32(struct pt_regs * const regs, unsigned int depth)
{
	return 0;
}
#endif /* CONFIG_COMPAT */

static struct frame_head *
dump_user_backtrace(struct frame_head * head)
{
	struct frame_head bufhead[2];

	/* Also check accessibility of one struct frame_head beyond */
	if (!access_ok(VERIFY_READ, head, sizeof(bufhead)))
		return NULL;
	if (__copy_from_user_inatomic(bufhead, head, sizeof(bufhead)))
		return NULL;

	oprofile_add_trace(bufhead[0].ret);

	/* frame pointers should strictly progress back up the stack
	 * (towards higher addresses) */
	if (head >= bufhead[0].ebp)
		return NULL;

	return bufhead[0].ebp;
}

/*
 * |             | /\ Higher addresses
 * |             |
 * --------------- stack base (address of current_thread_info)
 * | thread info |
 * .             .
 * |    stack    |
 * --------------- saved regs->ebp value if valid (frame_head address)
 * .             .
 * --------------- saved regs->rsp value if x86_64
 * |             |
 * --------------- struct pt_regs * stored on stack if 32-bit
 * |             |
 * .             .
 * |             |
 * --------------- %esp
 * |             |
 * |             | \/ Lower addresses
 *
 * Thus, regs (or regs->rsp for x86_64) <-> stack base restricts the
 * valid(ish) ebp values. Note: (1) for x86_64, NMI and several other
 * exceptions use special stacks, maintained by the interrupt stack table
 * (IST). These stacks are set up in trap_init() in
 * arch/x86_64/kernel/traps.c. Thus, for x86_64, regs now does not point
 * to the kernel stack; instead, it points to some location on the NMI
 * stack. On the other hand, regs->rsp is the stack pointer saved when the
 * NMI occurred. (2) For 32-bit, regs->esp is not valid because the
 * processor does not save %esp on the kernel stack when interrupts occur
 * in the kernel mode.
 */
#ifdef CONFIG_FRAME_POINTER
static int valid_kernel_stack(struct frame_head * head, struct pt_regs * regs)
{
	unsigned long headaddr = (unsigned long)head;
#ifdef CONFIG_X86_64
	unsigned long stack = (unsigned long)regs->rsp;
#else
	unsigned long stack = (unsigned long)regs;
#endif
	unsigned long stack_base = (stack & ~(THREAD_SIZE - 1)) + THREAD_SIZE;

	return headaddr > stack && headaddr < stack_base;
}
#else
/* without fp, it's just junk */
static int valid_kernel_stack(struct frame_head * head, struct pt_regs * regs)
{
	return 0;
}
#endif


void
x86_backtrace(struct pt_regs * const regs, unsigned int depth)
{
	struct frame_head *head;

#ifdef CONFIG_X86_64
	head = (struct frame_head *)regs->rbp;
#else
	head = (struct frame_head *)regs->ebp;
#endif

	if (!user_mode_vm(regs)) {
		while (depth-- && valid_kernel_stack(head, regs))
			head = dump_kernel_backtrace(head);
		return;
	}

	if (x86_backtrace_32(regs, depth))
		return;

	while (depth-- && head)
		head = dump_user_backtrace(head);
}
