/* 
 * X86-64 specific CPU setup.
 * Copyright (C) 1995  Linus Torvalds
 * Copyright 2001, 2002, 2003 SuSE Labs / Andi Kleen.
 * See setup.c for older changelog.
 *
 * Jun Nakajima <jun.nakajima@intel.com> 
 *   Modified for Xen
 *
 */ 
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/bootmem.h>
#include <linux/bitops.h>
#include <linux/module.h>
#include <asm/bootsetup.h>
#include <asm/pda.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/desc.h>
#include <asm/atomic.h>
#include <asm/mmu_context.h>
#include <asm/smp.h>
#include <asm/i387.h>
#include <asm/percpu.h>
#include <asm/proto.h>
#include <asm/sections.h>
#ifdef CONFIG_XEN
#include <asm/hypervisor.h>
#endif

char x86_boot_params[BOOT_PARAM_SIZE] __initdata = {0,};

cpumask_t cpu_initialized __cpuinitdata = CPU_MASK_NONE;

struct x8664_pda *_cpu_pda[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(_cpu_pda);
struct x8664_pda boot_cpu_pda[NR_CPUS] __cacheline_aligned;

#ifndef CONFIG_X86_NO_IDT
struct desc_ptr idt_descr = { 256 * 16 - 1, (unsigned long) idt_table }; 
#endif

char boot_cpu_stack[IRQSTACKSIZE] __attribute__((section(".bss.page_aligned")));

unsigned long __supported_pte_mask __read_mostly = ~0UL;
EXPORT_SYMBOL(__supported_pte_mask);
static int do_not_nx __cpuinitdata = 0;

/* noexec=on|off
Control non executable mappings for 64bit processes.

on	Enable(default)
off	Disable
*/ 
void __init nonx_setup(char *str)
{
	if (!strncmp(str, "on", 2)) {
                __supported_pte_mask |= _PAGE_NX; 
 		do_not_nx = 0; 
	} else if (!strncmp(str, "off", 3)) {
		do_not_nx = 1;
		__supported_pte_mask &= ~_PAGE_NX;
        }
}

/*
 * Great future plan:
 * Declare PDA itself and support (irqstack,tss,pgd) as per cpu data.
 * Always point %gs to its beginning
 */
void __init setup_per_cpu_areas(void)
{ 
	int i;
	unsigned long size;

#ifdef CONFIG_HOTPLUG_CPU
	prefill_possible_map();
#endif

	/* Copy section for each CPU (we discard the original) */
	size = ALIGN(__per_cpu_end - __per_cpu_start, SMP_CACHE_BYTES);
#ifdef CONFIG_MODULES
	if (size < PERCPU_ENOUGH_ROOM)
		size = PERCPU_ENOUGH_ROOM;
#endif

	for_each_cpu_mask (i, cpu_possible_map) {
		char *ptr;

		if (!NODE_DATA(cpu_to_node(i))) {
			printk("cpu with no node %d, num_online_nodes %d\n",
			       i, num_online_nodes());
			ptr = alloc_bootmem(size);
		} else { 
			ptr = alloc_bootmem_node(NODE_DATA(cpu_to_node(i)), size);
		}
		if (!ptr)
			panic("Cannot allocate cpu data for CPU %d\n", i);
		cpu_pda(i)->data_offset = ptr - __per_cpu_start;
		memcpy(ptr, __per_cpu_start, __per_cpu_end - __per_cpu_start);
	}
} 

#ifdef CONFIG_XEN
static void switch_pt(void)
{
	xen_pt_switch(__pa(init_level4_pgt));
        xen_new_user_pt(__pa(init_level4_user_pgt));
}

void __cpuinit cpu_gdt_init(struct desc_ptr *gdt_descr)
{
	unsigned long frames[16];
	unsigned long va;
	int f;

	for (va = gdt_descr->address, f = 0;
	     va < gdt_descr->address + gdt_descr->size;
	     va += PAGE_SIZE, f++) {
		frames[f] = virt_to_mfn(va);
		make_page_readonly(
			(void *)va, XENFEAT_writable_descriptor_tables);
	}
	if (HYPERVISOR_set_gdt(frames, gdt_descr->size /
                               sizeof (struct desc_struct)))
		BUG();
}
#else
static void switch_pt(void)
{
	asm volatile("movq %0,%%cr3" :: "r" (__pa_symbol(&init_level4_pgt)));
}

void __init cpu_gdt_init(struct desc_ptr *gdt_descr)
{
	asm volatile("lgdt %0" :: "m" (*gdt_descr));
	asm volatile("lidt %0" :: "m" (idt_descr));
}
#endif

void pda_init(int cpu)
{ 
	struct x8664_pda *pda = cpu_pda(cpu);

	/* Setup up data that may be needed in __get_free_pages early */
	asm volatile("movl %0,%%fs ; movl %0,%%gs" :: "r" (0)); 
#ifndef CONFIG_XEN
	wrmsrl(MSR_GS_BASE, pda);
#else
	HYPERVISOR_set_segment_base(SEGBASE_GS_KERNEL, (unsigned long)pda);
#endif
	pda->cpunumber = cpu; 
	pda->irqcount = -1;
	pda->kernelstack = 
		(unsigned long)stack_thread_info() - PDA_STACKOFFSET + THREAD_SIZE; 
	pda->active_mm = &init_mm;
	pda->mmu_state = 0;

	if (cpu == 0) {
#ifdef CONFIG_XEN
		xen_init_pt();
#endif
		/* others are initialized in smpboot.c */
		pda->pcurrent = &init_task;
		pda->irqstackptr = boot_cpu_stack; 
	} else {
		pda->irqstackptr = (char *)
			__get_free_pages(GFP_ATOMIC, IRQSTACK_ORDER);
		if (!pda->irqstackptr)
			panic("cannot allocate irqstack for cpu %d", cpu); 
	}

	switch_pt();

	pda->irqstackptr += IRQSTACKSIZE-64;
} 

#ifndef CONFIG_X86_NO_TSS
char boot_exception_stacks[(N_EXCEPTION_STACKS - 1) * EXCEPTION_STKSZ + DEBUG_STKSZ]
__attribute__((section(".bss.page_aligned")));
#endif

/* May not be marked __init: used by software suspend */
void syscall_init(void)
{
#ifndef CONFIG_XEN
	/* 
	 * LSTAR and STAR live in a bit strange symbiosis.
	 * They both write to the same internal register. STAR allows to set CS/DS
	 * but only a 32bit target. LSTAR sets the 64bit rip. 	 
	 */ 
	wrmsrl(MSR_STAR,  ((u64)__USER32_CS)<<48  | ((u64)__KERNEL_CS)<<32); 
	wrmsrl(MSR_LSTAR, system_call); 

	/* Flags to clear on syscall */
	wrmsrl(MSR_SYSCALL_MASK, EF_TF|EF_DF|EF_IE|0x3000); 
#endif
#ifdef CONFIG_IA32_EMULATION   		
	syscall32_cpu_init ();
#endif
}

void __cpuinit check_efer(void)
{
	unsigned long efer;

	rdmsrl(MSR_EFER, efer); 
        if (!(efer & EFER_NX) || do_not_nx) { 
                __supported_pte_mask &= ~_PAGE_NX; 
        }       
}

unsigned long kernel_eflags;

/*
 * cpu_init() initializes state that is per-CPU. Some data is already
 * initialized (naturally) in the bootstrap process, such as the GDT
 * and IDT. We reload them nevertheless, this function acts as a
 * 'CPU state barrier', nothing should get across.
 * A lot of state is already set up in PDA init.
 */
void __cpuinit cpu_init (void)
{
	int cpu = stack_smp_processor_id();
#ifndef CONFIG_X86_NO_TSS
	struct tss_struct *t = &per_cpu(init_tss, cpu);
	struct orig_ist *orig_ist = &per_cpu(orig_ist, cpu);
	unsigned long v; 
	char *estacks = NULL; 
	unsigned i;
#endif
	struct task_struct *me;

	/* CPU 0 is initialised in head64.c */
	if (cpu != 0) {
		pda_init(cpu);
	}
#ifndef CONFIG_X86_NO_TSS
	else
		estacks = boot_exception_stacks; 
#endif

	me = current;

	if (cpu_test_and_set(cpu, cpu_initialized))
		panic("CPU#%d already initialized!\n", cpu);

	printk("Initializing CPU#%d\n", cpu);

	clear_in_cr4(X86_CR4_VME|X86_CR4_PVI|X86_CR4_TSD|X86_CR4_DE);

	/*
	 * Initialize the per-CPU GDT with the boot GDT,
	 * and set up the GDT descriptor:
	 */
#ifndef CONFIG_XEN 
	if (cpu)
 		memcpy(cpu_gdt(cpu), cpu_gdt_table, GDT_SIZE);
#endif

	cpu_gdt_descr[cpu].size = GDT_SIZE;
	cpu_gdt_init(&cpu_gdt_descr[cpu]);

	memset(me->thread.tls_array, 0, GDT_ENTRY_TLS_ENTRIES * 8);
	syscall_init();

	wrmsrl(MSR_FS_BASE, 0);
	wrmsrl(MSR_KERNEL_GS_BASE, 0);
	barrier(); 

	check_efer();

#ifndef CONFIG_X86_NO_TSS
	/*
	 * set up and load the per-CPU TSS
	 */
	for (v = 0; v < N_EXCEPTION_STACKS; v++) {
		if (cpu) {
			static const unsigned int order[N_EXCEPTION_STACKS] = {
				[0 ... N_EXCEPTION_STACKS - 1] = EXCEPTION_STACK_ORDER,
				[DEBUG_STACK - 1] = DEBUG_STACK_ORDER
			};

			estacks = (char *)__get_free_pages(GFP_ATOMIC, order[v]);
			if (!estacks)
				panic("Cannot allocate exception stack %ld %d\n",
				      v, cpu); 
		}
		switch (v + 1) {
#if DEBUG_STKSZ > EXCEPTION_STKSZ
		case DEBUG_STACK:
			cpu_pda(cpu)->debugstack = (unsigned long)estacks;
			estacks += DEBUG_STKSZ;
			break;
#endif
		default:
			estacks += EXCEPTION_STKSZ;
			break;
		}
		orig_ist->ist[v] = t->ist[v] = (unsigned long)estacks;
	}

	t->io_bitmap_base = offsetof(struct tss_struct, io_bitmap);
	/*
	 * <= is required because the CPU will access up to
	 * 8 bits beyond the end of the IO permission bitmap.
	 */
	for (i = 0; i <= IO_BITMAP_LONGS; i++)
		t->io_bitmap[i] = ~0UL;
#endif

	atomic_inc(&init_mm.mm_count);
	me->active_mm = &init_mm;
	if (me->mm)
		BUG();
	enter_lazy_tlb(&init_mm, me);

#ifndef CONFIG_X86_NO_TSS
	set_tss_desc(cpu, t);
#endif
#ifndef CONFIG_XEN
	load_TR_desc();
#endif
	load_LDT(&init_mm.context);

	/*
	 * Clear all 6 debug registers:
	 */

	set_debugreg(0UL, 0);
	set_debugreg(0UL, 1);
	set_debugreg(0UL, 2);
	set_debugreg(0UL, 3);
	set_debugreg(0UL, 6);
	set_debugreg(0UL, 7);

	fpu_init(); 

	raw_local_save_flags(kernel_eflags);
}
