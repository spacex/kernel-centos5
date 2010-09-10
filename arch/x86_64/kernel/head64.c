/*
 *  linux/arch/x86_64/kernel/head64.c -- prepare to run common code
 *
 *  Copyright (C) 2000 Andrea Arcangeli <andrea@suse.de> SuSE
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/percpu.h>

#include <asm/processor.h>
#include <asm/proto.h>
#include <asm/smp.h>
#include <asm/bootsetup.h>
#include <asm/setup.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>

static void __init zap_identity_mappings(void)
{
	pgd_t *pgd = pgd_offset_k(0UL);
	pgd_clear(pgd);
	__flush_tlb();
}

/* Don't add a printk in there. printk relies on the PDA which is not initialized 
   yet. */
static void __init clear_bss(void)
{
	memset(__bss_start, 0,
	       (unsigned long) __bss_stop - (unsigned long) __bss_start);
}

#define NEW_CL_POINTER		0x228	/* Relative to real mode data */
#define OLD_CL_MAGIC_ADDR	0x20
#define OLD_CL_MAGIC            0xA33F
#define OLD_CL_OFFSET           0x22

extern char saved_command_line[];

static void __init copy_bootdata(char *real_mode_data)
{
	unsigned long new_data;
	char * command_line;

	memcpy(x86_boot_params, real_mode_data, BOOT_PARAM_SIZE);
	new_data = *(u32 *) (x86_boot_params + NEW_CL_POINTER);
	if (!new_data) {
		if (OLD_CL_MAGIC != *(u16 *)(real_mode_data + OLD_CL_MAGIC_ADDR)) {
			return;
		}
		new_data = __pa(real_mode_data) + *(u16 *)(real_mode_data + OLD_CL_OFFSET);
	}
	command_line = __va(new_data);
	memcpy(saved_command_line, command_line, COMMAND_LINE_SIZE);
}

static void __init setup_boot_cpu_data(void)
{
	unsigned int dummy, eax;

	/* get vendor info */
	cpuid(0, (unsigned int *)&boot_cpu_data.cpuid_level,
	      (unsigned int *)&boot_cpu_data.x86_vendor_id[0],
	      (unsigned int *)&boot_cpu_data.x86_vendor_id[8],
	      (unsigned int *)&boot_cpu_data.x86_vendor_id[4]);

	/* get cpu type */
	cpuid(1, &eax, &dummy, &dummy,
		(unsigned int *) &boot_cpu_data.x86_capability);
	boot_cpu_data.x86 = (eax >> 8) & 0xf;
	boot_cpu_data.x86_model = (eax >> 4) & 0xf;
	boot_cpu_data.x86_mask = eax & 0xf;
}

void __init x86_64_start_kernel(char * real_mode_data)
{
	char *s;
	int i;

	for (i = 0; i < 256; i++)
		set_intr_gate(i, early_idt_handler);
	asm volatile("lidt %0" :: "m" (idt_descr));
	clear_bss();
	barrier();

	/* Make NULL pointers segfault */
	zap_identity_mappings();

	early_printk("Kernel alive\n");

 	for (i = 0; i < NR_CPUS; i++)
 		cpu_pda(i) = &boot_cpu_pda[i];

	pda_init(0);
	copy_bootdata(__va(real_mode_data));
#ifdef CONFIG_SMP
	cpu_set(0, cpu_online_map);
#endif
	s = strstr(saved_command_line, "earlyprintk=");
	if (s != NULL)
		setup_early_printk(strchr(s, '=') + 1);
#ifdef CONFIG_NUMA
	s = strstr(saved_command_line, "numa=");
	if (s != NULL)
		numa_setup(s+5);
#endif
#ifdef CONFIG_X86_IO_APIC
	if (strstr(saved_command_line, "disableapic"))
		disable_apic = 1;
#endif
	/* You need early console to see that */
	if (((unsigned long)&_end) >= (__START_KERNEL_map + KERNEL_TEXT_SIZE))
		panic("Kernel too big for kernel mapping\n");

	setup_boot_cpu_data();
	start_kernel();
}
