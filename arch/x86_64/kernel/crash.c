/*
 * Architecture specific (x86_64) functions for kexec based crash dumps.
 *
 * Created by: Hariprasad Nellitheertha (hari@in.ibm.com)
 *
 * Copyright (C) IBM Corporation, 2004. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/reboot.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/elfcore.h>
#include <linux/pci.h>

#include <asm/processor.h>
#include <asm/hardirq.h>
#include <asm/nmi.h>
#include <asm/hw_irq.h>
#include <asm/mach_apic.h>
#include <linux/kvm_para.h>
#ifndef CONFIG_XEN
#include <asm/virtext.h>
#endif

/* This keeps a track of which one is crashing cpu. */
static int crashing_cpu;

static u32 *append_elf_note(u32 *buf, char *name, unsigned type,
						void *data, size_t data_len)
{
	struct elf_note note;

	note.n_namesz = strlen(name) + 1;
	note.n_descsz = data_len;
	note.n_type   = type;
	memcpy(buf, &note, sizeof(note));
	buf += (sizeof(note) +3)/4;
	memcpy(buf, name, note.n_namesz);
	buf += (note.n_namesz + 3)/4;
	memcpy(buf, data, note.n_descsz);
	buf += (note.n_descsz + 3)/4;

	return buf;
}

static void final_note(u32 *buf)
{
	struct elf_note note;

	note.n_namesz = 0;
	note.n_descsz = 0;
	note.n_type   = 0;
	memcpy(buf, &note, sizeof(note));
}

static void crash_save_this_cpu(struct pt_regs *regs, int cpu)
{
	struct elf_prstatus prstatus;
	u32 *buf;

	if ((cpu < 0) || (cpu >= NR_CPUS))
		return;

	/* Using ELF notes here is opportunistic.
	 * I need a well defined structure format
	 * for the data I pass, and I need tags
	 * on the data to indicate what information I have
	 * squirrelled away.  ELF notes happen to provide
	 * all of that that no need to invent something new.
	 */

	buf = (u32*)per_cpu_ptr(crash_notes, cpu);

	if (!buf)
		return;

	memset(&prstatus, 0, sizeof(prstatus));
	prstatus.pr_pid = current->pid;
	elf_core_copy_regs(&prstatus.pr_reg, regs);
	buf = append_elf_note(buf, "CORE", NT_PRSTATUS, &prstatus,
					sizeof(prstatus));
	final_note(buf);
}

static void crash_save_self(struct pt_regs *regs)
{
	int cpu;

	cpu = smp_processor_id();
	crash_save_this_cpu(regs, cpu);
}

#ifndef CONFIG_XEN
#ifdef CONFIG_SMP
static atomic_t waiting_for_crash_ipi;

static int crash_nmi_callback(struct pt_regs *regs, int cpu)
{
	/*
	 * Don't do anything if this handler is invoked on crashing cpu.
	 * Otherwise, system will completely hang. Crashing cpu can get
	 * an NMI if system was initially booted with nmi_watchdog parameter.
	 */
	if (cpu == crashing_cpu)
		return 1;
	local_irq_disable();

	crash_save_this_cpu(regs, cpu);

	/* Disable VMX or SVM if needed.
	 *
	 * We need to disable virtualization on all CPUs.
	 * Having VMX or SVM enabled on any CPU may break rebooting
	 * after the kdump kernel has finished its task.
	 */
	cpu_emergency_vmxoff();
	cpu_emergency_svm_disable();

	disable_local_APIC();
	atomic_dec(&waiting_for_crash_ipi);
	/* Assume hlt works */
	for(;;)
		halt();

	return 1;
}

static void smp_send_nmi_allbutself(void)
{
	send_IPI_allbutself(NMI_VECTOR);
}

/*
 * This code is a best effort heuristic to get the
 * other cpus to stop executing. So races with
 * cpu hotplug shouldn't matter.
 */

static void nmi_shootdown_cpus(void)
{
	unsigned long msecs;

	atomic_set(&waiting_for_crash_ipi, num_online_cpus() - 1);
	set_nmi_callback(crash_nmi_callback);

	/*
	 * Ensure the new callback function is set before sending
	 * out the NMI
	 */
	wmb();

	smp_send_nmi_allbutself();

	msecs = 1000; /* Wait at most a second for the other cpus to stop */
	while ((atomic_read(&waiting_for_crash_ipi) > 0) && msecs) {
		mdelay(1);
		msecs--;
	}
	/* Leave the nmi callback set */
	disable_local_APIC();
}
#else
static void nmi_shootdown_cpus(void)
{
	/* There are no cpus to shootdown */
}
#endif
#endif /* CONFIG_XEN */

extern struct pci_dev *mcp55_rewrite;
void machine_crash_shutdown(struct pt_regs *regs)
{

#ifndef CONFIG_XEN
	kvmclock_disable();
#endif
	/*
	 * This function is only called after the system
	 * has panicked or is otherwise in a critical state.
	 * The minimum amount of code to allow a kexec'd kernel
	 * to run successfully needs to happen here.
	 *
	 * In practice this means shooting down the other cpus in
	 * an SMP system.
	 */
	/* The kernel is broken so disable interrupts */
	local_irq_disable();

	/* Make a note of crashing cpu. Will be used in NMI callback.*/
	crashing_cpu = smp_processor_id();

#ifndef CONFIG_XEN
	nmi_shootdown_cpus();

	/* Booting kdump kernel with VMX or SVM enabled won't work,
	 * because (among other limitations) we can't disable paging
	 * with the virt flags.
	 */
	cpu_emergency_vmxoff();
	cpu_emergency_svm_disable();

	if(cpu_has_apic)
		 disable_local_APIC();

#if defined(CONFIG_X86_IO_APIC)
	disable_IO_APIC();
#endif
	if (crashing_cpu && mcp55_rewrite) {
		u32 cfg;
		printk(KERN_CRIT "REWRITING MCP55 CFG REG\n");
		/*
		 * We have a mcp55 chip on board which has been 
		 * flagged as only sending legacy interrupts
		 * to the BSP, and we are crashing on an AP
		 * This is obviously bad, and we need to 
		 * fix it up.  To do this we write to the 
		 * flagged device, to the register at offset 0x74
		 * and we make sure that bit 2 and bit 15 are clear
		 * This forces legacy interrupts to be broadcast
		 * to all cpus
		 */
		pci_read_config_dword(mcp55_rewrite, 0x74, &cfg);
		cfg &= ~((1 << 2) | (1 << 15));
		printk(KERN_CRIT "CFG = %x\n", cfg);
		pci_write_config_dword(mcp55_rewrite, 0x74, cfg);
	}
#endif /* CONFIG_XEN */
	crash_save_self(regs);
}
