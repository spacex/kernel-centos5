/*
 *  64-bit pSeries and RS/6000 setup code.
 *
 *  Copyright (C) 1995  Linus Torvalds
 *  Adapted from 'alpha' version by Gary Thomas
 *  Modified by Cort Dougan (cort@cs.nmt.edu)
 *  Modified by PPC64 Team, IBM Corp
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

/*
 * bootup setup stuff..
 */

#undef DEBUG

#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/tty.h>
#include <linux/major.h>
#include <linux/interrupt.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/console.h>
#include <linux/pci.h>
#include <linux/utsname.h>
#include <linux/adb.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/seq_file.h>
#include <linux/root_dev.h>
#include <linux/percpu.h>

#include <asm/mmu.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm/pgtable.h>
#include <asm/prom.h>
#include <asm/rtas.h>
#include <asm/pci-bridge.h>
#include <asm/iommu.h>
#include <asm/dma.h>
#include <asm/machdep.h>
#include <asm/irq.h>
#include <asm/kexec.h>
#include <asm/time.h>
#include <asm/nvram.h>
#include "xics.h"
#include <asm/pmc.h>
#include <asm/mpic.h>
#include <asm/ppc-pci.h>
#include <asm/i8259.h>
#include <asm/udbg.h>
#include <asm/smp.h>

#include "plpar_wrappers.h"
#include "ras.h"
#include "firmware.h"
#include "offline_states.h"

#ifdef DEBUG
#define DBG(fmt...) udbg_printf(fmt)
#else
#define DBG(fmt...)
#endif

static DEFINE_PER_CPU(enum cpu_state_vals, preferred_offline_state) =
							CPU_STATE_OFFLINE;
static DEFINE_PER_CPU(enum cpu_state_vals, current_state) = CPU_STATE_OFFLINE;

static enum cpu_state_vals default_offline_state = CPU_STATE_OFFLINE;

enum cpu_state_vals get_cpu_current_state(int cpu)
{
	return per_cpu(current_state, cpu);
}

void set_cpu_current_state(int cpu, enum cpu_state_vals state)
{
	per_cpu(current_state, cpu) = state;
}

enum cpu_state_vals get_preferred_offline_state(int cpu)
{
	return per_cpu(preferred_offline_state, cpu);
}

void set_preferred_offline_state(int cpu, enum cpu_state_vals state)
{
	per_cpu(preferred_offline_state, cpu) = state;
}

void set_default_offline_state(int cpu)
{
	per_cpu(preferred_offline_state, cpu) = default_offline_state;
}

/* move those away to a .h */
extern void smp_init_pseries_mpic(void);
extern void smp_init_pseries_xics(void);
extern void find_udbg_vterm(void);

int fwnmi_active;  /* TRUE if an FWNMI handler is present */

static void pseries_shared_idle_sleep(void);
static void pseries_dedicated_idle_sleep(void);

static struct device_node *pSeries_mpic_node;

static void pSeries_show_cpuinfo(struct seq_file *m)
{
	struct device_node *root;
	const char *model = "";

	root = of_find_node_by_path("/");
	if (root)
		model = get_property(root, "model", NULL);
	seq_printf(m, "machine\t\t: CHRP %s\n", model);
	of_node_put(root);
}

/* Initialize firmware assisted non-maskable interrupts if
 * the firmware supports this feature.
 */
static void __init fwnmi_init(void)
{
	unsigned long system_reset_addr, machine_check_addr;

	int ibm_nmi_register = rtas_token("ibm,nmi-register");
	if (ibm_nmi_register == RTAS_UNKNOWN_SERVICE)
		return;

	/* If the kernel's not linked at zero we point the firmware at low
	 * addresses anyway, and use a trampoline to get to the real code. */
	system_reset_addr  = __pa(system_reset_fwnmi) - PHYSICAL_START;
	machine_check_addr = __pa(machine_check_fwnmi) - PHYSICAL_START;

	if (0 == rtas_call(ibm_nmi_register, 2, 1, NULL, system_reset_addr,
				machine_check_addr))
		fwnmi_active = 1;
}

void pseries_8259_cascade(unsigned int irq, struct irq_desc *desc,
			  struct pt_regs *regs)
{
	unsigned int cascade_irq = i8259_irq(regs);
	if (cascade_irq != NO_IRQ)
		generic_handle_irq(cascade_irq, regs);
	desc->chip->eoi(irq);
}

static void __init pseries_mpic_init_IRQ(void)
{
	struct device_node *np, *old, *cascade = NULL;
        unsigned int *addrp;
	unsigned long intack = 0;
	unsigned int *opprop;
	unsigned long openpic_addr = 0;
	unsigned int cascade_irq;
	int naddr, n, i, opplen;
	struct mpic *mpic;

	np = of_find_node_by_path("/");
	naddr = prom_n_addr_cells(np);
	opprop = (unsigned int *) get_property(np, "platform-open-pic", &opplen);
	if (opprop != 0) {
		openpic_addr = of_read_number(opprop, naddr);
		printk(KERN_DEBUG "OpenPIC addr: %lx\n", openpic_addr);
	}
	of_node_put(np);

	BUG_ON(openpic_addr == 0);

	/* Setup the openpic driver */
	mpic = mpic_alloc(pSeries_mpic_node, openpic_addr,
			  MPIC_PRIMARY,
			  16, 250, /* isu size, irq count */
			  " MPIC     ");
	BUG_ON(mpic == NULL);

	/* Add ISUs */
	opplen /= sizeof(u32);
	for (n = 0, i = naddr; i < opplen; i += naddr, n++) {
		unsigned long isuaddr = of_read_number(opprop + i, naddr);
		mpic_assign_isu(mpic, n, isuaddr);
	}

	/* All ISUs are setup, complete initialization */
	mpic_init(mpic);

	/* Look for cascade */
	for_each_node_by_type(np, "interrupt-controller")
		if (device_is_compatible(np, "chrp,iic")) {
			cascade = np;
			break;
		}
	if (cascade == NULL)
		return;

	cascade_irq = irq_of_parse_and_map(cascade, 0);
	if (cascade == NO_IRQ) {
		printk(KERN_ERR "xics: failed to map cascade interrupt");
		return;
	}

	/* Check ACK type */
	for (old = of_node_get(cascade); old != NULL ; old = np) {
		np = of_get_parent(old);
		of_node_put(old);
		if (np == NULL)
			break;
		if (strcmp(np->name, "pci") != 0)
			continue;
		addrp = (u32 *)get_property(np, "8259-interrupt-acknowledge",
					    NULL);
		if (addrp == NULL)
			continue;
		naddr = prom_n_addr_cells(np);
		intack = addrp[naddr-1];
		if (naddr > 1)
			intack |= ((unsigned long)addrp[naddr-2]) << 32;
	}
	if (intack)
		printk(KERN_DEBUG "mpic: PCI 8259 intack at 0x%016lx\n",
		       intack);
	i8259_init(cascade, intack);
	of_node_put(cascade);
	set_irq_chained_handler(cascade_irq, pseries_8259_cascade);
}

static void pseries_lpar_enable_pmcs(void)
{
	unsigned long set, reset;

	set = 1UL << 63;
	reset = 0;
	plpar_hcall_norets(H_PERFMON, set, reset);

	/* instruct hypervisor to maintain PMCs */
	if (firmware_has_feature(FW_FEATURE_SPLPAR))
		get_lppaca()->pmcregs_in_use = 1;
}

#ifdef CONFIG_KEXEC
static void pseries_kexec_cpu_down_mpic(int crash_shutdown, int secondary)
{
	mpic_teardown_this_cpu(secondary);
}

static void pseries_kexec_cpu_down_xics(int crash_shutdown, int secondary)
{
	/* Don't risk a hypervisor call if we're crashing */
	if (firmware_has_feature(FW_FEATURE_SPLPAR) && !crash_shutdown) {
		unsigned long addr;

		addr = __pa(get_slb_shadow());
		if (unregister_slb_shadow(hard_smp_processor_id(), addr))
			printk("SLB shadow buffer deregistration of "
			       "cpu %u (hw_cpu_id %d) failed\n",
			       smp_processor_id(),
			       hard_smp_processor_id());

		addr = __pa(get_lppaca());
		if (unregister_vpa(hard_smp_processor_id(), addr)) {
			printk("VPA deregistration of cpu %u (hw_cpu_id %d) "
					"failed\n", smp_processor_id(),
					hard_smp_processor_id());
		}
	}
	xics_kexec_teardown_cpu(secondary);
}
#endif /* CONFIG_KEXEC */

static void __init pseries_discover_pic(void)
{
	struct device_node *np;
	char *typep;

	for (np = NULL; (np = of_find_node_by_name(np,
						   "interrupt-controller"));) {
		typep = (char *)get_property(np, "compatible", NULL);
		if (strstr(typep, "open-pic")) {
			pSeries_mpic_node = of_node_get(np);
			ppc_md.init_IRQ       = pseries_mpic_init_IRQ;
			ppc_md.get_irq        = mpic_get_irq;
#ifdef CONFIG_KEXEC
			ppc_md.kexec_cpu_down = pseries_kexec_cpu_down_mpic;
#endif
#ifdef CONFIG_SMP
			smp_init_pseries_mpic();
#endif
			return;
		} else if (strstr(typep, "ppc-xicp")) {
			ppc_md.init_IRQ       = xics_init_IRQ;
#ifdef CONFIG_KEXEC
			ppc_md.kexec_cpu_down = pseries_kexec_cpu_down_xics;
#endif
#ifdef CONFIG_SMP
			smp_init_pseries_xics();
#endif
			return;
		}
	}
	printk(KERN_ERR "pSeries_discover_pic: failed to recognize"
	       " interrupt-controller\n");
}

static void __init pSeries_setup_arch(void)
{
	/* Discover PIC type and setup ppc_md accordingly */
	pseries_discover_pic();

	/* openpic global configuration register (64-bit format). */
	/* openpic Interrupt Source Unit pointer (64-bit format). */
	/* python0 facility area (mmio) (64-bit format) REAL address. */

	/* init to some ~sane value until calibrate_delay() runs */
	loops_per_jiffy = 50000000;

	if (ROOT_DEV == 0) {
		printk("No ramdisk, default root is /dev/sda2\n");
		ROOT_DEV = Root_SDA2;
	}

	fwnmi_init();

	/* Find and initialize PCI host bridges */
	init_pci_config_tokens();
	find_and_init_phbs();
	eeh_init();

	pSeries_nvram_init();

	/* Choose an idle loop */
	if (firmware_has_feature(FW_FEATURE_SPLPAR)) {
		vpa_init(boot_cpuid);
		if (get_lppaca()->shared_proc) {
			printk(KERN_DEBUG "Using shared processor idle loop\n");
			ppc_md.power_save = pseries_shared_idle_sleep;
		} else {
			printk(KERN_DEBUG "Using dedicated idle loop\n");
			ppc_md.power_save = pseries_dedicated_idle_sleep;
		}
	} else {
		printk(KERN_DEBUG "Using default idle loop\n");
	}

	if (firmware_has_feature(FW_FEATURE_LPAR))
		ppc_md.enable_pmcs = pseries_lpar_enable_pmcs;
	else
		ppc_md.enable_pmcs = power4_enable_pmcs;
}

static int __init pSeries_init_panel(void)
{
	/* Manually leave the kernel version on the panel. */
	ppc_md.progress("Linux ppc64\n", 0);
	ppc_md.progress(system_utsname.release, 0);

	return 0;
}
arch_initcall(pSeries_init_panel);

static void pSeries_mach_cpu_die(void)
{
	unsigned int cpu = smp_processor_id();
	unsigned int hwcpu = hard_smp_processor_id();
	u8 cede_latency_hint = 0;

	local_irq_disable();
	idle_task_exit();
	xics_teardown_cpu();

	if (get_preferred_offline_state(cpu) == CPU_STATE_INACTIVE) {
		set_cpu_current_state(cpu, CPU_STATE_INACTIVE);
		pseries_suspend_cpu();

		cede_latency_hint = 2;
		get_lppaca()->idle = 1;

		while (get_preferred_offline_state(cpu) == CPU_STATE_INACTIVE) {
			extended_cede_processor(cede_latency_hint);
		}

		get_lppaca()->idle = 0;

		if (get_preferred_offline_state(cpu) == CPU_STATE_ONLINE) {
			unregister_slb_shadow(hwcpu, __pa(get_slb_shadow()));

			/*
			 * Call to start_secondary_resume() will not return.
			 * Kernel stack will be reset and start_secondary()
			 * will be called to continue the online operation.
			 */
			start_secondary_resume();
		}
	}

	/* Requested state is CPU_STATE_OFFLINE at this point */
	WARN_ON(get_preferred_offline_state(cpu) != CPU_STATE_OFFLINE);

	set_cpu_current_state(cpu, CPU_STATE_OFFLINE);
	unregister_slb_shadow(hard_smp_processor_id(), __pa(get_slb_shadow()));
	rtas_stop_self();
	/* Should never get here... */
	BUG();
	for(;;);
}

static int pseries_set_dabr(unsigned long dabr)
{
	return plpar_hcall_norets(H_SET_DABR, dabr);
}

static int pseries_set_xdabr(unsigned long dabr)
{
	/* We want to catch accesses from kernel and userspace */
	return plpar_hcall_norets(H_SET_XDABR, dabr,
			H_DABRX_KERNEL | H_DABRX_USER);
}

/*
 * Early initialization.  Relocation is on but do not reference unbolted pages
 */
static void __init pSeries_init_early(void)
{
	DBG(" -> pSeries_init_early()\n");

	fw_feature_init();

	if (firmware_has_feature(FW_FEATURE_LPAR))
		find_udbg_vterm();

	if (firmware_has_feature(FW_FEATURE_DABR))
		ppc_md.set_dabr = pseries_set_dabr;
	else if (firmware_has_feature(FW_FEATURE_XDABR))
		ppc_md.set_dabr = pseries_set_xdabr;

	iommu_init_early_pSeries();

	DBG(" <- pSeries_init_early()\n");
}


static int pSeries_check_legacy_ioport(unsigned int baseport)
{
	struct device_node *np = NULL;

#define I8042_DATA_REG	0x60
#define FDC_BASE	0x3f0

	switch(baseport) {
	case I8042_DATA_REG:
		np = of_find_node_by_type(NULL, "8042");
		break;
	case FDC_BASE:
		np = of_find_node_by_type(NULL, "fdc");
		break;
	default:
		/* ipmi is supposed to fail here */
		break;
	}
	if (!np)
		return -ENODEV;
	of_node_put(np);
	return 0;
}

/*
 * Called very early, MMU is off, device-tree isn't unflattened
 */

static int __init pSeries_probe_hypertas(unsigned long node,
					 const char *uname, int depth,
					 void *data)
{
	if (depth != 1 ||
	    (strcmp(uname, "rtas") != 0 && strcmp(uname, "rtas@0") != 0))
 		return 0;

	if (of_get_flat_dt_prop(node, "ibm,hypertas-functions", NULL) != NULL)
 		powerpc_firmware_features |= FW_FEATURE_LPAR;

	if (firmware_has_feature(FW_FEATURE_LPAR))
		hpte_init_lpar();
	else
		hpte_init_native();

 	return 1;
}

static int __init pSeries_probe(void)
{
	unsigned long root = of_get_flat_dt_root();
 	char *dtype = of_get_flat_dt_prop(of_get_flat_dt_root(),
 					  "device_type", NULL);
 	if (dtype == NULL)
 		return 0;
 	if (strcmp(dtype, "chrp"))
		return 0;

	/* Cell blades firmware claims to be chrp while it's not. Until this
	 * is fixed, we need to avoid those here.
	 */
	if (of_flat_dt_is_compatible(root, "IBM,CPBW-1.0") ||
	    of_flat_dt_is_compatible(root, "IBM,CBEA"))
		return 0;

	DBG("pSeries detected, looking for LPAR capability...\n");

	/* Now try to figure out if we are running on LPAR */
	of_scan_flat_dt(pSeries_probe_hypertas, NULL);

	DBG("Machine is%s LPAR !\n",
	    (powerpc_firmware_features & FW_FEATURE_LPAR) ? "" : " not");

	return 1;
}


DECLARE_PER_CPU(unsigned long, smt_snooze_delay);

static void pseries_dedicated_idle_sleep(void)
{ 
	unsigned int cpu = smp_processor_id();
	unsigned long start_snooze;
	unsigned long *smt_snooze_delay = &__get_cpu_var(smt_snooze_delay);
	unsigned long in_purr, out_purr;

	/*
	 * Indicate to the HV that we are idle. Now would be
	 * a good time to find other work to dispatch.
	 */
	get_lppaca()->idle = 1;
	get_lppaca()->cpuctls_task_attrs = 1;
	in_purr = mfspr(SPRN_PURR);

	/*
	 * We come in with interrupts disabled, and need_resched()
	 * has been checked recently.  If we should poll for a little
	 * while, do so.
	 */
	if (*smt_snooze_delay) {
		start_snooze = get_tb() +
			*smt_snooze_delay * tb_ticks_per_usec;
		local_irq_enable();
		set_thread_flag(TIF_POLLING_NRFLAG);

		while (get_tb() < start_snooze) {
			if (need_resched() || cpu_is_offline(cpu))
				goto out;
			ppc64_runlatch_off();
			HMT_low();
			HMT_very_low();
		}

		HMT_medium();
		clear_thread_flag(TIF_POLLING_NRFLAG);
		smp_mb();
		local_irq_disable();
		if (need_resched() || cpu_is_offline(cpu))
			goto out;
	}

	cede_processor();

out:
	HMT_medium();
	get_lppaca()->cpuctls_task_attrs = 0;
	out_purr = mfspr(SPRN_PURR);
	get_lppaca()->wait_state_cycles += out_purr - in_purr;
	get_lppaca()->idle = 0;
}

static void pseries_shared_idle_sleep(void)
{
	/*
	 * Indicate to the HV that we are idle. Now would be
	 * a good time to find other work to dispatch.
	 */
	get_lppaca()->idle = 1;

	/*
	 * Yield the processor to the hypervisor.  We return if
	 * an external interrupt occurs (which are driven prior
	 * to returning here) or if a prod occurs from another
	 * processor. When returning here, external interrupts
	 * are enabled.
	 */
	cede_processor();

	get_lppaca()->idle = 0;
}

static int pSeries_pci_probe_mode(struct pci_bus *bus)
{
	if (firmware_has_feature(FW_FEATURE_LPAR))
		return PCI_PROBE_DEVTREE;
	return PCI_PROBE_NORMAL;
}

/**
 * pSeries_power_off - tell firmware about how to power off the system.
 *
 * This function calls either the power-off rtas token in normal cases
 * or the ibm,power-off-ups token (if present & requested) in case of
 * a power failure. If power-off token is used, power on will only be
 * possible with power button press. If ibm,power-off-ups token is used
 * it will allow auto poweron after power is restored.
 */
void pSeries_power_off(void)
{
	int rc;
	int rtas_poweroff_ups_token = rtas_token("ibm,power-off-ups");

	if (rtas_flash_term_hook)
		rtas_flash_term_hook(SYS_POWER_OFF);

	if (rtas_poweron_auto == 0 ||
		rtas_poweroff_ups_token == RTAS_UNKNOWN_SERVICE) {
		rc = rtas_call(rtas_token("power-off"), 2, 1, NULL, -1, -1);
		printk(KERN_INFO "RTAS power-off returned %d\n", rc);
	} else {
		rc = rtas_call(rtas_poweroff_ups_token, 0, 1, NULL);
		printk(KERN_INFO "RTAS ibm,power-off-ups returned %d\n", rc);
	}
	for (;;);
}

define_machine(pseries) {
	.name			= "pSeries",
	.probe			= pSeries_probe,
	.setup_arch		= pSeries_setup_arch,
	.init_early		= pSeries_init_early,
	.show_cpuinfo		= pSeries_show_cpuinfo,
	.log_error		= pSeries_log_error,
	.pcibios_fixup		= pSeries_final_fixup,
	.pci_probe_mode		= pSeries_pci_probe_mode,
	.irq_bus_setup		= pSeries_irq_bus_setup,
	.restart		= rtas_restart,
	.power_off		= pSeries_power_off,
	.halt			= rtas_halt,
	.panic			= rtas_os_term,
	.cpu_die		= pSeries_mach_cpu_die,
	.get_boot_time		= rtas_get_boot_time,
	.get_rtc_time		= rtas_get_rtc_time,
	.set_rtc_time		= rtas_set_rtc_time,
	.calibrate_decr		= generic_calibrate_decr,
	.progress		= rtas_progress,
	.check_legacy_ioport	= pSeries_check_legacy_ioport,
	.system_reset_exception = pSeries_system_reset_exception,
	.machine_check_exception = pSeries_machine_check_exception,
#ifdef CONFIG_KEXEC
	.machine_kexec		= default_machine_kexec,
	.machine_kexec_prepare	= default_machine_kexec_prepare,
	.machine_crash_shutdown	= default_machine_crash_shutdown,
#endif
};
