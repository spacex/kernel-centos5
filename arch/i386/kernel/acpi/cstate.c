/*
 * arch/i386/kernel/acpi/cstate.c
 *
 * Copyright (C) 2005 Intel Corporation
 * 	Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 * 	- Added _PDC for SMP C-states on Intel CPUs
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/acpi.h>

#include <acpi/processor.h>
#include <asm/acpi.h>

/*
 * Initialize bm_flags based on the CPU cache properties
 * On SMP it depends on cache configuration
 * - When cache is not shared among all CPUs, we flush cache
 *   before entering C3.
 * - When cache is shared among all CPUs, we use bm_check
 *   mechanism as in UP case
 *
 * This routine is called only after all the CPUs are online
 */
void acpi_processor_power_init_bm_check(struct acpi_processor_flags *flags,
					unsigned int cpu)
{
	struct cpuinfo_x86 *c = cpu_data + cpu;

	flags->bm_check = 0;
	if (num_online_cpus() == 1)
		flags->bm_check = 1;
	else if (c->x86_vendor == X86_VENDOR_INTEL) {
		/*
		 * Today all MP CPUs that support C3 share cache.
		 * And caches should not be flushed by software while
		 * entering C3 type state.
		 */
		flags->bm_check = 1;
	}

	/*
	 * On all recent Intel platforms, ARB_DISABLE is a nop.
	 * So, set bm_control to zero to indicate that ARB_DISABLE
	 * is not required while entering C3 type state on
	 * P4, Core and beyond CPUs
	 */
	if (c->x86_vendor == X86_VENDOR_INTEL &&
	    (c->x86 > 0x6 || (c->x86 == 6 && c->x86_model >= 14)))
			flags->bm_control = 0;
}

EXPORT_SYMBOL(acpi_processor_power_init_bm_check);
