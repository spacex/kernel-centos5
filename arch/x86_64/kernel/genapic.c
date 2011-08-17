/*
 * Copyright 2004 James Cleverdon, IBM.
 * Subject to the GNU Public License, v.2
 *
 * Generic APIC sub-arch probe layer.
 *
 * Hacked for x86-64 by James Cleverdon from i386 architecture code by
 * Martin Bligh, Andi Kleen, James Bottomley, John Stultz, and
 * James Cleverdon.
 */
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/module.h>

#include <asm/smp.h>
#include <asm/ipi.h>

#if defined(CONFIG_ACPI)
#include <acpi/acpi_bus.h>
#endif

/* which logical CPU number maps to which CPU (physical APIC ID) */
u8 x86_cpu_to_apicid[NR_CPUS] __read_mostly = { [0 ... NR_CPUS-1] = BAD_APICID };
EXPORT_SYMBOL(x86_cpu_to_apicid);
u8 x86_cpu_to_log_apicid[NR_CPUS] = { [0 ... NR_CPUS-1] = BAD_APICID };

extern struct genapic apic_cluster;
extern struct genapic apic_flat;
extern struct genapic apic_physflat;

struct genapic *genapic = &apic_flat;


/*
 * Check the APIC IDs in bios_cpu_apicid and choose the APIC mode.
 */
void __init clustered_apic_check(void)
{
	int i, max_apic = 0;

	if (apic_is_clustered_box()) {
		genapic = &apic_cluster;
	} else {
#ifdef CONFIG_HOTPLUG_CPU
		/* Don't use APIC shortcuts in CPU hotplug to avoid races */
		genapic = &apic_physflat;
		/* In the CPU hotplug case we cannot use broadcast mode
		   because that opens a race when a CPU is removed.
		   Stay at physflat mode in this case.
		   It is bad to do this unconditionally though. Once
		   we have ACPI platform support for CPU hotplug
		   we should detect hotplug capablity from ACPI tables and
		   only do this when really needed. -AK */
		if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
			for (i = 0; i < NR_CPUS; i++) {
				if (bios_cpu_apicid[i] == BAD_APICID)
					continue;
				if (bios_cpu_apicid[i] > max_apic)
					max_apic = bios_cpu_apicid[i];
			}

			if (max_apic <= 8)
				genapic = &apic_flat;
		}
#else
		genapic = &apic_flat;
#endif
	}

	printk(KERN_INFO "Setting APIC routing to %s\n", genapic->name);
}

/* Same for both flat and clustered. */

void send_IPI_self(int vector)
{
	__send_IPI_shortcut(APIC_DEST_SELF, vector, APIC_DEST_PHYSICAL);
}
