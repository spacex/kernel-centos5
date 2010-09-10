/*
 * mce.c - x86 Machine Check Exception Reporting
 * (c) 2002 Alan Cox <alan@redhat.com>, Dave Jones <davej@codemonkey.org.uk>
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/thread_info.h>

#include <asm/processor.h> 
#include <asm/system.h>

#include "mce.h"

int mce_disabled = 0;
int nr_mce_banks;

EXPORT_SYMBOL_GPL(nr_mce_banks);	/* non-fatal.o */

/* Handle unconfigured int18 (should never happen) */
static fastcall void unexpected_machine_check(struct pt_regs * regs, long error_code)
{	
	printk(KERN_ERR "CPU#%d: Unexpected int18 (Machine Check).\n", smp_processor_id());
}

/* Call the installed machine check handler for this CPU setup. */
void fastcall (*machine_check_vector)(struct pt_regs *, long error_code) = unexpected_machine_check;

/* This has to be run for each processor */
void mcheck_init(struct cpuinfo_x86 *c)
{
	if (mce_disabled==1)
		return;

	switch (c->x86_vendor) {
		case X86_VENDOR_AMD:
			amd_mcheck_init(c);
			break;

		case X86_VENDOR_INTEL:
			if (c->x86==5)
				intel_p5_mcheck_init(c);
			if (c->x86==6)
				intel_p6_mcheck_init(c);
			if (c->x86==15)
				intel_p4_mcheck_init(c);
			break;

		case X86_VENDOR_CENTAUR:
			if (c->x86==5)
				winchip_mcheck_init(c);
			break;

		default:
			break;
	}
}

void mce_panic(char *msg)
{
	static atomic_t mce_entry = ATOMIC_INIT(0);
	/*
	 * Machine check panics often come up from multiple CPUs in parallel.
	 * panic doesn't handle that well and deadlocks, so synchronize here.
	 */
	int first = atomic_add_return(1, &mce_entry) == 1;

	if (!first) {
		/*
		 * Enable interrupts so that smp_stop_cpus() can interrupts us,
		 * but prevent scheduling in case someone compiles this
		 * preemptible.
		 * Then wait for the other panic to shut us down.
		 */
		preempt_disable();
		local_irq_enable();
		printk("CPU %d: MCE PANIC: %s\n", smp_processor_id(), msg);
		for (;;)
			cpu_relax();
	}

	oops_in_progress = 1;
	panic(msg);
}

static int __init mcheck_disable(char *str)
{
	mce_disabled = 1;
	return 1;
}

static int __init mcheck_enable(char *str)
{
	mce_disabled = -1;
	return 1;
}

__setup("nomce", mcheck_disable);
__setup("mce", mcheck_enable);
