/*
 *  linux/arch/i386/nmi.c
 *
 *  NMI watchdog support on APIC systems
 *
 *  Started by Ingo Molnar <mingo@redhat.com>
 *
 *  Fixes:
 *  Mikael Pettersson	: AMD K7 support for local APIC NMI watchdog.
 *  Mikael Pettersson	: Power Management for local APIC NMI watchdog.
 *  Mikael Pettersson	: Pentium 4 support for local APIC NMI watchdog.
 *  Pavel Machek and
 *  Mikael Pettersson	: PM converted to driver model. Disable/enable API.
 */

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/sysdev.h>
#include <linux/sysctl.h>
#include <linux/percpu.h>

#include <asm/smp.h>
#include <asm/nmi.h>
#include <asm/intel_arch_perfmon.h>
#include <asm/kdebug.h>

#include "mach_traps.h"

unsigned int nmi_watchdog = NMI_NONE;
int unknown_nmi_panic;
int nmi_watchdog_enabled;
static unsigned int nmi_hz = HZ;
extern void show_registers(struct pt_regs *regs);

static volatile unsigned long lapic_nmi_reserved;

/*
 * the upstream variable 'nmi_active' is called 'nmi_watchdog_active' on
 * RHEL-5 for kABI reasons.
 */
atomic_t nmi_watchdog_active = ATOMIC_INIT(0);

static DEFINE_PER_CPU(short, wd_enabled);

/* nmi_active:
 * +1: the lapic NMI watchdog is active, but can be disabled
 *  0: the lapic NMI watchdog has not been set up, and cannot
 *     be enabled
 * -1: the lapic NMI watchdog is disabled, but can be enabled
 */
int nmi_active;

static int endflag __initdata = 0;

#ifdef CONFIG_SMP
/* The performance counters used by NMI_LOCAL_APIC don't trigger when
 * the CPU is idle. To make sure the NMI watchdog really ticks on all
 * CPUs during the test make them busy.
 */
static __init void nmi_cpu_busy(void *data)
{
	local_irq_enable_in_hardirq();
	/* Intentionally don't use cpu_relax here. This is
	   to make sure that the performance counter really ticks,
	   even if there is a simulator or similar that catches the
	   pause instruction. On a real HT machine this is fine because
	   all other CPUs are busy with "useless" delay loops and don't
	   care if they get somewhat less cycles. */
	while (endflag == 0)
		mb();
}
#endif

static int __init check_nmi_watchdog(void)
{
	unsigned int *prev_nmi_count;
	int cpu;

	if (!atomic_read(&nmi_watchdog_active))
		return 0;

	if (nmi_watchdog == NMI_NONE)
		return 0;

	prev_nmi_count = kmalloc(NR_CPUS * sizeof(int), GFP_KERNEL);
	if (!prev_nmi_count)
		return -1;

	if (nmi_watchdog == NMI_LOCAL_APIC)
		smp_call_function(nmi_cpu_busy, NULL, 0, 0);

	for_each_possible_cpu(cpu)
		prev_nmi_count[cpu] = per_cpu(irq_stat, cpu).__nmi_count;
	local_irq_enable();
	mdelay((20*1000)/nmi_hz); // wait 20 ticks

	for_each_possible_cpu(cpu) {
		if (!per_cpu(wd_enabled, cpu))
			continue;

#ifdef CONFIG_SMP
		/* Check cpu_callin_map here because that is set
		   after the timer is started. */
		if (!cpu_isset(cpu, cpu_callin_map))
			continue;
#endif
		if (nmi_count(cpu) - prev_nmi_count[cpu] == 0) {
			endflag = 1;
			printk(KERN_WARNING "WARNING: CPU#%d: NMI "
			       "appears to be stuck (%d->%d)!\n",
				cpu,
				prev_nmi_count[cpu],
				nmi_count(cpu));
			if (atomic_dec_and_test(&nmi_watchdog_active))
				nmi_active = 0;
			per_cpu(wd_enabled, cpu) = 0;
			if (nmi_watchdog == NMI_LOCAL_APIC)
				lapic_watchdog_stop();
			else
				apic_write(APIC_LVT0, APIC_DM_NMI | APIC_LVT_MASKED);
			kfree(prev_nmi_count);
			return -1;
		} else {
			printk(KERN_DEBUG "CPU#%d: NMI watchdog performance "
					 "counter calibration - %d->%d\n",
					 cpu, prev_nmi_count[cpu],
					 nmi_count(cpu));
		}
	}
	if (!atomic_read(&nmi_watchdog_active)) {
		atomic_set(&nmi_watchdog_active, -1);
		nmi_active = -1;
		return -1;
	}

	endflag = 1;
	printk("NMI watchdog testing PASSED.\n");

	/* now that we know it works we can reduce NMI frequency to
	   something more reasonable; makes a difference in some configs */
	if (nmi_watchdog == NMI_LOCAL_APIC)
		nmi_hz = lapic_adjust_nmi_hz(1);

	kfree(prev_nmi_count);
	return 0;
}
/* This needs to happen later in boot so counters are working */
late_initcall(check_nmi_watchdog);

static int __init setup_nmi_watchdog(char *str)
{
	int nmi;

	get_option(&str, &nmi);

	if (nmi >= NMI_NONE && nmi < NMI_INVALID)
		nmi_watchdog = nmi;

	return 1;
}

__setup("nmi_watchdog=", setup_nmi_watchdog);

void acpi_nmi_enable(void);
void acpi_nmi_disable(void);
int reserve_lapic_nmi(void)
{
	if (!test_and_set_bit(1, &lapic_nmi_reserved)) {
		if (nmi_watchdog == NMI_LOCAL_APIC)
			disable_lapic_nmi_watchdog();
		return 0;
	}
	return 1;
}

void release_lapic_nmi(void)
{
	if (nmi_watchdog == NMI_LOCAL_APIC) {
		enable_lapic_nmi_watchdog();
		touch_nmi_watchdog();
	}
	clear_bit(1, &lapic_nmi_reserved);
}

static int old_ioapic_count;
void disable_timer_nmi_watchdog(void)
{
	unset_nmi_callback();
	old_ioapic_count = atomic_read(&nmi_watchdog_active);
	atomic_set(&nmi_watchdog_active, -1);
	nmi_active = -1;
}

void enable_timer_nmi_watchdog(void)
{
	if (nmi_watchdog == NMI_IO_APIC &&
	    atomic_read(&nmi_watchdog_active) < 0) {
		atomic_set(&nmi_watchdog_active, old_ioapic_count);
		touch_nmi_watchdog();
		nmi_active = 1;
	}
}

#ifdef CONFIG_PM

static int nmi_pm_active; /* nmi_active before suspend */

void stop_apic_nmi_watchdog(void);
static int lapic_nmi_suspend(struct sys_device *dev, pm_message_t state)
{
	nmi_pm_active = nmi_active;
	stop_apic_nmi_watchdog();
	return 0;
}

static int lapic_nmi_resume(struct sys_device *dev)
{
	if (nmi_pm_active > 0) {
		setup_apic_nmi_watchdog();
		touch_nmi_watchdog();
	}
	return 0;
}


static struct sysdev_class nmi_sysclass = {
	set_kset_name("lapic_nmi"),
	.resume		= lapic_nmi_resume,
	.suspend	= lapic_nmi_suspend,
};

static struct sys_device device_lapic_nmi = {
	.id	= 0,
	.cls	= &nmi_sysclass,
};

static int __init init_lapic_nmi_sysfs(void)
{
	int error;

	if (atomic_read(&nmi_watchdog_active) == 0 || nmi_watchdog != NMI_LOCAL_APIC)
		return 0;

	error = sysdev_class_register(&nmi_sysclass);
	if (!error)
		error = sysdev_register(&device_lapic_nmi);
	return error;
}
/* must come after the local APIC's device_initcall() */
late_initcall(init_lapic_nmi_sysfs);

#endif	/* CONFIG_PM */

void setup_apic_nmi_watchdog (void)
{
	if (__get_cpu_var(wd_enabled) == 1)
		return;

	switch (nmi_watchdog) {
	case NMI_LOCAL_APIC:
		__get_cpu_var(wd_enabled) = 1;
		if (lapic_watchdog_init(nmi_hz) < 0) {
			__get_cpu_var(wd_enabled) = 0;
			return;
		}
		/* FALL THROUGH */
	case NMI_IO_APIC:
		__get_cpu_var(wd_enabled) = 1;
		if (atomic_inc_return(&nmi_watchdog_active) == 1)
			nmi_active = 1;
	}
}

void stop_apic_nmi_watchdog(void)
{
	/* only support LOCAL and IO APICs for now */
	if ((nmi_watchdog != NMI_LOCAL_APIC) &&
	    (nmi_watchdog != NMI_IO_APIC))
		return;
	if (__get_cpu_var(wd_enabled) == 0)
		return;
	if (nmi_watchdog == NMI_LOCAL_APIC)
		lapic_watchdog_stop();
	__get_cpu_var(wd_enabled) = 0;
	if (atomic_dec_and_test(&nmi_watchdog_active))
		nmi_active = 0;
}

static void __acpi_nmi_enable(void *__unused)
{
	if (__get_cpu_var(wd_enabled) == 1)
		return;

	__get_cpu_var(wd_enabled) = 1;
	if (atomic_inc_return(&nmi_watchdog_active) == 1)
		nmi_active = 1;
	apic_write(APIC_LVT0, APIC_DM_NMI);
}

/*
 * Enable timer based NMIs on all CPUs:
 */
void acpi_nmi_enable(void)
{
	if (atomic_read(&nmi_watchdog_active) == 0)
		on_each_cpu(__acpi_nmi_enable, NULL, 0, 1);
	touch_nmi_watchdog();
}

static void __acpi_nmi_disable(void *__unused)
{
	if (__get_cpu_var(wd_enabled) == 0)
		return;
	apic_write(APIC_LVT0, APIC_DM_NMI | APIC_LVT_MASKED);
	__get_cpu_var(wd_enabled) = 0;
	if (atomic_dec_and_test(&nmi_watchdog_active))
		nmi_active = 0;
}

/*
 * Disable timer based NMIs on all CPUs:
 */
void acpi_nmi_disable(void)
{
	if (atomic_read(&nmi_watchdog_active))
		on_each_cpu(__acpi_nmi_disable, NULL, 0, 1);
}

/*
 * the best way to detect whether a CPU has a 'hard lockup' problem
 * is to check it's local APIC timer IRQ counts. If they are not
 * changing then that CPU has some problem.
 *
 * as these watchdog NMI IRQs are generated on every CPU, we only
 * have to check the current processor.
 *
 * since NMIs don't listen to _any_ locks, we have to be extremely
 * careful not to rely on unsafe variables. The printk might lock
 * up though, so we have to break up any console locks first ...
 * [when there will be more tty-related locks, break them up
 *  here too!]
 */

static unsigned int
	last_irq_sums [NR_CPUS],
	alert_counter [NR_CPUS];

void touch_nmi_watchdog (void)
{
	int i;

	/*
	 * Just reset the alert counters, (other CPUs might be
	 * spinning on locks we hold):
	 */
	for_each_possible_cpu(i)
		alert_counter[i] = 0;

	/*
	 * Tickle the softlockup detector too:
	 */
	touch_softlockup_watchdog();
}
EXPORT_SYMBOL(touch_nmi_watchdog);

extern void die_nmi(struct pt_regs *, const char *msg);

int nmi_watchdog_tick (struct pt_regs * regs)
{
	/*
	 * Since current_thread_info()-> is always on the stack, and we
	 * always switch the stack NMI-atomically, it's safe to use
	 * smp_processor_id().
	 */
	unsigned int sum, rc = 0;
	int cpu = smp_processor_id();

	sum = per_cpu(irq_stat, cpu).apic_timer_irqs;

	if (last_irq_sums[cpu] == sum) {
		/*
		 * Ayiee, looks like this CPU is stuck ...
		 * wait a few IRQs (30 seconds) before doing the oops ...
		 */
		alert_counter[cpu]++;
		if (alert_counter[cpu] == 30*nmi_hz)
			/*
			 * die_nmi will return ONLY if NOTIFY_STOP happens..
			 */
			die_nmi(regs, "BUG: NMI Watchdog detected LOCKUP");
	} else {
		last_irq_sums[cpu] = sum;
		alert_counter[cpu] = 0;
	}

	/* see if the nmi watchdog went off */
	if (!__get_cpu_var(wd_enabled))
		return rc;
	switch (nmi_watchdog) {
	case NMI_LOCAL_APIC:
		rc |= lapic_wd_event(nmi_hz);
		break;
	case NMI_IO_APIC:
		/* don't know how to accurately check for this.
		 * just assume it was a watchdog timer interrupt
		 * This matches the old behaviour.
		 */
		rc = 1;
		break;
 	}

	return rc;
}

static int unknown_nmi_panic_callback(struct pt_regs *regs, int cpu);
int do_nmi_callback(struct pt_regs *regs, int cpu)
{
#ifdef CONFIG_SYSCTL
	if (unknown_nmi_panic)
		unknown_nmi_panic_callback(regs, cpu);
#endif
	return 0;
}

#ifdef CONFIG_SYSCTL

static int unknown_nmi_panic_callback(struct pt_regs *regs, int cpu)
{
	unsigned char reason = get_nmi_reason();
	char buf[64];

	sprintf(buf, "NMI received for unknown reason %02x\n", reason);
	die_nmi(regs, buf);

	return 0;
}

/*
 * proc handler for /proc/sys/kernel/unknown_nmi_panic
 */
int proc_unknown_nmi_panic(ctl_table *table, int write, struct file *file,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	int old_state;

	old_state = unknown_nmi_panic;
	proc_dointvec(table, write, file, buffer, length, ppos);
	if (!!old_state == !!unknown_nmi_panic)
		return 0;

 	if (unknown_nmi_panic) {
		if (nmi_watchdog == NMI_LOCAL_APIC)
			disable_lapic_nmi_watchdog();
		else if (nmi_watchdog == NMI_IO_APIC)
			acpi_nmi_disable();
 	} else {
		if (nmi_watchdog == NMI_LOCAL_APIC)
			enable_lapic_nmi_watchdog();
		else if (nmi_watchdog == NMI_IO_APIC)
			acpi_nmi_enable();
 	}

	return 0;
}

/*
 * proc handler for /proc/sys/kernel/nmi_watchdog
 */
int proc_nmi_enabled(ctl_table *table, int write, struct file *file,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	int old_state;

	nmi_watchdog_enabled = (atomic_read(&nmi_watchdog_active) > 0) ? 1 : 0;
	old_state = nmi_watchdog_enabled;
	proc_dointvec(table, write, file, buffer, length, ppos);
	if (!!old_state == !!nmi_watchdog_enabled)
		return 0;

	if (nmi_watchdog_enabled) {
		if (nmi_watchdog == NMI_LOCAL_APIC)
			enable_lapic_nmi_watchdog();
		else if (nmi_watchdog == NMI_IO_APIC)
			acpi_nmi_enable();
	} else {
		if (nmi_watchdog == NMI_LOCAL_APIC)
			disable_lapic_nmi_watchdog();
		else if (nmi_watchdog == NMI_IO_APIC)
			acpi_nmi_disable();
	}

	return 0;
}

#endif

EXPORT_SYMBOL(nmi_active);
EXPORT_SYMBOL(nmi_watchdog);
EXPORT_SYMBOL(reserve_lapic_nmi);
EXPORT_SYMBOL(release_lapic_nmi);
EXPORT_SYMBOL(disable_timer_nmi_watchdog);
EXPORT_SYMBOL(enable_timer_nmi_watchdog);
