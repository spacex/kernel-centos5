/*
 * This code largely moved from arch/i386/kernel/timer/timer_tsc.c
 * which was originally moved from arch/i386/kernel/time.c.
 * See comments there for proper credits.
 */

#include <linux/clocksource.h>
#include <linux/workqueue.h>
#include <linux/cpufreq.h>
#include <linux/jiffies.h>
#include <linux/init.h>
#include <linux/dmi.h>
#include <linux/acpi.h>
#include <linux/acpi_pmtmr.h>
#include <linux/delay.h>
#include <asm/delay.h>
#include <asm/tsc.h>
#include <asm/hpet.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <asm/generic-hypervisor.h>
#include <linux/hpet.h>

#include "mach_timer.h"

int avoid_smi;

/*
 * On some systems the TSC frequency does not
 * change with the cpu frequency. So we need
 * an extra value to store the TSC freq
 */
unsigned int tsc_khz;

int tsc_disable __cpuinitdata = 0;

static unsigned long calculate_cpu_khz(void);

#ifdef CONFIG_X86_TSC
static int __init tsc_setup(char *str)
{
	printk(KERN_WARNING "notsc: Kernel compiled with CONFIG_X86_TSC, "
				"cannot disable TSC.\n");
	return 1;
}
#else
/*
 * disable flag for tsc. Takes effect by clearing the TSC cpu flag
 * in cpu/common.c
 */
static int __init tsc_setup(char *str)
{
	tsc_disable = 1;

	return 1;
}
#endif

__setup("notsc", tsc_setup);

/*
 * code to mark and check if the TSC is unstable
 * due to cpufreq or due to unsynced TSCs
 */
static int tsc_unstable;

static inline int check_tsc_unstable(void)
{
	return tsc_unstable;
}

void mark_tsc_unstable(void)
{
	tsc_unstable = 1;
}
EXPORT_SYMBOL_GPL(mark_tsc_unstable);

/* Accellerators for sched_clock()
 * convert from cycles(64bits) => nanoseconds (64bits)
 *  basic equation:
 *		ns = cycles / (freq / ns_per_sec)
 *		ns = cycles * (ns_per_sec / freq)
 *		ns = cycles * (10^9 / (cpu_khz * 10^3))
 *		ns = cycles * (10^6 / cpu_khz)
 *
 *	Then we use scaling math (suggested by george@mvista.com) to get:
 *		ns = cycles * (10^6 * SC / cpu_khz) / SC
 *		ns = cycles * cyc2ns_scale / SC
 *
 *	And since SC is a constant power of two, we can convert the div
 *  into a shift.
 *
 *  We can use khz divisor instead of mhz to keep a better percision, since
 *  cyc2ns_scale is limited to 10^6 * 2^10, which fits in 32 bits.
 *  (mathieu.desnoyers@polymtl.ca)
 *
 *			-johnstul@us.ibm.com "math is hard, lets go shopping!"
 */
static unsigned long cyc2ns_scale __read_mostly;

#define CYC2NS_SCALE_FACTOR 10 /* 2^10, carefully chosen */

static inline void set_cyc2ns_scale(unsigned long cpu_khz)
{
	cyc2ns_scale = (1000000 << CYC2NS_SCALE_FACTOR)/cpu_khz;
}

static inline unsigned long long cycles_2_ns(unsigned long long cyc)
{
	return (cyc * cyc2ns_scale) >> CYC2NS_SCALE_FACTOR;
}

#ifndef CONFIG_XEN
/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	unsigned long long this_offset;

	/*
	 * in the NUMA case we dont use the TSC as they are not
	 * synchronized across all CPUs.
	 */
#ifndef CONFIG_NUMA
	if (!cpu_khz || check_tsc_unstable())
#endif
		/* no locking but a rare wrong value is not a big deal */
		return (jiffies_64 - INITIAL_JIFFIES) * (1000000000 / HZ);

	/* read the Time Stamp Counter: */
	rdtscll(this_offset);

	/* return the value in ns */
	return cycles_2_ns(this_offset);
}

#define MAX_RETRIES     5
#define SMI_TRESHOLD    50000

/*
 * Read TSC and the reference counters. Take care of SMI disturbance
 */
static u64 tsc_read_refs(u64 *p, int hpet)
{
	u64 t1, t2;
	int i;

	for (i = 0; i < MAX_RETRIES; i++) {
		t1 = get_cycles();
		if (hpet)
			*p = hpet_readl(HPET_COUNTER) & 0xFFFFFFFF;
		else
			*p = acpi_pm_read_early();
		t2 = get_cycles();
		if ((t2 - t1) < SMI_TRESHOLD)
			return t2;
	}
	return ULLONG_MAX;
}

/*
 * Calculate the TSC frequency from HPET reference
 */
static unsigned long calc_hpet_ref(u64 deltatsc, u64 hpet1, u64 hpet2)
{
	u64 tmp;

	if (hpet2 < hpet1)
		hpet2 += 0x100000000ULL;
	hpet2 -= hpet1;
	tmp = ((u64)hpet2 * hpet_readl(HPET_PERIOD));
	do_div(tmp, 1000000);
	do_div(deltatsc, tmp);

	return (unsigned long) deltatsc;
}

/* Number of PMTMR ticks expected during calibration run */
#define PMTMR_TICKS_PER_SEC 3579545

/* Overrun value */
#define ACPI_PM_OVRRUN  (1<<24)

/*
 * Calculate the TSC frequency from PMTimer reference
 */
static unsigned long calc_pmtimer_ref(u64 deltatsc, u64 pm1, u64 pm2)
{
	u64 tmp;

	if (!pm1 && !pm2)
		return ULONG_MAX;

	if (pm2 < pm1)
		pm2 += (u64)ACPI_PM_OVRRUN;
	pm2 -= pm1;
	tmp = pm2 * 1000000000LL;
	do_div(tmp, PMTMR_TICKS_PER_SEC);
	do_div(deltatsc, tmp);

	return (unsigned long) deltatsc;
}

#define CAL_MS		10
#define CAL_LATCH	(CLOCK_TICK_RATE / (1000 / CAL_MS))
#define CAL_PIT_LOOPS	1000

#define CAL2_MS		50
#define CAL2_LATCH	(CLOCK_TICK_RATE / (1000 / CAL2_MS))
#define CAL2_PIT_LOOPS	5000


/*
 * Try to calibrate the TSC against the Programmable
 * Interrupt Timer and return the frequency of the TSC
 * in kHz.
 *
 * Return ULONG_MAX on failure to calibrate.
 */
static unsigned long pit_calibrate_tsc(u32 latch, unsigned long ms, int loopmin)
{
	u64 tsc, t1, t2, delta;
	unsigned long tscmin, tscmax;
	int pitcnt;

	/* Set the Gate high, disable speaker */
	outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	/*
	 * Setup CTC channel 2* for mode 0, (interrupt on terminal
	 * count mode), binary count. Set the latch register to 50ms
	 * (LSB then MSB) to begin countdown.
	 */
	outb(0xb0, 0x43);
	outb(latch & 0xff, 0x42);
	outb(latch >> 8, 0x42);

	tsc = t1 = t2 = get_cycles();

	pitcnt = 0;
	tscmax = 0;
	tscmin = ULONG_MAX;
	while ((inb(0x61) & 0x20) == 0) {
		t2 = get_cycles();
		delta = t2 - tsc;
		tsc = t2;
		if ((unsigned long) delta < tscmin)
			tscmin = (unsigned int) delta;
		if ((unsigned long) delta > tscmax)
			tscmax = (unsigned int) delta;
		pitcnt++;
	}

	/*
	 * Sanity checks:
	 *
	 * If we were not able to read the PIT more than loopmin
	 * times, then we have been hit by a massive SMI
	 *
	 * If the maximum is 10 times larger than the minimum,
	 * then we got hit by an SMI as well.
	 */
	if (pitcnt < loopmin || tscmax > 10 * tscmin)
		return ULONG_MAX;

	/* Calculate the PIT value */
	delta = t2 - t1;
	do_div(delta, ms);
	return delta;
}

/**
 * native_calibrate_tsc - calibrate the tsc on boot
 */
static unsigned long native_calibrate_tsc(void)
{
	u64 tsc1, tsc2, delta, ref1, ref2;
	unsigned long tsc_pit_min = ULONG_MAX, tsc_ref_min = ULONG_MAX;
	unsigned long flags, latch, ms, tsc_khz;
	int hpet = is_hpet_enabled(), i, loopmin;

	tsc_khz = get_hypervisor_tsc_freq();
	if (tsc_khz) {
		printk(KERN_INFO "TSC: Frequency read from the hypervisor\n");
		return tsc_khz;
	}

	/*
	 * Run 5 calibration loops to get the lowest frequency value
	 * (the best estimate). We use two different calibration modes
	 * here:
	 *
	 * 1) PIT loop. We set the PIT Channel 2 to oneshot mode and
	 * load a timeout of 50ms. We read the time right after we
	 * started the timer and wait until the PIT count down reaches
	 * zero. In each wait loop iteration we read the TSC and check
	 * the delta to the previous read. We keep track of the min
	 * and max values of that delta. The delta is mostly defined
	 * by the IO time of the PIT access, so we can detect when a
	 * SMI/SMM disturbance happend between the two reads. If the
	 * maximum time is significantly larger than the minimum time,
	 * then we discard the result and have another try.
	 *
	 * 2) Reference counter. If available we use the HPET or the
	 * PMTIMER as a reference to check the sanity of that value.
	 * We use separate TSC readouts and check inside of the
	 * reference read for a SMI/SMM disturbance. We dicard
	 * disturbed values here as well. We do that around the PIT
	 * calibration delay loop as we have to wait for a certain
	 * amount of time anyway.
	 */

	/* Preset PIT loop values */
	latch = CAL_LATCH;
	ms = CAL_MS;
	loopmin = CAL_PIT_LOOPS;

	for (i = 0; i < 3; i++) {
		unsigned long tsc_pit_khz;

		/*
		 * Read the start value and the reference count of
		 * hpet/pmtimer when available. Then do the PIT
		 * calibration, which will take at least 50ms, and
		 * read the end value.
		 */
		local_irq_save(flags);
		tsc1 = tsc_read_refs(&ref1, hpet);
		tsc_pit_khz = pit_calibrate_tsc(latch, ms, loopmin);
		tsc2 = tsc_read_refs(&ref2, hpet);
		local_irq_restore(flags);

		/* Pick the lowest PIT TSC calibration so far */
		tsc_pit_min = min(tsc_pit_min, tsc_pit_khz);

		/* hpet or pmtimer available ? */
		if (!hpet && !ref1 && !ref2)
			continue;

		/* Check, whether the sampling was disturbed by an SMI */
		if (tsc1 == ULLONG_MAX || tsc2 == ULLONG_MAX)
			continue;

		tsc2 = (tsc2 - tsc1) * 1000000LL;
		if (hpet)
			tsc2 = calc_hpet_ref(tsc2, ref1, ref2);
		else
			tsc2 = calc_pmtimer_ref(tsc2, ref1, ref2);

		tsc_ref_min = min(tsc_ref_min, (unsigned long) tsc2);

		/* Check the reference deviation */
		delta = ((u64) tsc_pit_min) * 100;
		do_div(delta, tsc_ref_min);

		/*
		 * If both calibration results are inside a 10% window
		 * then we can be sure, that the calibration
		 * succeeded. We break out of the loop right away. We
		 * use the reference value, as it is more precise.
		 */
		if (delta >= 90 && delta <= 110) {
			printk(KERN_INFO
			       "TSC: PIT calibration matches %s. %d loops\n",
			       hpet ? "HPET" : "PMTIMER", i + 1);
			return tsc_ref_min;
		}

		/*
		 * Check whether PIT failed more than once. This
		 * happens in virtualized environments. We need to
		 * give the virtual PC a slightly longer timeframe for
		 * the HPET/PMTIMER to make the result precise.
		 */
		if (i == 1 && tsc_pit_min == ULONG_MAX) {
			latch = CAL2_LATCH;
			ms = CAL2_MS;
			loopmin = CAL2_PIT_LOOPS;
		}
	}

	/*
	 * Now check the results.
	 */
	if (tsc_pit_min == ULONG_MAX) {
		/* PIT gave no useful value */
		printk(KERN_WARNING "TSC: Unable to calibrate against PIT\n");

		/* We don't have an alternative source, disable TSC */
		if (!hpet && !ref1 && !ref2) {
			printk("TSC: No reference (HPET/PMTIMER) available\n");
			return 0;
		}

		/* The alternative source failed as well, disable TSC */
		if (tsc_ref_min == ULONG_MAX) {
			printk(KERN_WARNING "TSC: HPET/PMTIMER calibration "
			       "failed.\n");
			return 0;
		}

		/* Use the alternative source */
		printk(KERN_INFO "TSC: using %s reference calibration\n",
		       hpet ? "HPET" : "PMTIMER");

		return tsc_ref_min;
	}

	/* We don't have an alternative source, use the PIT calibration value */
	if (!hpet && !ref1 && !ref2) {
		printk(KERN_INFO "TSC: Using PIT calibration value\n");
		return tsc_pit_min;
	}

	/* The alternative source failed, use the PIT calibration value */
	if (tsc_ref_min == ULONG_MAX) {
		printk(KERN_WARNING "TSC: HPET/PMTIMER calibration failed. "
		       "Using PIT calibration\n");
		return tsc_pit_min;
	}

	/*
	 * The calibration values differ too much. In doubt, we use
	 * the PIT value as we know that there are PMTIMERs around
	 * running at double speed. At least we let the user know:
	 */
	printk(KERN_WARNING "TSC: PIT calibration deviates from %s: %lu %lu.\n",
	       hpet ? "HPET" : "PMTIMER", tsc_pit_min, tsc_ref_min);
	printk(KERN_INFO "TSC: Using PIT calibration value\n");
	return tsc_pit_min;
}
#else
static unsigned long native_calibrate_tsc(void)
{
	return calculate_cpu_khz();
}
#endif

static unsigned long calculate_cpu_khz(void)
{
	unsigned long long start, end;
	unsigned long count;
	u64 delta64;
	int i;
	unsigned long flags;

#ifndef CONFIG_XEN
	tsc_khz = get_hypervisor_tsc_freq();
	if (tsc_khz) {
		printk(KERN_INFO "TSC: Frequency read from the hypervisor\n");
		return tsc_khz;
	}
#endif

	local_irq_save(flags);

	/* run 3 times to ensure the cache is warm */
	for (i = 0; i < 3; i++) {
		mach_prepare_counter();
		rdtscll(start);
		mach_countup(&count);
		rdtscll(end);
	}
	/*
	 * Error: ECTCNEVERSET
	 * The CTC wasn't reliable: we got a hit on the very first read,
	 * or the CPU was so fast/slow that the quotient wouldn't fit in
	 * 32 bits..
	 */
	if (count <= 1)
		goto err;

	delta64 = end - start;

	/* cpu freq too fast: */
	if (delta64 > (1ULL<<32))
		goto err;

	/* cpu freq too slow: */
	if (delta64 <= CALIBRATE_TIME_MSEC)
		goto err;

	delta64 += CALIBRATE_TIME_MSEC/2; /* round for do_div */
	do_div(delta64,CALIBRATE_TIME_MSEC);

	local_irq_restore(flags);
	return (unsigned long)delta64;
err:
	local_irq_restore(flags);
	return 0;
}

int recalibrate_cpu_khz(void)
{
#ifndef CONFIG_SMP
	unsigned long cpu_khz_old = cpu_khz;

	if (cpu_has_tsc) {
		if (avoid_smi) {
			printk(KERN_INFO
			       "Enabling SMI avoidance in CPU calibration\n");
			cpu_khz = native_calibrate_tsc();
		} else
			cpu_khz = calculate_cpu_khz();
		tsc_khz = cpu_khz;
		cpu_data[0].loops_per_jiffy =
			cpufreq_scale(cpu_data[0].loops_per_jiffy,
					cpu_khz_old, cpu_khz);
		return 0;
	} else
		return -ENODEV;
#else
	return -ENODEV;
#endif
}

EXPORT_SYMBOL(recalibrate_cpu_khz);

void tsc_init(void)
{
	u64 lpj;

	if (!cpu_has_tsc || tsc_disable)
		return;

	if (avoid_smi) {
		printk(KERN_INFO "Enabling SMI avoidance in CPU calibration\n");
		cpu_khz = native_calibrate_tsc();
	} else
		cpu_khz = calculate_cpu_khz();
	tsc_khz = cpu_khz;

	if (!cpu_khz)
		return;

	printk("Detected %lu.%03lu MHz processor.\n",
				(unsigned long)cpu_khz / 1000,
				(unsigned long)cpu_khz % 1000);

	set_cyc2ns_scale(cpu_khz);

	lpj = ((u64)tsc_khz * 1000);
	do_div(lpj, HZ);
	lpj_fine = lpj;

	use_tsc_delay();
}

#ifdef CONFIG_CPU_FREQ

static unsigned int cpufreq_delayed_issched = 0;
static unsigned int cpufreq_init = 0;
static struct work_struct cpufreq_delayed_get_work;

static void handle_cpufreq_delayed_get(void *v)
{
	unsigned int cpu;

	for_each_online_cpu(cpu)
		cpufreq_get(cpu);

	cpufreq_delayed_issched = 0;
}

/*
 * if we notice cpufreq oddness, schedule a call to cpufreq_get() as it tries
 * to verify the CPU frequency the timing core thinks the CPU is running
 * at is still correct.
 */
static inline void cpufreq_delayed_get(void)
{
	if (cpufreq_init && !cpufreq_delayed_issched) {
		cpufreq_delayed_issched = 1;
		printk(KERN_DEBUG "Checking if CPU frequency changed.\n");
		schedule_work(&cpufreq_delayed_get_work);
	}
}

/*
 * if the CPU frequency is scaled, TSC-based delays will need a different
 * loops_per_jiffy value to function properly.
 */
static unsigned int ref_freq = 0;
static unsigned long loops_per_jiffy_ref = 0;
static unsigned long cpu_khz_ref = 0;

static int
time_cpufreq_notifier(struct notifier_block *nb, unsigned long val, void *data)
{
	struct cpufreq_freqs *freq = data;

	if (!ref_freq) {
		if (!freq->old){
			ref_freq = freq->new;
			return 0;
		}
		ref_freq = freq->old;
		loops_per_jiffy_ref = cpu_data[freq->cpu].loops_per_jiffy;
		cpu_khz_ref = cpu_khz;
	}

	if ((val == CPUFREQ_PRECHANGE  && freq->old < freq->new) ||
	    (val == CPUFREQ_POSTCHANGE && freq->old > freq->new) ||
	    (val == CPUFREQ_RESUMECHANGE)) {
		if (!(freq->flags & CPUFREQ_CONST_LOOPS))
			cpu_data[freq->cpu].loops_per_jiffy =
				cpufreq_scale(loops_per_jiffy_ref,
						ref_freq, freq->new);

		if (cpu_khz) {

			if (num_online_cpus() == 1)
				cpu_khz = cpufreq_scale(cpu_khz_ref,
						ref_freq, freq->new);
			if (!(freq->flags & CPUFREQ_CONST_LOOPS)) {
				tsc_khz = cpu_khz;
				set_cyc2ns_scale(cpu_khz);
				/*
				 * TSC based sched_clock turns
				 * to junk w/ cpufreq
				 */
				mark_tsc_unstable();
			}
		}
	}

	return 0;
}

static struct notifier_block time_cpufreq_notifier_block = {
	.notifier_call	= time_cpufreq_notifier
};

static int __init cpufreq_tsc(void)
{
	int ret;

	INIT_WORK(&cpufreq_delayed_get_work, handle_cpufreq_delayed_get, NULL);
	ret = cpufreq_register_notifier(&time_cpufreq_notifier_block,
					CPUFREQ_TRANSITION_NOTIFIER);
	if (!ret)
		cpufreq_init = 1;

	return ret;
}

core_initcall(cpufreq_tsc);

#endif

/* clock source code */

static unsigned long current_tsc_khz = 0;
static int tsc_update_callback(void);
static struct clocksource clocksource_tsc;

/*
 * We compare the TSC to the cycle_last value in the clocksource
 * structure to avoid a nasty time-warp issue. This can be observed in
 * a very small window right after one CPU updated cycle_last under
 * xtime lock and the other CPU reads a TSC value which is smaller
 * than the cycle_last reference value due to a TSC which is slighty
 * behind. This delta is nowhere else observable, but in that case it
 * results in a forward time jump in the range of hours due to the
 * unsigned delta calculation of the time keeping core code, which is
 * necessary to support wrapping clocksources like pm timer.
 */
static cycle_t read_tsc(void)
{
	cycle_t ret;

	rdtscll(ret);

	return ret >= clocksource_tsc.cycle_last ?
		ret : clocksource_tsc.cycle_last;
}

static struct clocksource clocksource_tsc = {
	.name			= "tsc",
	.rating			= 300,
	.read			= read_tsc,
	.mask			= CLOCKSOURCE_MASK(64),
	.mult			= 0, /* to be set */
	.shift			= 22,
	.update_callback	= tsc_update_callback,
	.is_continuous		= 1,
};

static int tsc_update_callback(void)
{
	int change = 0;

	/* check to see if we should switch to the safe clocksource: */
	if (clocksource_tsc.rating != 50 && check_tsc_unstable()) {
		clocksource_tsc.rating = 50;
		clocksource_reselect();
		change = 1;
	}

	/* only update if tsc_khz has changed: */
	if (current_tsc_khz != tsc_khz) {
		current_tsc_khz = tsc_khz;
		clocksource_tsc.mult = clocksource_khz2mult(current_tsc_khz,
							clocksource_tsc.shift);
		change = 1;
	}

	return change;
}

static int __init dmi_mark_tsc_unstable(struct dmi_system_id *d)
{
	printk(KERN_NOTICE "%s detected: marking TSC unstable.\n",
		       d->ident);
	mark_tsc_unstable();
	return 0;
}

/* List of systems that have known TSC problems */
static struct dmi_system_id __initdata bad_tsc_dmi_table[] = {
	{
	 .callback = dmi_mark_tsc_unstable,
	 .ident = "IBM Thinkpad 380XD",
	 .matches = {
		     DMI_MATCH(DMI_BOARD_VENDOR, "IBM"),
		     DMI_MATCH(DMI_BOARD_NAME, "2635FA0"),
		     },
	 },
	 {}
};

#define TSC_FREQ_CHECK_INTERVAL (10*MSEC_PER_SEC) /* 10sec in MS */
static struct timer_list verify_tsc_freq_timer;

/* XXX - Probably should add locking */
static void verify_tsc_freq(unsigned long unused)
{
	static u64 last_tsc;
	static unsigned long last_jiffies;

	u64 now_tsc, interval_tsc;
	unsigned long now_jiffies, interval_jiffies;

	/* TSC is reliable, no need to verify as it may have false positives */
	if (boot_cpu_has(X86_FEATURE_TSC_RELIABLE))
		return;

	if (check_tsc_unstable())
		return;

	rdtscll(now_tsc);
	now_jiffies = jiffies;

	if (!last_jiffies) {
		goto out;
	}

	interval_jiffies = now_jiffies - last_jiffies;
	interval_tsc = now_tsc - last_tsc;
	interval_tsc *= HZ;
	do_div(interval_tsc, cpu_khz*1000);

	if (interval_tsc < (interval_jiffies * 3 / 4)) {
		printk("TSC appears to be running slowly. "
			"Marking it as unstable\n");
		mark_tsc_unstable();
		return;
	}

out:
	last_tsc = now_tsc;
	last_jiffies = now_jiffies;
	/* set us up to go off on the next interval: */
	mod_timer(&verify_tsc_freq_timer,
		jiffies + msecs_to_jiffies(TSC_FREQ_CHECK_INTERVAL));
}

/*
 * Make an educated guess if the TSC is trustworthy and synchronized
 * over all CPUs.
 */
static __init int unsynchronized_tsc(void)
{
	/* AMD and Intel systems with constant TSCs have synchronized clocks */
	if (boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
		return 0;

	/* Most intel systems have synchronized TSCs except for
	   multi node systems */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
#ifdef CONFIG_ACPI
		/* But TSC doesn't tick in C3 so don't use it there */
		if (acpi_fadt.length > 0 && acpi_fadt.plvl3_lat < 1000 &&
		    max_cstate > 1)
			return 1;
#endif
 		return 0;
	}

	/* TSC is reliable, usually exported by hypervisors */
	if (boot_cpu_has(X86_FEATURE_TSC_RELIABLE))
		return 0;

	/* assume multi socket systems are not synchronized: */
 	return num_possible_cpus() > 1;
}

static int __init init_tsc_clocksource(void)
{

	if (cpu_has_tsc && tsc_khz && !tsc_disable) {
		/* check blacklist */
		dmi_check_system(bad_tsc_dmi_table);

		if (unsynchronized_tsc()) /* mark unstable if unsynced */
			mark_tsc_unstable();
		current_tsc_khz = tsc_khz;
		clocksource_tsc.mult = clocksource_khz2mult(current_tsc_khz,
							clocksource_tsc.shift);
		/* lower the rating if we already know its unstable: */
		if (check_tsc_unstable())
			clocksource_tsc.rating = 50;

		init_timer(&verify_tsc_freq_timer);
#ifndef CONFIG_XEN
		init_tsc_timer();
#endif
		verify_tsc_freq_timer.function = verify_tsc_freq;
		verify_tsc_freq_timer.expires =
			jiffies + msecs_to_jiffies(TSC_FREQ_CHECK_INTERVAL);
		add_timer(&verify_tsc_freq_timer);

		return clocksource_register(&clocksource_tsc);
	}

	return 0;
}

module_init(init_tsc_clocksource);
