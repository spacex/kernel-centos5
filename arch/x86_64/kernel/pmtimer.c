/* Ported over from i386 by AK, original copyright was:
 *
 * (C) Dominik Brodowski <linux@brodo.de> 2003
 *
 * Driver to use the Power Management Timer (PMTMR) available in some
 * southbridges as primary timing source for the Linux kernel.
 *
 * Based on parts of linux/drivers/acpi/hardware/hwtimer.c, timer_pit.c,
 * timer_hpet.c, and on Arjan van de Ven's implementation for 2.4.
 *
 * This file is licensed under the GPL v2.
 *
 * Dropped all the hardware bug workarounds for now. Hopefully they
 * are not needed on 64bit chipsets.
 */

#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/cpumask.h>
#include <asm/io.h>
#include <asm/proto.h>
#include <asm/msr.h>
#include <asm/vsyscall.h>
#include <asm/apicdef.h>
#include <asm/apic.h>

/* The I/O port the PMTMR resides at.
 * The location is detected during setup_arch(),
 * in arch/i386/kernel/acpi/boot.c */
u32 pmtmr_ioport __read_mostly;

/* value of the Power timer at last timer interrupt */
static u32 offset_delay;
static u32 last_pmtmr_tick;
static u32 cycles_not_accounted_HZ;

#define PM_TIMER_FREQUENCY 3579545UL

#define ACPI_PM_MASK 0xFFFFFF /* limit it to 24 bits */

static inline u32 cyc2us(u32 cycles)
{
	/* The Power Management Timer ticks at 3.579545 ticks per microsecond.
	 * 1 / PM_TIMER_FREQUENCY == 0.27936511 =~ 286/1024 [error: 0.024%]
	 *
	 * Even with HZ = 100, delta is at maximum 35796 ticks, so it can
	 * easily be multiplied with 286 (=0x11E) without having to fear
	 * u32 overflows.
	 */
	cycles *= 286;
	return (cycles >> 10);
}

int pmtimer_mark_offset(void)
{
	static int first_run = 1;
	unsigned long tsc;
	u32 lost;

	u32 tick = inl(pmtmr_ioport);
	u32 delta;

	delta = cyc2us((tick - last_pmtmr_tick) & ACPI_PM_MASK);

	last_pmtmr_tick = tick;
	monotonic_base += delta * NSEC_PER_USEC;

	delta += offset_delay;

	lost = delta / (USEC_PER_SEC / REAL_HZ);
	offset_delay = delta % (USEC_PER_SEC / REAL_HZ);

	rdtscll(tsc);
	vxtime.last_tsc = tsc - offset_delay * (u64)cpu_khz / 1000;

	/* don't calculate delay for first run,
	   or if we've got less then a tick */
	if (first_run || (lost < 1)) {
		first_run = 0;
		offset_delay = 0;
	}

	return lost - 1;
}

/*
 * This function facilitates fine-grained accounting of 'jiffies' in the
 * timer interrupt handler if the actual length of the current real tick
 * is not equal to the expected length of a real tick. This is useful if
 * 'tick_divider' is greater than 1 because 'tick_divider' specifies the
 * number of logical ticks ('jiffies') per real tick. The actual length
 * of the current real tick is returned in the location which is pointed
 * to by the argument 'njiffies'.
 *
 * In order to avoid inexact results due to the error margin of cyc2us(),
 * the number of 'jiffies' to account is computed based on the PM timer
 * frequency. Conceptually, this is being done as follows:
 *
 *   -  Determine the number of PM timer cycles that have elapsed between
 *      the current PM timer sample and the previous PM timer sample.
 *      This is the 'delta'.
 *
 *   -  The number of jiffies to account is equal to the 'delta' divided
 *      by the number of PM timer cycles per jiffy.
 *
 * In order to avoid rounding errors by scaling the PM timer frequency
 * down to a jiffy (i.e. PM_TIMER_FREQUENCY/HZ), the 'delta' is instead
 * scaled up to HZ (i.e. delta*HZ).
 */
int pmtimer_mark_offset_return_njiffies(unsigned int *njiffies)
{
	unsigned long tsc;
	u64 delta;
	u32 real_ticks;
	u32 jiffies_to_account;
	u32 prev_offset_delay = offset_delay;
	u32 tick = inl(pmtmr_ioport);

	/*
	 * Determine the number of elapsed cycles, scale up to HZ,
	 * and add the unaccounted amount from the previous tick.
	 */
	delta = (u64)((tick - last_pmtmr_tick) & ACPI_PM_MASK) * HZ;
	delta += cycles_not_accounted_HZ;

	/*
	 * Postpone accounting if the delta is less than a jiffy.
	 */
	if (delta < PM_TIMER_FREQUENCY) {
		*njiffies = 0;
		return -1;
	}

	last_pmtmr_tick = tick;

	/*
	 * Compute the number of jiffies to account.
	 */
	jiffies_to_account = (u32)(delta / PM_TIMER_FREQUENCY);

	/*
	 * Remember the unaccounted amount and compute the 'offset_delay'
	 * for use by do_gettimeoffset_pm(). The unaccounted amount needs
	 * to be scaled down (divided by HZ) to compute the 'offset_delay'.
	 */
	cycles_not_accounted_HZ = (u32)(delta % PM_TIMER_FREQUENCY);
	offset_delay = cyc2us(cycles_not_accounted_HZ / HZ);

	/*
	 * Compute the number of real ticks that have elapsed.
	 * Consider three cases:
	 *
	 * 1. If 'real_ticks' is less than 1, the current real tick is
	 *    shorter than expected. Return the actual length in jiffies
	 *    where 1 <= *njiffies < tick_divider.
	 *
	 * 2. If 'real_ticks' is equal 1, the current real tick may be
	 *    longer than expected. Return the actual length in jiffies
	 *    where tick_divider <= *njiffies < tick_divider*2.
	 *
	 * 3. If 'real_ticks' is greater than 1, we lost some real ticks.
	 *    Return one full real tick plus a fraction of a real tick
	 *    where tick_divider <= *njiffies < tick_divider*2 (similar
	 *    to case 2.) and where the function's return value reflects
	 *    the number of lost real ticks.
	 */
	real_ticks = jiffies_to_account / tick_divider;
	if (real_ticks < 1)
		*njiffies = jiffies_to_account;
	else
		*njiffies = tick_divider + (jiffies_to_account % tick_divider);

	/*
	 * Account the elapsed jiffies plus the current 'offset_delay' in
	 * 'monotonic_base' and set a time stamp in 'vxtime.last_tsc' for
	 * use by monotonic_clock(). The previous 'offset_delay' which was
	 * accounted in 'monotonic_base' at the previous real tick must be
	 * un-accounted (subtracted) during the current real tick because
	 * it is now included in the current 'jiffies_to_account' and/or
	 * in the current 'offset_delay'.
	 */
	monotonic_base += (u64)jiffies_to_account * (u64)(NSEC_PER_SEC / HZ) +
	    ((u64)offset_delay - (u64)prev_offset_delay) * (u64)NSEC_PER_USEC;
	rdtscll(tsc);
	vxtime.last_tsc = tsc;

	return real_ticks - 1;
}

static unsigned pmtimer_wait_tick(void)
{
	u32 a, b;
	for (a = b = inl(pmtmr_ioport) & ACPI_PM_MASK;
	     a == b;
	     b = inl(pmtmr_ioport) & ACPI_PM_MASK)
		cpu_relax();
	return b;
}

/* note: wait time is rounded up to one tick */
void pmtimer_wait(unsigned us)
{
	u32 a, b;
	a = pmtimer_wait_tick();
	do {
		b = inl(pmtmr_ioport);
		cpu_relax();
	} while (cyc2us(b - a) < us);
}

int pmtimer_calibrate_apic(unsigned us, int *tries)
{
	u32 a, b;
	unsigned int apic = 0, apic_start = 0;

	while(*tries) {
		apic_start = apic_read(APIC_TMCCT);
		a = pmtimer_wait_tick();
		do {
			b = inl(pmtmr_ioport);
			cpu_relax();
		} while (cyc2us(b - a) < us);
		apic = apic_read(APIC_TMCCT);
		b = inl(pmtmr_ioport);

		/* if wait is longer that ~10% of expected time, try again */
		if ((cyc2us(b - a)) < (us + (us >> 3)))
			break;
		(*tries)--;
	}

	return (apic_start - apic);
}

void pmtimer_resume(void)
{
	last_pmtmr_tick = inl(pmtmr_ioport);
}

long do_gettimeoffset_pm(void)
{
	u32 now, offset, delta = 0;

	offset = last_pmtmr_tick;
	now = inl(pmtmr_ioport);
	delta = (now - offset) & ACPI_PM_MASK;

	/* seems crazy to do with PM timer resolution but we need nsec
	   resolution in arch/x86_64/kernel/time.c code */
	return ((offset_delay + cyc2us(delta)) * NSEC_PER_USEC);
}


static int __init nopmtimer_setup(char *s)
{
	pmtmr_ioport = 0;
	return 1;
}

__setup("nopmtimer", nopmtimer_setup);
