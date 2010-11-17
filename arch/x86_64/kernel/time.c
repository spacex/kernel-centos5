/*
 *  linux/arch/x86-64/kernel/time.c
 *
 *  "High Precision Event Timer" based timekeeping.
 *
 *  Copyright (c) 1991,1992,1995  Linus Torvalds
 *  Copyright (c) 1994  Alan Modra
 *  Copyright (c) 1995  Markus Kuhn
 *  Copyright (c) 1996  Ingo Molnar
 *  Copyright (c) 1998  Andrea Arcangeli
 *  Copyright (c) 2002,2006  Vojtech Pavlik
 *  Copyright (c) 2003  Andi Kleen
 *  RTC support code taken from arch/i386/kernel/timers/time_hpet.c
 *
 *  March 2008: Upstream has diverged significantly from this codebase.
 *  Modifications to this file to convert the gettimeofday call into nsecs
 *  (but still return usec values) were done in order to resolve a large
 *  number of gettimeofday issues seen across a wide swath of Intel and
 *  AMD systems.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mc146818rtc.h>
#include <linux/time.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/sysdev.h>
#include <linux/bcd.h>
#include <linux/notifier.h>
#include <linux/cpu.h>
#include <linux/kallsyms.h>
#include <linux/efi.h>
#include <linux/acpi.h>
#include <linux/acpi_pmtmr.h>
#include <linux/delay.h>
#include <linux/kvm_para.h>
#ifdef CONFIG_ACPI
#include <acpi/achware.h>	/* for PM timer frequency */
#include <acpi/acpi_bus.h>
#endif
#include <asm/8253pit.h>
#include <asm/pgtable.h>
#include <asm/vsyscall.h>
#include <asm/timex.h>
#include <asm/proto.h>
#include <asm/hpet.h>
#include <asm/sections.h>
#include <asm/nmi.h>
#include <asm/generic-hypervisor.h>
#include <linux/cpufreq.h>
#include <linux/hpet.h>
#ifdef CONFIG_X86_LOCAL_APIC
#include <asm/apic.h>
#endif

#ifdef CONFIG_CPU_FREQ
static void cpufreq_delayed_get(void);
#endif
extern void i8254_timer_resume(void);
extern int using_apic_timer;

static char *timename = NULL;

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);
DEFINE_SPINLOCK(i8253_lock);

int nohpet __initdata = 0;
static int notsc __initdata = 0;
int avoid_smi;

#define USEC_PER_TICK (USEC_PER_SEC / HZ)
#define NSEC_PER_TICK (NSEC_PER_SEC / HZ)
#define FSEC_PER_TICK (FSEC_PER_SEC / HZ)

#define NSEC_PER_REAL_TICK (NSEC_PER_SEC / REAL_HZ)

#define NS_SCALE	10 /* 2^10, carefully chosen */
#define US_SCALE	32 /* 2^32, arbitralrily chosen */

unsigned int cpu_khz;					/* TSC clocks / usec, not used here */
EXPORT_SYMBOL(cpu_khz);
unsigned int tsc_khz;
EXPORT_SYMBOL(tsc_khz);
static unsigned long hpet_period;			/* fsecs / HPET clock */
unsigned long hpet_tick;				/* HPET clocks / HZ */
unsigned long hpet_tick_real;				/* HPET clocks / interrupt */
int hpet_use_timer;				/* Use counter of hpet for time keeping, otherwise PIT */
unsigned long vxtime_hz = PIT_TICK_RATE;
int report_lost_ticks;				/* command line option */
unsigned long long monotonic_base;

struct vxtime_data __vxtime __section_vxtime;	/* for vsyscalls */

volatile unsigned long __jiffies __section_jiffies = INITIAL_JIFFIES;
unsigned long __wall_jiffies __section_wall_jiffies = INITIAL_JIFFIES;
struct timespec __xtime __section_xtime;
struct timezone __sys_tz __section_sys_tz;

/* -1=>disabled, 0=>autoconfigure, 1=>enabled */
int timekeeping_use_tsc;

/* 0=>disabled, 1=>enabled (default) */
static unsigned int pmtimer_fine_grained = 1;

static cycles_t cycles_per_tick, cycles_accounted_limit;

/*
 * do_gettimeoffset() returns nanoseconds since last timer interrupt was
 * triggered by hardware. A memory read of HPET is slower than a register read
 * of TSC, but much more reliable. It's also synchronized to the timer
 * interrupt. Note that do_gettimeoffset() may return more than hpet_tick, if a
 * timer interrupt has happened already, but vxtime.trigger wasn't updated yet.
 * This is not a problem, because jiffies hasn't updated either. They are bound
 * together by xtime_lock.
 */

static inline long do_gettimeoffset_tsc(void)
{
	unsigned long t;
	unsigned long x;
	t = get_cycles_sync();
	if (t < vxtime.last_tsc) 
		t = vxtime.last_tsc; /* hack */
	x = ((t - vxtime.last_tsc) * vxtime.tsc_quot) >> NS_SCALE;
	return x;
}

static inline long do_gettimeoffset_kvm(void)
{
	unsigned long t;
	t = kvm_clock_read();
	if (t < vxtime.last_kvm)
		t = vxtime.last_kvm;
	return t -vxtime.last_kvm;
}

static inline long do_gettimeoffset_hpet(void)
{
	/* cap counter read to one tick to avoid inconsistencies */
	unsigned long counter = hpet_readl(HPET_COUNTER) - vxtime.last;
	/* The hpet counter runs at a fixed rate so we don't care about HZ
	   scaling here. We do however care that the limit is in real ticks */
	return (min(counter,hpet_tick_real) * vxtime.quot) >> NS_SCALE;
}

long (*do_gettimeoffset)(void) = do_gettimeoffset_tsc;

/*
 * This version of gettimeofday() has microsecond resolution and better than
 * microsecond precision, as we're using at least a 10 MHz (usually 14.31818
 * MHz) HPET timer.
 */

void do_gettimeofday(struct timeval *tv)
{
	unsigned long seq;
 	long sec, nsec;

	do {
		seq = read_seqbegin(&xtime_lock);

		sec = xtime.tv_sec;
		nsec = xtime.tv_nsec + (jiffies - wall_jiffies) * NSEC_PER_TICK;

		nsec += do_gettimeoffset();

	} while (read_seqretry(&xtime_lock, seq));

	tv->tv_sec = sec;
	while (nsec >= NSEC_PER_SEC) {
		tv->tv_sec += 1;
		nsec -= NSEC_PER_SEC;
	}
	tv->tv_usec = nsec / NSEC_PER_USEC;
}

EXPORT_SYMBOL(do_gettimeofday);

/*
 * settimeofday() first undoes the correction that gettimeofday would do
 * on the time, and then saves it. This is ugly, but has been like this for
 * ages already.
 */

int do_settimeofday(struct timespec *tv)
{
	time_t wtm_sec, sec = tv->tv_sec;
	long wtm_nsec, nsec = tv->tv_nsec;

	if ((unsigned long)tv->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	write_seqlock_irq(&xtime_lock);

	nsec -= do_gettimeoffset() + (jiffies - wall_jiffies) * NSEC_PER_TICK;

	wtm_sec  = wall_to_monotonic.tv_sec + (xtime.tv_sec - sec);
	wtm_nsec = wall_to_monotonic.tv_nsec + (xtime.tv_nsec - nsec);

	set_normalized_timespec(&xtime, sec, nsec);
	set_normalized_timespec(&wall_to_monotonic, wtm_sec, wtm_nsec);

	ntp_clear();

	write_sequnlock_irq(&xtime_lock);
	clock_was_set();
	return 0;
}

EXPORT_SYMBOL(do_settimeofday);

unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	/* Assume the lock function has either no stack frame or only a single 
	   word.  This checks if the address on the stack looks like a kernel 
	   text address.
	   There is a small window for false hits, but in that case the tick
	   is just accounted to the spinlock function.
	   Better would be to write these functions in assembler again
	   and check exactly. */
	if (!user_mode(regs) && in_lock_functions(pc)) {
		char *v = *(char **)regs->rsp;
		if ((v >= _stext && v <= _etext) ||
			(v >= _sinittext && v <= _einittext) ||
			(v >= (char *)MODULES_VADDR  && v <= (char *)MODULES_END))
			return (unsigned long)v;
		return ((unsigned long *)regs->rsp)[1];
	}
	return pc;
}
EXPORT_SYMBOL(profile_pc);

/*
 * In order to set the CMOS clock precisely, set_rtc_mmss has to be called 500
 * ms after the second nowtime has started, because when nowtime is written
 * into the registers of the CMOS clock, it will jump to the next second
 * precisely 500 ms later. Check the Motorola MC146818A or Dallas DS12887 data
 * sheet for details.
 */

static void set_rtc_mmss(unsigned long nowtime)
{
	int real_seconds, real_minutes, cmos_minutes;
	unsigned char control, freq_select;

/*
 * IRQs are disabled when we're called from the timer interrupt,
 * no need for spin_lock_irqsave()
 */

	spin_lock(&rtc_lock);
	if (efi_enabled) {
		efi_set_rtc_mmss(nowtime);
		spin_unlock(&rtc_lock);
		return;
	}

/*
 * Tell the clock it's being set and stop it.
 */

	control = CMOS_READ(RTC_CONTROL);
	CMOS_WRITE(control | RTC_SET, RTC_CONTROL);

	freq_select = CMOS_READ(RTC_FREQ_SELECT);
	CMOS_WRITE(freq_select | RTC_DIV_RESET2, RTC_FREQ_SELECT);

	cmos_minutes = CMOS_READ(RTC_MINUTES);
		BCD_TO_BIN(cmos_minutes);

/*
 * since we're only adjusting minutes and seconds, don't interfere with hour
 * overflow. This avoids messing with unknown time zones but requires your RTC
 * not to be off by more than 15 minutes. Since we're calling it only when
 * our clock is externally synchronized using NTP, this shouldn't be a problem.
 */

	real_seconds = nowtime % 60;
	real_minutes = nowtime / 60;
	if (((abs(real_minutes - cmos_minutes) + 15) / 30) & 1)
		real_minutes += 30;		/* correct for half hour time zone */
	real_minutes %= 60;

	if (abs(real_minutes - cmos_minutes) >= 30) {
		printk(KERN_WARNING "time.c: can't update CMOS clock "
		       "from %d to %d\n", cmos_minutes, real_minutes);
	} else {
		BIN_TO_BCD(real_seconds);
		BIN_TO_BCD(real_minutes);
		CMOS_WRITE(real_seconds, RTC_SECONDS);
		CMOS_WRITE(real_minutes, RTC_MINUTES);
	}

/*
 * The following flags have to be released exactly in this order, otherwise the
 * DS12887 (popular MC146818A clone with integrated battery and quartz) will
 * not reset the oscillator and will not update precisely 500 ms later. You
 * won't find this mentioned in the Dallas Semiconductor data sheets, but who
 * believes data sheets anyway ... -- Markus Kuhn
 */

	CMOS_WRITE(control, RTC_CONTROL);
	CMOS_WRITE(freq_select, RTC_FREQ_SELECT);

	spin_unlock(&rtc_lock);
}


/* monotonic_clock(): returns # of nanoseconds passed since time_init()
 *		Note: This function is required to return accurate
 *		time even in the absence of multiple timer ticks.
 */
unsigned long long monotonic_clock(void)
{
	unsigned long seq;
 	u32 last_offset, this_offset, offset;
	unsigned long long base;

	if (vxtime.mode == VXTIME_KVM) {
		do {
			seq = read_seqbegin(&xtime_lock);

			last_offset = vxtime.last_kvm;
			base = monotonic_base;
			this_offset = kvm_clock_read();
		} while (read_seqretry(&xtime_lock, seq));
		offset = (this_offset - last_offset);
	} else if (vxtime.mode == VXTIME_HPET) {
		do {
			seq = read_seqbegin(&xtime_lock);

			last_offset = vxtime.last;
			base = monotonic_base;
			this_offset = hpet_readl(HPET_COUNTER);
		} while (read_seqretry(&xtime_lock, seq));
		offset = (this_offset - last_offset);
		offset *= NSEC_PER_TICK / hpet_tick_real;
	} else {
		do {
			seq = read_seqbegin(&xtime_lock);

			last_offset = vxtime.last_tsc;
			base = monotonic_base;
		} while (read_seqretry(&xtime_lock, seq));
		this_offset = get_cycles_sync();
		/* FIXME: 1000 or 1000000? */
		offset = (this_offset - last_offset)*1000 / cpu_khz;
	}
	return base + offset;
}
EXPORT_SYMBOL(monotonic_clock);

static void do_timer_jiffy(struct pt_regs *regs)
{
	do_timer(regs);
#ifndef CONFIG_SMP
	update_process_times(user_mode(regs), regs);
#endif

	/*
	 * In the SMP case we use the local APIC timer interrupt to do the profiling,
	 * except when we simulate SMP mode on a uniprocessor system, in that case we
	 * have to call the local interrupt handler.
	 */

#ifndef CONFIG_X86_LOCAL_APIC
	profile_tick(CPU_PROFILING, regs);
#else
	if (!using_apic_timer)
		smp_local_timer_interrupt(regs);
#endif
}

static noinline void handle_lost_ticks(int lost, struct pt_regs *regs)
{
	static long lost_count;
	static int warned;
	if (report_lost_ticks) {
		printk(KERN_WARNING "time.c: Lost %d timer tick(s)! ", lost);
		print_symbol("rip %s)\n", regs->rip);
	}

	if (lost_count == 1000 && !warned && report_lost_ticks) {
		printk(KERN_WARNING "warning: many lost ticks.\n"
		       KERN_WARNING "Your time source seems to be instable or "
		   		"some driver is hogging interupts\n");
		print_symbol("rip %s\n", regs->rip);
		if (vxtime.mode == VXTIME_TSC && vxtime.hpet_address) {
			printk(KERN_WARNING "Falling back to HPET\n");
			if (hpet_use_timer)
				vxtime.last = hpet_readl(HPET_T0_CMP) - 
							hpet_tick_real;
			else
				vxtime.last = hpet_readl(HPET_COUNTER);
			vxtime.mode = VXTIME_HPET;
			do_gettimeoffset = do_gettimeoffset_hpet;
		}
		/* else should fall back to PIT, but code missing. */
		warned = 1;
	} else
		lost_count++;

#ifdef CONFIG_CPU_FREQ
	/* In some cases the CPU can change frequency without us noticing
	   Give cpufreq a change to catch up. */
	if ((lost_count+1) % 25 == 0)
		cpufreq_delayed_get();
#endif
}

static void do_timer_account_lost_ticks(struct pt_regs *regs)
{
	unsigned long tsc;
	int delay = 0, offset = 0, lost = 0, i;
	unsigned int njiffies = tick_divider;

	if (vxtime.hpet_address)
		offset = hpet_readl(HPET_COUNTER);

	if (hpet_use_timer) {
		/* if we're using the hpet timer functionality,
		 * we can more accurately know the counter value
		 * when the timer interrupt occured.
		 * 
		 * We are working in physical time here
		 */
		offset = hpet_readl(HPET_T0_CMP) - hpet_tick_real;
		delay = hpet_readl(HPET_COUNTER) - offset;
	} else if (!pmtmr_ioport) {
		spin_lock(&i8253_lock);
		outb_p(0x00, 0x43);
		delay = inb_p(0x40);
		delay |= inb(0x40) << 8;
		spin_unlock(&i8253_lock);
		delay = LATCH - 1 - delay;
	}

	tsc = get_cycles_sync();

	if (vxtime.mode == VXTIME_HPET) {
		if (offset - vxtime.last > hpet_tick_real) {
			lost = (offset - vxtime.last) / hpet_tick_real - 1;
		}

		monotonic_base += 
			(offset - vxtime.last) * NSEC_PER_TICK / hpet_tick_real;

		vxtime.last = offset;
#ifdef CONFIG_X86_PM_TIMER
	} else if (vxtime.mode == VXTIME_PMTMR) {
		if (tick_divider == 1) {
			lost = pmtimer_mark_offset();
		} else {
			/*
			 * Fine-grained accounting with tick_divider > 1 is
			 * enabled by default. It can be disabled by setting
			 * the kernel parameter 'pmtimer_fine_grained=0'.
			 */
			if (pmtimer_fine_grained)
				lost = pmtimer_mark_offset_return_njiffies(&njiffies);
			else
				lost = pmtimer_mark_offset();
		}
#endif
	} else {
		offset = (((tsc - vxtime.last_tsc) *
			   vxtime.tsc_quot) >> NS_SCALE) - NSEC_PER_REAL_TICK;

		if (offset < 0)
			offset = 0;

		lost = 0;
		while (offset > NSEC_PER_REAL_TICK) {
			lost++;
			offset -= NSEC_PER_REAL_TICK;
		}

		/* FIXME: 1000 or 1000000? */
		monotonic_base += (tsc - vxtime.last_tsc) * 1000000 / cpu_khz;

		vxtime.last_tsc = tsc - vxtime.quot * delay / vxtime.tsc_quot;

		if ((((tsc - vxtime.last_tsc) *
		      vxtime.tsc_quot) >> NS_SCALE) < offset)
			vxtime.last_tsc = tsc -
				(((long) offset << NS_SCALE) / vxtime.tsc_quot) - 1;
	}
	if (lost > 0) {
		/* Lost is now in real ticks but we want logical */
		lost *= tick_divider;
		handle_lost_ticks(lost, regs);
		jiffies += lost;
	}

	/*
	 * Do the timer stuff.
	 *
	 * On entry to this routine, 'njiffies' is set to 'tick_divider'.
	 * However, if 'tick_divider' is greater than 1 and if the actual
	 * length of the current real tick is not equal to the expected
	 * length of a real tick, pmtimer_mark_offset_return_njiffies()
	 * returns the actual tick length in 'njiffies' so that we can do
	 * a fine-grained accounting. 'njiffies' can even be zero if the
	 * current real tick is shorter than a jiffy. Accounting is being
	 * postponed in this case.
	 */
	for (i = 0; i < njiffies; i++)
		do_timer_jiffy(regs);
}

/*
 * Measure time based on the TSC, rather than counting interrupts.
 */
static void do_timer_tsc_timekeeping(struct pt_regs *regs)
{
	int i;
	cycles_t tsc, tsc_accounted, tsc_not_accounted;
	unsigned long *last = NULL;


	if (use_kvm_time) {
		tsc = kvm_clock_read();
		last = &vxtime.last_kvm;
	}
	else {
		tsc = get_cycles_sync();
		last = &vxtime.last_tsc;
	}
	tsc_accounted = *last;

	if (unlikely(tsc < tsc_accounted))
		return;

	tsc_not_accounted = tsc - tsc_accounted;

	if (tsc_not_accounted > cycles_accounted_limit) {
		/* Be extra safe and limit the loop below. */
		tsc_accounted += tsc_not_accounted - cycles_accounted_limit;
		tsc_not_accounted = cycles_accounted_limit;
	}

	while (tsc_not_accounted >= cycles_per_tick) {
		for (i = 0; i < tick_divider; i++)
			do_timer_jiffy(regs);
		tsc_not_accounted -= cycles_per_tick;
		tsc_accounted += cycles_per_tick;
	}

	if (use_kvm_time) {
		monotonic_base += (tsc_accounted - *last);
		vxtime.last_tsc = get_cycles_sync();
	} else
		monotonic_base += ((tsc_accounted - *last) *
					1000000 / cpu_khz);

	*last = tsc_accounted;
}

void main_timer_handler(struct pt_regs *regs)
{
	static unsigned long rtc_update = 0;

/*
 * Here we are in the timer irq handler. We have irqs locally disabled (so we
 * don't need spin_lock_irqsave()) but we don't know if the timer_bh is running
 * on the other CPU, so we need a lock. We also need to lock the vsyscall
 * variables, because both do_timer() and us change them -arca+vojtech
 */

	write_seqlock(&xtime_lock);

	if (timekeeping_use_tsc > 0)
		do_timer_tsc_timekeeping(regs);
	else
		do_timer_account_lost_ticks(regs);


/*
 * If we have an externally synchronized Linux clock, then update CMOS clock
 * accordingly every ~11 minutes. set_rtc_mmss() will be called in the jiffy
 * closest to exactly 500 ms before the next second. If the update fails, we
 * don't care, as it'll be updated on the next turn, and the problem (time way
 * off) isn't likely to go away much sooner anyway.
 */

	if (ntp_synced() && xtime.tv_sec > rtc_update &&
		abs(xtime.tv_nsec - 500000000) <= tick_nsec / 2) {
		set_rtc_mmss(xtime.tv_sec);
		rtc_update = xtime.tv_sec + 660;
	}
 
	write_sequnlock(&xtime_lock);

	leap_second_message();
}

static irqreturn_t timer_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	if (apic_runs_main_timer > 1)
		return IRQ_HANDLED;
	main_timer_handler(regs);
#ifdef CONFIG_X86_LOCAL_APIC
	if (using_apic_timer)
		smp_send_timer_broadcast_ipi();
#endif
	return IRQ_HANDLED;
}

static unsigned int cyc2ns_scale __read_mostly;

static inline void set_cyc2ns_scale(unsigned long cpu_khz)
{
	cyc2ns_scale = (NSEC_PER_MSEC << NS_SCALE) / cpu_khz;
}

static inline unsigned long long cycles_2_ns(unsigned long long cyc)
{
	return (cyc * cyc2ns_scale) >> NS_SCALE;
}

unsigned long long sched_clock(void)
{
	unsigned long a = 0;

#if 0
	/* Don't do a HPET read here. Using TSC always is much faster
	   and HPET may not be mapped yet when the scheduler first runs.
           Disadvantage is a small drift between CPUs in some configurations,
	   but that should be tolerable. */
	if (__vxtime.mode == VXTIME_HPET)
		return (hpet_readl(HPET_COUNTER) * vxtime.quot) >> US_SCALE;
#endif

	/* Could do CPU core sync here. Opteron can execute rdtsc speculatively,
	   which means it is not completely exact and may not be monotonous between
	   CPUs. But the errors should be too small to matter for scheduling
	   purposes. */

	rdtscll(a);
	return cycles_2_ns(a);
}

static unsigned long get_cmos_time(void)
{
	unsigned int year, mon, day, hour, min, sec;
	unsigned long flags, retval;
	unsigned extyear = 0;

	spin_lock_irqsave(&rtc_lock, flags);
 	if (efi_enabled) {
 		retval = efi_get_time();
 		spin_unlock_irqrestore(&rtc_lock, flags);
 		return retval;
 	}

	do {
		sec = CMOS_READ(RTC_SECONDS);
		min = CMOS_READ(RTC_MINUTES);
		hour = CMOS_READ(RTC_HOURS);
		day = CMOS_READ(RTC_DAY_OF_MONTH);
		mon = CMOS_READ(RTC_MONTH);
		year = CMOS_READ(RTC_YEAR);
#ifdef CONFIG_ACPI
		if (acpi_fadt.revision >= FADT2_REVISION_ID &&
					acpi_fadt.century)
			extyear = CMOS_READ(acpi_fadt.century);
#endif
	} while (sec != CMOS_READ(RTC_SECONDS));

	spin_unlock_irqrestore(&rtc_lock, flags);

	/*
	 * We know that x86-64 always uses BCD format, no need to check the
	 * config register.
 	 */

	BCD_TO_BIN(sec);
	BCD_TO_BIN(min);
	BCD_TO_BIN(hour);
	BCD_TO_BIN(day);
	BCD_TO_BIN(mon);
	BCD_TO_BIN(year);

	if (extyear) {
		BCD_TO_BIN(extyear);
		year += extyear;
		printk(KERN_INFO "Extended CMOS year: %d\n", extyear);
	} else { 
		/*
		 * x86-64 systems only exists since 2002.
		 * This will work up to Dec 31, 2100
	 	 */
		year += 2000;
	}

	return mktime(year, mon, day, hour, min, sec);
}

static unsigned long get_wallclock(void)
{
	if (use_kvm_time)
		return kvm_get_wallclock();
	else
		return get_cmos_time();
}


/* calibrate_cpu is used on systems with fixed rate TSCs to determine
 * processor frequency */
#define TICK_COUNT 100000000
static unsigned int __init tsc_calibrate_cpu_khz(void)
{
	int tsc_start, tsc_now;
	int i, no_ctr_free;
	unsigned long evntsel3 = 0, pmc3 = 0, pmc_now = 0;
	unsigned long flags;

	for (i = 0; i < 4; i++)
		if (avail_to_resrv_perfctr_nmi_bit(i))
			break;
	no_ctr_free = (i == 4);
	if (no_ctr_free) {
		/* It is possible that cpu_khz will still be calculated
		   correctly.  Upstream WARN's here. */
		panic("AMD no free perfctr.  cpu_khz calibration incorrect.... reboot system");
		i = 3;
		rdmsrl(MSR_K7_EVNTSEL3, evntsel3);
		wrmsrl(MSR_K7_EVNTSEL3, 0);
		rdmsrl(MSR_K7_PERFCTR3, pmc3);
	} else {
		reserve_perfctr_nmi(MSR_K7_PERFCTR0 + i);
		reserve_evntsel_nmi(MSR_K7_EVNTSEL0 + i);
	}
	local_irq_save(flags);
	/* start measuring cycles, incrementing from 0 */
	wrmsrl(MSR_K7_PERFCTR0 + i, 0);
	wrmsrl(MSR_K7_EVNTSEL0 + i, 1 << 22 | 3 << 16 | 0x76);
	rdtscl(tsc_start);
	do {
		rdmsrl(MSR_K7_PERFCTR0 + i, pmc_now);
		tsc_now = get_cycles();
	} while ((tsc_now - tsc_start) < TICK_COUNT);

	local_irq_restore(flags);
	if (no_ctr_free) {
		wrmsrl(MSR_K7_EVNTSEL3, 0);
		wrmsrl(MSR_K7_PERFCTR3, pmc3);
		wrmsrl(MSR_K7_EVNTSEL3, evntsel3);
	} else {
		release_perfctr_nmi(MSR_K7_PERFCTR0 + i);
		release_evntsel_nmi(MSR_K7_EVNTSEL0 + i);
	}

	return pmc_now * tsc_khz / (tsc_now - tsc_start);
}
#ifdef CONFIG_CPU_FREQ

/* Frequency scaling support. Adjust the TSC based timer when the cpu frequency
   changes.
   
   RED-PEN: On SMP we assume all CPUs run with the same frequency.  It's
   not that important because current Opteron setups do not support
   scaling on SMP anyroads.

   Should fix up last_tsc too. Currently gettimeofday in the
   first tick after the change will be slightly wrong. */

#include <linux/workqueue.h>

static unsigned int cpufreq_delayed_issched = 0;
static unsigned int cpufreq_init = 0;
static struct work_struct cpufreq_delayed_get_work;

static void handle_cpufreq_delayed_get(void *v)
{
	unsigned int cpu;
	for_each_online_cpu(cpu) {
		cpufreq_get(cpu);
	}
	cpufreq_delayed_issched = 0;
}

/* if we notice lost ticks, schedule a call to cpufreq_get() as it tries
 * to verify the CPU frequency the timing core thinks the CPU is running
 * at is still correct.
 */
static void cpufreq_delayed_get(void)
{
	static int warned;
	if (cpufreq_init && !cpufreq_delayed_issched) {
		cpufreq_delayed_issched = 1;
		if (!warned && report_lost_ticks) {
			warned = 1;
			printk(KERN_DEBUG 
	"Losing some ticks... checking if CPU frequency changed.\n");
		}
		schedule_work(&cpufreq_delayed_get_work);
	}
}

static unsigned int  ref_freq = 0;
static unsigned long loops_per_jiffy_ref = 0;

static unsigned long tsc_khz_ref = 0;

static int time_cpufreq_notifier(struct notifier_block *nb, unsigned long val,
				 void *data)
{
        struct cpufreq_freqs *freq = data;
	unsigned long *lpj, dummy;

	if (cpu_has(&cpu_data[freq->cpu], X86_FEATURE_CONSTANT_TSC))
		return 0;

	lpj = &dummy;
	if (!(freq->flags & CPUFREQ_CONST_LOOPS))
#ifdef CONFIG_SMP
		lpj = &cpu_data[freq->cpu].loops_per_jiffy;
#else
		lpj = &boot_cpu_data.loops_per_jiffy;
#endif

	if (!ref_freq) {
		ref_freq = freq->old;
		loops_per_jiffy_ref = *lpj;
		tsc_khz_ref = tsc_khz;
	}
        if ((val == CPUFREQ_PRECHANGE  && freq->old < freq->new) ||
            (val == CPUFREQ_POSTCHANGE && freq->old > freq->new) ||
	    (val == CPUFREQ_RESUMECHANGE)) {
                *lpj =
		cpufreq_scale(loops_per_jiffy_ref, ref_freq, freq->new);

		tsc_khz = cpufreq_scale(tsc_khz_ref, ref_freq, freq->new);
		if (!(freq->flags & CPUFREQ_CONST_LOOPS))
			vxtime.tsc_quot = (NSEC_PER_MSEC << NS_SCALE) / cpu_khz;
	}
	
	set_cyc2ns_scale(tsc_khz_ref);

	return 0;
}
 
static struct notifier_block time_cpufreq_notifier_block = {
         .notifier_call  = time_cpufreq_notifier
};

static int __init cpufreq_tsc(void)
{
	INIT_WORK(&cpufreq_delayed_get_work, handle_cpufreq_delayed_get, NULL);
	if (!cpufreq_register_notifier(&time_cpufreq_notifier_block,
				       CPUFREQ_TRANSITION_NOTIFIER))
		cpufreq_init = 1;
	return 0;
}

core_initcall(cpufreq_tsc);

#endif

/*
 * calibrate_tsc() calibrates the processor TSC in a very simple way, comparing
 * it to the HPET timer of known frequency.
 */

#define TICK_COUNT 100000000
#define SMI_TRESHOLD 50000
#define MAX_RETRIES 5

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
			*p = inl(pmtmr_ioport) & ACPI_PM_MASK;
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
static unsigned long pit_calibrate_tsc_smi(u32 latch, unsigned long ms, int 
loopmin)
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
unsigned long native_calibrate_tsc(void)
{
	u64 tsc1, tsc2, delta, ref1, ref2;
	unsigned long tsc_pit_min = ULONG_MAX, tsc_ref_min = ULONG_MAX;
	unsigned long flags, latch, ms, tsc_khz;
	int hpet = is_hpet_enabled(), i, loopmin;

#ifndef CONFIG_XEN
	tsc_khz = get_hypervisor_tsc_freq();
	if (tsc_khz) {
		printk(KERN_INFO "TSC: Frequency read from the hypervisor\n");
		return tsc_khz;
	}
#endif

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
		tsc_pit_khz = pit_calibrate_tsc_smi(latch, ms, loopmin);
		tsc2 = tsc_read_refs(&ref2, hpet);
		local_irq_restore(flags);

		/* Pick the lowest PIT TSC calibration so far */
		tsc_pit_min = min(tsc_pit_min, tsc_pit_khz);

		/* hpet or pmtimer available ? */
		if (!hpet && !ref1 && !ref2)
			continue;

		/* Check, whether the sampling was disturbed by an SMI 
*/
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

	/* We don't have an alternative source, use the PIT calibration 
value */
	if (!hpet && !ref1 && !ref2) {
		printk(KERN_INFO "TSC: Using PIT calibration value\n");
		return tsc_pit_min;
	}

	/* The alternative source failed, use the PIT calibration value 
*/
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



static unsigned int __init hpet_calibrate_tsc(void)
{
	int tsc_start, hpet_start;
	int tsc_now, hpet_now;
	unsigned long flags;

	local_irq_save(flags);
	local_irq_disable();

	hpet_start = hpet_readl(HPET_COUNTER);
	rdtscl(tsc_start);

	do {
		local_irq_disable();
		hpet_now = hpet_readl(HPET_COUNTER);
		tsc_now = get_cycles_sync();
		local_irq_restore(flags);
	} while ((tsc_now - tsc_start) < TICK_COUNT &&
		 (hpet_now - hpet_start) < TICK_COUNT);

	return (tsc_now - tsc_start) * 1000000000L
		/ ((hpet_now - hpet_start) * hpet_period / 1000);
}

/*
 * pit_calibrate_tsc() uses the speaker output (channel 2) of
 * the PIT. This is better than using the timer interrupt output,
 * because we can read the value of the speaker with just one inb(),
 * where we need three i/o operations for the interrupt channel.
 * We count how many ticks the TSC does in 50 ms.
 */

static unsigned int __init pit_calibrate_tsc(void)
{
	unsigned long start, end;
	unsigned long flags;

	spin_lock_irqsave(&i8253_lock, flags);

	outb((inb(0x61) & ~0x02) | 0x01, 0x61);

	outb(0xb0, 0x43);
	outb((PIT_TICK_RATE / (1000 / 50)) & 0xff, 0x42);
	outb((PIT_TICK_RATE / (1000 / 50)) >> 8, 0x42);
	start = get_cycles_sync();
	while ((inb(0x61) & 0x20) == 0);
	end = get_cycles_sync();

	spin_unlock_irqrestore(&i8253_lock, flags);
	
	return (end - start) / 50;
}

#ifdef	CONFIG_HPET
static __init int late_hpet_init(void)
{
	struct hpet_data	hd;
	unsigned int 		ntimer;

	if (!vxtime.hpet_address)
        	return 0;

	memset(&hd, 0, sizeof (hd));

	ntimer = hpet_readl(HPET_ID);
	ntimer = (ntimer & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;
	ntimer++;

	/*
	 * Register with driver.
	 * Timer0 and Timer1 is used by platform.
	 */
	hd.hd_phys_address = vxtime.hpet_address;
	hd.hd_address = (void __iomem *)fix_to_virt(FIX_HPET_BASE);
	hd.hd_nirqs = ntimer;
	hd.hd_flags = HPET_DATA_PLATFORM;
	hpet_reserve_timer(&hd, 0);
#ifdef	CONFIG_HPET_EMULATE_RTC
	hpet_reserve_timer(&hd, 1);
#endif
	hd.hd_irq[0] = HPET_LEGACY_8254;
	hd.hd_irq[1] = HPET_LEGACY_RTC;
	if (ntimer > 2) {
		struct hpet		*hpet;
		struct hpet_timer	*timer;
		int			i;

		hpet = (struct hpet *) fix_to_virt(FIX_HPET_BASE);
		timer = &hpet->hpet_timers[2];
		for (i = 2; i < ntimer; timer++, i++)
			hd.hd_irq[i] = (timer->hpet_config &
					Tn_INT_ROUTE_CNF_MASK) >>
				Tn_INT_ROUTE_CNF_SHIFT;

	}

	hpet_alloc(&hd);
	return 0;
}
fs_initcall(late_hpet_init);
#endif

static int hpet_timer_stop_set_go(unsigned long tick)
{
	unsigned int cfg;

/*
 * Stop the timers and reset the main counter.
 */

	cfg = hpet_readl(HPET_CFG);
	cfg &= ~(HPET_CFG_ENABLE | HPET_CFG_LEGACY);
	hpet_writel(cfg, HPET_CFG);
	hpet_writel(0, HPET_COUNTER);
	hpet_writel(0, HPET_COUNTER + 4);

/*
 * Set up timer 0, as periodic with first interrupt to happen at hpet_tick,
 * and period also hpet_tick.
 */
	if (hpet_use_timer) {
		hpet_writel(HPET_TN_ENABLE | HPET_TN_PERIODIC | HPET_TN_SETVAL |
		    HPET_TN_32BIT, HPET_T0_CFG);
		hpet_writel(hpet_tick_real, HPET_T0_CMP); /* next interrupt */
		hpet_writel(hpet_tick_real, HPET_T0_CMP); /* period */
		cfg |= HPET_CFG_LEGACY;
	}
/*
 * Go!
 */

	cfg |= HPET_CFG_ENABLE;
	hpet_writel(cfg, HPET_CFG);

	return 0;
}

static int hpet_init(void)
{
	unsigned int id;

	if (!vxtime.hpet_address)
		return -1;
	set_fixmap_nocache(FIX_HPET_BASE, vxtime.hpet_address);
	__set_fixmap(VSYSCALL_HPET, vxtime.hpet_address, PAGE_KERNEL_VSYSCALL_NOCACHE);

/*
 * Read the period, compute tick and quotient.
 */

	id = hpet_readl(HPET_ID);

	if (!(id & HPET_ID_VENDOR) || !(id & HPET_ID_NUMBER))
		return -1;

	hpet_period = hpet_readl(HPET_PERIOD);
	if (hpet_period < 100000 || hpet_period > 100000000)
		return -1;

	/* Logical ticks */
	hpet_tick = (FSEC_PER_TICK + hpet_period / 2) / hpet_period;
	/* Ticks per real interrupt */
	hpet_tick_real = hpet_tick * tick_divider;

	hpet_use_timer = (id & HPET_ID_LEGSUP);

	return hpet_timer_stop_set_go(hpet_tick_real);
}

static int hpet_reenable(void)
{
	return hpet_timer_stop_set_go(hpet_tick_real);
}

#define PIT_MODE 0x43
#define PIT_CH0  0x40

static void __init __pit_init(int val, u8 mode)
{
	unsigned long flags;

	spin_lock_irqsave(&i8253_lock, flags);
	outb_p(mode, PIT_MODE);
	outb_p(val & 0xff, PIT_CH0);	/* LSB */
	outb_p(val >> 8, PIT_CH0);	/* MSB */
	spin_unlock_irqrestore(&i8253_lock, flags);
}

void __init pit_init(void)
{
	/* LATCH is in actual interrupt ticks */
	__pit_init(LATCH, 0x34); /* binary, mode 2, LSB/MSB, ch 0 */
}

void __init pit_stop_interrupt(void)
{
	__pit_init(0, 0x30); /* mode 0 */
}

void __init stop_timer_interrupt(void)
{
	char *name;
	if (vxtime.hpet_address) {
		name = "HPET";
		hpet_timer_stop_set_go(0);
	} else {
		name = "PIT";
		pit_stop_interrupt();
	}
	printk(KERN_INFO "timer: %s interrupt stopped.\n", name);
}

int __init time_setup(char *str)
{
	report_lost_ticks = 1;
	return 1;
}

static struct irqaction irq0 = {
	timer_interrupt, IRQF_DISABLED, CPU_MASK_NONE, "timer", NULL, NULL
};

static int __cpuinit
time_cpu_notifier(struct notifier_block *nb, unsigned long action, void *hcpu)
{
	unsigned cpu = (unsigned long) hcpu;
 	if (action == CPU_ONLINE)
 		vsyscall_set_cpu(cpu);
	return NOTIFY_DONE;
}

void __init time_init(void)
{
	unsigned int hypervisor_khz;

	/*
	 * 'tick_nsec' is set to TICK_NSEC at compile time. The value of
	 * TICK_NSEC depends on HZ. The kernel parameter 'tick_divider'
	 * allows to change REAL_HZ at boottime, so 'tick_nsec' needs to
	 * be adjusted to REAL_HZ. Otherwise time will drift backwards.
	 *
	 * For example, with HZ=1000 the initial value of 'tick_nsec'
	 * is 999848 and with HZ=100 the initial value of 'tick_nsec'
	 * is 10000000. Therefore, with 'tick_divider=10' the value of
	 * 'tick_nsec' needs to be adjusted to 10000000 / 10 = 1000000.
	 * Otherwise time drifts backwards by 1000000 - 999848 = 152 ns
	 * per logical tick. This accumulates to 152 * 1000 * 3600 =
	 * 547200000 ns = 0.5472 seconds per hour.
	 */
	if (tick_divider > 1 && pmtimer_fine_grained) {
		unsigned long acthz = SH_DIV(CLOCK_TICK_RATE, LATCH, 8);
		tick_nsec = SH_DIV(NSEC_PER_SEC, acthz, 8) / tick_divider;
	}

	if (nohpet)
		vxtime.hpet_address = 0;

	xtime.tv_sec = get_wallclock();
	xtime.tv_nsec = 0;

	set_normalized_timespec(&wall_to_monotonic,
	                        -xtime.tv_sec, -xtime.tv_nsec);

	if (!hpet_init())
                vxtime_hz = (FSEC_PER_SEC + hpet_period / 2) / hpet_period;
	else
		vxtime.hpet_address = 0;

	if (use_kvm_time) {
		timename = "KVM";
		/* no need to get frequency here, since we'll skip the calibrate loop anyway */
		timekeeping_use_tsc = 1;
		vxtime.last_kvm = kvm_clock_read();
	} else if (avoid_smi) {
		printk(KERN_INFO "Enabling SMI avoidance in CPU calibration\n");
		if (hpet_use_timer) {
			tick_nsec = TICK_NSEC_HPET;
			timename = "HPET";
		} else if (pmtmr_ioport && !vxtime.hpet_address) {
			vxtime_hz = PM_TIMER_FREQUENCY;
			timename = "PM";
			pit_init();
		} else {
			pit_init();
			timename = "PIT";
		}
		tsc_khz = native_calibrate_tsc();
	} else if (hpet_use_timer) {
		/* set tick_nsec to use the proper rate for HPET */
	  	tick_nsec = TICK_NSEC_HPET;
		tsc_khz = hpet_calibrate_tsc();
		timename = "HPET";
#ifdef CONFIG_X86_PM_TIMER
	} else if (pmtmr_ioport && !vxtime.hpet_address) {
		vxtime_hz = PM_TIMER_FREQUENCY;
		timename = "PM";
		pit_init();
		tsc_khz = pit_calibrate_tsc();
#endif
	} else {	
		pit_init();
		tsc_khz = pit_calibrate_tsc();
		timename = "PIT";
	}

	cpu_khz = tsc_khz;
	if (cpu_has(&boot_cpu_data, X86_FEATURE_CONSTANT_TSC) &&
		boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
		boot_cpu_data.x86 == 16 && !avoid_smi)
		cpu_khz = tsc_calibrate_cpu_khz();

	/* Should we get tsc_khz from the hypervisor? */
	hypervisor_khz = get_hypervisor_tsc_freq();
	if (hypervisor_khz) {
		tsc_khz = hypervisor_khz;
		cpu_khz = tsc_khz;
	}

	lpj_fine = ((unsigned long)tsc_khz * 1000)/HZ;

	/* Keep time based on the TSC rather than by counting interrupts. */
	if (timekeeping_use_tsc > 0) {
		cycles_per_tick = get_hypervisor_cycles_per_tick();
		/*
		 * The maximum cycles we will account per
		 * timer interrupt is 10 minutes.
		 */
		cycles_accounted_limit = cycles_per_tick * REAL_HZ * 60 * 10;
		tick_nsec = NSEC_PER_SEC / HZ;
		printk(KERN_INFO
			"time.c: Using tsc for timekeeping HZ %d\n", HZ);
	}

	vxtime.mode = VXTIME_TSC;
	vxtime.quot = (NSEC_PER_SEC << NS_SCALE) / vxtime_hz;
	vxtime.tsc_quot = (NSEC_PER_MSEC << NS_SCALE) / cpu_khz;
	vxtime.last_tsc = get_cycles_sync();
	setup_irq(0, &irq0);

	set_cyc2ns_scale(tsc_khz);

	hotcpu_notifier(time_cpu_notifier, 0);
	time_cpu_notifier(NULL, CPU_ONLINE, (void *)(long)smp_processor_id());

#ifndef CONFIG_SMP
	time_init_gtod();
#endif
}

/*
 * Make an educated guess if the TSC is trustworthy and synchronized
 * over all CPUs.
 */
__cpuinit int unsynchronized_tsc(void)
{
#ifdef CONFIG_SMP
	if (apic_is_clustered_box())
		return 1;
#endif

	/* AMD or Intel systems with constant TSCs have synchronized clocks */
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

 	/* Assume multi socket systems are not synchronized */
 	return num_present_cpus() > 1;
}

/*
 * Decide what mode gettimeofday should use.
 */
void time_init_gtod(void)
{
	char *timetype;

	if (unsynchronized_tsc())
		notsc = 1;

 	if (cpu_has(&boot_cpu_data, X86_FEATURE_RDTSCP))
		vgetcpu_mode = VGETCPU_RDTSCP;
	else
		vgetcpu_mode = VGETCPU_LSL;

	if (use_kvm_time) {
		timetype = "KVM";
		vxtime.last_kvm = kvm_clock_read();
		vxtime.mode = VXTIME_KVM;
		do_gettimeoffset = do_gettimeoffset_kvm;
	} else if (timekeeping_use_tsc > 0) {
		timetype = "TSC Timekeeping";
		vxtime.mode = VXTIME_TSC;
	} else if (vxtime.hpet_address && notsc) {
		timetype = hpet_use_timer ? "HPET" : "PIT/HPET";
		if (hpet_use_timer)
			vxtime.last = hpet_readl(HPET_T0_CMP) - hpet_tick_real;
		else
			vxtime.last = hpet_readl(HPET_COUNTER);
		vxtime.mode = VXTIME_HPET;
		do_gettimeoffset = do_gettimeoffset_hpet;
#ifdef CONFIG_X86_PM_TIMER
	/* Using PM for gettimeofday is quite slow, but we have no other
	   choice because the TSC is too unreliable on some systems. */
	} else if (pmtmr_ioport && !vxtime.hpet_address && notsc) {
		timetype = "PM";
		do_gettimeoffset = do_gettimeoffset_pm;
		vxtime.mode = VXTIME_PMTMR;
		sysctl_vsyscall = 0;
		printk(KERN_INFO "Disabling vsyscall due to use of PM timer\n");
#endif
	} else {
		timetype = hpet_use_timer ? "HPET/TSC" : "PIT/TSC";
		vxtime.mode = VXTIME_TSC;
	}

	printk(KERN_INFO "time.c: Using %ld.%06ld MHz WALL %s GTOD %s timer.\n", 
		vxtime_hz / 1000000, vxtime_hz % 1000000, timename, timetype);
	printk(KERN_INFO "time.c: Detected %d.%03d MHz processor.\n", 
		cpu_khz / 1000, cpu_khz % 1000);
	vxtime.quot = (NSEC_PER_SEC << NS_SCALE) / vxtime_hz;
	vxtime.tsc_quot = (NSEC_PER_MSEC << NS_SCALE) / tsc_khz;
	vxtime.last_tsc = get_cycles_sync();

	set_cyc2ns_scale(tsc_khz);
}

__setup("report_lost_ticks", time_setup);

static long clock_cmos_diff;
static unsigned long sleep_start;

/*
 * sysfs support for the timer.
 */

static int timer_suspend(struct sys_device *dev, pm_message_t state)
{
	/*
	 * Estimate time zone so that set_time can update the clock
	 */
	long cmos_time =  get_wallclock();

	clock_cmos_diff = -cmos_time;
	clock_cmos_diff += get_seconds();
	sleep_start = cmos_time;
	return 0;
}

static int timer_resume(struct sys_device *dev)
{
	unsigned long flags;
	unsigned long sec;
	unsigned long ctime = get_wallclock();
	unsigned long sleep_length = (ctime - sleep_start) * HZ;

	if (vxtime.hpet_address)
		hpet_reenable();
	else
		i8254_timer_resume();

	sec = ctime + clock_cmos_diff;
	write_seqlock_irqsave(&xtime_lock,flags);
	xtime.tv_sec = sec;
	xtime.tv_nsec = 0;
	if (vxtime.mode == VXTIME_KVM) {
		vxtime.last_kvm = kvm_clock_read();
		vxtime.last_tsc = get_cycles_sync();
	} else if (vxtime.mode == VXTIME_HPET) {
		if (hpet_use_timer)
			vxtime.last = hpet_readl(HPET_T0_CMP) - hpet_tick_real;
		else
			vxtime.last = hpet_readl(HPET_COUNTER);
#ifdef CONFIG_X86_PM_TIMER
	} else if (vxtime.mode == VXTIME_PMTMR) {
		pmtimer_resume();
#endif
	} else
		vxtime.last_tsc = get_cycles_sync();
	write_sequnlock_irqrestore(&xtime_lock,flags);
	jiffies += sleep_length;
	wall_jiffies += sleep_length;
	monotonic_base += sleep_length * (NSEC_PER_SEC/HZ);
	touch_softlockup_watchdog();
	return 0;
}

static struct sysdev_class timer_sysclass = {
	.resume = timer_resume,
	.suspend = timer_suspend,
	set_kset_name("timer"),
};

/* XXX this driverfs stuff should probably go elsewhere later -john */
static struct sys_device device_timer = {
	.id	= 0,
	.cls	= &timer_sysclass,
};

static int time_init_device(void)
{
	int error = sysdev_class_register(&timer_sysclass);
	if (!error)
		error = sysdev_register(&device_timer);
	return error;
}

device_initcall(time_init_device);

#ifdef CONFIG_HPET_EMULATE_RTC
/* HPET in LegacyReplacement Mode eats up RTC interrupt line. When, HPET
 * is enabled, we support RTC interrupt functionality in software.
 * RTC has 3 kinds of interrupts:
 * 1) Update Interrupt - generate an interrupt, every sec, when RTC clock
 *    is updated
 * 2) Alarm Interrupt - generate an interrupt at a specific time of day
 * 3) Periodic Interrupt - generate periodic interrupt, with frequencies
 *    2Hz-8192Hz (2Hz-64Hz for non-root user) (all freqs in powers of 2)
 * (1) and (2) above are implemented using polling at a frequency of
 * 64 Hz. The exact frequency is a tradeoff between accuracy and interrupt
 * overhead. (DEFAULT_RTC_INT_FREQ)
 * For (3), we use interrupts at 64Hz or user specified periodic
 * frequency, whichever is higher.
 */
#include <linux/rtc.h>

#define DEFAULT_RTC_INT_FREQ 	64
#define RTC_NUM_INTS 		1

static unsigned long UIE_on;
static unsigned long prev_update_sec;

static unsigned long AIE_on;
static struct rtc_time alarm_time;

static unsigned long PIE_on;
static unsigned long PIE_freq = DEFAULT_RTC_INT_FREQ;
static unsigned long PIE_count;

static unsigned long hpet_rtc_int_freq; /* RTC interrupt frequency */
static unsigned int hpet_t1_cmp; /* cached comparator register */

int is_hpet_enabled(void)
{
	return vxtime.hpet_address != 0;
}

int is_hpet_legacy_int_enabled()
{
	return (is_hpet_enabled() && hpet_use_timer);
}

/*
 * Timer 1 for RTC, we do not use periodic interrupt feature,
 * even if HPET supports periodic interrupts on Timer 1.
 * The reason being, to set up a periodic interrupt in HPET, we need to
 * stop the main counter. And if we do that everytime someone diables/enables
 * RTC, we will have adverse effect on main kernel timer running on Timer 0.
 * So, for the time being, simulate the periodic interrupt in software.
 *
 * hpet_rtc_timer_init() is called for the first time and during subsequent
 * interuppts reinit happens through hpet_rtc_timer_reinit().
 */
int hpet_rtc_timer_init(void)
{
	unsigned int cfg, cnt;
	unsigned long flags;

	if (!is_hpet_legacy_int_enabled())
		return 0;
	/*
	 * Set the counter 1 and enable the interrupts.
	 */
	if (PIE_on && (PIE_freq > DEFAULT_RTC_INT_FREQ))
		hpet_rtc_int_freq = PIE_freq;
	else
		hpet_rtc_int_freq = DEFAULT_RTC_INT_FREQ;

	local_irq_save(flags);
	cnt = hpet_readl(HPET_COUNTER);
	cnt += ((hpet_tick*HZ)/hpet_rtc_int_freq);
	hpet_writel(cnt, HPET_T1_CMP);
	hpet_t1_cmp = cnt;
	local_irq_restore(flags);

	cfg = hpet_readl(HPET_T1_CFG);
	cfg &= ~HPET_TN_PERIODIC;
	cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
	hpet_writel(cfg, HPET_T1_CFG);

	return 1;
}

static void hpet_rtc_timer_reinit(void)
{
	unsigned int cfg, cnt;

	if (unlikely(!(PIE_on | AIE_on | UIE_on))) {
		cfg = hpet_readl(HPET_T1_CFG);
		cfg &= ~HPET_TN_ENABLE;
		hpet_writel(cfg, HPET_T1_CFG);
		return;
	}

	if (PIE_on && (PIE_freq > DEFAULT_RTC_INT_FREQ))
		hpet_rtc_int_freq = PIE_freq;
	else
		hpet_rtc_int_freq = DEFAULT_RTC_INT_FREQ;

	/* It is more accurate to use the comparator value than current count.*/
	cnt = hpet_t1_cmp;
	cnt += hpet_tick*HZ/hpet_rtc_int_freq;
	hpet_writel(cnt, HPET_T1_CMP);
	hpet_t1_cmp = cnt;
}

/*
 * The functions below are called from rtc driver.
 * Return 0 if HPET is not being used.
 * Otherwise do the necessary changes and return 1.
 */
int hpet_mask_rtc_irq_bit(unsigned long bit_mask)
{
	if (!is_hpet_legacy_int_enabled())
		return 0;

	if (bit_mask & RTC_UIE)
		UIE_on = 0;
	if (bit_mask & RTC_PIE)
		PIE_on = 0;
	if (bit_mask & RTC_AIE)
		AIE_on = 0;

	return 1;
}

int hpet_set_rtc_irq_bit(unsigned long bit_mask)
{
	int timer_init_reqd = 0;

	if (!is_hpet_legacy_int_enabled())
		return 0;

	if (!(PIE_on | AIE_on | UIE_on))
		timer_init_reqd = 1;

	if (bit_mask & RTC_UIE) {
		UIE_on = 1;
	}
	if (bit_mask & RTC_PIE) {
		PIE_on = 1;
		PIE_count = 0;
	}
	if (bit_mask & RTC_AIE) {
		AIE_on = 1;
	}

	if (timer_init_reqd)
		hpet_rtc_timer_init();

	return 1;
}

int hpet_set_alarm_time(unsigned char hrs, unsigned char min, unsigned char sec)
{
	if (!is_hpet_legacy_int_enabled())
		return 0;

	alarm_time.tm_hour = hrs;
	alarm_time.tm_min = min;
	alarm_time.tm_sec = sec;

	return 1;
}

int hpet_set_periodic_freq(unsigned long freq)
{
	if (!is_hpet_legacy_int_enabled())
		return 0;

	PIE_freq = freq;
	PIE_count = 0;

	return 1;
}

int hpet_rtc_dropped_irq(void)
{
	if (!is_hpet_legacy_int_enabled())
		return 0;

	return 1;
}

irqreturn_t hpet_rtc_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct rtc_time curr_time;
	unsigned long rtc_int_flag = 0;
	int call_rtc_interrupt = 0;

	hpet_rtc_timer_reinit();

	if (UIE_on | AIE_on) {
		rtc_get_rtc_time(&curr_time);
	}
	if (UIE_on) {
		if (curr_time.tm_sec != prev_update_sec) {
			/* Set update int info, call real rtc int routine */
			call_rtc_interrupt = 1;
			rtc_int_flag = RTC_UF;
			prev_update_sec = curr_time.tm_sec;
		}
	}
	if (PIE_on) {
		PIE_count++;
		if (PIE_count >= hpet_rtc_int_freq/PIE_freq) {
			/* Set periodic int info, call real rtc int routine */
			call_rtc_interrupt = 1;
			rtc_int_flag |= RTC_PF;
			PIE_count = 0;
		}
	}
	if (AIE_on) {
		if ((curr_time.tm_sec == alarm_time.tm_sec) &&
		    (curr_time.tm_min == alarm_time.tm_min) &&
		    (curr_time.tm_hour == alarm_time.tm_hour)) {
			/* Set alarm int info, call real rtc int routine */
			call_rtc_interrupt = 1;
			rtc_int_flag |= RTC_AF;
		}
	}
	if (call_rtc_interrupt) {
		rtc_int_flag |= (RTC_IRQF | (RTC_NUM_INTS << 8));
		rtc_interrupt(rtc_int_flag, dev_id, regs);
	}
	return IRQ_HANDLED;
}
#endif

static int __init nohpet_setup(char *s) 
{ 
	nohpet = 1;
	return 1;
} 

__setup("nohpet", nohpet_setup);

int __init notsc_setup(char *s)
{
	notsc = 1;
	return 1;
}

__setup("notsc", notsc_setup);

static int __init boot_override_clock(char *str)
{
	/* For x86, only have hpet, pmtmr, tsc */
	if (!strcmp(str, "hpet")) {
		pmtmr_ioport = 0;
		notsc = 1;
		use_kvm_time = 0;
	} else if (!strcmp(str, "pmtmr") || !strcmp(str, "pmtimer")) {
		nohpet = 1;
		notsc = 1;
		use_kvm_time = 0;
	} else if (!strcmp(str, "tsc")) {
		nohpet = 1;
		pmtmr_ioport = 0;
		use_kvm_time = 0;
	} else if (!strcmp(str, "tsccount")) {
		timekeeping_use_tsc = 1;
		use_kvm_time = 0;
	} else if (!strcmp(str, "notsccount")) {
		timekeeping_use_tsc = -1;
		use_kvm_time = 0;
	} else
		printk(KERN_WARNING "%s is unknown clock source\n", str);

	return 1;
}
__setup("clock=", boot_override_clock);

#ifdef CONFIG_TICK_DIVIDER


unsigned int tick_divider = 1;

static int __init divider_setup(char *s)
{
	unsigned int divider = 1;
	get_option(&s, &divider);
	if (divider >= 1 && HZ/divider >= 25)
		tick_divider = divider;
	else
		printk(KERN_ERR "tick_divider: %d is out of range.\n", divider);
	return 1;
}

__setup("divider=", divider_setup);
#endif


/*
 * If the kernel parameter 'divider' is set to a value greater than 1,
 * the kernel parameter 'pmtimer_fine_grained' enables / disables the
 * functionality of pmtimer_mark_offset_return_njiffies() as well as
 * the divider-specific initialization of 'tick_nsec' in time_init().
 */

static int __init pmtimer_fine_grained_setup(char *s)
{
	unsigned int fine_grained = 1;
	int ret = get_option(&s, (int *)&fine_grained);

	if (ret == 1 && fine_grained < 2)
		pmtimer_fine_grained = fine_grained;
	else
		printk(KERN_ERR "pmtimer_fine_grained: incorrect value\n");

	if (!pmtimer_fine_grained)
		printk(KERN_INFO "PM timer fine grained accounting disabled\n");

	return 1;
}

__setup("pmtimer_fine_grained=", pmtimer_fine_grained_setup);
