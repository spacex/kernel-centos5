/*
 * Copyright 2006 Andi Kleen, SUSE Labs.
 * Subject to the GNU Public License, v.2
 *
 * Fast user context implementation of clock_gettime and gettimeofday.
 *
 * The code should have no internal unresolved relocations.
 * Check with readelf after changing.
 * Also alternative() doesn't work.
 */

#include <linux/kernel.h>
#include <linux/posix-timers.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/clocksource.h>
#include <asm/vsyscall.h>
#include <asm/timex.h>
#include <asm/hpet.h>
#include <asm/unistd.h>
#include <asm/io.h>
#include "vextern.h"

#define NS_SCALE	10 /* 2^10, carefully chosen */

static long vdso_fallback_gettime(long clock, struct timespec *ts)
{
	long ret;
	asm("syscall" : "=a" (ret) :
	    "0" (__NR_clock_gettime),"D" (clock), "S" (ts) : "memory");
	return ret;
}

static inline cycle_t vread_hpet(void)
{
	return readl((void __iomem *)fix_to_virt(VSYSCALL_HPET) + 0xf0);
}

static inline cycle_t vread_tsc(void)
{
	cycle_t ret = (cycle_t)get_cycles_sync();
	return ret;
}

static inline long vgetns(void)
{
	cycles_t vread;
	long cycle_last, mult;

	if (vdso_vxtime->mode == VXTIME_HPET) {
		vread = vread_hpet();
		cycle_last = vdso_vxtime->last;
		mult = vdso_vxtime->quot;
	} else if (vdso_vxtime->mode == VXTIME_TSC) {
		vread = vread_tsc();
		cycle_last = vdso_vxtime->last_tsc;
		mult = vdso_vxtime->tsc_quot;
	}

	return ((vread - cycle_last) * mult) >>
			NS_SCALE;
}

static noinline int do_realtime(struct timespec *ts)
{
	unsigned long seq, ns;
	do {
		seq = read_seqbegin(vdso_xtime_lock);
		ts->tv_sec = vdso_xtime->tv_sec;
		ts->tv_nsec = vdso_xtime->tv_nsec;
		ns = vgetns();
	} while (unlikely(read_seqretry(vdso_xtime_lock, seq)));
	timespec_add_ns(ts, ns);
	return 0;
}

/* Copy of the version in kernel/time.c which we cannot directly access */
static void vset_normalized_timespec(struct timespec *ts, long sec, long nsec)
{
	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts->tv_sec = sec;
	ts->tv_nsec = nsec;
}

static noinline int do_monotonic(struct timespec *ts)
{
	unsigned long seq, ns, secs;
	do {
		seq = read_seqbegin(vdso_xtime_lock);
		secs = vdso_xtime->tv_sec;
		ns = vdso_xtime->tv_nsec + vgetns();
		secs += wall_to_monotonic.tv_sec;
		ns += wall_to_monotonic.tv_nsec;
	} while (unlikely(read_seqretry(vdso_xtime_lock, seq)));
	vset_normalized_timespec(ts, secs, ns);
	return 0;
}

int __vdso_clock_gettime(clockid_t clock, struct timespec *ts)
{
	if (likely(vdso_sysctl_vsyscall && (vdso_vxtime->mode != VXTIME_KVM)))
		switch (clock) {
		case CLOCK_REALTIME:
			return do_realtime(ts);
		case CLOCK_MONOTONIC:
			return do_monotonic(ts);
		}
	return vdso_fallback_gettime(clock, ts);
}
int clock_gettime(clockid_t, struct timespec *)
	 __attribute__((weak, alias("__vdso_clock_gettime")));

int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret;

	if (likely(vdso_sysctl_vsyscall && (vdso_vxtime->mode != VXTIME_KVM))) {
		BUILD_BUG_ON(offsetof(struct timeval, tv_usec) !=
			     offsetof(struct timespec, tv_nsec) ||
			     sizeof(*tv) != sizeof(struct timespec));
		do_realtime((struct timespec *)tv);
		tv->tv_usec /= 1000;
		if (unlikely(tz != NULL)) {
			/* This relies on gcc inlining the memcpy. We'll notice
			   if it ever fails to do so. */
			memcpy(tz, vdso_sys_tz, sizeof(struct timezone));
		}
		return 0;
	}
	asm("syscall" : "=a" (ret) :
	    "0" (__NR_gettimeofday), "D" (tv), "S" (tz) : "memory");
	return ret;
}
int gettimeofday(struct timeval *, struct timezone *)
	__attribute__((weak, alias("__vdso_gettimeofday")));
