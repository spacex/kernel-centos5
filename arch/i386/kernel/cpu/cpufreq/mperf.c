#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/slab.h>

#include "mperf.h"

#define dprintk(msg...) cpufreq_debug_printk(CPUFREQ_DEBUG_DRIVER, "acpi-cpufreq", msg)

/*
 * Return the measured active (C0) frequency on this CPU since last call
 * to this function.
 * Input: cpu number
 * Return: Average CPU frequency in terms of max frequency (zero on error)
 *
 * We use IA32_MPERF and IA32_APERF MSRs to get the measured performance
 * over a period of time, while CPU is in C0 state.
 * IA32_MPERF counts at the rate of max advertised frequency
 * IA32_APERF counts at the rate of actual CPU frequency
 * Only IA32_APERF/IA32_MPERF ratio is architecturally defined and
 * no meaning should be associated with absolute values of these MSRs.
 */
unsigned int cpufreq_get_measured_perf(unsigned int cpu)
{
	union {
		struct {
			u32 lo;
			u32 hi;
		} split;
		u64 whole;
	} aperf_cur, mperf_cur;

	cpumask_t saved_mask;
	unsigned int perf_percent;
	unsigned int retval;
	struct cpufreq_policy *policy = NULL;

	saved_mask = current->cpus_allowed;
	set_cpus_allowed(current, cpumask_of_cpu(cpu));
	if (get_cpu() != cpu) {
		/* We were not able to run on requested processor */
		put_cpu();
		return 0;
	}

	policy = cpufreq_cpu_get(cpu);
	if (unlikely(!policy)) {
		put_cpu();
		return 0;
	}

	rdmsr(MSR_IA32_APERF, aperf_cur.split.lo, aperf_cur.split.hi);
	rdmsr(MSR_IA32_MPERF, mperf_cur.split.lo, mperf_cur.split.hi);

	wrmsr(MSR_IA32_APERF, 0,0);
	wrmsr(MSR_IA32_MPERF, 0,0);

#ifdef __i386__
	/*
	 * We dont want to do 64 bit divide with 32 bit kernel
	 * Get an approximate value. Return failure in case we cannot get
	 * an approximate value.
	 */
	if (unlikely(aperf_cur.split.hi || mperf_cur.split.hi)) {
		int shift_count;
		u32 h;

		h = max_t(u32, aperf_cur.split.hi, mperf_cur.split.hi);
		shift_count = fls(h);

		aperf_cur.whole >>= shift_count;
		mperf_cur.whole >>= shift_count;
	}

	if (((unsigned long)(-1) / 100) < aperf_cur.split.lo) {
		int shift_count = 7;
		aperf_cur.split.lo >>= shift_count;
		mperf_cur.split.lo >>= shift_count;
	}

	if (aperf_cur.split.lo && mperf_cur.split.lo)
		perf_percent = (aperf_cur.split.lo * 100) / mperf_cur.split.lo;
	else
		perf_percent = 0;

#else
	if (unlikely(((unsigned long)(-1) / 100) < aperf_cur.whole)) {
		int shift_count = 7;
		aperf_cur.whole >>= shift_count;
		mperf_cur.whole >>= shift_count;
	}

	if (aperf_cur.whole && mperf_cur.whole)
		perf_percent = (aperf_cur.whole * 100) / mperf_cur.whole;
	else
		perf_percent = 0;

#endif

	retval = policy->cpuinfo.max_freq * perf_percent / 100;

	cpufreq_cpu_put(policy);
	put_cpu();
	set_cpus_allowed(current, saved_mask);

	dprintk("cpu %d: performance percent %d\n", cpu, perf_percent);
	return retval;
}

EXPORT_SYMBOL_GPL(cpufreq_get_measured_perf);
MODULE_LICENSE("GPL");
