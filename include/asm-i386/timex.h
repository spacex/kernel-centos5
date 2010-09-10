/*
 * linux/include/asm-i386/timex.h
 *
 * i386 architecture timex specifications
 */
#ifndef _ASMi386_TIMEX_H
#define _ASMi386_TIMEX_H

#include <asm/processor.h>
#include <asm/tsc.h>

#ifdef CONFIG_X86_ELAN
#  define CLOCK_TICK_RATE 1189200 /* AMD Elan has different frequency! */
#else
#  define CLOCK_TICK_RATE 1193182 /* Underlying HZ */
#endif

/*
 * Stop RDTSC speculation. This is needed when you need to use RDTSC
 * (or get_cycles or vread that possibly accesses the TSC) in a defined
 * code region.
 *
 * (Could use an alternative three way for this if there was one.)
 */
static inline void rdtsc_barrier(void)
{
	alternative(ASM_NOP3, "mfence", X86_FEATURE_MFENCE_RDTSC);
	alternative(ASM_NOP3, "lfence", X86_FEATURE_LFENCE_RDTSC);
}

extern int read_current_timer(unsigned long *timer_value);
#define ARCH_HAS_READ_CURRENT_TIMER	1

#endif
