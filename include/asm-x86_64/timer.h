#ifndef _ASM_X86_64_TIMER_H
#define _ASM_X86_64_TIMER_H
extern int timekeeping_use_tsc;

extern int enable_tsc_timer;
extern cycles_t cycles_per_tick, cycles_accounted_limit, last_tsc_accounted;
#endif
