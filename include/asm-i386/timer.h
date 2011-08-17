#ifndef _ASMi386_TIMER_H
#define _ASMi386_TIMER_H
#include <linux/init.h>
#include <linux/pm.h>
#include <asm/tsc.h>

#define TICK_SIZE (tick_nsec / 1000)
void setup_pit_timer(void);
/* Modifiers for buggy PIT handling */
extern int pit_latch_buggy;
extern int timer_ack;
extern int recalibrate_cpu_khz(void);

extern void do_timer_tsc_timekeeping(struct pt_regs *regs);
extern int enable_tsc_timer;
extern cycles_t cycles_per_tick, cycles_accounted_limit, last_tsc_accounted;

#endif
