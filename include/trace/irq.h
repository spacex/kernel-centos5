#ifndef _TRACE_IRQ_H
#define _TRACE_IRQ_H

#include <linux/tracepoint.h>
#include <linux/interrupt.h>

struct irqaction;
struct softirq_action;

DEFINE_TRACE(irq_entry,
	TPPROTO(unsigned int id, struct pt_regs *regs),
	TPARGS(id, regs));
DEFINE_TRACE(irq_exit,
	TPPROTO(unsigned int id, irqreturn_t retval),
	TPARGS(id, retval));
DEFINE_TRACE(irq_softirq_entry,
	TPPROTO(struct softirq_action *h, struct softirq_action *softirq_vec),
	TPARGS(h, softirq_vec));
DEFINE_TRACE(irq_softirq_exit,
	TPPROTO(struct softirq_action *h, struct softirq_action *softirq_vec),
	TPARGS(h, softirq_vec));
DEFINE_TRACE(irq_tasklet_low_entry,
	TPPROTO(struct tasklet_struct *t),
	TPARGS(t));
DEFINE_TRACE(irq_tasklet_low_exit,
	TPPROTO(struct tasklet_struct *t),
	TPARGS(t));
DEFINE_TRACE(irq_tasklet_high_entry,
	TPPROTO(struct tasklet_struct *t),
	TPARGS(t));
DEFINE_TRACE(irq_tasklet_high_exit,
	TPPROTO(struct tasklet_struct *t),
	TPARGS(t));
DEFINE_TRACE(softirq_raise,
	TPPROTO(unsigned int h, struct softirq_action *vec),
	TPARGS(h, vec));
#endif
