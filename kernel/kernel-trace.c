/*
 * kernel/kernel-trace.c
 *
 * kernel tracepoint probes.
 */

#include <linux/autoconf.h>
#include <linux/module.h>
#include <trace/sched.h>
#include <trace/irq.h>

static void probe_irq_entry(unsigned int id, struct pt_regs *regs)
{
	trace_mark(kernel_irq_entry, "irq_id %u kernel_mode %u", id,
		(regs)?(!user_mode(regs)):(1));
}

static void probe_irq_exit(unsigned int id, irqreturn_t retval)
{
	trace_mark(kernel_irq_exit, "irq_id %u retval %ld", id, (long)retval);
}

static void probe_activate_task(struct task_struct *p, struct rq *rq)
{
	trace_mark(kernel_activate_task, "pid %d state %ld cpu_id %u",
		p->pid, p->state, task_cpu(p));
}

static void probe_deactivate_task(struct task_struct *p, struct rq *rq)
{
	trace_mark(kernel_deactivate_task, "pid %d state %ld cpu_id %u",
		p->pid, p->state, task_cpu(p));
}

static void probe_sched_wakeup(struct rq *rq, struct task_struct *p)
{
	trace_mark(kernel_sched_wakeup, "pid %d state %ld cpu_id %u",
		p->pid, p->state, task_cpu(p));
}

static void probe_sched_wakeup_new(struct rq *rq, struct task_struct *p)
{
	trace_mark(kernel_sched_wakeup_new, "pid %d state %ld cpu_id %u",
		p->pid, p->state, task_cpu(p));
}

static void probe_sched_switch(struct rq *rq, struct task_struct *prev,
		struct task_struct *next)
{
	trace_mark(kernel_sched_switch,
		"prev_pid %d next_pid %d prev_state %ld prev_prio %d "
		"next_prio %d",
		prev->pid, next->pid, prev->state, prev->prio, next->prio);
}

static void probe_softirq_entry(struct softirq_action *h,
	struct softirq_action *softirq_vec)
{
	trace_mark(kernel_softirq_entry, "softirq_id %lu func %p",
		((unsigned long)h - (unsigned long)softirq_vec) / sizeof(*h),
		(void *)h->action);
}

static void probe_softirq_exit(struct softirq_action *h,
	struct softirq_action *softirq_vec)
{
	trace_mark(kernel_softirq_exit, "softirq_id %lu",
		((unsigned long)h - (unsigned long)softirq_vec) / sizeof(*h));
}

static void probe_tasklet_low_entry(struct tasklet_struct *t)
{
	trace_mark(kernel_tasklet_low_entry, "func %p data %lu",
		t->func, t->data);
}

static void probe_tasklet_low_exit(struct tasklet_struct *t)
{
	trace_mark(kernel_tasklet_low_exit, "func %p data %lu",
		t->func, t->data);
}

static void probe_tasklet_high_entry(struct tasklet_struct *t)
{
	trace_mark(kernel_tasklet_high_entry, "func %p data %lu",
		t->func, t->data);
}

static void probe_tasklet_high_exit(struct tasklet_struct *t)
{
	trace_mark(kernel_tasklet_high_exit, "func %p data %lu",
		t->func, t->data);
}

static void probe_process_free(struct task_struct *p)
{
	trace_mark(kernel_process_free, "pid %d", p->pid);
}

static void probe_process_exit(struct task_struct *p)
{
	trace_mark(kernel_process_exit, "pid %d", p->pid);
}

static void probe_process_wait(pid_t pid)
{
	trace_mark(kernel_process_wait, "pid %d", (int)pid);
}

static void probe_process_fork(struct task_struct *parent,
		struct task_struct *child)
{
	trace_mark(kernel_process_fork,
		"parent_pid %d child_pid %d child_tgid %d",
		parent->pid, child->pid, child->tgid);
}

int __init kernel_trace_init(void)
{
	int ret;

	ret = register_trace_irq_entry(probe_irq_entry);
	WARN_ON(ret);
	ret = register_trace_irq_exit(probe_irq_exit);
	WARN_ON(ret);
	ret = register_trace_activate_task(
		probe_activate_task);
	WARN_ON(ret);
	ret = register_trace_deactivate_task(
		probe_deactivate_task);
	WARN_ON(ret);
	ret = register_trace_sched_wakeup(
		probe_sched_wakeup);
	WARN_ON(ret);
	ret = register_trace_sched_wakeup_new(
		probe_sched_wakeup_new);
	WARN_ON(ret);
	ret = register_trace_sched_switch(
		probe_sched_switch);
	WARN_ON(ret);
	ret = register_trace_irq_softirq_entry(probe_softirq_entry);
	WARN_ON(ret);
	ret = register_trace_irq_softirq_exit(probe_softirq_exit);
	WARN_ON(ret);
	ret = register_trace_irq_tasklet_low_entry(
		probe_tasklet_low_entry);
	WARN_ON(ret);
	ret = register_trace_irq_tasklet_low_exit(
		probe_tasklet_low_exit);
	WARN_ON(ret);
	ret = register_trace_irq_tasklet_high_entry(
		probe_tasklet_high_entry);
	WARN_ON(ret);
	ret = register_trace_irq_tasklet_high_exit(
		probe_tasklet_high_exit);
	WARN_ON(ret);
	ret = register_trace_sched_process_free(probe_process_free);
	WARN_ON(ret);
	ret = register_trace_sched_process_exit(probe_process_exit);
	WARN_ON(ret);
	ret = register_trace_sched_process_wait(probe_process_wait);
	WARN_ON(ret);
	ret = register_trace_sched_process_fork(probe_process_fork);
	WARN_ON(ret);

	return 0;
}

module_init(kernel_trace_init);

void __exit kernel_trace_exit(void)
{
	unregister_trace_sched_process_fork(probe_process_fork);
	unregister_trace_sched_process_wait(probe_process_wait);
	unregister_trace_sched_process_exit(probe_process_exit);
	unregister_trace_sched_process_free(probe_process_free);
	unregister_trace_irq_tasklet_high_exit(
		probe_tasklet_high_exit);
	unregister_trace_irq_tasklet_high_entry(
		probe_tasklet_high_entry);
	unregister_trace_irq_tasklet_low_exit(
		probe_tasklet_low_exit);
	unregister_trace_irq_tasklet_low_entry(
		probe_tasklet_low_entry);
	unregister_trace_irq_softirq_exit(probe_softirq_exit);
	unregister_trace_irq_softirq_entry(probe_softirq_entry);
	unregister_trace_sched_switch(probe_sched_switch);
	unregister_trace_sched_wakeup_new(
		probe_sched_wakeup_new);
	unregister_trace_sched_wakeup(
		probe_sched_wakeup);
	unregister_trace_deactivate_task(probe_deactivate_task);
	unregister_trace_activate_task(probe_activate_task);
	unregister_trace_irq_exit(probe_irq_exit);
	unregister_trace_irq_entry(probe_irq_entry);
}

module_exit(kernel_trace_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathieu Desnoyers");
MODULE_DESCRIPTION("kernel Tracepoint Probes");
