#ifndef _TRACE_SCHED_H
#define _TRACE_SCHED_H

#include <linux/tracepoint.h>
#include <linux/sched.h>

struct rq;

DEFINE_TRACE(activate_task,
	TPPROTO(struct task_struct *p, struct rq *rq),
	TPARGS(p, rq));
DEFINE_TRACE(deactivate_task,
	TPPROTO(struct task_struct *p, struct rq *rq),
	TPARGS(p, rq));
DEFINE_TRACE(sched_wakeup,
	TPPROTO(struct rq *rq, struct task_struct *p, int success),
	TPARGS(rq, p, success));
DEFINE_TRACE(sched_wakeup_new,
	TPPROTO(struct rq *rq, struct task_struct *p, int success),
	TPARGS(rq, p, success));
DEFINE_TRACE(sched_switch,
	TPPROTO(struct rq *rq, struct task_struct *prev,
		struct task_struct *next),
	TPARGS(rq, prev, next));
DEFINE_TRACE(sched_process_free,
	TPPROTO(struct task_struct *p),
	TPARGS(p));
DEFINE_TRACE(sched_process_exit,
	TPPROTO(struct task_struct *p),
	TPARGS(p));
DEFINE_TRACE(sched_process_wait,
	TPPROTO(pid_t pid),
	TPARGS(pid));
DEFINE_TRACE(sched_process_fork,
	TPPROTO(struct task_struct *parent, struct task_struct *child),
	TPARGS(parent, child));

#endif
