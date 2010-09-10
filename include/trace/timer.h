#ifndef _TRACE_TIMER_H
#define _TRACE_TIMER_H

#include <linux/tracepoint.h>

DEFINE_TRACE(itimer_state,
	TPPROTO(int which, struct itimerval *value,
		cputime_t expires),
	TPARGS(which, value, expires));
DEFINE_TRACE(itimer_expire,
	TPPROTO(int which, struct signal_struct *sig, cputime_t now),
	TPARGS(which, sig, now));
DEFINE_TRACE(timer_expire_entry,
	TPPROTO(struct timer_list *timer),
	TPARGS(timer));
DEFINE_TRACE(timer_expire_exit,
	TPPROTO(struct timer_list *timer),
	TPARGS(timer));
DEFINE_TRACE(timer_init,
	TPPROTO(struct timer_list *timer),
	TPARGS(timer));
DEFINE_TRACE(timer_start,
	TPPROTO(struct timer_list *timer, unsigned long expires),
	TPARGS(timer, expires));
DEFINE_TRACE(timer_cancel,
	TPPROTO(struct timer_list *timer),
	TPARGS(timer));


#endif
