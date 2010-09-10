#ifndef _TRACE_SIGNAL_H
#define _TRACE_SIGNAL_H

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/tracepoint.h>

/**
 * signal_generate - called when a signal is generated
 * @sig: signal number
 * @info: pointer to struct siginfo
 * @task: pointer to struct task_struct
 *
 * Current process sends a 'sig' signal to 'task' process with
 * 'info' siginfo. If 'info' is SEND_SIG_NOINFO or SEND_SIG_PRIV,
 * 'info' is not a pointer and you can't access its field. Instead,
 * SEND_SIG_NOINFO means that si_code is SI_USER, and SEND_SIG_PRIV
 * means that si_code is SI_KERNEL.
 */
DEFINE_TRACE(signal_generate,
	TPPROTO(int sig, struct siginfo *info, struct task_struct *task),
	TPARGS(sig, info, task)
);

/**
 * signal_deliver - called when a signal is delivered
 * @sig: signal number
 * @info: pointer to struct siginfo
 * @ka: pointer to struct k_sigaction
 *
 * A 'sig' signal is delivered to current process with 'info' siginfo,
 * and it will be handled by 'ka'. ka->sa.sa_handler can be SIG_IGN or
 * SIG_DFL.
 * Note that some signals reported by signal_generate tracepoint can be
 * lost, ignored or modified (by debugger) before hitting this tracepoint.
 * This means, this can show which signals are actually delivered, but
 * matching generated signals and delivered signals may not be correct.
 */
DEFINE_TRACE(signal_deliver,
	TPPROTO(int sig, struct siginfo *info, struct k_sigaction *ka),
	TPARGS(sig, info, ka)
);

/**
 * signal_overflow_fail - called when signal queue is overflow
 * @sig: signal number
 * @info: pointer to struct siginfo
 *
 * Kernel fails to generate 'sig' signal with 'info' siginfo, because
 * siginfo queue is overflow, and the signal is dropped.
 * 'sig' is always one of RT signals.
 */
DEFINE_TRACE(signal_overflow_fail,
	TPPROTO(int sig, struct siginfo *info),
	TPARGS(sig, info)
);

/**
 * signal_lose_info - called when siginfo is lost
 * @sig: signal number
 * @info: pointer to struct siginfo
 *
 * Kernel generates 'sig' signal but loses 'info' siginfo, because siginfo
 * queue is overflow.
 * 'sig' is always one of non-RT signals.
 */
DEFINE_TRACE(signal_lose_info,
	TPPROTO(int sig, struct siginfo *info),
	TPARGS(sig, info)
);

/**
 * signal_coredump - called when dumping core by signal
 * @cprm: pointer to struct coredump_params
 * @core_name: core-name string
 *
 * Current process dumps core file to 'core_name' file, because 'cprm->signr'
 * signal is delivered.
 * 'cprm->file' is a pointer to file structure of core file, if it is NULL
 * or an error number(IS_ERR(cprm->file)), coredump should be failed.
 */
DEFINE_TRACE(signal_coredump,
	TPPROTO(struct coredump_params *cprm, const char *core_name),
	TPARGS(cprm, core_name)
);
#endif /* _TRACE_SIGNAL_H */
