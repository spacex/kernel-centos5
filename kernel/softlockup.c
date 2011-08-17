/*
 * Detect Soft Lockups
 *
 * started by Ingo Molnar, Copyright (C) 2005, 2006 Red Hat, Inc.
 *
 * this code detects soft lockups: incidents in where on a CPU
 * the kernel does not reschedule for 10 seconds or more.
 */
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/notifier.h>
#include <linux/module.h>
#include <linux/sched.h>

static DEFINE_SPINLOCK(print_lock);

static DEFINE_PER_CPU(unsigned long, touch_timestamp);
static DEFINE_PER_CPU(unsigned long, print_timestamp);
static DEFINE_PER_CPU(struct task_struct *, watchdog_task);

static int did_panic = 0;
unsigned long softlockup_thresh = 60;

/*
 * Should we panic (and reboot, if panic_timeout= is set) when a
 * soft-lockup occurs:
 */
unsigned int __read_mostly softlockup_panic = 0;

static int __init softlockup_panic_setup(char *str)
{
	softlockup_panic = simple_strtoul(str, NULL, 0);

	return 1;
}
__setup("softlockup_panic=", softlockup_panic_setup);

static int
softlock_panic(struct notifier_block *this, unsigned long event, void *ptr)
{
	did_panic = 1;

	return NOTIFY_DONE;
}

static struct notifier_block panic_block = {
	.notifier_call = softlock_panic,
};

void touch_softlockup_watchdog(void)
{
	__raw_get_cpu_var(touch_timestamp) = jiffies;
}
EXPORT_SYMBOL(touch_softlockup_watchdog);

unsigned long softlockup_get_next_event(void)
{
	int this_cpu = smp_processor_id();
	unsigned long touch_timestamp = per_cpu(touch_timestamp, this_cpu);

	if (per_cpu(print_timestamp, this_cpu) == touch_timestamp ||
		did_panic ||
			!per_cpu(watchdog_task, this_cpu))
		return MAX_JIFFY_OFFSET;

	return max_t(long, 0, touch_timestamp + HZ - jiffies);
}

void touch_all_softlockup_watchdogs(void)
{
	int cpu;

	/* Cause each CPU to re-update its timestamp rather than complain */
	for_each_online_cpu(cpu)
		per_cpu(touch_timestamp, cpu) = 0;
}
EXPORT_SYMBOL(touch_all_softlockup_watchdogs);

/*
 * This callback runs from the timer interrupt, and checks
 * whether the watchdog thread has hung or not:
 */
void softlockup_tick(struct pt_regs *regs)
{
	int this_cpu = smp_processor_id();
	unsigned long touch_timestamp = per_cpu(touch_timestamp, this_cpu);
	unsigned long print_timestamp;
	unsigned long now;

	if (touch_timestamp == 0) {
		touch_softlockup_watchdog();
		return;
	}

	print_timestamp = per_cpu(print_timestamp, this_cpu);
	/* report at most once a second */
	if (time_after_eq(print_timestamp, touch_timestamp) &&
	    time_before(print_timestamp, touch_timestamp + HZ) ||
 	    did_panic || !per_cpu(watchdog_task, this_cpu)) {
		return;
	}

	/* do not print during early bootup: */
	if (unlikely(system_state != SYSTEM_RUNNING)) {
		touch_softlockup_watchdog();
		return;
	}

	now = jiffies;

	/* Wake up the high-prio watchdog task every second: */
	if (time_after(now, touch_timestamp + HZ))
		wake_up_process(per_cpu(watchdog_task, this_cpu));

	/* Warn about unreasonable 10+ seconds delays: */
	if (time_before(now, touch_timestamp + softlockup_thresh*HZ))
		return;

	per_cpu(print_timestamp, this_cpu) = touch_timestamp;

	spin_lock(&print_lock);
	printk(KERN_ERR "BUG: soft lockup - CPU#%d stuck for %lus! [%s:%d]\n",
	       this_cpu, (now - touch_timestamp)/HZ,
	       current->comm, current->pid);
	if (regs)
		show_regs(regs);
	else
		dump_stack();
	spin_unlock(&print_lock);

	if (softlockup_panic)
		panic("softlockup: hung tasks");
}

/*
 * The watchdog thread - runs every second and touches the timestamp.
 */
static int watchdog(void * __bind_cpu)
{
	struct sched_param param = { .sched_priority = 99 };

	sched_setscheduler(current, SCHED_FIFO, &param);
	current->flags |= PF_NOFREEZE;

	/*
	 * Run briefly once per second to reset the softlockup timestamp.
	 * If this gets delayed for more than 10 seconds then the
	 * debug-printout triggers in softlockup_tick().
	 */
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		touch_softlockup_watchdog();
		schedule();
	}

	return 0;
}

/*
 * Create/destroy watchdog threads as CPUs come and go:
 */
static int __cpuinit
cpu_callback(struct notifier_block *nfb, unsigned long action, void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
		BUG_ON(per_cpu(watchdog_task, hotcpu));
		p = kthread_create(watchdog, hcpu, "watchdog/%d", hotcpu);
		if (IS_ERR(p)) {
			printk("watchdog for %i failed\n", hotcpu);
			return NOTIFY_BAD;
		}
  		per_cpu(touch_timestamp, hotcpu) = jiffies;
  		per_cpu(watchdog_task, hotcpu) = p;
		kthread_bind(p, hotcpu);
 		break;
	case CPU_ONLINE:
		wake_up_process(per_cpu(watchdog_task, hotcpu));
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
		if (!per_cpu(watchdog_task, hotcpu))
			break;
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(watchdog_task, hotcpu),
			     any_online_cpu(cpu_online_map));
	case CPU_DEAD:
		p = per_cpu(watchdog_task, hotcpu);
		per_cpu(watchdog_task, hotcpu) = NULL;
		kthread_stop(p);
		break;
#endif /* CONFIG_HOTPLUG_CPU */
 	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

__init void spawn_softlockup_task(void)
{
	void *cpu = (void *)(long)smp_processor_id();

	cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);
	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
	register_cpu_notifier(&cpu_nfb);

	atomic_notifier_chain_register(&panic_notifier_list, &panic_block);
}
