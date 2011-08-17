/*
 *  Kernel Probes (KProbes)
 *  kernel/kprobes.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2002, 2004
 *
 * 2002-Oct	Created by Vamsi Krishna S <vamsi_krishna@in.ibm.com> Kernel
 *		Probes initial implementation (includes suggestions from
 *		Rusty Russell).
 * 2004-Aug	Updated by Prasanna S Panchamukhi <prasanna@in.ibm.com> with
 *		hlists and exceptions notifier as suggested by Andi Kleen.
 * 2004-July	Suparna Bhattacharya <suparna@in.ibm.com> added jumper probes
 *		interface to access function arguments.
 * 2004-Sep	Prasanna S Panchamukhi <prasanna@in.ibm.com> Changed Kprobes
 *		exceptions notifier to be first on the priority list.
 * 2005-May	Hien Nguyen <hien@us.ibm.com>, Jim Keniston
 *		<jkenisto@us.ibm.com> and Prasanna S Panchamukhi
 *		<prasanna@in.ibm.com> added function-return probes.
 */
#include <linux/kprobes.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/kallsyms.h>
#include <linux/cpu.h>
#include <linux/sysctl.h>
#include <asm-generic/sections.h>
#include <asm/cacheflush.h>
#include <asm/errno.h>
#include <asm/kdebug.h>

#define KPROBE_HASH_BITS 6
#define KPROBE_TABLE_SIZE (1 << KPROBE_HASH_BITS)


/*
 * Some oddball architectures like 64bit powerpc have function descriptors
 * so this must be overridable.
 */
#ifndef kprobe_lookup_name
#define kprobe_lookup_name(name, addr) \
	addr = ((kprobe_opcode_t *)(kallsyms_lookup_name(name)))
#endif

static struct hlist_head kprobe_table[KPROBE_TABLE_SIZE];
static struct hlist_head kretprobe_inst_table[KPROBE_TABLE_SIZE];
static atomic_t kprobe_count;

DEFINE_MUTEX(kprobe_mutex);		/* Protects kprobe_table */
DEFINE_SPINLOCK(kretprobe_lock);	/* Protects kretprobe_inst_table */
static DEFINE_PER_CPU(struct kprobe *, kprobe_instance) = NULL;

static struct notifier_block kprobe_page_fault_nb = {
	.notifier_call = kprobe_exceptions_notify,
	.priority = 0x7fffffff /* we need to notified first */
};

#ifdef __ARCH_WANT_KPROBES_INSN_SLOT
/*
 * kprobe->ainsn.insn points to the copy of the instruction to be
 * single-stepped. x86_64, POWER4 and above have no-exec support and
 * stepping on the instruction on a vmalloced/kmalloced/data page
 * is a recipe for disaster
 */

struct kprobe_insn_page {
	struct list_head list;
	kprobe_opcode_t *insns;		/* Page of instruction slots */
	int nused;
	char slot_used[0];
};

#define KPROBE_INSN_PAGE_SIZE(slots)			\
	(offsetof(struct kprobe_insn_page, slot_used) +	\
	 (sizeof(char) * (slots)))

struct kprobe_insn_cache {
	struct list_head pages;	/* list of kprobe_insn_page */
	size_t insn_size;	/* size of instruction slot */
};

static int slots_per_page(struct kprobe_insn_cache *c)
{
	return PAGE_SIZE/(c->insn_size * sizeof(kprobe_opcode_t));
}

static struct kprobe_insn_cache kprobe_insn_slots = {
	.pages = LIST_HEAD_INIT(kprobe_insn_slots.pages),
	.insn_size = MAX_INSN_SIZE,
};

/**
 * get_insn_slot() - Find a slot on an executable page for an instruction.
 * We allocate an executable page if there's no room on existing ones.
 */
static kprobe_opcode_t __kprobes *__get_insn_slot(struct kprobe_insn_cache *c)
{
	struct kprobe_insn_page *kip;

	list_for_each_entry(kip, &c->pages, list) {
		if (kip->nused < slots_per_page(c)) {
			int i;
			for (i = 0; i < slots_per_page(c); i++) {
				if (!kip->slot_used[i]) {
					kip->slot_used[i] = 1;
					kip->nused++;
					return kip->insns + (i * c->insn_size);
				}
			}
			/* kip->nused is broken. Fix it. */
			kip->nused = slots_per_page(c);
			WARN_ON(1);
		}
	}


	/* All out of space.  Need to allocate a new page. */
	kip = kmalloc(KPROBE_INSN_PAGE_SIZE(slots_per_page(c)), GFP_KERNEL);
	if (!kip) {
		return NULL;
	}

	/*
	 * Use module_alloc so this page is within +/- 2GB of where the
	 * kernel image and loaded module images reside. This is required
	 * so x86_64 can correctly handle the %rip-relative fixups.
	 */
	kip->insns = module_alloc(PAGE_SIZE);
	if (!kip->insns) {
		kfree(kip);
		return NULL;
	}
	INIT_LIST_HEAD(&kip->list);
	memset(kip->slot_used, 0, slots_per_page(c));
	kip->slot_used[0] = 1;
	kip->nused = 1;
	list_add(&kip->list, &c->pages);
	return kip->insns;
}

kprobe_opcode_t __kprobes *get_insn_slot(void)
{
	return __get_insn_slot(&kprobe_insn_slots);
}

static void __kprobes __free_insn_slot(struct kprobe_insn_cache *c,
				       kprobe_opcode_t *slot)
{
	struct kprobe_insn_page *kip;

	list_for_each_entry(kip, &c->pages, list) {
		long idx = ((long)slot - (long)kip->insns) /
				(c->insn_size * sizeof(kprobe_opcode_t));
		if (idx >= 0 && idx < slots_per_page(c)) {
			kip->slot_used[idx] = 0;
			kip->nused--;
			if (kip->nused == 0) {
				/*
				 * Page is no longer in use.  Free it unless
				 * it's the last one.  We keep the last one
				 * so as not to have to set it up again the
				 * next time somebody inserts a probe.
				 */
				if (!list_is_singular(&kip->list)) {
					list_del(&kip->list);
					module_free(NULL, kip->insns);
					kfree(kip);
				}
			}
			return;
		}
	}
}

void __kprobes free_insn_slot(kprobe_opcode_t *slot)
{
	__free_insn_slot(&kprobe_insn_slots, slot);
}
#ifdef CONFIG_OPTPROBES
/* For optimized_kprobe buffer */
static DEFINE_MUTEX(kprobe_optinsn_mutex); /* Protects kprobe_optinsn_slots */
static struct kprobe_insn_cache kprobe_optinsn_slots = {
	.pages = LIST_HEAD_INIT(kprobe_optinsn_slots.pages),
	/* .insn_size is initialized later */
};
/* Get a slot for optimized_kprobe buffer */
kprobe_opcode_t __kprobes *get_optinsn_slot(void)
{
	kprobe_opcode_t *ret = NULL;

	mutex_lock(&kprobe_optinsn_mutex);
	ret = __get_insn_slot(&kprobe_optinsn_slots);
	mutex_unlock(&kprobe_optinsn_mutex);

	return ret;
}

void __kprobes free_optinsn_slot(kprobe_opcode_t * slot, int dirty)
{
	mutex_lock(&kprobe_optinsn_mutex);
	__free_insn_slot(&kprobe_optinsn_slots, slot);
	mutex_unlock(&kprobe_optinsn_mutex);
}
#endif
#endif

/* We have preemption disabled.. so it is safe to use __ versions */
static inline void set_kprobe_instance(struct kprobe *kp)
{
	__get_cpu_var(kprobe_instance) = kp;
}

static inline void reset_kprobe_instance(void)
{
	__get_cpu_var(kprobe_instance) = NULL;
}

/*
 * This routine is called either:
 * 	- under the kprobe_mutex - during kprobe_[un]register()
 * 				OR
 * 	- with preemption disabled - from arch/xxx/kernel/kprobes.c
 */
struct kprobe __kprobes *get_kprobe(void *addr)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;

	head = &kprobe_table[hash_ptr(addr, KPROBE_HASH_BITS)];
	hlist_for_each_entry_rcu(p, node, head, hlist) {
		if (p->addr == addr)
			return p;
	}
	return NULL;
}

static int __kprobes aggr_pre_handler(struct kprobe *p, struct pt_regs *regs);

/* Return true if the kprobe is an aggregator */
static inline int kprobe_aggrprobe(struct kprobe *p)
{
	return p->pre_handler == aggr_pre_handler;
}

/*
 * Keep all fields in the kprobe consistent
 */
static inline void copy_kprobe(struct kprobe *old_p, struct kprobe *p)
{
	memcpy(&p->opcode, &old_p->opcode, sizeof(kprobe_opcode_t));
	memcpy(&p->ainsn, &old_p->ainsn, sizeof(struct arch_specific_insn));
}

#ifdef CONFIG_OPTPROBES
/* NOTE: change this value only with kprobe_mutex held */
static bool kprobes_allow_optimization;

/*
 * Call all pre_handler on the list, but ignores its return value.
 * This must be called from arch-dep optimized caller.
 */
void __kprobes opt_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *kp;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->pre_handler) {
			set_kprobe_instance(kp);
			kp->pre_handler(kp, regs);
		}
		reset_kprobe_instance();
	}
}

/* Return true(!0) if the kprobe is ready for optimization. */
static inline int kprobe_optready(struct kprobe *p)
{
	struct optimized_kprobe *op;

	if (kprobe_aggrprobe(p)) {
		op = container_of(p, struct optimized_kprobe, kp);
		return arch_prepared_optinsn(&op->optinsn);
	}

	return 0;
}

/*
 * Return an optimized kprobe whose optimizing code replaces
 * instructions including addr (exclude breakpoint).
 */
struct kprobe *__kprobes get_optimized_kprobe(unsigned long addr)
{
	int i;
	struct kprobe *p = NULL;
	struct optimized_kprobe *op;

	/* Don't check i == 0, since that is a breakpoint case. */
	for (i = 1; !p && i < MAX_OPTIMIZED_LENGTH; i++)
		p = get_kprobe((void *)(addr - i));

	if (p && kprobe_optready(p)) {
		op = container_of(p, struct optimized_kprobe, kp);
		if (arch_within_optimized_kprobe(op, addr))
			return p;
	}

	return NULL;
}

/* Optimization staging list, protected by kprobe_mutex */
static LIST_HEAD(optimizing_list);

static void kprobe_optimizer(void *dummy);
static DECLARE_WORK(optimizing_work, kprobe_optimizer, 0);
#define OPTIMIZE_DELAY 5

/* Kprobe jump optimizer */
static __kprobes void kprobe_optimizer(void *dummy)
{
	struct optimized_kprobe *op, *tmp;

	mutex_lock(&kprobe_mutex);
	if (!kprobes_allow_optimization)
  		goto end;
	/*
	 * Wait for quiesence period to ensure all running interrupts
	 * are done. Because optprobe may modify multiple instructions
	 * there is a chance that Nth instruction is interrupted. In that
	 * case, running interrupt can return to 2nd-Nth byte of jump
	 * instruction. This wait is for avoiding it.
	 */
	synchronize_sched();

	/*
	 * The optimization/unoptimization refers online_cpus via
	 * stop_machine() and cpu-hotplug modifies online_cpus.
	 * And same time, text_mutex will be held in cpu-hotplug and here.
	 * This combination can cause a deadlock (cpu-hotplug try to lock
	 * text_mutex but stop_machine can not be done because online_cpus
	 * has been changed)
	 * To avoid this deadlock, we need to call get_online_cpus()
	 * for preventing cpu-hotplug outside of text_mutex locking.
	 */
	/* get_online_cpus();	no, stop_machine_run locks cpu_hotplug) */
	/* mutex_lock(&text_mutex); no text_mutex */
	list_for_each_entry_safe(op, tmp, &optimizing_list, list) {
		if (arch_optimize_kprobe(op) < 0)
			kprobe_set_optimized(&op->kp, 0);
		list_del_init(&op->list);
	}
	/* mutex_unlock(&text_mutex); no text_mutex */
	/* put_online_cpus(); */
end:
	mutex_unlock(&kprobe_mutex);
}

/* Optimize kprobe if p is ready to be optimized */
static __kprobes void optimize_kprobe(struct kprobe *p)
{
	struct optimized_kprobe *op;

	/* Check if the kprobe is not ready for optimization. */
	if (!kprobe_optready(p) || !kprobes_allow_optimization)
		return;

	/* Both of break_handler and post_handler are not supported. */
	if (p->break_handler || p->post_handler)
		return;

	op = container_of(p, struct optimized_kprobe, kp);

	/* Check there is no other kprobes at the optimized instructions */
	if (arch_check_optimized_kprobe(op) < 0)
		return;

	/* Check if it is already optimized. */
	if (kprobe_get_optimized(&op->kp))
		return;

	kprobe_set_optimized(&op->kp, 1);
	list_add(&op->list, &optimizing_list);
	if (!delayed_work_pending(&optimizing_work))
		schedule_delayed_work(&optimizing_work, OPTIMIZE_DELAY);
}

/* Unoptimize a kprobe if p is optimized */
static __kprobes void unoptimize_kprobe(struct kprobe *p)
{
	struct optimized_kprobe *op;

	if (kprobe_get_optimized(p) && kprobe_aggrprobe(p)) {
		op = container_of(p, struct optimized_kprobe, kp);
		if (!list_empty(&op->list))
			/* Dequeue from the optimization queue */
			list_del_init(&op->list);
		else
			/* Replace jump with break */
			arch_unoptimize_kprobe(op);
		kprobe_set_optimized(&op->kp, 0);
	}
}

/* Free optimized instructions and optimized_kprobe */
static __kprobes void free_aggr_kprobe(struct kprobe *p)
{
	struct optimized_kprobe *op;

	op = container_of(p, struct optimized_kprobe, kp);
	arch_remove_optimized_kprobe(op);
	kfree(op);
}

/* Allocate new optimized_kprobe and try to prepare optimized instructions */
static __kprobes struct kprobe *alloc_aggr_kprobe(struct kprobe *p)
{
	struct optimized_kprobe *op;

	op = kzalloc(sizeof(struct optimized_kprobe), GFP_KERNEL);
	if (!op)
		return NULL;

	INIT_LIST_HEAD(&op->list);
	op->kp.addr = p->addr;
	arch_prepare_optimized_kprobe(op);

	return &op->kp;
}

static void __kprobes init_aggr_kprobe(struct kprobe *ap, struct kprobe *p);

/*
 * Prepare an optimized_kprobe and optimize it
 * NOTE: p must be a normal registered kprobe
 */
static __kprobes void try_to_optimize_kprobe(struct kprobe *p)
{
	struct kprobe *ap;
	struct optimized_kprobe *op;

	ap = alloc_aggr_kprobe(p);
	if (!ap)
		return;

	op = container_of(ap, struct optimized_kprobe, kp);
	if (!arch_prepared_optinsn(&op->optinsn)) {
		/* If failed to setup optimizing, fallback to kprobe */
		free_aggr_kprobe(ap);
		return;
	}

	init_aggr_kprobe(ap, p);
	optimize_kprobe(ap);
}

#ifdef CONFIG_SYSCTL
static void __kprobes optimize_all_kprobes(void)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;
	unsigned int i;

	/* If optimization is already allowed, just return */
	if (kprobes_allow_optimization)
		return;

	kprobes_allow_optimization = true;
	for (i = 0; i < KPROBE_TABLE_SIZE; i++) {
		head = &kprobe_table[i];
		hlist_for_each_entry_rcu(p, node, head, hlist)
			optimize_kprobe(p);
	}
	printk(KERN_INFO "Kprobes globally optimized\n");
}

static void __kprobes unoptimize_all_kprobes(void)
{
	struct hlist_head *head;
	struct hlist_node *node;
	struct kprobe *p;
	unsigned int i;

	/* If optimization is already prohibited, just return */
	if (!kprobes_allow_optimization)
		return;

	kprobes_allow_optimization = false;
	printk(KERN_INFO "Kprobes globally unoptimized\n");
	for (i = 0; i < KPROBE_TABLE_SIZE; i++) {
		head = &kprobe_table[i];
		hlist_for_each_entry_rcu(p, node, head, hlist) {
			unoptimize_kprobe(p);
		}
	}

	/* Allow all currently running kprobes to complete */
	synchronize_sched();
}

int sysctl_kprobes_optimization;
int proc_kprobes_optimization_handler(struct ctl_table *table,
				      int write, struct file *filp,
				      void __user *buffer, size_t *length,
				      loff_t *ppos)
{
	int ret;

	mutex_lock(&kprobe_mutex);
	sysctl_kprobes_optimization = kprobes_allow_optimization ? 1 : 0;
	ret = proc_dointvec_minmax(table, write, filp, buffer, length, ppos);

	if (sysctl_kprobes_optimization)
		optimize_all_kprobes();
	else
		unoptimize_all_kprobes();
	mutex_unlock(&kprobe_mutex);

	return ret;
}
#endif /* CONFIG_SYSCTL */

static void __kprobes __arm_kprobe(struct kprobe *p)
{
	struct kprobe *old_p;

	/* Check collision with other optimized kprobes */
	old_p = get_optimized_kprobe((unsigned long)p->addr);
	if (unlikely(old_p))
		unoptimize_kprobe(old_p); /* Fallback to unoptimized kprobe */

	arch_arm_kprobe(p);
	optimize_kprobe(p);	/* Try to optimize (add kprobe to a list) */
}

static void __kprobes __disarm_kprobe(struct kprobe *p)
{
	struct kprobe *old_p;

	unoptimize_kprobe(p);	/* Try to unoptimize */
	arch_disarm_kprobe(p);

	/* If another kprobe was blocked, optimize it. */
	old_p = get_optimized_kprobe((unsigned long)p->addr);
	if (unlikely(old_p))
		optimize_kprobe(old_p);
}

#else /* !CONFIG_OPTPROBES */

#define optimize_kprobe(p)			do {} while (0)
#define unoptimize_kprobe(p)			do {} while (0)
#define kill_optimized_kprobe(p)		do {} while (0)
#define prepare_optimized_kprobe(p)		do {} while (0)
#define try_to_optimize_kprobe(p)		do {} while (0)
#define __arm_kprobe(p)				arch_arm_kprobe(p)
#define __disarm_kprobe(p)			arch_disarm_kprobe(p)

static __kprobes void free_aggr_kprobe(struct kprobe *p)
{
	kfree(p);
}

static __kprobes struct kprobe *alloc_aggr_kprobe(struct kprobe *p)
{
	return kzalloc(sizeof(struct kprobe), GFP_KERNEL);
}
#endif /* CONFIG_OPTPROBES */

/* Arm a kprobe with text_mutex */
static void __kprobes arm_kprobe(struct kprobe *kp)
{
	__arm_kprobe(kp);
}

/* Disarm a kprobe with text_mutex */
static void __kprobes disarm_kprobe(struct kprobe *kp)
{
	__disarm_kprobe(kp);
}

/*
 * Aggregate handlers for multiple kprobes support - these handlers
 * take care of invoking the individual kprobe handlers on p->list
 */
static int __kprobes aggr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *kp;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->pre_handler) {
			set_kprobe_instance(kp);
			if (kp->pre_handler(kp, regs))
				return 1;
		}
		reset_kprobe_instance();
	}
	return 0;
}

static void __kprobes aggr_post_handler(struct kprobe *p, struct pt_regs *regs,
					unsigned long flags)
{
	struct kprobe *kp;

	list_for_each_entry_rcu(kp, &p->list, list) {
		if (kp->post_handler) {
			set_kprobe_instance(kp);
			kp->post_handler(kp, regs, flags);
			reset_kprobe_instance();
		}
	}
	return;
}

static int __kprobes aggr_fault_handler(struct kprobe *p, struct pt_regs *regs,
					int trapnr)
{
	struct kprobe *cur = __get_cpu_var(kprobe_instance);

	/*
	 * if we faulted "during" the execution of a user specified
	 * probe handler, invoke just that probe's fault handler
	 */
	if (cur && cur->fault_handler) {
		if (cur->fault_handler(cur, regs, trapnr))
			return 1;
	}
	return 0;
}

static int __kprobes aggr_break_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe *cur = __get_cpu_var(kprobe_instance);
	int ret = 0;

	if (cur && cur->break_handler) {
		if (cur->break_handler(cur, regs))
			ret = 1;
	}
	reset_kprobe_instance();
	return ret;
}

/* Walks the list and increments nmissed count for multiprobe case */
void __kprobes kprobes_inc_nmissed_count(struct kprobe *p)
{
	struct kprobe *kp;
	if (!kprobe_aggrprobe(p)) {
		p->nmissed++;
	} else {
		list_for_each_entry_rcu(kp, &p->list, list)
			kp->nmissed++;
	}
	return;
}

/* Called with kretprobe_lock held */
struct kretprobe_instance __kprobes *get_free_rp_inst(struct kretprobe *rp)
{
	struct hlist_node *node;
	struct kretprobe_instance *ri;
	hlist_for_each_entry(ri, node, &rp->free_instances, uflist)
		return ri;
	return NULL;
}

/* Called with kretprobe_lock held */
void __kprobes add_rp_inst(struct kretprobe_instance *ri)
{
	/*
	 * Remove rp inst off the free list -
	 * Add it back when probed function returns
	 */
	hlist_del(&ri->uflist);

	/* Add rp inst onto table */
	INIT_HLIST_NODE(&ri->hlist);
	hlist_add_head(&ri->hlist,
			&kretprobe_inst_table[hash_ptr(ri->task, KPROBE_HASH_BITS)]);

	/* Also add this rp inst to the used list. */
	INIT_HLIST_NODE(&ri->uflist);
	hlist_add_head(&ri->uflist, &ri->rp->used_instances);
}

/* Called with kretprobe_lock held */
void __kprobes recycle_rp_inst(struct kretprobe_instance *ri,
				struct hlist_head *head)
{
	/* remove rp inst off the rprobe_inst_table */
	hlist_del(&ri->hlist);
	if (ri->rp) {
		/* remove rp inst off the used list */
		hlist_del(&ri->uflist);
		/* put rp inst back onto the free list */
		INIT_HLIST_NODE(&ri->uflist);
		hlist_add_head(&ri->uflist, &ri->rp->free_instances);
	} else
		/* Unregistering */
		hlist_add_head(&ri->hlist, head);
}

struct hlist_head __kprobes *kretprobe_inst_table_head(struct task_struct *tsk)
{
	return &kretprobe_inst_table[hash_ptr(tsk, KPROBE_HASH_BITS)];
}

/*
 * This function is called from finish_task_switch when task tk becomes dead,
 * so that we can recycle any function-return probe instances associated
 * with this task. These left over instances represent probed functions
 * that have been called but will never return.
 */
void __kprobes kprobe_flush_task(struct task_struct *tk)
{
        struct kretprobe_instance *ri;
	struct hlist_head *head, empty_rp;
	struct hlist_node *node, *tmp;
	unsigned long flags = 0;

	INIT_HLIST_HEAD(&empty_rp);
	spin_lock_irqsave(&kretprobe_lock, flags);
        head = kretprobe_inst_table_head(tk);
        hlist_for_each_entry_safe(ri, node, tmp, head, hlist) {
                if (ri->task == tk)
			recycle_rp_inst(ri, &empty_rp);
        }
	spin_unlock_irqrestore(&kretprobe_lock, flags);

	hlist_for_each_entry_safe(ri, node, tmp, &empty_rp, hlist) {
		hlist_del(&ri->hlist);
		kfree(ri);
	}
}

static inline void free_rp_inst(struct kretprobe *rp)
{
	struct kretprobe_instance *ri;
	while ((ri = get_free_rp_inst(rp)) != NULL) {
		hlist_del(&ri->uflist);
		kfree(ri);
	}
}

static void __kprobes cleanup_rp_inst(struct kretprobe *rp)
{
	unsigned long flags;
	struct kretprobe_instance *ri;
	struct hlist_node *pos, *next;
	/* No race here */
	spin_lock_irqsave(&kretprobe_lock, flags);
	hlist_for_each_entry_safe(ri, pos, next, &rp->used_instances, uflist) {
		ri->rp = NULL;
		hlist_del(&ri->uflist);
	}
	spin_unlock_irqrestore(&kretprobe_lock, flags);
	free_rp_inst(rp);
}

/*
* Add the new probe to old_p->list. Fail if this is the
* second jprobe at the address - two jprobes can't coexist
*/
static int __kprobes add_new_kprobe(struct kprobe *old_p, struct kprobe *p)
{
	if (p->break_handler || p->post_handler)
		unoptimize_kprobe(old_p);	/* Fall back to normal kprobe */

	if (p->break_handler) {
		if (old_p->break_handler)
			return -EEXIST;
		list_add_tail_rcu(&p->list, &old_p->list);
		old_p->break_handler = aggr_break_handler;
	} else
		list_add_rcu(&p->list, &old_p->list);
	if (p->post_handler && !old_p->post_handler)
		old_p->post_handler = aggr_post_handler;
	return 0;
}

/*
 * Fill in the required fields of the "manager kprobe". Replace the
 * earlier kprobe in the hlist with the manager kprobe
 */
static void __kprobes init_aggr_kprobe(struct kprobe *ap, struct kprobe *p)
{
	/* Copy p's insn slot to ap */
	copy_kprobe(p, ap);
	flush_insn_slot(ap);
	ap->addr = p->addr;
	ap->pre_handler = aggr_pre_handler;
	ap->fault_handler = aggr_fault_handler;
	if (p->post_handler)
		ap->post_handler = aggr_post_handler;
	if (p->break_handler)
		ap->break_handler = aggr_break_handler;

	INIT_LIST_HEAD(&ap->list);
	INIT_HLIST_NODE(&ap->hlist);

	list_add_rcu(&p->list, &ap->list);
	hlist_replace_rcu(&p->hlist, &ap->hlist);
}

/*
 * This is the second or subsequent kprobe at the address - handle
 * the intricacies
 */
static int __kprobes register_aggr_kprobe(struct kprobe *old_p,
					  struct kprobe *p)
{
	int ret = 0;
	struct kprobe *ap = old_p;

	if (!kprobe_aggrprobe(old_p)) {
		/* If old_p is not an aggr_kprobe, create new aggr_kprobe. */
		ap = alloc_aggr_kprobe(old_p);
		if (!ap)
			return -ENOMEM;
		init_aggr_kprobe(ap, old_p);
	}
	/* Copy ap's insn slot to p */
	copy_kprobe(ap, p);
	ret = add_new_kprobe(ap, p);
	return ret;
}

static int __kprobes in_kprobes_functions(unsigned long addr)
{
	if (addr >= (unsigned long)__kprobes_text_start
		&& addr < (unsigned long)__kprobes_text_end)
		return -EINVAL;
	return 0;
}
/*
* If we have a symbol_name argument, look it up and add the offset field
* to it. This way, we can specify a relative address to a symbol.
*/
static kprobe_opcode_t __kprobes *kprobe_addr(struct kprobe *p)
{
	kprobe_opcode_t *addr = p->addr;
	if (p->symbol_name) {
		if (addr)
			return NULL;
		kprobe_lookup_name(p->symbol_name, addr);
	}

	if (!addr)
		return NULL;
	return (kprobe_opcode_t *)(((char *)addr) + p->offset);
}

static int __kprobes __register_kprobe(struct kprobe *p,
	unsigned long called_from)
{
	int ret = 0;
	struct kprobe *old_p;
	struct module *probed_mod;
	kprobe_opcode_t *addr;

	addr = kprobe_addr(p);
	if (!addr)
		return -EINVAL;
	p->addr = addr;

	if ((!kernel_text_address((unsigned long) p->addr)) ||
		in_kprobes_functions((unsigned long) p->addr))
		return -EINVAL;

	p->mod_refcounted = 0;
	/* Check are we probing a module */
	if ((probed_mod = module_text_address((unsigned long) p->addr))) {
		struct module *calling_mod = module_text_address(called_from);
		/* We must allow modules to probe themself and
		 * in this case avoid incrementing the module refcount,
		 * so as to allow unloading of self probing modules.
		 */
		if (calling_mod && (calling_mod != probed_mod)) {
			if (unlikely(!try_module_get(probed_mod)))
				return -EINVAL;
			p->mod_refcounted = 1;
		} else
			probed_mod = NULL;
	}

	p->nmissed = 0;
	INIT_LIST_HEAD(&p->list);
	mutex_lock(&kprobe_mutex);
	old_p = get_kprobe(p->addr);
	if (old_p) {
		ret = register_aggr_kprobe(old_p, p);
		if (!ret)
			atomic_inc(&kprobe_count);
		goto out;
	}

	if ((ret = arch_prepare_kprobe(p)) != 0)
		goto out;

	INIT_HLIST_NODE(&p->hlist);
	hlist_add_head_rcu(&p->hlist,
		       &kprobe_table[hash_ptr(p->addr, KPROBE_HASH_BITS)]);

	if (atomic_add_return(1, &kprobe_count) == \
				(ARCH_INACTIVE_KPROBE_COUNT + 1))
		register_page_fault_notifier(&kprobe_page_fault_nb);

	arm_kprobe(p);

	/* Try to optimize kprobe */
	try_to_optimize_kprobe(p);

out:
	mutex_unlock(&kprobe_mutex);

	if (ret && probed_mod)
		module_put(probed_mod);
	return ret;
}

/*
 * Unregister a kprobe without a scheduler synchronization.
 */
static int __kprobes __unregister_kprobe_top(struct kprobe *p)
{
	struct kprobe *old_p, *list_p;

	old_p = get_kprobe(p->addr);
	if (unlikely(!old_p))
		return -EINVAL;

	if (p != old_p) {
		list_for_each_entry_rcu(list_p, &old_p->list, list)
			if (list_p == p)
			/* kprobe p is a valid probe */
				goto valid_p;
		return -EINVAL;
	}
valid_p:
	if ((old_p == p) || (kprobe_aggrprobe(old_p) &&
		list_is_singular(&old_p->list))) {
		/* Only probe on the hash list */
		disarm_kprobe(old_p);
		hlist_del_rcu(&old_p->hlist);
	} else {
		if (p->break_handler)
			old_p->break_handler = NULL;
		if (p->post_handler) {
			list_for_each_entry_rcu(list_p, &old_p->list, list) {
				if ((list_p != p) && (list_p->post_handler))
					goto noclean;
			}
			old_p->post_handler = NULL;
		}
noclean:
		list_del_rcu(&p->list);
	}
	return 0;
}

static void __kprobes __unregister_kprobe_bottom(struct kprobe *p)
{
	struct module *mod;
	struct kprobe *old_p;

	if (p->mod_refcounted &&
	    (mod = module_text_address((unsigned long)p->addr)))
		module_put(mod);

	if (list_empty(&p->list) || list_is_singular(&p->list)) {
		if (!list_empty(&p->list)) {
			/* "p" is the last child of an aggr_kprobe */
			old_p = list_entry(p->list.next, struct kprobe, list);
			list_del(&p->list);
			free_aggr_kprobe(old_p);
		}
		arch_remove_kprobe(p);
	}

	/* Call unregister_page_fault_notifier()
	 * if no probes are active
	 */
	mutex_lock(&kprobe_mutex);
	if (atomic_add_return(-1, &kprobe_count) == \
				ARCH_INACTIVE_KPROBE_COUNT)
		unregister_page_fault_notifier(&kprobe_page_fault_nb);
	mutex_unlock(&kprobe_mutex);
	return;
}

static int __register_kprobes(struct kprobe **kps, int num,
		unsigned long called_from)
{
	int i, ret = 0;

	if (num <= 0)
		return -EINVAL;
	for (i = 0; i < num; i++) {
		ret = __register_kprobe(kps[i], called_from);
		if (ret < 0) {
			if (i > 0)
				unregister_kprobes(kps, i);
			break;
		}
	}
	return ret;
}

/*
 * Registration and unregistration functions for kprobe.
 */
int __kprobes register_kprobe(struct kprobe *p)
{
	return __register_kprobes(&p, 1,
			(unsigned long)__builtin_return_address(0));
}

void __kprobes unregister_kprobe(struct kprobe *p)
{
	unregister_kprobes(&p, 1);
}

int __kprobes register_kprobes(struct kprobe **kps, int num)
{
	return __register_kprobes(kps, num,
			(unsigned long)__builtin_return_address(0));
}

void __kprobes unregister_kprobes(struct kprobe **kps, int num)
{
	int i;

	if (num <= 0)
		return;
	mutex_lock(&kprobe_mutex);
	for (i = 0; i < num; i++)
		if (__unregister_kprobe_top(kps[i]) < 0)
			kps[i]->addr = NULL;
	mutex_unlock(&kprobe_mutex);

	synchronize_sched();
	for (i = 0; i < num; i++)
		if (kps[i]->addr)
			__unregister_kprobe_bottom(kps[i]);
}

static struct notifier_block kprobe_exceptions_nb = {
	.notifier_call = kprobe_exceptions_notify,
	.priority = 0x7fffffff /* we need to be notified first */
};

unsigned long __attribute__((weak)) arch_deref_entry_point(void *entry)
{
	return (unsigned long)entry;
}

static int __register_jprobes(struct jprobe **jps, int num,
	unsigned long called_from)
{
	struct jprobe *jp;
	int ret = 0, i;

	if (num <= 0)
		return -EINVAL;
	for (i = 0; i < num; i++) {
		unsigned long addr;
		jp = jps[i];
		addr = arch_deref_entry_point(jp->entry);

		if (!kernel_text_address(addr))
			ret = -EINVAL;
		else {
			/* Todo: Verify probepoint is a function entry point */
			jp->kp.pre_handler = setjmp_pre_handler;
			jp->kp.break_handler = longjmp_break_handler;
			ret = __register_kprobe(&jp->kp, called_from);
		}
		if (ret < 0) {
			if (i > 0)
				unregister_jprobes(jps, i);
			break;
		}
	}
	return ret;
}

int __kprobes register_jprobe(struct jprobe *jp)
{
	return __register_jprobes(&jp, 1,
		(unsigned long)__builtin_return_address(0));
}

void __kprobes unregister_jprobe(struct jprobe *jp)
{
	unregister_jprobes(&jp, 1);
}

int __kprobes register_jprobes(struct jprobe **jps, int num)
{
	return __register_jprobes(jps, num,
		(unsigned long)__builtin_return_address(0));
}

void __kprobes unregister_jprobes(struct jprobe **jps, int num)
{
	int i;

	if (num <= 0)
		return;
	mutex_lock(&kprobe_mutex);
	for (i = 0; i < num; i++)
		if (__unregister_kprobe_top(&jps[i]->kp) < 0)
			jps[i]->kp.addr = NULL;
	mutex_unlock(&kprobe_mutex);

	synchronize_sched();
	for (i = 0; i < num; i++) {
		if (jps[i]->kp.addr)
			__unregister_kprobe_bottom(&jps[i]->kp);
	}
}

#ifdef ARCH_SUPPORTS_KRETPROBES

/*
 * This kprobe pre_handler is registered with every kretprobe. When probe
 * hits it will set up the return probe.
 */
static int __kprobes pre_handler_kretprobe(struct kprobe *p,
					   struct pt_regs *regs)
{
	struct kretprobe *rp = container_of(p, struct kretprobe, kp);
	unsigned long flags = 0;

	/*TODO: consider to only swap the RA after the last pre_handler fired */
	spin_lock_irqsave(&kretprobe_lock, flags);
	arch_prepare_kretprobe(rp, regs);
	spin_unlock_irqrestore(&kretprobe_lock, flags);
	return 0;
}

static int __kprobes __register_kretprobe(struct kretprobe *rp,
					  unsigned long called_from)
{
	int ret = 0;
	struct kretprobe_instance *inst;
	int i;
	void *addr;

	if (kretprobe_blacklist_size) {
		addr = kprobe_addr(&rp->kp);
		if (!addr)
			return -EINVAL;

		for (i = 0; kretprobe_blacklist[i].name != NULL; i++) {
			if (kretprobe_blacklist[i].addr == addr)
				return -EINVAL;
		}
	}

	rp->kp.pre_handler = pre_handler_kretprobe;
	rp->kp.post_handler = NULL;
	rp->kp.fault_handler = NULL;
	rp->kp.break_handler = NULL;

	/* Pre-allocate memory for max kretprobe instances */
	if (rp->maxactive <= 0) {
#ifdef CONFIG_PREEMPT
		rp->maxactive = max(10, 2 * NR_CPUS);
#else
		rp->maxactive = NR_CPUS;
#endif
	}
	INIT_HLIST_HEAD(&rp->used_instances);
	INIT_HLIST_HEAD(&rp->free_instances);
	for (i = 0; i < rp->maxactive; i++) {
		inst = kmalloc(sizeof(struct kretprobe_instance), GFP_KERNEL);
		if (inst == NULL) {
			free_rp_inst(rp);
			return -ENOMEM;
		}
		INIT_HLIST_NODE(&inst->uflist);
		hlist_add_head(&inst->uflist, &rp->free_instances);
	}

	rp->nmissed = 0;
	/* Establish function entry probe point */
	ret = __register_kprobe(&rp->kp, called_from);
	if (ret != 0)
		free_rp_inst(rp);
	return ret;
}

static int __register_kretprobes(struct kretprobe **rps, int num,
		unsigned long called_from)
{
	int ret = 0, i;

	if (num <= 0)
		return -EINVAL;
	for (i = 0; i < num; i++) {
		ret = __register_kretprobe(rps[i], called_from);
		if (ret < 0) {
			if (i > 0)
				unregister_kretprobes(rps, i);
			break;
		}
	}
	return ret;
}

int __kprobes register_kretprobe(struct kretprobe *rp)
{
	return __register_kretprobes(&rp, 1,
			(unsigned long)__builtin_return_address(0));
}

void __kprobes unregister_kretprobe(struct kretprobe *rp)
{
	unregister_kretprobes(&rp, 1);
}

int __kprobes register_kretprobes(struct kretprobe **rps, int num)
{
	return __register_kretprobes(rps, num,
			(unsigned long)__builtin_return_address(0));
}

void __kprobes unregister_kretprobes(struct kretprobe **rps, int num)
{
	int i;

	if (num <= 0)
		return;
	mutex_lock(&kprobe_mutex);
	for (i = 0; i < num; i++)
		if (__unregister_kprobe_top(&rps[i]->kp) < 0)
			rps[i]->kp.addr = NULL;
	mutex_unlock(&kprobe_mutex);

	synchronize_sched();
	for (i = 0; i < num; i++) {
		if (rps[i]->kp.addr) {
			__unregister_kprobe_bottom(&rps[i]->kp);
			cleanup_rp_inst(rps[i]);
		}
	}
}

#else /* ARCH_SUPPORTS_KRETPROBES */

int __kprobes register_kretprobe(struct kretprobe *rp)
{
	return -ENOSYS;
}

int __kprobes register_kretprobes(struct kretprobe **rps, int num)
{
		return -ENOSYS;
}
void __kprobes unregister_kretprobe(struct kretprobe *rp)
{
}

void __kprobes unregister_kretprobes(struct kretprobe **rps, int num)
{
}

static int __kprobes pre_handler_kretprobe(struct kprobe *p,
							   struct pt_regs *regs)
{
		return 0;
}

#endif /* ARCH_SUPPORTS_KRETPROBES */

void __kprobes dump_kprobe(struct kprobe *kp)
{
	printk(KERN_WARNING "Dumping kprobe:\n");
	printk(KERN_WARNING "Name: %s\nAddress: %p\nOffset: %x\n",
	       kp->symbol_name, kp->addr, kp->offset);
}

static int __init init_kprobes(void)
{
	int i, err = 0;

	/* FIXME allocate the probe table, currently defined statically */
	/* initialize all list heads */
	for (i = 0; i < KPROBE_TABLE_SIZE; i++) {
		INIT_HLIST_HEAD(&kprobe_table[i]);
		INIT_HLIST_HEAD(&kretprobe_inst_table[i]);
	}

	if (kretprobe_blacklist_size) {
		/* lookup the function address from its name */
		for (i = 0; kretprobe_blacklist[i].name != NULL; i++) {
			kprobe_lookup_name(kretprobe_blacklist[i].name,
					   kretprobe_blacklist[i].addr);
			if (!kretprobe_blacklist[i].addr)
				printk("kretprobe: lookup failed: %s\n",
					kretprobe_blacklist[i].name);
		}
	}

#if defined(CONFIG_OPTPROBES)
#if defined(__ARCH_WANT_KPROBES_INSN_SLOT)
	/* Init kprobe_optinsn_slots */
	kprobe_optinsn_slots.insn_size = MAX_OPTINSN_SIZE;
#endif
	/* By default, kprobes can be optimized */
	kprobes_allow_optimization = true;
#endif

	atomic_set(&kprobe_count, 0);

	err = arch_init_kprobes();
	if (!err)
		err = register_die_notifier(&kprobe_exceptions_nb);

	return err;
}

__initcall(init_kprobes);

EXPORT_SYMBOL_GPL(register_kprobe);
EXPORT_SYMBOL_GPL(unregister_kprobe);
EXPORT_SYMBOL_GPL(register_kprobes);
EXPORT_SYMBOL_GPL(unregister_kprobes);
EXPORT_SYMBOL_GPL(register_jprobe);
EXPORT_SYMBOL_GPL(unregister_jprobe);
EXPORT_SYMBOL_GPL(register_jprobes);
EXPORT_SYMBOL_GPL(unregister_jprobes);
EXPORT_SYMBOL_GPL(jprobe_return);
EXPORT_SYMBOL_GPL(register_kretprobe);
EXPORT_SYMBOL_GPL(unregister_kretprobe);
EXPORT_SYMBOL_GPL(register_kretprobes);
EXPORT_SYMBOL_GPL(unregister_kretprobes);
