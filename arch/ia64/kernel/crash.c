/*
 * arch/ia64/kernel/crash.c
 *
 * Architecture specific (ia64) functions for kexec based crash dumps.
 *
 * Created by: Khalid Aziz <khalid.aziz@hp.com>
 * Copyright (C) 2005 Hewlett-Packard Development Company, L.P.
 * Copyright (C) 2005 Intel Corp	Zou Nan hai <nanhai.zou@intel.com>
 *
 */
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/crash_dump.h>
#include <linux/bootmem.h>
#include <linux/kexec.h>
#include <linux/elfcore.h>
#include <linux/sysctl.h>
#include <linux/init.h>

#include <asm/kdebug.h>
#include <asm/mca.h>
#include <asm/uaccess.h>

int kdump_status[NR_CPUS];
atomic_t kdump_cpu_freezed;
int kdump_on_init = 1;
atomic_t kdump_in_progress;
static int kdump_freeze_monarch;

ssize_t
copy_oldmem_page(unsigned long pfn, char *buf,
		size_t csize, unsigned long offset, int userbuf)
{
	void  *vaddr;

	if (!csize)
		return 0;
	vaddr = __va(pfn<<PAGE_SHIFT);
	if (userbuf) {
		if (copy_to_user(buf, (vaddr + offset), csize)) {
			return -EFAULT;
		}
	} else
		memcpy(buf, (vaddr + offset), csize);
	return csize;
}

static inline Elf64_Word
*append_elf_note(Elf64_Word *buf, char *name, unsigned type, void *data,
		size_t data_len)
{
	struct elf_note *note = (struct elf_note *)buf;
	note->n_namesz = strlen(name) + 1;
	note->n_descsz = data_len;
	note->n_type   = type;
	buf += (sizeof(*note) + 3)/4;
	memcpy(buf, name, note->n_namesz);
	buf += (note->n_namesz + 3)/4;
	memcpy(buf, data, data_len);
	buf += (data_len + 3)/4;
	return buf;
}

static void
final_note(void *buf)
{
	memset(buf, 0, sizeof(struct elf_note));
}

extern void ia64_dump_cpu_regs(void *);

static DEFINE_PER_CPU(struct elf_prstatus, elf_prstatus);

void
crash_save_this_cpu()
{
	void *buf;
	unsigned long cfm, sof, sol;

	int cpu = smp_processor_id();
	struct elf_prstatus *prstatus = &per_cpu(elf_prstatus, cpu);

	elf_greg_t *dst = (elf_greg_t *)&(prstatus->pr_reg);
	memset(prstatus, 0, sizeof(*prstatus));
	prstatus->pr_pid = current->pid;

	ia64_dump_cpu_regs(dst);
	cfm = dst[43];
	sol = (cfm >> 7) & 0x7f;
	sof = cfm & 0x7f;
	dst[46] = (unsigned long)ia64_rse_skip_regs((unsigned long *)dst[46],
			sof - sol);

	buf = (u64 *) per_cpu_ptr(crash_notes, cpu);
	if (!buf)
		return;
	buf = append_elf_note(buf, "CORE", NT_PRSTATUS, prstatus,
			sizeof(*prstatus));
	final_note(buf);
}

static int
kdump_wait_cpu_freeze(void)
{
	int cpu_num = num_online_cpus() - 1;
	int timeout = 1000;
	while(timeout-- > 0) {
		if (atomic_read(&kdump_cpu_freezed) == cpu_num)
			return 0;
		udelay(1000);
	}
	return 1;
}

static int kdump_sending_init;

void
machine_crash_shutdown(struct pt_regs *pt)
{
	/* This function is only called after the system
	 * has paniced or is otherwise in a critical state.
	 * The minimum amount of code to allow a kexec'd kernel
	 * to run successfully needs to happen here.
	 *
	 * In practice this means shooting down the other cpus in
	 * an SMP system.
	 */
	kexec_disable_iosapic();
#ifdef CONFIG_SMP
	/*
	 * If kdump_on_init is set and an INIT is asserted here, kdump will
	 * be started again via INIT monarch.
	 */
	local_irq_disable();
	ia64_set_psr_mc();	/* mask MCA/INIT */
	if (atomic_inc_return(&kdump_in_progress) != 1)
		unw_init_running(kdump_cpu_freeze, NULL);

	/*
	 * Now this cpu is ready for kdump.
	 * Stop all others by IPI or INIT.  They could receive INIT from
	 * outside and might be INIT monarch, but only thing they have to
	 * do is falling into kdump_cpu_freeze().
	 *
	 * If an INIT is asserted here:
	 * - All receivers might be slaves, since some of cpus could already
	 *   be frozen and INIT might be masked on monarch.  In this case,
	 *   all slaves will be frozen soon since kdump_in_progress will let
	 *   them into DIE_INIT_SLAVE_LEAVE.
	 * - One might be a monarch, but INIT rendezvous will fail since
	 *   at least this cpu already have INIT masked so it never join
	 *   to the rendezvous.  In this case, all slaves and monarch will
	 *   be frozen soon with no wait since the INIT rendezvous is skipped
	 *   by kdump_in_progress.
	 */
	kdump_smp_send_stop();
	if (kdump_wait_cpu_freeze()) {
		kdump_smp_send_init();
		/* wait again, don't go ahead if possible */
		kdump_wait_cpu_freeze();
	}

#endif
}

static void
machine_kdump_on_init(void)
{
	crash_save_vmcoreinfo();
	local_irq_disable();
	kexec_disable_iosapic();
	machine_kexec(ia64_kimage);
}

void
kdump_cpu_freeze(struct unw_frame_info *info, void *arg)
{
	int cpuid = smp_processor_id();

	local_irq_disable();
	crash_save_this_cpu();
	current->thread.ksp = (__u64)info->sw - 16;
	ia64_set_psr_mc();      /* mask MCA/INIT and stop reentrance */
	atomic_inc(&kdump_cpu_freezed);
	kdump_status[cpuid] = 1;
	mb();
	for (;;)
		cpu_relax();
}

static int
kdump_init_notifier(struct notifier_block *self, unsigned long val, void *data)
{
	struct ia64_mca_notify_die *nd;
	struct die_args *args = data;

	if (atomic_read(&kdump_in_progress)) {
		switch (val) {
		case DIE_INIT_MONARCH_LEAVE:
			if (!kdump_freeze_monarch)
				break;
			/* fall through */
		case DIE_INIT_SLAVE_LEAVE:
		case DIE_INIT_MONARCH_ENTER:
		case DIE_MCA_RENDZVOUS_LEAVE:
			unw_init_running(kdump_cpu_freeze, NULL);
			break;
		}
	}

	if (!kdump_on_init)
		return NOTIFY_DONE;

	if (!ia64_kimage) {
		if (val == DIE_INIT_MONARCH_LEAVE)
			printk(KERN_NOTICE
				"%s: kdump not configured\n",
				__FUNCTION__);
		return NOTIFY_DONE;
	}

	if (val != DIE_INIT_MONARCH_LEAVE &&
	    val != DIE_INIT_MONARCH_PROCESS &&
	    val != DIE_MCA_MONARCH_LEAVE)
		return NOTIFY_DONE;

	nd = (struct ia64_mca_notify_die *)args->err;

	if (kdump_sending_init)
		unw_init_running(kdump_cpu_freeze, NULL);

	switch (val) {
		case DIE_INIT_MONARCH_PROCESS:
			/* Reason code 1 means machine check rendezvous*/
			if (kdump_on_init && (nd->sos->rv_rc != 1)) {
				if (atomic_inc_return(&kdump_in_progress) != 1)
					kdump_freeze_monarch = 1;
			}
			break;
		case DIE_INIT_MONARCH_LEAVE:
			/* Reason code 1 means machine check rendezvous*/
			if (kdump_on_init && (nd->sos->rv_rc != 1))
				machine_kdump_on_init();
			break;
		case DIE_MCA_MONARCH_LEAVE:
			if (atomic_read(&kdump_in_progress) == 1)
				machine_kdump_on_init();
			/* We got fatal MCA while kdump!? No way!! */
			break;
	}
	return NOTIFY_DONE;
}

#ifdef CONFIG_SYSCTL
static ctl_table kdump_on_init_table[] = {
	{
		.ctl_name = KERN_KDUMP_ON_INIT,
		.procname = "kdump_on_init",
		.data = &kdump_on_init,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = &proc_dointvec,
	},
	{ .ctl_name = 0 }
};

static ctl_table sys_table[] = {
	{
	  .ctl_name = CTL_KERN,
	  .procname = "kernel",
	  .mode = 0555,
	  .child = kdump_on_init_table,
	},
	{ .ctl_name = 0 }
};
#endif

static int
machine_crash_setup(void)
{
	char *from = strstr(saved_command_line, "elfcorehdr=");
	/* be notified before default_monarch_init_process */
	static struct notifier_block kdump_init_notifier_nb = {
		.notifier_call = kdump_init_notifier,
		.priority = 1,
	};
	int ret;
	if (from)
		elfcorehdr_addr = memparse(from+11, &from);
	saved_max_pfn = (unsigned long)-1;
	if((ret = register_die_notifier(&kdump_init_notifier_nb)) != 0)
		return ret;
#ifdef CONFIG_SYSCTL
	register_sysctl_table(sys_table, 0);
#endif
	return 0;
}

__initcall(machine_crash_setup);

