/*  KVM paravirtual clock driver. A clocksource implementation
    Copyright (C) 2008 Glauber de Oliveira Costa, Red Hat Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <linux/clocksource.h>
#include <linux/kvm_para.h>
#include <asm/pvclock.h>
#ifdef CONFIG_X86_32
#include <asm/arch_hooks.h>
#endif
#include <asm/msr.h>
#include <asm/apic.h>
#include <linux/percpu.h>

#define KVM_SCALE 22

static int kvmclock = 1;

unsigned int use_kvm_time = 0; /* RHEL specific */

static int parse_no_kvmclock(char *arg)
{
	kvmclock = 0;
	return 0;
}
early_param("no-kvmclock", parse_no_kvmclock);

/* The hypervisor will put information about time periodically here */
static DEFINE_PER_CPU(struct pvclock_vcpu_time_info, hv_clock);
static struct pvclock_wall_clock wall_clock;

/*
 * The wallclock is the time of day when we booted. Since then, some time may
 * have elapsed since the hypervisor wrote the data. So we try to account for
 * that with system time
 */
unsigned long kvm_get_wallclock(void)
{
	struct pvclock_vcpu_time_info *vcpu_time;
	struct timespec ts;
	int low, high;

	low = (int)__pa_symbol(&wall_clock);
	high = ((u64)__pa_symbol(&wall_clock) >> 32);
	wrmsr(MSR_KVM_WALL_CLOCK, low, high);

	vcpu_time = &get_cpu_var(hv_clock);
	pvclock_read_wallclock(&wall_clock, vcpu_time, &ts);
	put_cpu_var(hv_clock);

	return ts.tv_sec;
}

cycle_t kvm_clock_read(void)
{
	struct pvclock_vcpu_time_info *src;
	cycle_t ret;

	src = &get_cpu_var(hv_clock);
	ret = pvclock_clocksource_read(src);
	put_cpu_var(hv_clock);
	return ret;
}

#ifdef CONFIG_X86_32
static struct clocksource kvm_clock = {
	.name = "kvm-clock",
	.read = kvm_clock_read,
	.rating = 400,
	.mask = CLOCKSOURCE_MASK(64),
	.mult = 1 << KVM_SCALE,
	.shift = KVM_SCALE,
	.is_continuous = 1,
};
#endif

int kvm_register_clock(char *txt)
{
	int cpu = smp_processor_id();
	int low, high;
	/* upstream kernel does not use this, because the smp_ops structure
	 * guarantees it won't be called at all when disabled
	 */
	if (use_kvm_time == 0)
		return 0;
	low = (int)__pa(&per_cpu(hv_clock, cpu)) | 1;
	high = ((u64)__pa(&per_cpu(hv_clock, cpu)) >> 32);
	printk(KERN_INFO "kvm-clock: cpu %d, msr %x:%x, %s\n",
	       cpu, high, low, txt);
	return wrmsr_safe(MSR_KVM_SYSTEM_TIME, low, high);
}

/* warning: thus function is not upstream. Upstream does it through machine_ops,
 * which we lack. It exists to avoid exposing kvmclock related structures throughout
 * the rest of our kernel code - glommer
 */
void kvmclock_disable(void)
{
	if (use_kvm_time > 0)
		wrmsr(MSR_KVM_SYSTEM_TIME, 0, 0);
}
void __cpuinit kvmclock_init(void)
{
	if (!kvm_para_available())
		return;

	if (kvmclock && kvm_para_has_feature(KVM_FEATURE_CLOCKSOURCE)) {
		use_kvm_time = 1;
		if (kvm_register_clock("boot clock")) {
			use_kvm_time = 0;
			return;
		}
#ifdef CONFIG_X86_32
		clocksource_register(&kvm_clock);
#endif
	}
}
