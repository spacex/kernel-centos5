/*
 * Common hypervisor code
 *
 * Copyright (C) 2008, VMware, Inc.
 * Author : Alok N Kataria <akataria@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kvm_para.h>
#include <asm/processor.h>
#include <asm/vmware.h>
#include <asm/generic-hypervisor.h>
#include <linux/jiffies.h>

static inline void __cpuinit
detect_hypervisor_vendor(struct cpuinfo_x86 *c)
{
	if (vmware_platform()) {
		c->x86_hyper_vendor = X86_HYPER_VENDOR_VMWARE;
	} else if (kvm_para_available()) {
		c->x86_hyper_vendor = X86_HYPER_VENDOR_KVM;
	} else {
		c->x86_hyper_vendor = X86_HYPER_VENDOR_NONE;
	}
}

unsigned long get_hypervisor_tsc_freq(void)
{
	if (boot_cpu_data.x86_hyper_vendor == X86_HYPER_VENDOR_VMWARE)
		return vmware_get_tsc_khz();
	if (boot_cpu_data.x86_hyper_vendor == X86_HYPER_VENDOR_KVM)
		return kvm_get_tsc_khz();
	return 0;
}

cycles_t get_hypervisor_cycles_per_tick(void)
{
	/* Same thing for VMware or baremetal, in case we force it */
	cycles_t cycles_per_tick = cpu_khz * 1000ULL;
	do_div(cycles_per_tick, REAL_HZ);
	return cycles_per_tick;
}

static inline void __cpuinit
hypervisor_set_feature_bits(struct cpuinfo_x86 *c)
{
	if (boot_cpu_data.x86_hyper_vendor == X86_HYPER_VENDOR_VMWARE) {
		vmware_set_feature_bits(c);
		return;
	}
}

extern cycles_t cycles_per_tick, cycles_accounted_limit, last_tsc_accounted;
extern int timekeeping_use_tsc;

void init_tsc_timer(void)
{
	if (timekeeping_use_tsc > 0) {
#ifdef __i386__
		extern int enable_tsc_timer;
		enable_tsc_timer = 1;
		rdtscll(last_tsc_accounted);
#else
		tick_nsec = NSEC_PER_SEC / HZ;
#endif
		if (use_kvm_time) /* KVM time is already in nanoseconds units */
			cycles_per_tick = 1000000000 / REAL_HZ;
		else
			cycles_per_tick = get_hypervisor_cycles_per_tick();
		/*
		 * The maximum cycles we will account per
		 * timer interrupt is 1 minute.
		 */
		cycles_accounted_limit = cycles_per_tick * REAL_HZ * 60;
		printk(KERN_INFO "Using TSC for driving interrupts\n");
	}
}

void __cpuinit init_hypervisor(struct cpuinfo_x86 *c)
{
	detect_hypervisor_vendor(c);
	hypervisor_set_feature_bits(c);
}
