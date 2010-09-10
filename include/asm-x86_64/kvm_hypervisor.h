
/*  Stripped down version of kvmclock.
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

#include <asm/kvm_para.h>
#include <asm/pvclock-abi.h>
#include <linux/bootmem.h>
#include <asm/msr.h>
#include <asm/apic.h>

static inline unsigned long pvclock_tsc_khz(struct pvclock_vcpu_time_info *src)
{
        u64 pv_tsc_khz = 1000000ULL << 32;

        do_div(pv_tsc_khz, src->tsc_to_system_mul);
        if (src->tsc_shift < 0)
                pv_tsc_khz <<= -src->tsc_shift;
        else
                pv_tsc_khz >>= src->tsc_shift;
        return pv_tsc_khz;
}

static inline unsigned long kvm_get_tsc_khz(void)
{
	int cpu = smp_processor_id();
	int low, high;
	unsigned long kvm_tsc_khz;
	struct pvclock_vcpu_time_info *hv_clock;

	if (!kvm_para_has_feature(KVM_FEATURE_CLOCKSOURCE))
		return 0;

	hv_clock = alloc_bootmem_pages(PAGE_SIZE);
	if (!hv_clock)
		return 0;

	low = (int)__pa(hv_clock) | 1;
	high = ((u64)__pa(hv_clock) >> 32);
	printk(KERN_INFO "%s: cpu %d, msr %x:%x\n", __func__,
	       cpu, high, low);

	if (wrmsr_safe(MSR_KVM_SYSTEM_TIME, low, high)) {
		printk(KERN_ERR "%s: MSR_KVM_SYSTEM_TIME init failure\n",
				__func__);
		free_bootmem(__pa(hv_clock), PAGE_SIZE);
		return 0;
	}

	kvm_tsc_khz = pvclock_tsc_khz(hv_clock);

	if (wrmsr_safe(MSR_KVM_SYSTEM_TIME, 0, 0))
		printk(KERN_ERR "%s: MSR_KVM_SYSTEM_TIME shutdown failure\n",
				__func__);
	else
		free_bootmem(__pa(hv_clock), PAGE_SIZE);

	return kvm_tsc_khz;
}

